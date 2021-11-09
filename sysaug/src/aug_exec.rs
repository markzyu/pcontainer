use crate::aug_common::{calc_real_path, notify_mods_about_path, path_from_bytes};
use crate::common;
use crate::common::{SysAugError, SyscallInfo};
use crate::handler::TraceeHandler;
use crate::mods::PathAction;
use ptrace::{GenericPurposeRegs, USIZE_SIZE};
use std::io::{BufRead, Read, Seek};
use std::os::unix::ffi::OsStrExt;
use std::sync::Arc;
use tracing::{event, Level};

pub struct AugmentExec<PtraceClient: executor::PtraceClient> {
    pub handler: Arc<TraceeHandler<PtraceClient>>,
}

impl<PtraceClient: executor::PtraceClient> common::AugmentSyscall for AugmentExec<PtraceClient> {
    fn before_call(
        &self,
        mut regs: GenericPurposeRegs,
        syscall: &SyscallInfo,
    ) -> Result<(), SysAugError> {
        let pid = self.handler.pid;
        if !self.expand_exec_with_parser(&mut regs, syscall)? {
            self.handler.skip_syscall(-libc::ENOENT as usize)?;
            return Ok(());
        }
        self.handler
            .ptrace_client
            .execute(move || ptrace::setregs(pid, regs))??;
        Ok(())
    }

    fn after_call(
        &self,
        _regs: GenericPurposeRegs,
        _syscall: &SyscallInfo,
    ) -> Result<(), SysAugError> {
        Ok(())
    }
}

impl<PtraceClient: executor::PtraceClient> AugmentExec<PtraceClient> {
    pub fn new(handler: Arc<TraceeHandler<PtraceClient>>) -> Self {
        AugmentExec { handler }
    }

    fn expand_exec_with_parser(
        &self,
        regs: &mut GenericPurposeRegs,
        syscall: &SyscallInfo,
    ) -> Result<bool, SysAugError> {
        // If the file doesn't exist or isn't elf, just skip that file (return false).
        // Otherwise, return true.
        // TODO: in the future, only skip if the file doesn't exist. If it's of unknown file type, don't execute it.
        let pid = self.handler.pid;
        let ptrace_client = &self.handler.ptrace_client;

        let arg0 = regs.arg0;
        let arg1 = regs.arg1;
        let path_bytes =
            ptrace_client.execute(move || ptrace::read_bytes_until_zero(pid, arg0))??;
        let argv_bytes = ptrace_client
            .execute(move || ptrace::read_bytes_until_num_zeroes(pid, arg1, *USIZE_SIZE))??;

        // Translate elf path to real path
        let elf_path_buf = path_from_bytes(path_bytes)?;
        let mut new_elf_path = elf_path_buf.clone();
        {
            let path_action = calc_real_path(&self.handler, &new_elf_path, syscall)?;
            notify_mods_about_path(&self.handler, syscall, &new_elf_path, &path_action)?;
            if let PathAction::Override(new_path_val) = path_action {
                new_elf_path = new_path_val;
            }
        }

        if !new_elf_path.exists() {
            return Ok(false);
        }
        event!(Level::INFO, "Binary file: {:?}", new_elf_path);

        let mut file = std::fs::File::open(new_elf_path.as_path()).map_err(SysAugError::ReadBin)?;
        if let Ok(elf_file) = elf::File::open_stream(&mut file) {
            let header = elf_file
                .phdrs
                .iter()
                .find(|x| x.progtype.0 == libc::PT_INTERP)
                .unwrap();

            // READ interpreter path FROM header.offset FOR header.filesz BYTES
            let mut buf: Vec<u8> = vec![0; header.filesz as usize];
            file.seek(std::io::SeekFrom::Start(header.offset))
                .map_err(SysAugError::ReadBin)?;
            file.read_exact(buf.as_mut_slice())
                .map_err(SysAugError::ReadBin)?;

            // Calculate real path of interpreter
            let interp_path_buf = path_from_bytes(buf)?;
            let path_action = calc_real_path(&self.handler, &interp_path_buf, syscall)?;
            notify_mods_about_path(&self.handler, syscall, &interp_path_buf, &path_action)?;
            let mut new_interp_path = interp_path_buf;
            if let PathAction::Override(new_path_val) = path_action {
                new_interp_path = new_path_val;
            }
            event!(
                Level::INFO,
                "Setting ELF interpreter = {}, exe = {}",
                new_interp_path.to_string_lossy(),
                elf_path_buf.to_string_lossy(),
            );

            // Replace argv[0] = ld.so, argv[1] = elf.FAKEpath, argv[2:] = argv[1:]
            // TODO: Consider edge case: https://unix.stackexchange.com/questions/315812/why-does-argv-include-the-program-name
            let interp_str_size = new_interp_path.as_os_str().as_bytes().len() + *USIZE_SIZE;
            let interp_addr = ptrace_client.execute(move || {
                let final_bytes: &[u8] = new_interp_path.as_os_str().as_bytes();
                ptrace::bytes_to_stack(pid, 0, final_bytes)
            })??;
            let new_argv_len = argv_bytes.len() + *USIZE_SIZE;
            let mut new_argv: Vec<u8> = Vec::with_capacity(new_argv_len);
            new_argv.append(&mut interp_addr.to_ne_bytes().to_vec());
            new_argv.append(&mut regs.arg0.to_ne_bytes().to_vec());
            new_argv.append(&mut argv_bytes[*USIZE_SIZE..].to_vec());
            new_argv.append(&mut 0_usize.to_ne_bytes().to_vec());
            let new_argv_addr = ptrace_client.execute(move || {
                ptrace::bytes_to_stack(pid, ptrace::aligned(interp_str_size)?, &new_argv)
            })??;
            regs.arg0 = interp_addr;
            regs.arg1 = new_argv_addr;
            return Ok(true);
        } else if let Some(shebang) = self.parse_shebang(&mut file)? {
            event!(Level::DEBUG, "Script file: {:?}", new_elf_path);
            let parts: Vec<&str> = shebang.split(' ').collect();
            if parts.len() > 2 || parts.is_empty() {
                event!(
                    Level::ERROR,
                    "Cannot execute file {} because of invalid shebang: {:?}",
                    elf_path_buf.to_string_lossy(),
                    shebang,
                );
                return Ok(false);
            }
            let (part0, maybe_part1) = {
                let part0 = parts[0].to_string();
                let maybe_part1 = parts.get(1).map(|&x| x.to_string());
                (part0, maybe_part1)
            };
            let mut new_argv: Vec<u8> = Vec::new();

            event!(
                Level::INFO,
                "Setting shebang interpreter = {}, script = {}",
                part0,
                elf_path_buf.to_string_lossy(),
            );

            let mut skip = 8192;
            let part0_size = part0.as_bytes().len() + *USIZE_SIZE;
            let interp_addr = ptrace_client.execute(move || {
                let final_bytes: &[u8] = part0.as_bytes();
                ptrace::bytes_to_stack(pid, ptrace::aligned(skip)?, final_bytes)
            })??;
            new_argv.append(&mut interp_addr.to_ne_bytes().to_vec());
            skip += part0_size;

            if let Some(part1) = maybe_part1 {
                let part1_size = part1.as_bytes().len() + *USIZE_SIZE;
                let part1_addr = ptrace_client.execute(move || {
                    let final_bytes: &[u8] = part1.as_bytes();
                    ptrace::bytes_to_stack(pid, ptrace::aligned(skip)?, final_bytes)
                })??;
                new_argv.append(&mut part1_addr.to_ne_bytes().to_vec());
                skip += part1_size;
            }

            new_argv.append(&mut regs.arg0.to_ne_bytes().to_vec());
            new_argv.append(&mut argv_bytes[*USIZE_SIZE..].to_vec());
            new_argv.append(&mut 0_usize.to_ne_bytes().to_vec());
            let new_argv_addr = ptrace_client.execute(move || {
                ptrace::bytes_to_stack(pid, ptrace::aligned(skip)?, &new_argv)
            })??;
            regs.arg0 = interp_addr;
            regs.arg1 = new_argv_addr;
            return self.expand_exec_with_parser(regs, syscall);
        }
        event!(
            Level::ERROR,
            "Cannot execute file {} because we don't know what type of file it is",
            elf_path_buf.to_string_lossy(),
        );
        Ok(false)
    }

    fn parse_shebang(&self, file: &mut std::fs::File) -> Result<Option<String>, SysAugError> {
        file.seek(std::io::SeekFrom::Start(0))
            .map_err(SysAugError::ReadBin)?;
        let mut reader = std::io::BufReader::new(file);
        let mut line = String::new();
        reader.read_line(&mut line).map_err(SysAugError::ReadBin)?;
        Ok(if line.starts_with("#!") {
            Some(line[2..].trim().to_string())
        } else {
            None
        })
    }
}
