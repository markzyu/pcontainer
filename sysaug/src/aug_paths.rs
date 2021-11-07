use crate::common;
use crate::common::{SysAugError, SyscallInfo};
use crate::handler::TraceeHandler;
use crate::mods;
use crate::mods::PathAction;
use crate::rwoption_take_ok;
use ptrace::{GenericPurposeRegs, USIZE_SIZE};
use std::cell::RefCell;
use std::ffi::OsString;
use std::io::{BufRead, Read, Seek};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{event, Level};

const META_INIT: &'static str = "{}\n";

pub struct AugmentPaths<PtraceClient: executor::PtraceClient> {
    pub handler: Arc<TraceeHandler<PtraceClient>>,
}

impl<PtraceClient: executor::PtraceClient> common::AugmentSyscall for AugmentPaths<PtraceClient> {
    fn before_call(
        &self,
        mut regs: GenericPurposeRegs,
        syscall: &SyscallInfo,
    ) -> Result<(), SysAugError> {
        let pid = self.handler.pid;
        let ptrace_client = &self.handler.ptrace_client;

        // Translate paths from host namespace to tracee namespace
        let save_dirfd_path = self.get_dirfd_path(&regs, syscall)?;
        let mut possible_args = [&mut regs.arg0, &mut regs.arg1, &mut regs.arg2];
        let mut need_write_regs = false;
        let mut save_paths: [Option<PathBuf>; 3] = Default::default();
        for (i, ref_arg_i) in possible_args.iter_mut().enumerate() {
            if syscall.num == libc::SYS_execve as usize {
                continue;
            }
            let check_bit: usize = 1 << i;
            if (check_bit & syscall.path_positions) == 0 {
                continue;
            }
            let arg_i = **ref_arg_i;
            if **ref_arg_i == 0 {
                continue;
            }

            // Read orig_path from registers
            let path_bytes =
                ptrace_client.execute(move || ptrace::read_bytes_until_zero(pid, arg_i))??;
            let orig_path_buf = self.path_from_bytes(path_bytes)?;

            // Calculate path_action, notify mods, and maybe update tracee
            let path_action = self.calc_real_path(&orig_path_buf, syscall)?;
            self.notify_mods(syscall, &orig_path_buf, &path_action)?;
            if let PathAction::Override(new_path_val) = path_action {
                save_paths[i] = Some(new_path_val.clone());
                let addr = ptrace_client.execute(move || {
                    let final_bytes: &[u8] = new_path_val.as_os_str().as_bytes();
                    ptrace::bytes_to_stack(pid, final_bytes)
                })??;
                **ref_arg_i = addr;
                need_write_regs = true;
            } else {
                save_paths[i] = Some(orig_path_buf);
            }
        }

        // Handle getdents (make the buffer seem smaller)
        if syscall.getdents_bits.is_some() {
            regs.arg2 = regs.arg2 / 2;
            need_write_regs = true;
        }

        if syscall.num == libc::SYS_execve as usize {
            need_write_regs = self.expand_exec_with_parser(&mut regs, &syscall)?;
        }

        common::rwoption_replace(&self.handler.curr_paths, save_paths)?;
        common::rwoption_replace(&self.handler.curr_dirfd_path, save_dirfd_path)?;

        if need_write_regs {
            ptrace_client.execute(move || ptrace::setregs(pid, regs))??;
        }
        Ok(())
    }

    fn after_call(
        &self,
        regs: GenericPurposeRegs,
        syscall: &SyscallInfo,
    ) -> Result<(), SysAugError> {
        let paths = rwoption_take_ok!(self.handler.curr_paths)?;
        let dirfd_path = rwoption_take_ok!(self.handler.curr_dirfd_path)?;
        for maybe_path in paths.iter() {
            if let Some(path) = maybe_path {
                self.save_metadata_for_file(path, &dirfd_path)?;
            }
        }

        let retval = regs.syscall_retval();
        if retval as isize <= 0 {
            return Ok(());
        }
        match syscall.getdents_bits {
            Some(32) => self.replace_getdents_result::<Dirent>(syscall, regs)?,
            Some(64) => self.replace_getdents_result::<Dirent64>(syscall, regs)?,
            _ => (),
        };
        Ok(())
    }
}

impl<PtraceClient: executor::PtraceClient> AugmentPaths<PtraceClient> {
    fn path_from_bytes(&self, path_bytes: Vec<u8>) -> Result<PathBuf, SysAugError> {
        let path_osstr: OsString = OsStringExt::from_vec(path_bytes);
        Ok(path_osstr.into())
    }

    fn parse_shebang(&self, file: &mut std::fs::File) -> Result<Option<String>, SysAugError> {
        file.seek(std::io::SeekFrom::Start(0))
            .map_err(SysAugError::ReadBin)?;
        let mut reader = std::io::BufReader::new(file);
        let mut line = String::new();
        reader.read_line(&mut line).map_err(SysAugError::ReadBin)?;
        Ok(if line.starts_with("#!") {
            Some(line.trim().to_string())
        } else {
            None
        })
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
        let elf_path_buf = self.path_from_bytes(path_bytes)?;
        let mut new_elf_path = elf_path_buf;
        {
            let path_action = self.calc_real_path(&new_elf_path, syscall)?;
            self.notify_mods(syscall, &new_elf_path, &path_action)?;
            if let PathAction::Override(new_path_val) = path_action {
                new_elf_path = new_path_val;
            }
        }

        event!(Level::DEBUG, "Binary file: {:?}", new_elf_path);
        if !new_elf_path.exists() {
            return Ok(false);
        }

        let mut file = std::fs::File::open(new_elf_path.as_path()).map_err(SysAugError::ReadBin)?;
        if let Ok(elf_file) = elf::File::open_stream(&mut file) {
            let header = elf_file
                .phdrs
                .iter()
                .filter(|x| x.progtype.0 == libc::PT_INTERP)
                .nth(0)
                .unwrap();

            // READ interpreter path FROM header.offset FOR header.filesz BYTES
            let mut buf: Vec<u8> = Vec::with_capacity(header.filesz as usize);
            buf.resize(header.filesz as usize, 0);
            file.seek(std::io::SeekFrom::Start(header.offset))
                .map_err(SysAugError::ReadBin)?;
            file.read_exact(buf.as_mut_slice())
                .map_err(SysAugError::ReadBin)?;

            // Calculate real path of interpreter
            let interp_path_buf = self.path_from_bytes(buf)?;
            let path_action = self.calc_real_path(&interp_path_buf, syscall)?;
            self.notify_mods(syscall, &interp_path_buf, &path_action)?;
            let mut new_interp_path = interp_path_buf;
            if let PathAction::Override(new_path_val) = path_action {
                new_interp_path = new_path_val;
            }
            event!(
                Level::INFO,
                "Setting ELF interpreter = {}",
                new_interp_path.to_string_lossy(),
            );

            // Replace argv[0] = ld.so, argv[1] = elf.FAKEpath, argv[2:] = argv[1:]
            // TODO: Consider edge case: https://unix.stackexchange.com/questions/315812/why-does-argv-include-the-program-name
            let interp_str_size = new_interp_path.as_os_str().as_bytes().len() + *USIZE_SIZE;
            let interp_addr = ptrace_client.execute(move || {
                let final_bytes: &[u8] = new_interp_path.as_os_str().as_bytes();
                ptrace::bytes_to_stack(pid, final_bytes)
            })??;
            let new_argv_len = argv_bytes.len() + *USIZE_SIZE;
            let mut new_argv: Vec<u8> = Vec::with_capacity(new_argv_len);
            new_argv.append(&mut interp_addr.to_ne_bytes().to_vec());
            new_argv.append(&mut regs.arg0.to_ne_bytes().to_vec());
            new_argv.append(&mut argv_bytes[*USIZE_SIZE..].to_vec());
            new_argv.append(&mut 0_usize.to_ne_bytes().to_vec());
            let new_argv_addr = ptrace_client.execute(move || {
                ptrace::bytes_to_stack_with_skip(pid, &new_argv, interp_str_size)
            })??;
            regs.arg0 = interp_addr;
            regs.arg1 = new_argv_addr;
            return Ok(true);
        } else if let Some(shebang) = self.parse_shebang(&mut file)? {
            event!(Level::DEBUG, "Script file: {:?}", new_elf_path);
            let parts: Vec<&str> = shebang[2..].split(' ').collect();
            if parts.len() > 2 || parts.len() == 0 {
                return Ok(false);
            }
            let (part0, maybe_part1) = {
                let part0 = parts[0].to_string();
                let maybe_part1 = parts.get(1).map(|&x| x.to_string());
                (part0, maybe_part1)
            };
            let mut new_argv: Vec<u8> = Vec::new();

            let mut skip = 8192;
            let part0_size = part0.as_bytes().len() + *USIZE_SIZE;
            let interp_addr = ptrace_client.execute(move || {
                let final_bytes: &[u8] = part0.as_bytes();
                ptrace::bytes_to_stack_with_skip(pid, final_bytes, skip)
            })??;
            new_argv.append(&mut interp_addr.to_ne_bytes().to_vec());
            skip += part0_size;

            if let Some(part1) = maybe_part1 {
                let part1_size = part1.as_bytes().len() + *USIZE_SIZE;
                let part1_addr = ptrace_client.execute(move || {
                    let final_bytes: &[u8] = part1.as_bytes();
                    ptrace::bytes_to_stack_with_skip(pid, final_bytes, skip)
                })??;
                new_argv.append(&mut part1_addr.to_ne_bytes().to_vec());
                skip += part1_size;
            }

            new_argv.append(&mut regs.arg0.to_ne_bytes().to_vec());
            new_argv.append(&mut argv_bytes[*USIZE_SIZE..].to_vec());
            new_argv.append(&mut 0_usize.to_ne_bytes().to_vec());
            let new_argv_addr = ptrace_client
                .execute(move || ptrace::bytes_to_stack_with_skip(pid, &new_argv, skip))??;
            regs.arg0 = interp_addr;
            regs.arg1 = new_argv_addr;
            return self.expand_exec_with_parser(regs, &syscall);
        }
        Ok(false)
    }

    fn notify_mods(
        &self,
        syscall: &SyscallInfo,
        orig_path: &Path,
        path_action: &PathAction,
    ) -> Result<(), SysAugError> {
        self.handler.call_mods(mods::ModFeature::OnFilePath, |m| {
            m.on_file_path(orig_path, syscall)
        })?;
        let notify_path = match path_action {
            PathAction::Override(path) => path.as_path(),
            _ => orig_path,
        };
        event!(
            Level::DEBUG,
            "Translate {} -> {}",
            orig_path.to_string_lossy(),
            notify_path.to_string_lossy()
        );
        self.handler
            .call_mods(mods::ModFeature::OnFileRealPath, |m| {
                m.on_file_real_path(notify_path, syscall)
            })?;
        Ok(())
    }

    fn calc_real_path(
        &self,
        orig_path: &Path,
        syscall: &SyscallInfo,
    ) -> Result<PathAction, SysAugError> {
        let mut new_path = PathAction::None;
        let prefix_maybe = common::rwlock_read(&self.handler.states.path_prefix)?;
        if let Some(prefix) = prefix_maybe.as_ref() {
            if orig_path.is_absolute() {
                let val = prefix.as_path().join(orig_path.strip_prefix("/").unwrap());
                new_path = PathAction::Override(val);
            }
        }

        self.get_mod_path(syscall, orig_path, new_path, false)
    }

    fn get_dirfd_path(
        &self,
        regs: &GenericPurposeRegs,
        syscall: &SyscallInfo,
    ) -> Result<PathBuf, SysAugError> {
        if let Some(dirfd_reg) = syscall.dirfd_position {
            if dirfd_reg >= 3 {
                return Err(SysAugError::DirfdReg);
            }
            let possible_args = [&regs.arg0, &regs.arg1, &regs.arg2];
            let dirfd = *possible_args[dirfd_reg as usize] as libc::c_int;
            if dirfd != libc::AT_FDCWD {
                return Ok(procfs::getfd_path(self.handler.pid, dirfd as isize)?);
            }
        }
        // Otherwise, use cwd of tracee
        Ok(procfs::getcwd(self.handler.pid)?)
    }

    fn replace_getdents_result<T>(
        &self,
        syscall: &SyscallInfo,
        mut regs: GenericPurposeRegs,
    ) -> Result<(), SysAugError>
    where
        T: IDirent + Clone + Send + 'static,
    {
        let addr = regs.arg1;
        let buf_size = regs.arg2 * 2;
        let list_size = regs.syscall_retval();
        let pid = self.handler.pid;
        let ptrace_client = &self.handler.ptrace_client;
        let mut dirents: Vec<T> = ptrace_client
            .execute(move || ptrace::read_bytes_to_structs(pid, addr, list_size))??;
        event!(Level::DEBUG, "Intercepting {} dir entries", dirents.len());

        let mut is_delete: Vec<bool> = Vec::new();
        for entry in dirents.iter_mut() {
            event!(Level::TRACE, "Intercepting {:?}", entry);
            let orig_path_buf = self.path_from_bytes(entry.get_name().to_vec())?;
            let orig_path: &Path = &(orig_path_buf.as_path());
            let action = self.get_mod_path(syscall, orig_path, PathAction::None, true)?;
            // event!(Level::INFO, "Intercepting dir entry {:?} -> {:?}", orig_path, &action);
            let delete = match &action {
                PathAction::Override(override_path) => {
                    let bytes = override_path.as_os_str().as_bytes();
                    entry.get_name().fill(0);
                    for (i, byte) in bytes.iter().take_while(|x| **x != 0).enumerate() {
                        entry.get_name()[i] = *byte;
                    }
                    false
                }
                PathAction::HidePath => true,
                _ => false,
            };
            is_delete.push(delete);
        }

        let mut i = 0;
        dirents.retain(|_e| {
            let ans = is_delete[i];
            i += 1;
            !ans
        });

        let num_dirents = dirents.len();
        let num_bytes = ptrace_client
            .execute(move || ptrace::structs_to_tracee_buffer(pid, addr, buf_size, dirents, 2))??;
        event!(
            Level::DEBUG,
            "Returning {} dir entries, {} bytes",
            num_dirents,
            num_bytes
        );

        // Restore buffer size value so program doesn't reuse wrong values crash
        regs.arg2 = regs.arg2 * 2;
        regs.set_syscall_retval(num_bytes);
        ptrace_client.execute(move || ptrace::setregs(pid, regs))??;
        Ok(())
    }

    fn save_metadata_for_file(&self, path: &Path, dirfd_path: &Path) -> Result<(), SysAugError> {
        event!(
            Level::TRACE,
            "Checking metadata for: {:?}/{:?}",
            dirfd_path.to_string_lossy(),
            path.to_string_lossy()
        );
        let maybe_meta_path = self
            .handler
            .call_first_mod(mods::ModFeature::ResolveMetadataPath, |m| {
                m.resolve_metadata_path(path, dirfd_path)
            })?
            .flatten();
        if let Some(meta_path) = maybe_meta_path {
            event!(
                Level::TRACE,
                "Writing metadata file: {:?}",
                meta_path.to_string_lossy()
            );
            return match std::fs::write(meta_path, META_INIT) {
                Ok(_) => Ok(()),
                Err(e) => match e.kind() {
                    std::io::ErrorKind::PermissionDenied => Ok(()),
                    std::io::ErrorKind::NotFound => Ok(()),
                    _ => Err(SysAugError::WriteMetadata(e.to_string())),
                },
            };
        }
        Ok(())
    }

    // reverse: false = generating real paths on disk, true = generating fake paths from container
    // perspective
    fn get_mod_path(
        &self,
        syscall: &SyscallInfo,
        orig_path: &Path,
        initial_override: PathAction,
        reverse: bool,
    ) -> Result<PathAction, SysAugError> {
        let override_path: RefCell<PathAction> = RefCell::new(initial_override);
        let feature = if reverse {
            mods::ModFeature::OverrideFileFakePath
        } else {
            mods::ModFeature::OverrideFileRealPath
        };
        self.handler.call_mods(feature, |m| {
            let old_override = override_path.replace(PathAction::None);
            let curr_path = match &old_override {
                PathAction::Override(path) => path.as_path(),
                _ => orig_path,
            };
            let new_override = if reverse {
                m.override_file_fake_path(curr_path, syscall)?
            } else {
                m.override_file_real_path(curr_path, syscall)?
            };
            override_path.replace(if new_override == PathAction::None {
                old_override
            } else {
                new_override
            });
            Ok(mods::ModAction::None)
        })?;
        Ok(override_path.into_inner())
    }

    pub fn new(handler: Arc<TraceeHandler<PtraceClient>>) -> Self {
        AugmentPaths { handler }
    }
}

trait IDirent: ptrace::CStruct + std::fmt::Debug {
    fn get_name(&mut self) -> &mut [u8];
}

#[derive(Debug, Clone)]
#[repr(C)]
struct Dirent64 {
    pub inode: libc::ino64_t,
    pub offset: libc::off64_t,
    pub reclen: libc::c_ushort,
    pub type_: libc::c_uchar,
    pub name: [u8; 512],
}

#[derive(Debug, Clone)]
#[repr(C)]
struct Dirent64Header {
    pub inode: libc::ino64_t,
    pub offset: libc::off64_t,
    pub reclen: libc::c_ushort,
}

#[derive(Debug, Clone)]
#[repr(C)]
struct Dirent {
    pub inode: libc::ino_t,
    pub offset: libc::off_t,
    pub reclen: libc::c_ushort,
    pub name: [u8; 512],
}

#[derive(Debug, Clone)]
#[repr(C)]
struct DirentHeader {
    pub inode: libc::ino_t,
    pub offset: libc::off_t,
    pub reclen: libc::c_ushort,
}

impl IDirent for Dirent64 {
    fn get_name(&mut self) -> &mut [u8] {
        &mut self.name
    }
}
impl ptrace::CStruct for Dirent64 {
    type H = Dirent64Header;
}
impl ptrace::CHeader for Dirent64Header {
    fn item_size_deducer(&self) -> usize {
        self.reclen.into()
    }

    fn item_size_updater(&mut self, size: usize) -> () {
        self.reclen = size as u16;
    }
}

impl IDirent for Dirent {
    fn get_name(&mut self) -> &mut [u8] {
        &mut self.name
    }
}
impl ptrace::CStruct for Dirent {
    type H = DirentHeader;
}
impl ptrace::CHeader for DirentHeader {
    fn item_size_deducer(&self) -> usize {
        self.reclen.into()
    }

    fn item_size_updater(&mut self, size: usize) -> () {
        self.reclen = size as u16;
    }
}
