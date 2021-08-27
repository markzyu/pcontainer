use crate::common;
use crate::common::{SysAugError, SyscallInfo};
use crate::handler::TraceeHandler;
use crate::mods;
use crate::mods::PathAction;
use ptrace::GenericPurposeRegs;
use std::cell::RefCell;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
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

        let mut possible_args = [&mut regs.arg0, &mut regs.arg1, &mut regs.arg2];
        let mut need_write_regs = false;
        for (i, ref_arg_i) in possible_args.iter_mut().enumerate() {
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
            let path_osstr: &OsStr = OsStrExt::from_bytes(&path_bytes);
            let orig_path: &Path = Path::new(path_osstr);

            // Calculate path_action
            self.handler.call_mods(mods::ModFeature::OnFilePath, |m| {
                m.on_file_path(orig_path, syscall)
            })?;
            let path_action = self.calc_real_path(orig_path, syscall)?;
            let notify_path = match &path_action {
                PathAction::Override(path) => path.as_path(),
                _ => orig_path,
            };
            self.save_metadata_for_file(notify_path)?;
            self.handler
                .call_mods(mods::ModFeature::OnFileRealPath, |m| {
                    m.on_file_real_path(notify_path, syscall)
                })?;

            // if path_action exists, overwrite registers
            if let PathAction::Override(new_path_val) = path_action {
                let addr = ptrace_client.execute(move || {
                    let final_bytes: &[u8] = new_path_val.as_os_str().as_bytes();
                    ptrace::bytes_to_stack(pid, final_bytes)
                })??;
                **ref_arg_i = addr;
                need_write_regs = true;
            }
        }

        // Handle getdents (make the buffer seem smaller)
        if syscall.getdents_bits.is_some() {
            regs.arg2 = regs.arg2 / 2;
            need_write_regs = true;
        }

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
    fn calc_real_path(
        &self,
        orig_path: &Path,
        syscall: &SyscallInfo,
    ) -> Result<PathAction, SysAugError> {
        let mut new_path = PathAction::None;
        let prefix_maybe = self
            .handler
            .states
            .path_prefix
            .read()
            .or(Err(SysAugError::LockTraceeHandler))?;

        if let Some(prefix) = prefix_maybe.as_ref() {
            if orig_path.is_absolute() {
                let val = prefix.as_path().join(orig_path.strip_prefix("/").unwrap());
                new_path = PathAction::Override(val);
            }
        }

        self.get_mod_path(syscall, orig_path, new_path, false)
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
        event!(Level::INFO, "Intercepting {} dir entries", dirents.len());

        let mut is_delete: Vec<bool> = Vec::new();
        for entry in dirents.iter_mut() {
            event!(Level::TRACE, "Intercepting {:?}", entry);
            let path_osstr: &OsStr = OsStrExt::from_bytes(&entry.get_name()[..]);
            let orig_path: &Path = Path::new(path_osstr);
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
            Level::INFO,
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

    fn save_metadata_for_file(&self, path: &Path) -> Result<(), SysAugError> {
        event!(
            Level::DEBUG,
            "Checking metadata for: {:?}",
            path.to_string_lossy()
        );
        let maybe_meta_path = self
            .handler
            .call_first_mod(mods::ModFeature::ResolveMetadataPath, |m| {
                m.resolve_metadata_path(path)
            })?
            .flatten();
        if let Some(meta_path) = maybe_meta_path {
            event!(
                Level::DEBUG,
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
