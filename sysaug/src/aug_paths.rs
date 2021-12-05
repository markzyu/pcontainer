use crate::aug_common::{calc_real_path, get_mod_path, notify_mods_about_path, path_from_bytes};
use crate::common;
use crate::common::{SysAugError, SyscallInfo};
use crate::handler::TraceeHandler;
use crate::mods;
use crate::mods::PathAction;
use crate::rwoption_take_ok;
use ptrace::GenericPurposeRegs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{event, Level};

const META_INIT: &str = "{}\n";

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
        let dirfd_path = self.get_dirfd_path(&regs, syscall)?;
        let mut possible_args = [&mut regs.arg0, &mut regs.arg1, &mut regs.arg2];
        let mut need_write_regs = false;
        let mut save_paths: [Option<PathBuf>; 3] = Default::default();
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
            let orig_path_buf = path_from_bytes(path_bytes)?;

            // Calculate path_action, notify mods, and maybe update tracee
            let path_action = calc_real_path(&self.handler, &orig_path_buf, syscall)?;
            notify_mods_about_path(&self.handler, syscall, &orig_path_buf, &path_action)?;
            if let PathAction::Override(new_path_val) = path_action {
                save_paths[i] = Some(dirfd_path.join(&new_path_val));
                **ref_arg_i = self.handler.tracee_stack_append_path(new_path_val)?;
                need_write_regs = true;
            } else {
                save_paths[i] = Some(dirfd_path.join(orig_path_buf));
            }
        }

        // Handle getdents (make the buffer seem smaller)
        if syscall.getdents_bits.is_some() {
            regs.arg2 /= 2;
            need_write_regs = true;
        }

        // Delete metadata before unlink & rmdir
        if syscall.deletion_type.is_some() {
            let ref_save_paths = &save_paths;
            for path in ref_save_paths.iter().flatten() {
                self.delete_metadata_for_file(path)?;
            }
        }

        common::rwoption_replace(&self.handler.curr_paths, save_paths)?;

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
        let del_type = &syscall.deletion_type;
        let retval = regs.syscall_retval() as isize;
        if del_type.is_none() || retval < 0 {
            for path in paths.iter().flatten() {
                self.save_metadata_for_file(path)?;
            }
        }

        if retval <= 0 {
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
            let orig_path_buf = path_from_bytes(entry.get_name().to_vec())?;
            let orig_path: &Path = orig_path_buf.as_path();
            let action = get_mod_path(&self.handler, syscall, orig_path, PathAction::None, true)?;
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
        regs.arg2 *= 2;
        regs.set_syscall_retval(num_bytes);
        ptrace_client.execute(move || ptrace::setregs(pid, regs))??;
        Ok(())
    }

    fn _get_metadata_path(&self, path: &Path) -> Result<Option<PathBuf>, SysAugError> {
        let maybe_meta_path = self
            .handler
            .call_first_mod(mods::ModFeature::ResolveMetadataPath, |m| {
                m.resolve_metadata_path(path)
            })?
            .flatten();
        event!(
            Level::TRACE,
            "Checking metadata for: {:?} = {:?}",
            path.to_string_lossy(),
            maybe_meta_path,
        );
        Ok(maybe_meta_path)
    }

    fn save_metadata_for_file(&self, path: &Path) -> Result<(), SysAugError> {
        if let Some(meta_path) = self._get_metadata_path(path)? {
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

    fn _log_and_delete_metadata(&self, path: &Path) -> Result<(), SysAugError> {
        event!(
            Level::TRACE,
            "Deleting metadata file: {:?}",
            path.to_string_lossy()
        );
        if !path.exists() {
            return Ok(());
        }
        let _ = std::fs::remove_file(path)
            .map_err(SysAugError::DeleteMetadata)
            .map_err(common::display_err);
        Ok(())
    }

    fn delete_metadata_for_file(&self, path: &Path) -> Result<(), SysAugError> {
        if let Some(meta_path) = self._get_metadata_path(path)? {
            self._log_and_delete_metadata(&meta_path)?;
        }

        if path.is_dir() {
            for child in std::fs::read_dir(path).map_err(SysAugError::ListMetadata)? {
                let child = child.map_err(SysAugError::ListMetadata)?;
                let child_path = child.path();
                if child_path.is_dir() {
                    continue;
                }
                let is_metadata = self
                    .handler
                    .call_first_mod(mods::ModFeature::IsMetadataPath, |m| {
                        m.is_metadata_path(&child_path)
                    })?
                    .unwrap_or(false);
                if is_metadata {
                    self._log_and_delete_metadata(&child_path)?;
                }
            }
        }
        Ok(())
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

    fn item_size_updater(&mut self, size: usize) {
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

    fn item_size_updater(&mut self, size: usize) {
        self.reclen = size as u16;
    }
}
