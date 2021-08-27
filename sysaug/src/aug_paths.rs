use crate::common;
use crate::common::SysAugError;
use crate::handler::TraceeHandler;
use crate::mods;
use crate::mods::PathAction;
use lazy_static::lazy_static;
use ptrace::GenericPurposeRegs;
use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::Arc;
use tracing::{event, Level};

const META_INIT: &'static str = "{}\n";

struct SyscallInfo {
    /// Bitwise representation
    path_positions: usize,
}

macro_rules! define_syscall {
    ($name:expr, $path_positions:expr, $ans:ident) => {
        $ans.insert(
            $name as usize,
            SyscallInfo {
                path_positions: $path_positions,
            },
        )
    };
}

lazy_static! {
    static ref SYSCALL_INFOS: HashMap<usize, SyscallInfo> = {
        let mut ans = HashMap::new();
        define_syscall!(libc::SYS_acct, 1, ans);
        define_syscall!(libc::SYS_chdir, 1, ans);
        define_syscall!(libc::SYS_chroot, 1, ans);
        define_syscall!(libc::SYS_getxattr, 1, ans);
        define_syscall!(libc::SYS_listxattr, 1, ans);
        define_syscall!(libc::SYS_removexattr, 1, ans);
        define_syscall!(libc::SYS_setxattr, 1, ans);
        define_syscall!(libc::SYS_statfs, 1, ans);
        define_syscall!(libc::SYS_swapoff, 1, ans);
        define_syscall!(libc::SYS_swapon, 1, ans);
        define_syscall!(libc::SYS_truncate, 1, ans);
        define_syscall!(libc::SYS_umount2, 1, ans);
        define_syscall!(libc::SYS_lgetxattr, 1, ans);
        define_syscall!(libc::SYS_llistxattr, 1, ans);
        define_syscall!(libc::SYS_execve, 1, ans);

        define_syscall!(libc::SYS_openat, 2, ans);
        define_syscall!(libc::SYS_name_to_handle_at, 2, ans);
        define_syscall!(libc::SYS_faccessat, 2, ans);
        define_syscall!(libc::SYS_mkdirat, 2, ans);
        define_syscall!(libc::SYS_utimensat, 2, ans);
        define_syscall!(libc::SYS_getdents64, 0, ans);
        add_xplat_syscalls(&mut ans);
        ans
    };
    static ref VALID_SYSCALLS: HashMap<usize, common::Augments> = {
        let mut ans = HashMap::new();
        for key in SYSCALL_INFOS.keys() {
            ans.insert(*key, common::Augments::Paths);
        }
        ans
    };
}

#[cfg(target_arch = "arm")]
fn add_xplat_syscalls(ans: &mut HashMap<usize, SyscallInfo>) {
    define_syscall!(libc::SYS_access, 1, ans);
    define_syscall!(libc::SYS_chmod, 1, ans);
    define_syscall!(libc::SYS_chown, 1, ans);
    define_syscall!(libc::SYS_chown32, 1, ans);
    define_syscall!(libc::SYS_mknod, 1, ans);
    define_syscall!(libc::SYS_creat, 1, ans);
    define_syscall!(libc::SYS_stat, 1, ans);
    define_syscall!(libc::SYS_stat64, 1, ans);
    define_syscall!(libc::SYS_statfs64, 1, ans);
    define_syscall!(libc::SYS_truncate64, 1, ans);
    define_syscall!(libc::SYS_uselib, 1, ans);
    define_syscall!(libc::SYS_utimes, 1, ans);
    define_syscall!(libc::SYS_open, 1, ans);
    define_syscall!(libc::SYS_readlink, 1, ans);
    define_syscall!(libc::SYS_lchown, 1, ans);
    define_syscall!(libc::SYS_lchown32, 1, ans);
    define_syscall!(libc::SYS_lstat, 1, ans);
    define_syscall!(libc::SYS_lstat64, 1, ans);
    define_syscall!(libc::SYS_unlink, 1, ans);
    define_syscall!(libc::SYS_rmdir, 1, ans);
    define_syscall!(libc::SYS_mkdir, 1, ans);
}

#[cfg(target_arch = "aarch64")]
fn add_xplat_syscalls(ans: &mut HashMap<usize, SyscallInfo>) {
    define_syscall!(libc::SYS_newfstatat, 2, ans);
}

pub struct AugmentPaths<PtraceClient: executor::PtraceClient> {
    pub handler: Arc<TraceeHandler<PtraceClient>>,
}

impl<PtraceClient: executor::PtraceClient> common::AugmentSyscall for AugmentPaths<PtraceClient> {
    fn valid_calls() -> &'static HashMap<usize, common::Augments> {
        &*VALID_SYSCALLS
    }

    fn before_call(&self, mut regs: GenericPurposeRegs) -> Result<(), SysAugError> {
        let pid = self.handler.pid;
        let ptrace_client = &self.handler.ptrace_client;

        let syscall_num = regs.syscall_num;
        let syscall = SYSCALL_INFOS.get(&syscall_num).unwrap();
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
                m.on_file_path(orig_path, syscall_num)
            })?;
            let path_action = self.calc_real_path(orig_path, syscall_num)?;
            let notify_path = match &path_action {
                PathAction::Override(path) => path.as_path(),
                _ => orig_path,
            };
            self.save_metadata_for_file(notify_path)?;
            self.handler
                .call_mods(mods::ModFeature::OnFileRealPath, |m| {
                    m.on_file_real_path(notify_path, syscall_num)
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
        if syscall_num == libc::SYS_getdents64 as usize {
            regs.arg2 = regs.arg2 / 2;
            need_write_regs = true;
        }

        if need_write_regs {
            ptrace_client.execute(move || ptrace::setregs(pid, regs))??;
        }
        Ok(())
    }

    fn after_call(&self, mut regs: GenericPurposeRegs) -> Result<(), SysAugError> {
        let pid = self.handler.pid;
        let ptrace_client = &self.handler.ptrace_client;
        let syscall_num = regs.syscall_num;
        if syscall_num == libc::SYS_getdents64 as usize {
            let addr = regs.arg1;
            let buf_size = regs.arg2 * 2;
            let list_size = regs.syscall_retval();
            if list_size as isize <= 0 {
                return Ok(());
            }

            // TODO: Don't perform this expensive call unless we have mods that need the data
            let mut dirents: Vec<Dirent64> = ptrace_client
                .execute(move || ptrace::read_bytes_to_structs(pid, addr, list_size))??;
            event!(Level::INFO, "Intercepting {} dir entries", dirents.len());

            let mut is_delete: Vec<bool> = Vec::new();
            for entry in dirents.iter_mut() {
                let path_osstr: &OsStr = OsStrExt::from_bytes(&entry.name[..]);
                let orig_path: &Path = Path::new(path_osstr);
                let action = self.get_mod_path(syscall_num, orig_path, PathAction::None, true)?;
                // event!(Level::INFO, "Intercepting dir entry {:?} -> {:?}", orig_path, &action);
                let delete = match &action {
                    PathAction::Override(override_path) => {
                        let bytes = override_path.as_os_str().as_bytes();
                        entry.name.fill(0);
                        for (i, byte) in bytes.iter().take_while(|x| **x != 0).enumerate() {
                            entry.name[i] = *byte;
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
            let num_bytes = ptrace_client.execute(move || {
                ptrace::structs_to_tracee_buffer(pid, addr, buf_size, dirents, 2)
            })??;
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
        }
        Ok(())
    }
}

impl<PtraceClient: executor::PtraceClient> AugmentPaths<PtraceClient> {
    fn calc_real_path(
        &self,
        orig_path: &Path,
        syscall_num: usize,
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

        self.get_mod_path(syscall_num, orig_path, new_path, false)
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
        syscall_num: usize,
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
                m.override_file_fake_path(curr_path, syscall_num)?
            } else {
                m.override_file_real_path(curr_path, syscall_num)?
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

#[derive(Debug, Clone)]
#[repr(C)]
struct Dirent64 {
    pub inode: u64,
    pub offset: u64,
    pub reclen: libc::c_ushort,
    pub type_: libc::c_uchar,
    pub name: [u8; 512],
}

#[derive(Debug, Clone)]
#[repr(C)]
struct Dirent64Header {
    pub ino: libc::ino64_t,
    pub off: libc::off64_t,
    pub reclen: libc::c_ushort,
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
