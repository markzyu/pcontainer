use crate::common;
use crate::common::SysAugError;
use crate::handler::TraceeHandler;
use crate::mods;
use lazy_static::lazy_static;
use ptrace::GenericPurposeRegs;
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

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
        add_xplat_syscalls(&mut ans);
        ans
    };
    static ref SYSCALL_NAMES: HashSet<usize> = {
        let mut ans = HashSet::new();
        for key in SYSCALL_INFOS.keys() {
            ans.insert(*key);
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

pub struct AugmentPaths {
    pub handler: Arc<TraceeHandler>,
}

impl common::AugmentSyscall for AugmentPaths {
    fn valid_calls(&self) -> &HashSet<usize> {
        &*SYSCALL_NAMES
    }

    fn before_call(&self, regs: &mut GenericPurposeRegs) -> Result<(), SysAugError> {
        let pid = self.handler.pid;
        let ptrace_client = &self.handler.ptrace_client;

        let syscall = SYSCALL_INFOS.get(&regs.syscall_num).unwrap();
        let mut possible_args = [&mut regs.arg0, &mut regs.arg1, &mut regs.arg2];

        let mut need_write_regs = false;
        for (i, ref_arg_i) in possible_args.iter_mut().enumerate() {
            let check_bit: usize = 1 << i;
            if (check_bit & syscall.path_positions) == 0 {
                continue;
            }

            let arg_i = **ref_arg_i;
            let path_bytes =
                ptrace_client.execute(move || ptrace::read_bytes_until_zero(pid, arg_i))??;
            let path_osstr: &OsStr = OsStrExt::from_bytes(&path_bytes);
            let orig_path: &Path = Path::new(path_osstr);

            self.handler
                .call_mods(mods::ModFeature::OnFilePath, |m| m.on_file_path(orig_path))?;

            let mut new_path: Option<PathBuf> = None;
            let prefix_maybe = self
                .handler
                .states
                .path_prefix
                .read()
                .or(Err(SysAugError::LockTraceeHandler))?;

            if let Some(prefix) = prefix_maybe.as_ref() {
                if orig_path.is_absolute() {
                    let val = prefix.as_path().join(orig_path.strip_prefix("/").unwrap());
                    self.handler
                        .call_mods(mods::ModFeature::OnFileRealPath, |m| {
                            m.on_file_real_path(&val)
                        })?;
                    new_path.replace(val);
                }
            }
            if let Some(new_path_val) = new_path {
                let addr = ptrace_client.execute(move || {
                    let final_bytes: &[u8] = new_path_val.as_os_str().as_bytes();
                    ptrace::bytes_to_stack(pid, final_bytes)
                })??;
                **ref_arg_i = addr;
                need_write_regs = true;
            } else {
                self.handler
                    .call_mods(mods::ModFeature::OnFileRealPath, |m| {
                        m.on_file_real_path(orig_path)
                    })?;
            }
        }
        if need_write_regs {
            let regs2 = regs.clone();
            ptrace_client.execute(move || ptrace::setregs(pid, regs2.clone()))??;
        }
        Ok(())
    }

    fn after_call(&self, _regs: &mut GenericPurposeRegs) -> Result<(), SysAugError> {
        Ok(())
    }

    fn new(handler: Arc<TraceeHandler>) -> Self {
        AugmentPaths { handler }
    }
}
