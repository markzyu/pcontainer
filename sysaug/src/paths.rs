use crate::common;
use crate::common::SysAugError;
use lazy_static::lazy_static;
use ptrace::GenericPurposeRegs;
use std::collections::{HashMap, HashSet};
use std::path;
use tracing::{event, Level};

struct SyscallInfo {
    /// Bitwise representation
    path_positions: usize,
}

macro_rules! define_syscall {
    ($name:expr, $path_positions:expr, $ans:ident) => {
        $ans.insert($name as usize, SyscallInfo {path_positions: $path_positions})
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
        define_syscall!(libc::SYS_newfstatat, 2, ans);
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
fn add_xplat_syscalls(_ans: &mut HashMap<usize, SyscallInfo>) {}

pub struct AugmentPaths {
    pub pid: nix::unistd::Pid,
    pub ptrace_client: executor::PtraceClient,
    pub chroot: Option<path::PathBuf>,
}

impl AugmentPaths {
    pub fn set_chroot(&mut self, chroot: path::PathBuf) -> Result<(), SysAugError> {
        let is_usable = {
            let chroot_path = chroot.as_path();
            chroot_path.is_absolute() && chroot_path.is_dir()
        };
        if is_usable {
            self.chroot = Some(chroot);
            Ok(())
        } else {
            Err(SysAugError::AbsolutePath(chroot))
        }
    }
}

impl common::AugmentSyscall for AugmentPaths {
    fn valid_calls(&self) -> &HashSet<usize> {
        &*SYSCALL_NAMES
    }

    fn before_call(&self, regs: &GenericPurposeRegs) -> Result<(), SysAugError> {
        let pid = self.pid;
        let syscall = SYSCALL_INFOS.get(&regs.syscall_num).unwrap();
        let possible_args = [regs.arg0, regs.arg1, regs.arg2];

        for (i, ref_arg_i) in possible_args.iter().enumerate() {
            let check_bit: usize = 1 << i;
            if (check_bit & syscall.path_positions) == 0 {
                continue;
            }

            let arg_i = *ref_arg_i;
            let path = self
                .ptrace_client
                .execute(move || ptrace::read_bytes_until_zero(pid, arg_i))??;
            event!(Level::INFO, "Input Path: {:?}", String::from_utf8_lossy(&path));
        }
        Ok(())
    }

    fn after_call(&self, _regs: &GenericPurposeRegs) -> Result<(), SysAugError> {
        Ok(())
    }

    fn new(pid: nix::unistd::Pid, ptrace_client: executor::PtraceClient) -> Self {
        AugmentPaths {
            pid,
            ptrace_client,
            chroot: None,
        }
    }
}
