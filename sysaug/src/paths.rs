use crate::common;
use crate::common::SysAugError;
use lazy_static::lazy_static;
use ptrace::GenericPurposeRegs;
use std::collections::HashSet;
use std::path;
use tracing::{event, Level};

lazy_static! {
    static ref SYSCALL_NAMES: HashSet<usize> = {
        let mut ans = HashSet::new();
        ans.insert(libc::SYS_acct as usize);
        ans.insert(libc::SYS_chdir as usize);
        ans.insert(libc::SYS_chroot as usize);
        ans.insert(libc::SYS_getxattr as usize);
        ans.insert(libc::SYS_listxattr as usize);
        ans.insert(libc::SYS_removexattr as usize);
        ans.insert(libc::SYS_setxattr as usize);
        ans.insert(libc::SYS_statfs as usize);
        ans.insert(libc::SYS_swapoff as usize);
        ans.insert(libc::SYS_swapon as usize);
        ans.insert(libc::SYS_truncate as usize);
        ans.insert(libc::SYS_umount2 as usize);
        ans.insert(libc::SYS_lgetxattr as usize);
        ans.insert(libc::SYS_llistxattr as usize);

        ans.insert(libc::SYS_execve as usize);
        add_xplat_syscalls(&mut ans);
        ans
    };
}

#[cfg(target_arch = "arm")]
fn add_xplat_syscalls(ans: &mut HashSet<usize>) {
    ans.insert(libc::SYS_access as usize);
    ans.insert(libc::SYS_chmod as usize);
    ans.insert(libc::SYS_chown as usize);
    ans.insert(libc::SYS_chown32 as usize);
    ans.insert(libc::SYS_mknod as usize);
    ans.insert(libc::SYS_creat as usize);
    ans.insert(libc::SYS_stat as usize);
    ans.insert(libc::SYS_stat64 as usize);
    ans.insert(libc::SYS_statfs64 as usize);
    ans.insert(libc::SYS_truncate64 as usize);
    ans.insert(libc::SYS_uselib as usize);
    ans.insert(libc::SYS_utimes as usize);
    ans.insert(libc::SYS_open as usize);
    ans.insert(libc::SYS_readlink as usize);
    ans.insert(libc::SYS_lchown as usize);
    ans.insert(libc::SYS_lchown32 as usize);
    ans.insert(libc::SYS_lstat as usize);
    ans.insert(libc::SYS_lstat64 as usize);
    ans.insert(libc::SYS_unlink as usize);
    ans.insert(libc::SYS_rmdir as usize);
    ans.insert(libc::SYS_mkdir as usize);
}

#[cfg(target_arch = "aarch64")]
fn add_xplat_syscalls(_ans: &mut HashSet<usize>) {}

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
        let new_regs = regs.clone();
        let path = self
            .ptrace_client
            .execute(move || ptrace::read_bytes_until_zero(pid, new_regs.arg0))??;
        let path_str = String::from_utf8_lossy(&path);
        event!(Level::INFO, "Input Path: {:?}", path_str,);
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
