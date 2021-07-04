use crate::common;
use crate::common::SysAugError;
use lazy_static::lazy_static;
use ptrace::GenericPurposeRegs;
use std::collections::HashSet;
use std::path;
use tracing::{event, Level};

lazy_static! {
    static ref SYSCALL_NAMES: HashSet<ptrace::SysNum> = {
        let mut ans = HashSet::new();
        ans.insert(libc::SYS_acct);
        ans.insert(libc::SYS_chdir);
        ans.insert(libc::SYS_chroot);
        ans.insert(libc::SYS_getxattr);
        ans.insert(libc::SYS_listxattr);
        ans.insert(libc::SYS_removexattr);
        ans.insert(libc::SYS_setxattr);
        ans.insert(libc::SYS_statfs);
        ans.insert(libc::SYS_swapoff);
        ans.insert(libc::SYS_swapon);
        ans.insert(libc::SYS_truncate);
        ans.insert(libc::SYS_umount2);
        ans.insert(libc::SYS_lgetxattr);
        ans.insert(libc::SYS_llistxattr);

        ans.insert(libc::SYS_execve);
        add_xplat_syscalls(&mut ans);
        ans
    };
}

#[cfg(target_arch = "arm")]
fn add_xplat_syscalls(ans: &mut HashSet<ptrace::SysNum>) {
    ans.insert(libc::SYS_access);
    ans.insert(libc::SYS_chmod);
    ans.insert(libc::SYS_chown);
    ans.insert(libc::SYS_chown32);
    ans.insert(libc::SYS_mknod);
    ans.insert(libc::SYS_creat);
    ans.insert(libc::SYS_stat);
    ans.insert(libc::SYS_stat64);
    ans.insert(libc::SYS_statfs64);
    ans.insert(libc::SYS_truncate64);
    ans.insert(libc::SYS_uselib);
    ans.insert(libc::SYS_utimes);
    ans.insert(libc::SYS_open);
    ans.insert(libc::SYS_readlink);
    ans.insert(libc::SYS_lchown);
    ans.insert(libc::SYS_lchown32);
    ans.insert(libc::SYS_lstat);
    ans.insert(libc::SYS_lstat64);
    ans.insert(libc::SYS_unlink);
    ans.insert(libc::SYS_rmdir);
    ans.insert(libc::SYS_mkdir);
}

#[cfg(target_arch = "aarch64")]
fn add_xplat_syscalls(_ans: &mut HashSet<ptrace::SysNum>) {}

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
    fn valid_calls(&self) -> &HashSet<ptrace::SysNum> {
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
