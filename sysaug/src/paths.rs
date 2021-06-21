use crate::common;
use crate::common::SysAugError;
use crate::handler;
use lazy_static::lazy_static;
use ptrace::GenericPurposeRegs;
use std::collections::HashSet;
use std::convert::TryInto;
use std::path;
use std::thread;
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
fn add_xplat_syscalls(_ans: &mut HashSet<ptrace::SysNum>) {
}

pub struct AugmentPaths {
    pub pid: nix::unistd::Pid,
    pub ptrace_client: executor::PtraceClient,
    pub chroot: Option<path::PathBuf>,
}

impl common::AugmentSyscall for AugmentPaths {
    fn valid_calls(&self) -> &HashSet<ptrace::SysNum> {
        &*SYSCALL_NAMES
    }

    fn before_call(&self, regs: &GenericPurposeRegs) -> Result<(), SysAugError> {
        let mut new_regs = regs.clone();
        let pid2 = self.pid;
        let new_flag: ptrace::SysNum = libc::CLONE_PTRACE
            .try_into()
            .or(Err(SysAugError::IntoInt))?;
        new_regs.arg0 |= new_flag;
        self.ptrace_client
            .execute(move || ptrace::setregs(pid2, new_regs.clone()))??;
        let confirm_regs = self
            .ptrace_client
            .execute(move || ptrace::getregs(pid2))??;
        event!(
            Level::DEBUG,
            "Clone new arg: {:x}, {:x}, {:x}",
            confirm_regs.arg0,
            confirm_regs.arg1,
            confirm_regs.arg2,
        );
        Ok(())
    }

    fn after_call(&self, regs: &GenericPurposeRegs) -> Result<(), SysAugError> {
        let raw_pid = regs.syscall_retval();
        if raw_pid > 0 {
            let child_pid: nix::unistd::Pid =
                nix::unistd::Pid::from_raw(raw_pid.try_into().or(Err(SysAugError::IntoInt))?);
            event!(Level::INFO, "Clone pid {}", child_pid);
            let new_ptrace_client = self.ptrace_client.clone();
            let new_tracee_handler = handler::TraceeHandler::new(child_pid, new_ptrace_client);
            thread::spawn(move || {
                new_tracee_handler.event_loop().unwrap();
            });
        }
        Ok(())
    }

    fn new(pid: nix::unistd::Pid, ptrace_client: executor::PtraceClient) -> Self {
        return AugmentPaths {pid, ptrace_client, chroot: None}
    }
}
