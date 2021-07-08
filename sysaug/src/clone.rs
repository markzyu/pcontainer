use crate::common;
use crate::common::SysAugError;
use crate::handler;
use lazy_static::lazy_static;
use ptrace::GenericPurposeRegs;
use std::collections::HashSet;
use std::convert::TryInto;
use std::thread;
use tracing::{event, Level};

lazy_static! {
    static ref SYSCALL_NAMES: HashSet<ptrace::SysNum> = {
        let mut ans = HashSet::new();
        ans.insert(libc::SYS_clone as usize);
        ans
    };
}

pub struct AugmentClone {
    pub pid: nix::unistd::Pid,
    pub ptrace_client: executor::PtraceClient,
}

impl common::AugmentSyscall for AugmentClone {
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
        AugmentClone { pid, ptrace_client }
    }
}
