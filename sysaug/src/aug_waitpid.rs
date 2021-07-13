use crate::common;
use crate::common::SysAugError;
use crate::handler::TraceeHandler;
use lazy_static::lazy_static;
use ptrace::GenericPurposeRegs;
use std::collections::HashSet;
use std::convert::TryInto;
use std::sync::Arc;
use tracing::{event, Level};

lazy_static! {
    static ref SYSCALL_NAMES: HashSet<usize> = {
        let mut ans = HashSet::new();
        ans.insert(libc::SYS_wait4 as usize);
        ans
    };
}

pub struct AugmentWaitpid<PtraceClient: executor::PtraceClient> {
    pub handler: Arc<TraceeHandler<PtraceClient>>,
}

impl<PtraceClient: executor::PtraceClient> common::AugmentSyscall for AugmentWaitpid<PtraceClient> {
    fn valid_calls(&self) -> &HashSet<usize> {
        &*SYSCALL_NAMES
    }

    fn before_call(&self, regs: &mut GenericPurposeRegs) -> Result<(), SysAugError> {
        event!(Level::INFO, "before waitpid({}, {:x}, {:x})", regs.arg0 as isize, regs.arg1, regs.arg2);
        Ok(())
    }

    fn after_call(&self, regs: &mut GenericPurposeRegs) -> Result<(), SysAugError> {
        let retval = regs.syscall_retval() as isize;
        event!(Level::INFO, "after waitpid() = {}", retval);
        if retval > 0 {
            let child_pid: nix::unistd::Pid =
                nix::unistd::Pid::from_raw(retval.try_into().or(Err(SysAugError::IntoInt))?);
            let mut ignores = self.handler.ignore_sigstops.write().or(Err(SysAugError::LockTraceeHandler))?;
            if ignores.remove(&child_pid) {
                regs.set_syscall_retval(0);
                let pid2 = self.handler.pid;
                let regs2 = regs.clone();
                self.handler
                    .ptrace_client
                    .execute(move || ptrace::setregs(pid2, regs2.clone()))??;
            }
        }
        Ok(())
    }
}

impl<PtraceClient: executor::PtraceClient> AugmentWaitpid<PtraceClient> {
    pub fn new(handler: Arc<TraceeHandler<PtraceClient>>) -> Self {
        AugmentWaitpid { handler }
    }
}
