use crate::common;
use crate::common::{SysAugError, SyscallInfo};
use crate::handler::TraceeHandler;
use ptrace::GenericPurposeRegs;
use std::convert::TryInto;
use std::sync::Arc;
use tracing::{event, Level};

pub struct AugmentClone<PtraceClient: executor::PtraceClient> {
    pub handler: Arc<TraceeHandler<PtraceClient>>,
}

impl<PtraceClient: executor::PtraceClient> common::AugmentSyscall for AugmentClone<PtraceClient> {
    fn before_call(
        &self,
        mut regs: GenericPurposeRegs,
        _syscall: &SyscallInfo,
    ) -> Result<(), SysAugError> {
        let pid2 = self.handler.pid;

        event!(Level::TRACE, "A");
        let new_flag: usize = libc::CLONE_PTRACE
            .try_into()
            .or(Err(SysAugError::IntoInt))?;
        regs.arg0 |= new_flag;
        event!(Level::TRACE, "B {:x}", regs.arg0);
        self.handler
            .ptrace_client
            .execute(move || ptrace::setregs(pid2, regs))??;
        event!(Level::TRACE, "C");
        Ok(())
    }

    fn after_call(
        &self,
        regs: GenericPurposeRegs,
        _syscall: &SyscallInfo,
    ) -> Result<(), SysAugError> {
        event!(Level::TRACE, "D");
        let raw_pid = regs.syscall_retval() as isize;
        if raw_pid > 0 {
            let child_pid = nix::unistd::Pid::from_raw(raw_pid as i32);
            self.handler.fork(child_pid)?;
        }
        Ok(())
    }
}

impl<PtraceClient: executor::PtraceClient> AugmentClone<PtraceClient> {
    pub fn new(handler: Arc<TraceeHandler<PtraceClient>>) -> Self {
        AugmentClone { handler }
    }
}
