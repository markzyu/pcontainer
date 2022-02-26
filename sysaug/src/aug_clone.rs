use crate::common;
use crate::common::{SysAugError, SyscallInfo};
use crate::handler::TraceeHandler;
use ptrace::GenericPurposeRegs;
use std::sync::Arc;

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

        regs.arg0 |= libc::CLONE_PTRACE as usize;
        regs.arg0 &= !(libc::CLONE_UNTRACED as usize);
        self.handler
            .ptrace_client
            .execute(move || ptrace::setregs(pid2, regs))??;
        Ok(())
    }

    fn after_call(
        &self,
        _regs: GenericPurposeRegs,
        _syscall: &SyscallInfo,
    ) -> Result<(), SysAugError> {
        Ok(())
    }
}

impl<PtraceClient: executor::PtraceClient> AugmentClone<PtraceClient> {
    pub fn new(handler: Arc<TraceeHandler<PtraceClient>>) -> Self {
        AugmentClone { handler }
    }
}
