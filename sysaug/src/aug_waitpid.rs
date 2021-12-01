use crate::common;
use crate::common::{SysAugError, SyscallInfo};
use crate::handler::TraceeHandler;
use ptrace::GenericPurposeRegs;
use std::sync::Arc;
use tracing::info;

pub struct AugmentWaitpid<PtraceClient: executor::PtraceClient> {
    pub handler: Arc<TraceeHandler<PtraceClient>>,
}

impl<PtraceClient: executor::PtraceClient> common::AugmentSyscall for AugmentWaitpid<PtraceClient> {
    fn before_call(
        &self,
        mut regs: GenericPurposeRegs,
        _syscall: &SyscallInfo,
    ) -> Result<(), SysAugError> {
        let pid = self.handler.pid;
        let ignore_sigstops = common::rwlock_read(&self.handler.ignore_sigstops)?;
        std::thread::sleep(std::time::Duration::from_millis(1));
        if !ignore_sigstops.is_empty() {
            regs.arg2 &= !(libc::WUNTRACED as usize);
            info!("New arg2 = {}", regs.arg2);
            self.handler
                .ptrace_client
                .execute(move || ptrace::setregs(pid, regs))??;
        }
        Ok(())
    }

    fn after_call(
        &self,
        regs: GenericPurposeRegs,
        _syscall: &SyscallInfo,
    ) -> Result<(), SysAugError> {
        let retval = regs.syscall_retval();
        info!("Returning {}", retval);
        if retval > 0 {
            let pid = nix::unistd::Pid::from_raw(retval as i32);
            let mut pids = common::rwlock_write(&self.handler.ignore_sigstops)?;
            pids.remove(&pid);
        }
        Ok(())
    }
}

impl<PtraceClient: executor::PtraceClient> AugmentWaitpid<PtraceClient> {
    pub fn new(handler: Arc<TraceeHandler<PtraceClient>>) -> Self {
        AugmentWaitpid { handler }
    }
}
