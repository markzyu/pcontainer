use crate::common;
use crate::common::{SysAugError, SyscallInfo};
use crate::handler::TraceeHandler;
use nix::sys::signal::Signal;
use nix::sys::wait::WaitStatus;
use ptrace::GenericPurposeRegs;
use std::sync::Arc;
use tracing::info;

pub struct AugmentWaitpid<PtraceClient: executor::PtraceClient> {
    pub handler: Arc<TraceeHandler<PtraceClient>>,
}

impl<PtraceClient: executor::PtraceClient> common::AugmentSyscall for AugmentWaitpid<PtraceClient> {
    fn before_call(
        &self,
        regs: GenericPurposeRegs,
        _syscall: &SyscallInfo,
    ) -> Result<(), SysAugError> {
        let parent_pid = self.handler.pid;
        let stat_addr = regs.arg1;
        let stat_int = self
            .handler
            .ptrace_client
            .execute(move || ptrace::read(parent_pid, stat_addr))??;
        common::rwlock_replace(&self.handler.orig_wait_status, stat_int)?;
        Ok(())
    }

    fn after_call(
        &self,
        mut regs: GenericPurposeRegs,
        _syscall: &SyscallInfo,
    ) -> Result<(), SysAugError> {
        let parent_pid = self.handler.pid;
        let retval = regs.syscall_retval() as i32;
        if retval > 0 {
            let pid = nix::unistd::Pid::from_raw(retval);
            let mut pids = common::rwlock_write(&self.handler.ignore_sigstops)?;

            let stat_addr = regs.arg1;
            let stat_int = self
                .handler
                .ptrace_client
                .execute(move || ptrace::read(parent_pid, stat_addr))??;
            let stat = WaitStatus::from_raw(pid, stat_int as i32);

            if pids.contains(&pid) && matches!(stat, Ok(WaitStatus::Stopped(_, Signal::SIGSTOP))) {
                let nohang = regs.arg2 & libc::WNOHANG as usize;
                let override_retval = if nohang == 0 {
                    -libc::EINTR as usize
                } else {
                    0_usize
                };

                // Override syscall return value
                regs.set_syscall_retval(override_retval);
                self.handler
                    .ptrace_client
                    .execute(move || ptrace::setregs(parent_pid, regs))??;

                // Restore wait status to its value before syscall
                let orig_ref = common::rwlock_read(&self.handler.orig_wait_status)?;
                let orig = *orig_ref;
                self.handler
                    .ptrace_client
                    .execute(move || ptrace::write(parent_pid, stat_addr, orig))??;

                info!(
                    "Override {:?} -> Returning {}",
                    stat, override_retval as isize
                );
                pids.remove(&pid);
            } else {
                info!("Returning status {:?}", stat);
            }
        } else {
            info!("Returning {}", retval);
        }
        Ok(())
    }
}

impl<PtraceClient: executor::PtraceClient> AugmentWaitpid<PtraceClient> {
    pub fn new(handler: Arc<TraceeHandler<PtraceClient>>) -> Self {
        AugmentWaitpid { handler }
    }
}
