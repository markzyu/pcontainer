use crate::common;
use crate::common::{SysAugError, SyscallInfo};
use crate::handler::{get_mem_helper, AsyncTraceeHandler};
use nix::sys::signal::Signal;
use nix::sys::wait::WaitStatus;
use ptrace::{GenericPurposeRegs, MemHelpers};
use tracing::info;

impl<PtraceClient: executor::PtraceClient> AsyncTraceeHandler<'_, PtraceClient> {
    pub async fn augment_sys_waitpid(
        &self,
        orig_regs: GenericPurposeRegs,
        _syscall: &SyscallInfo,
    ) -> Result<(), SysAugError> {
        let MemHelpers { read, .. } = get_mem_helper();
        let parent_pid = self.pid;
        let orig_status_addr = orig_regs.arg1;
        let orig_wait_status = self
            .ptrace_client
            .execute(move || (read)(parent_pid, orig_status_addr))??;

        let mut regs = self.do_resume_syscall().await?;

        let retval = regs.syscall_retval() as i32;
        if retval > 0 {
            let pid = nix::unistd::Pid::from_raw(retval);
            let mut pids = common::rwlock_write(self.ignore_sigstops.as_ref())?;

            let wait_status_addr = regs.arg1;
            let wait_status = self
                .ptrace_client
                .execute(move || (read)(parent_pid, wait_status_addr))??;
            let stat = WaitStatus::from_raw(pid, wait_status as i32);

            if pids.contains(&pid) && matches!(stat, Ok(WaitStatus::Stopped(_, Signal::SIGSTOP))) {
                let nohang = regs.arg2 & libc::WNOHANG as usize;
                let override_retval = if nohang == 0 {
                    -libc::EINTR as usize
                } else {
                    0_usize
                };

                // Override syscall return value
                regs.set_syscall_retval(override_retval);
                self.ptrace_client
                    .execute(move || ptrace::setregs(parent_pid, regs))??;

                // Restore wait status to its value before syscall
                self.ptrace_client.execute(move || {
                    ptrace::write(parent_pid, wait_status_addr, orig_wait_status)
                })??;

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
