use crate::common;
use crate::common::{SysAugError, SyscallInfo};
use crate::handler::TraceeHandler;
use nix::sys::wait::WaitStatus;
use ptrace::{GenericPurposeRegs, USIZE_SIZE};
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
        let retval = regs.syscall_retval() as i32;
        let parent_pid = self.handler.pid;
        info!("Returning {}", retval);
        if retval >= 0 {
            let pid = nix::unistd::Pid::from_raw(retval);
            let mut pids = common::rwlock_write(&self.handler.ignore_sigstops)?;
            pids.remove(&pid);

            let stat_addr = regs.arg1;
            let stat_int = self
                .handler
                .ptrace_client
                .execute(move || ptrace::read(parent_pid, stat_addr))??;

            if retval == 0 {
                let low_flag: usize = -1_isize as usize - (-1_i32 as u32 as usize);
                let new_int = if stat_int as i32 == 0 {
                    stat_int
                } else if (stat_int & low_flag) as i32 == 0 {
                    stat_int & low_flag
                } else {
                    let mask1: usize = -1_i32 as u32 as usize;
                    let mask2: usize = mask1 << (*USIZE_SIZE - 4) * 8;
                    stat_int & !mask2
                };
                info!("Overriding status {:x} -> {:x}", stat_int, new_int);

                self.handler
                    .ptrace_client
                    .execute(move || ptrace::write(parent_pid, stat_addr, new_int))??;
            } else {
                let stat = WaitStatus::from_raw(pid, stat_int as i32);
                info!("Returning status {:?}", stat);
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
