use crate::common;
use crate::common::{SysAugError, SyscallInfo};
use crate::handler::TraceeHandler;
use nix::sys;
use ptrace::GenericPurposeRegs;
use std::convert::TryInto;
use std::sync::Arc;
use tracing::{event, Level};

pub struct AugmentWaitpid<PtraceClient: executor::PtraceClient> {
    pub handler: Arc<TraceeHandler<PtraceClient>>,
}

impl<PtraceClient: executor::PtraceClient> common::AugmentSyscall for AugmentWaitpid<PtraceClient> {
    fn before_call(
        &self,
        regs: GenericPurposeRegs,
        _syscall: &SyscallInfo,
    ) -> Result<(), SysAugError> {
        event!(
            Level::INFO,
            "before waitpid({}, {:x}, {:x})",
            regs.arg0 as isize,
            regs.arg1,
            regs.arg2
        );
        let mut maybe_orig_regs = self
            .handler
            .orig_request_regs
            .write()
            .or(Err(SysAugError::LockTraceeHandler))?;
        maybe_orig_regs.replace(regs);
        Ok(())
    }

    fn after_call(
        &self,
        regs: GenericPurposeRegs,
        _syscall: &SyscallInfo,
    ) -> Result<(), SysAugError> {
        let pid = self.handler.pid;
        let retval = regs.syscall_retval() as isize;
        event!(Level::INFO, "after waitpid() = {}", retval);
        if retval <= 0 {
            return Ok(());
        }

        let child_pid: nix::unistd::Pid =
            nix::unistd::Pid::from_raw(retval.try_into().or(Err(SysAugError::IntoInt))?);
        let raw_child_status = self
            .handler
            .ptrace_client
            .execute(move || sys::ptrace::read(pid, regs.arg1 as *mut libc::c_void))?
            .map_err(SysAugError::PtraceRead)? as i32;
        let child_status = sys::wait::WaitStatus::from_raw(child_pid, raw_child_status)
            .map_err(SysAugError::ParseWaitStatus)?;
        let mut ignores = self
            .handler
            .ignore_sigstops
            .write()
            .or(Err(SysAugError::LockTraceeHandler))?;
        event!(Level::INFO, "Child status: {:?}", child_status);
        if !matches!(
            child_status,
            sys::wait::WaitStatus::Stopped(_, sys::signal::Signal::SIGSTOP)
        ) {
            ignores.remove(&child_pid);
            return Ok(());
        }

        if ignores.remove(&child_pid) {
            // Restart system call with orignal arguments, stack pointer, etc.
            event!(Level::INFO, "restarting waitpid()");
            let mut maybe_orig_regs = self
                .handler
                .orig_request_regs
                .write()
                .or(Err(SysAugError::LockTraceeHandler))?;
            let pid2 = self.handler.pid;
            let orig_regs = maybe_orig_regs.take().unwrap();
            self.handler
                .ptrace_client
                .execute(move || ptrace::setregs(pid2, orig_regs))??;
        }
        Ok(())
    }
}

impl<PtraceClient: executor::PtraceClient> AugmentWaitpid<PtraceClient> {
    pub fn new(handler: Arc<TraceeHandler<PtraceClient>>) -> Self {
        AugmentWaitpid { handler }
    }
}
