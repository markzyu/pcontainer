use crate::common;
use crate::common::{SysAugError, SyscallInfo};
use crate::handler::TraceeHandler;
use crate::mods;
use nix::sys;
use ptrace::GenericPurposeRegs;
use std::convert::TryInto;
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

        let new_flag: usize = libc::CLONE_PTRACE
            .try_into()
            .or(Err(SysAugError::IntoInt))?;
        regs.arg0 |= new_flag;
        self.handler
            .ptrace_client
            .execute(move || ptrace::setregs(pid2, regs))??;

        let mut wait = common::rwlock_write(&self.handler.pid_to_wait_for)?;
        *wait = nix::unistd::Pid::from_raw(-1);

        Ok(())
    }

    fn after_call(
        &self,
        regs: GenericPurposeRegs,
        _syscall: &SyscallInfo,
    ) -> Result<(), SysAugError> {
        let raw_pid = regs.syscall_retval();
        if raw_pid > 0 {
            let mut wait = common::rwlock_write(&self.handler.pid_to_wait_for)?;
            *wait = self.handler.pid;

            let child_pid: nix::unistd::Pid =
                nix::unistd::Pid::from_raw(raw_pid.try_into().or(Err(SysAugError::IntoInt))?);

            self.handler
                .ptrace_client
                .prep_attach_to(child_pid, &self.handler.ignore_sigstops)?;

            let new_tracee_handler = self.handler.fork(child_pid)?;
            let new_tracee_handler2 = Arc::clone(&new_tracee_handler);
            let root_pid = self.handler.states.root_pid;
            let fail_fast = self.handler.states.args.fail_fast;
            new_tracee_handler.start(move || {
                if fail_fast && new_tracee_handler2.failed() {
                    let _ = sys::signal::kill(root_pid, Some(sys::signal::Signal::SIGKILL))
                        .map_err(common::display_err);
                }
            });

            self.handler
                .call_mods(mods::ModFeature::OnCloneComplete, |m| {
                    m.on_clone_complete(raw_pid as isize)
                })?;
        }
        Ok(())
    }
}

impl<PtraceClient: executor::PtraceClient> AugmentClone<PtraceClient> {
    pub fn new(handler: Arc<TraceeHandler<PtraceClient>>) -> Self {
        AugmentClone { handler }
    }
}
