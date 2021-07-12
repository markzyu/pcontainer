use crate::common;
use crate::common::SysAugError;
use crate::handler::TraceeHandler;
use crate::mods;
use lazy_static::lazy_static;
use ptrace::GenericPurposeRegs;
use std::collections::HashSet;
use std::convert::TryInto;
use std::sync::Arc;

lazy_static! {
    static ref SYSCALL_NAMES: HashSet<usize> = {
        let mut ans = HashSet::new();
        ans.insert(libc::SYS_clone as usize);
        ans
    };
}

pub struct AugmentClone<PtraceClient: executor::PtraceClient> {
    pub handler: Arc<TraceeHandler<PtraceClient>>,
}

impl<PtraceClient: executor::PtraceClient> common::AugmentSyscall for AugmentClone<PtraceClient> {
    fn valid_calls(&self) -> &HashSet<usize> {
        &*SYSCALL_NAMES
    }

    fn before_call(&self, regs: &mut GenericPurposeRegs) -> Result<(), SysAugError> {
        let pid2 = self.handler.pid;
        self.handler.ptrace_client.set_clone_flags(pid2, regs)?;
        Ok(())
    }

    fn after_call(&self, regs: &mut GenericPurposeRegs) -> Result<(), SysAugError> {
        let raw_pid = regs.syscall_retval();
        if raw_pid > 0 {
            let child_pid: nix::unistd::Pid =
                nix::unistd::Pid::from_raw(raw_pid.try_into().or(Err(SysAugError::IntoInt))?);

            let new_tracee_handler = self.handler.fork(child_pid)?;
            std::thread::spawn(move || {
                new_tracee_handler
                    .event_loop()
                    .map_err(common::display_err)
                    .unwrap();
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
