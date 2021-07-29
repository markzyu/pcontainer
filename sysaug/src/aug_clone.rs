use crate::common;
use crate::common::SysAugError;
use crate::handler::TraceeHandler;
use crate::mods;
use lazy_static::lazy_static;
use ptrace::GenericPurposeRegs;
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::sync::Arc;

lazy_static! {
    static ref SYSCALL_NAMES: HashSet<usize> = {
        let mut ans = HashSet::new();
        ans.insert(libc::SYS_clone as usize);
        ans
    };
    static ref VALID_SYSCALLS: HashMap<usize, common::Augments> = {
        let mut ans = HashMap::new();
        for item in SYSCALL_NAMES.iter() {
            ans.insert(*item, common::Augments::Clone);
        }
        ans
    };
}

pub struct AugmentClone<PtraceClient: executor::PtraceClient> {
    pub handler: Arc<TraceeHandler<PtraceClient>>,
}

impl<PtraceClient: executor::PtraceClient> common::AugmentSyscall for AugmentClone<PtraceClient> {
    fn valid_calls() -> &'static HashMap<usize, common::Augments> {
        &*VALID_SYSCALLS
    }

    fn before_call(&self, mut regs: GenericPurposeRegs) -> Result<(), SysAugError> {
        let pid2 = self.handler.pid;

        let new_flag: usize = libc::CLONE_PTRACE
            .try_into()
            .or(Err(SysAugError::IntoInt))?;
        regs.arg0 |= new_flag;
        self.handler
            .ptrace_client
            .execute(move || ptrace::setregs(pid2, regs))??;
        Ok(())
    }

    fn after_call(&self, regs: GenericPurposeRegs) -> Result<(), SysAugError> {
        let raw_pid = regs.syscall_retval();
        if raw_pid > 0 {
            let child_pid: nix::unistd::Pid =
                nix::unistd::Pid::from_raw(raw_pid.try_into().or(Err(SysAugError::IntoInt))?);

            self.handler
                .ptrace_client
                .prep_attach_to(child_pid, &self.handler.ignore_sigstops)?;

            let new_tracee_handler = self.handler.fork(child_pid)?;
            std::thread::spawn(move || {
                let _span = new_tracee_handler.trace_span().entered();
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
