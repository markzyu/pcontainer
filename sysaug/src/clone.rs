use crate::common;
use crate::common::SysAugError;
use crate::handler::TraceeHandler;
use crate::mods;
use lazy_static::lazy_static;
use ptrace::GenericPurposeRegs;
use std::collections::HashSet;
use std::convert::TryInto;
use std::sync::Arc;
use tracing::{event, Level};

lazy_static! {
    static ref SYSCALL_NAMES: HashSet<usize> = {
        let mut ans = HashSet::new();
        ans.insert(libc::SYS_clone as usize);
        ans
    };
}

pub struct AugmentClone {
    pub handler: Arc<TraceeHandler>,
}

impl common::AugmentSyscall for AugmentClone {
    fn valid_calls(&self) -> &HashSet<usize> {
        &*SYSCALL_NAMES
    }

    fn before_call(&self, regs: &mut GenericPurposeRegs) -> Result<(), SysAugError> {
        let mut new_regs = regs.clone();
        let pid2 = self.handler.pid;
        let ptrace_client = &self.handler.ptrace_client;

        let new_flag: usize = libc::CLONE_PTRACE
            .try_into()
            .or(Err(SysAugError::IntoInt))?;
        new_regs.arg0 |= new_flag;
        ptrace_client.execute(move || ptrace::setregs(pid2, new_regs.clone()))??;
        let confirm_regs = ptrace_client.execute(move || ptrace::getregs(pid2))??;
        event!(
            Level::DEBUG,
            "Clone new arg: {:x}, {:x}, {:x}",
            confirm_regs.arg0,
            confirm_regs.arg1,
            confirm_regs.arg2,
        );
        Ok(())
    }

    fn after_call(&self, regs: &mut GenericPurposeRegs) -> Result<(), SysAugError> {
        let raw_pid = regs.syscall_retval();
        self.handler
            .call_mods(mods::ModFeature::OnCloneComplete, |m| {
                m.on_clone_complete(raw_pid as isize)
            })
    }

    fn new(handler: Arc<TraceeHandler>) -> Self {
        AugmentClone { handler }
    }
}
