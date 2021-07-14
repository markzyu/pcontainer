use crate::common;
use crate::common::SysAugError;
use crate::handler::TraceeHandler;
use lazy_static::lazy_static;
use ptrace::GenericPurposeRegs;
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::sync::Arc;
use tracing::{event, Level};

lazy_static! {
    static ref SYSCALL_NAMES: HashSet<usize> = {
        let mut ans = HashSet::new();
        ans.insert(libc::SYS_wait4 as usize);
        ans
    };
    static ref VALID_SYSCALLS: HashMap<usize, common::Augments> = {
        let mut ans = HashMap::new();
        for item in SYSCALL_NAMES.iter() {
            ans.insert(*item, common::Augments::Waitpid);
        }
        ans
    };
}

pub struct AugmentWaitpid<PtraceClient: executor::PtraceClient> {
    pub handler: Arc<TraceeHandler<PtraceClient>>,
}

impl<PtraceClient: executor::PtraceClient> common::AugmentSyscall for AugmentWaitpid<PtraceClient> {
    fn valid_calls() -> &'static HashMap<usize, common::Augments> {
        &*VALID_SYSCALLS
    }

    fn before_call(&self, regs: GenericPurposeRegs) -> Result<(), SysAugError> {
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

    fn after_call(&self, regs: GenericPurposeRegs) -> Result<(), SysAugError> {
        let retval = regs.syscall_retval() as isize;
        event!(Level::INFO, "after waitpid() = {}", retval);
        if retval > 0 {
            let child_pid: nix::unistd::Pid =
                nix::unistd::Pid::from_raw(retval.try_into().or(Err(SysAugError::IntoInt))?);
            let mut ignores = self
                .handler
                .ignore_sigstops
                .write()
                .or(Err(SysAugError::LockTraceeHandler))?;
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
        }
        Ok(())
    }
}

impl<PtraceClient: executor::PtraceClient> AugmentWaitpid<PtraceClient> {
    pub fn new(handler: Arc<TraceeHandler<PtraceClient>>) -> Self {
        AugmentWaitpid { handler }
    }
}
