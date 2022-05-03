use crate::handler::TraceeHandlerStates;
use crate::mods;
use ptrace::GenericPurposeRegs;
use std::collections::HashMap;
use std::fmt::Display;
use std::sync::Arc;
use thiserror::Error;
use tracing::{event, Level};

#[derive(Debug, Error)]
pub enum SysAugError {
    #[error("Unexpected internal error from ptrace() executor: {0}")]
    InternalExecutor(#[from] executor::PtraceExecutorError),

    #[error("Failed to parse waitpid result: {0}")]
    ParseWaitStatus(nix::Error),

    #[error("Ptrace error: {0}")]
    Ptrace(#[from] ptrace::PtraceError),

    #[error("PTRACE_DETACH error")]
    PtraceDetach(nix::Error),

    #[error("PTRACE_GETSIGINFO error")]
    PtraceGetSigInfo,

    #[error("PTRACE_PEEKDATA error: {0}")]
    PtraceRead(nix::Error),

    #[error("PTRACE_SETOPTIONS error: {0}")]
    PtraceSetOptions(nix::Error),

    #[error("PTRACE_SYSCALL error: {0}")]
    PtraceSyscall(nix::Error),

    #[error("Not a valid absolute path: {0}")]
    AbsolutePath(std::path::PathBuf),

    #[error("Interger conversion error")]
    IntoInt,

    #[error("Cannot lock/unlock tracee handler")]
    LockTraceeHandler,

    #[error("Tracee process exited/crashed unexpectedly")]
    TraceeCrashed,

    #[error("Failed to write metadata: {0}")]
    WriteMetadata(String),

    #[error("{kind} error from '{mod_name}' mod: {message}")]
    Mod {
        kind: String,
        message: String,
        mod_name: String,
    },
}

pub type ModProvider = fn(Arc<TraceeHandlerStates>) -> Box<dyn mods::Mod>;
pub type ModBox = Box<dyn mods::Mod + Send + Sync>;
pub type ModsByFeature = HashMap<mods::ModFeature, Vec<ModBox>>;

#[allow(dead_code)]
pub fn clone_mods_by_feature(src: &ModsByFeature) -> ModsByFeature {
    let mut ans: ModsByFeature = HashMap::new();
    for (feature, arr) in src.iter() {
        let mut arr2 = Vec::new();
        for m in arr.iter() {
            arr2.push(m.clone_box());
        }
        ans.insert(feature.clone(), arr2);
    }
    ans
}

pub fn display_err<E: Display>(e: E) -> E {
    event!(Level::ERROR, "Error: {}", e);
    e
}

pub trait AugmentSyscall {
    fn before_call(&self, regs: GenericPurposeRegs) -> Result<(), SysAugError>;
    fn after_call(&self, regs: GenericPurposeRegs) -> Result<(), SysAugError>;
    fn valid_calls() -> &'static HashMap<usize, Augments>;

    fn dispatch(
        &self,
        last_syscall: &SyscallCounter,
        regs: GenericPurposeRegs,
    ) -> Result<(), SysAugError> {
        if last_syscall.times % 2 == 1 {
            self.before_call(regs)
        } else {
            self.after_call(regs)
        }
    }
}

#[derive(Debug)]
pub enum Augments {
    Clone,
    Paths,
    Perms,
    Waitpid,
}

#[derive(Debug)]
pub struct SyscallCounter {
    pub syscall: Option<usize>,
    pub times: u64,
}

impl SyscallCounter {
    pub fn count(&mut self, syscall_name: usize) {
        let curr_syscall = Some(syscall_name);
        if self.syscall != curr_syscall {
            self.syscall = curr_syscall;
            self.times = 1;
        } else {
            self.times += 1;
        }
    }

    pub fn new() -> SyscallCounter {
        SyscallCounter {
            syscall: None,
            times: 0,
        }
    }
}
