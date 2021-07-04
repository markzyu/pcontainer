use ptrace::GenericPurposeRegs;
use std::collections::HashSet;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SysAugError {
    #[error("Unexpected internal error from ptrace() executor: {0}")]
    InternalExecutor(#[from] executor::PtraceExecutorError),

    #[error("Ptrace error: {0}")]
    Ptrace(#[from] ptrace::PtraceError),

    #[error("OS Error: {0}")]
    LinuxOSErr(#[from] nix::Error),

    #[error("Not a valid absolute path: {0}")]
    AbsolutePath(std::path::PathBuf),

    #[error("Interger conversion error")]
    IntoInt,
}

pub trait AugmentSyscall {
    fn before_call(&self, regs: &GenericPurposeRegs) -> Result<(), SysAugError>;
    fn after_call(&self, regs: &GenericPurposeRegs) -> Result<(), SysAugError>;
    fn valid_calls(&self) -> &HashSet<ptrace::SysNum>;

    fn new(pid: nix::unistd::Pid, ptrace_client: executor::PtraceClient) -> Self;

    fn dispatch(
        &self,
        last_syscall: &SyscallCounter,
        regs: &GenericPurposeRegs,
    ) -> Result<(), SysAugError> {
        if let Some(syscall) = last_syscall.syscall.as_ref() {
            if !self.valid_calls().contains(syscall) {
                return Ok(());
            }
        }
        if last_syscall.times % 2 == 1 {
            self.before_call(&regs)?;
        }
        if last_syscall.times % 2 == 0 {
            self.after_call(&regs)?;
        }
        Ok(())
    }
}

pub struct SyscallCounter {
    pub syscall: Option<ptrace::SysNum>,
    pub times: u64,
}

impl SyscallCounter {
    pub fn count(&mut self, syscall_name: ptrace::SysNum) {
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
