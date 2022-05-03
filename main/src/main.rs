use lazy_static::lazy_static;
use nix::sys;
use ptrace::GenericPurposeRegs;
use std::collections::HashMap;
use std::convert::TryInto;
use std::thread;
use thiserror::Error;
use tracing::{event, span, Level};

lazy_static! {
    static ref SYSCALL_NAMES: HashMap<ptrace::SysNum, String> = {
        let mut map = HashMap::new();
        map.insert(libc::SYS_openat, "openat".into());
        map.insert(libc::SYS_close, "close".into());
        map.insert(libc::SYS_read, "read".into());
        map.insert(libc::SYS_write, "write".into());
        map.insert(libc::SYS_clone, "clone".into());
        map
    };
}

#[derive(Debug, Error)]
pub enum CLIError {
    #[error("Unexpected internal error from ptrace() executor: {0}")]
    InternalExecutor(#[from] executor::PtraceExecutorError),

    #[error("Ptrace error: {0}")]
    Ptrace(#[from] ptrace::PtraceError),

    #[error("OS Error: {0}")]
    LinuxOSErr(#[from] nix::Error),

    #[error("Interger conversion error")]
    IntoInt,
}

trait AugmentSyscall {
    fn before_call(&self, regs: &GenericPurposeRegs) -> Result<(), CLIError>;
    fn after_call(&self, regs: &GenericPurposeRegs) -> Result<(), CLIError>;
    fn dispatch(&self, last_syscall_times: u64, regs: &GenericPurposeRegs) -> Result<(), CLIError> {
        if last_syscall_times % 2 == 1 {
            self.before_call(&regs)?;
        }
        if last_syscall_times % 2 == 0 {
            self.after_call(&regs)?;
        }
        Ok(())
    }
}

struct AugmentClone {
    pid: nix::unistd::Pid,
    ptrace_client: executor::PtraceClient,
}

impl AugmentSyscall for AugmentClone {
    fn before_call(&self, regs: &GenericPurposeRegs) -> Result<(), CLIError> {
        let mut new_regs = regs.clone();
        let pid2 = self.pid;
        let new_flag: ptrace::SysNum = libc::CLONE_PTRACE.try_into().or(Err(CLIError::IntoInt))?;
        new_regs.arg0 |= new_flag;
        self.ptrace_client
            .execute(move || ptrace::setregs(pid2, new_regs.clone()))??;
        let confirm_regs = self
            .ptrace_client
            .execute(move || ptrace::getregs(pid2))??;
        event!(
            Level::DEBUG,
            "Clone new arg: {:x}, {:x}, {:x}",
            confirm_regs.arg0,
            confirm_regs.arg1,
            confirm_regs.arg2,
        );
        Ok(())
    }

    fn after_call(&self, regs: &GenericPurposeRegs) -> Result<(), CLIError> {
        let raw_pid = regs.syscall_retval();
        if raw_pid > 0 {
            let child_pid: nix::unistd::Pid =
                nix::unistd::Pid::from_raw(raw_pid.try_into().or(Err(CLIError::IntoInt))?);
            event!(Level::INFO, "Clone pid {}", child_pid);
            let new_ptrace_client = self.ptrace_client.clone();
            thread::spawn(move || {
                event_thread(child_pid, new_ptrace_client).unwrap();
            });
        }
        Ok(())
    }
}

struct SyscallCounter {
    name: Option<String>,
    times: u64,
}

impl SyscallCounter {
    fn count(&mut self, syscall_name: &str) {
        let curr_syscall = Some(syscall_name.to_string());
        if self.name != curr_syscall {
            self.name = curr_syscall;
            self.times = 1;
        } else {
            self.times += 1;
        }
    }

    fn new() -> SyscallCounter {
        SyscallCounter {
            name: None,
            times: 0,
        }
    }
}

pub fn event_thread(
    pid: nix::unistd::Pid,
    ptrace_client: executor::PtraceClient,
) -> Result<(), CLIError> {
    ptrace_client.execute(move || {
        sys::ptrace::setoptions(pid, sys::ptrace::Options::PTRACE_O_TRACESYSGOOD)
    })??;

    let augment_clone = AugmentClone {
        pid,
        ptrace_client: ptrace_client.clone(),
    };

    let mut last_syscall = SyscallCounter::new();
    loop {
        let span = span!(Level::TRACE, "event_loop", ?pid);
        let _span_enter = span.enter();

        ptrace_client.execute(move || sys::ptrace::syscall(pid, None))??;
        let status = ptrace::waitpid_hang(pid)?;
        event!(Level::TRACE, "child status {:?}", &status);

        if !ptrace::is_trace_stop(&status) && !ptrace::is_still_alive(&status) {
            break;
        }

        if !ptrace::is_syscall_stop(&status) {
            continue;
        }

        let regs = ptrace_client.execute(move || ptrace::getregs(pid))??;
        let unknown: String = "Unknown syscall".into();
        let name = SYSCALL_NAMES.get(&regs.syscall_num).unwrap_or(&unknown);

        last_syscall.count(&name);
        if last_syscall.times % 2 == 1 {
            event!(
                Level::DEBUG,
                "Syscall {} {} ({:x}, {:x}, {:x})",
                name,
                times = &last_syscall.times,
                arg0 = regs.arg0,
                arg1 = regs.arg1,
                arg2 = regs.arg2,
            );
        }
        if name == "clone" {
            augment_clone.dispatch(last_syscall.times, &regs)?;
        }
    }
    Ok(())
}

fn main() -> Result<(), CLIError> {
    tracing_subscriber::fmt::init();
    let (proc1_client, ptrace_loop) = executor::new_ptrace_executor();

    let mut cmd = std::process::Command::new("bash");
    let child = ptrace::start(&mut cmd)?;

    let pid1 = ptrace::pid(&child)?;
    event!(Level::INFO, "First tracee pid: {:?}", pid1);
    thread::spawn(move || {
        let proc1_client2 = proc1_client.clone();
        let result = event_thread(pid1, proc1_client);
        proc1_client2.stop();
        result.unwrap();
    });

    ptrace_loop.serve()?;
    event!(Level::INFO, "Done. (all tracees exited)");

    Ok(())
}
