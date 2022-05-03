use lazy_static::lazy_static;
use nix::sys;
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
}

pub fn event_thread(
    pid: nix::unistd::Pid,
    ptrace_client: executor::PtraceClient,
) -> Result<(), CLIError> {
    ptrace_client.execute(move || {
        sys::ptrace::setoptions(pid, sys::ptrace::Options::PTRACE_O_TRACESYSGOOD).unwrap()
    })?;

    let mut last_syscall: Option<String> = None;
    let mut last_syscall_times: u64 = 0;
    loop {
        let span = span!(Level::TRACE, "event_loop", ?pid);
        let _span_enter = span.enter();

        ptrace_client.execute(move || sys::ptrace::syscall(pid, None).unwrap())?;
        let status = ptrace::waitpid_hang(pid).unwrap();
        event!(Level::TRACE, "child status {:?}", &status);

        if !ptrace::is_trace_stop(&status) && !ptrace::is_still_alive(&status) {
            break;
        }

        if !ptrace::is_syscall_stop(&status) {
            continue;
        }

        let regs = ptrace_client.execute(move || ptrace::getregs(pid).unwrap())?;
        let unknown: String = "Unknown syscall".into();
        let name = SYSCALL_NAMES.get(&regs.syscall_num).unwrap_or(&unknown);

        let curr_syscall = Some(name.clone());
        if last_syscall != curr_syscall {
            last_syscall = curr_syscall;
            last_syscall_times = 1;
        } else {
            last_syscall_times += 1;
        }

        if last_syscall_times % 2 == 1 {
            event!(
                Level::DEBUG,
                "Syscall {} {} ({:x}, {:x}, {:x})",
                name,
                times = &last_syscall_times,
                arg0 = regs.arg0,
                arg1 = regs.arg1,
                arg2 = regs.arg2,
            );
        }
        // Before clone()
        if name == "clone" && last_syscall_times % 2 == 1 {
            let mut new_regs = regs.clone();
            let new_flag: ptrace::SysNum = libc::CLONE_PTRACE.try_into().unwrap();
            new_regs.arg0 |= new_flag;
            ptrace_client.execute(move || ptrace::setregs(pid, new_regs.clone()).unwrap())?;
            let confirm_regs = ptrace_client.execute(move || ptrace::getregs(pid).unwrap())?;
            event!(
                Level::DEBUG,
                "Clone new arg: {:x}, {:x}, {:x}",
                confirm_regs.arg0,
                confirm_regs.arg1,
                confirm_regs.arg2,
            );
        }
        // After clone()
        if name == "clone" && last_syscall_times % 2 == 0 {
            let raw_pid = regs.syscall_retval();
            if raw_pid > 0 {
                let child_pid: nix::unistd::Pid =
                    nix::unistd::Pid::from_raw(raw_pid.try_into().unwrap());
                event!(Level::INFO, "Clone pid {}", child_pid);
                let new_ptrace_client = ptrace_client.clone();
                thread::spawn(move || {
                    event_thread(child_pid, new_ptrace_client).unwrap();
                });
            }
        }
    }
    Ok(())
}

fn main() -> Result<(), CLIError> {
    tracing_subscriber::fmt::init();
    let (proc1_client, ptrace_loop) = executor::new_ptrace_executor();

    let mut cmd = std::process::Command::new("bash");
    let child = ptrace::start(&mut cmd).unwrap();

    let pid1 = ptrace::pid(&child).unwrap();
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
