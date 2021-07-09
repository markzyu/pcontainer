use std::thread;
use sysaug::{display_err, ModProvider};
use thiserror::Error;
use tracing::{event, Level};

#[derive(Debug, Error)]
pub enum CLIError {
    #[error("Unexpected internal error from ptrace() executor: {0}")]
    InternalExecutor(#[from] executor::PtraceExecutorError),

    #[error("Ptrace error: {0}")]
    Ptrace(#[from] ptrace::PtraceError),

    #[error("Syscall error: {0}")]
    SysAugErr(#[from] sysaug::SysAugError),
}

fn main() -> Result<(), CLIError> {
    tracing_subscriber::fmt::init();
    let (proc1_client, ptrace_loop) = executor::new_ptrace_executor();

    let mut cmd = std::process::Command::new("bash");
    let child = ptrace::start(&mut cmd)?;

    let mods: Vec<ModProvider> = vec![mods::ChrootMod::new_box, mods::TraceChildMod::new_box];

    let pid1 = ptrace::pid(&child)?;
    event!(Level::INFO, "First tracee pid: {:?}", pid1);

    let new_tracee_handler = sysaug::TraceeHandler::new(pid1, proc1_client.clone(), mods)?;
    thread::spawn(move || {
        let proc1_client2 = proc1_client.clone();
        let result = new_tracee_handler.event_loop();
        proc1_client2.stop();
        result.map_err(display_err).unwrap()
    });

    ptrace_loop.serve()?;
    event!(Level::INFO, "Done. (all tracees exited)");

    Ok(())
}
