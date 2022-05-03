use clap::Clap;
use std::sync::RwLock;
use std::thread;
use sysaug::{display_err, ModProvider};
use thiserror::Error;
use tracing::{event, Level};

#[derive(Clap, Debug)]
pub struct CLIArgs {
    /// Trace syscalls like strace (slow). Not all syscalls are supported.
    #[clap(long)]
    pub strace: bool,

    /// Chroot to this path upon tracee startup.
    #[clap(long)]
    pub chroot: Option<String>,
}

#[derive(Debug, Error)]
pub enum CLIError {
    #[error("Unexpected internal error from ptrace() executor: {0}")]
    InternalExecutor(#[from] executor::PtraceExecutorError),

    #[error("Ptrace error: {0}")]
    Ptrace(#[from] ptrace::PtraceError),

    #[error("Syscall error: {0}")]
    SysAugErr(#[from] sysaug::SysAugError),

    #[error("Invalid command line arguments: {0}")]
    ParseArgs(String),
}

fn main() -> Result<(), CLIError> {
    // Initialize, parse args
    tracing_subscriber::fmt::init();
    let args = CLIArgs::parse();

    // Spawn first tracee
    let pid1 = {
        let mut cmd = std::process::Command::new("bash");
        let child = ptrace::start(&mut cmd)?;
        ptrace::pid(&child)?
    };
    event!(Level::INFO, "First tracee pid: {:?}", pid1);

    // Setup mods
    let mut mods: Vec<ModProvider> = vec![mods::ChrootMod::new_box, mods::TraceChildMod::new_box];
    if args.strace {
        mods.push(mods::StraceMod::new_box);
    }

    // Setup tracee handler states
    let states = sysaug::TraceeHandlerStates {
        path_prefix: RwLock::new(args.chroot.map(|s| s.into())),
    };

    // Start tracee handler thread
    let (proc1_client, ptrace_loop) = executor::new_ptrace_executor();
    let new_tracee_handler =
        sysaug::TraceeHandler::new(pid1, mods, Some(states))?;
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
