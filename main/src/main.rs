use clap::Clap;
use executor::PtraceServer;
use std::sync::{Arc, RwLock};
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

    /// Only use this flag if you see "PTRACE_ATTACH error: EPERM: Permission denied".
    /// This will solve those permission errors, but will also cause slowdowns.
    #[clap(long)]
    pub fix_attach: bool,
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

    #[error("Unable to complete")]
    UnableToComplete,
}

fn main() -> Result<(), CLIError> {
    // Initialize, parse args
    tracing_subscriber::fmt::init();
    let args = CLIArgs::parse();

    // Setup mods
    let mut mods: Vec<ModProvider> = vec![mods::ChrootMod::new_box, mods::TraceChildMod::new_box];
    if args.strace {
        mods.push(mods::StraceMod::new_box);
    }

    if args.fix_attach {
        let (ptrace_client, ptrace_loop) = executor::new_main_thread_executor();
        let join = actual_main(&args, mods, ptrace_client)?;
        ptrace_loop.serve()?;
        join.join().map_err(|_| CLIError::UnableToComplete)?;
    } else {
        actual_main(&args, mods, executor::new_local_executor())?
            .join()
            .map_err(|_| CLIError::UnableToComplete)?;
    }

    event!(Level::INFO, "Done. (all tracees exited)");
    Ok(())
}

fn actual_main<PtraceClient: executor::PtraceClient>(
    args: &CLIArgs,
    mods: Vec<ModProvider>,
    ptrace_client: PtraceClient,
) -> Result<thread::JoinHandle<()>, CLIError> {
    // Spawn first tracee
    let pid1 = {
        let mut cmd = std::process::Command::new("bash");
        ptrace::start(&mut cmd, args.fix_attach)?
    };
    event!(Level::INFO, "First tracee pid: {:?}", pid1);

    // Setup tracee handler states
    let mut states = sysaug::TraceeHandlerStates::default(); 
    states.path_prefix = RwLock::new(args.chroot.as_ref().map(|s| s.into()));

    // Start tracee handler thread
    let new_tracee_handler =
        sysaug::TraceeHandler::new(pid1, ptrace_client.clone(), mods, Some(Arc::new(states)))?;
    Ok(thread::spawn(move || {
        let ptrace_client2 = ptrace_client.clone();
        let result = new_tracee_handler.event_loop();
        ptrace_client2.stop();
        result.map_err(display_err).unwrap()
    }))
}
