use clap::Clap;
use executor::PtraceServer;
use std::sync::{Arc, RwLock};
use std::thread;
use sysaug::ModProvider;
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

    /// Make your applications think they are root when they are not.
    #[clap(long)]
    pub root: bool,

    /// Make your applications think they are root when they are not.
    #[clap(long)]
    pub rootfs: bool,

    /// Make your applications think they can sudo when they cannot. Not compatible with --root
    #[clap(long)]
    pub sudo: bool,

    /// Override the command to execute
    #[clap(long, default_value = "bash")]
    pub cmd: String,

    /// Quit as soon as any application fails
    #[clap(long)]
    pub fail_fast: bool,
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

    if args.root && args.sudo {
        event!(Level::ERROR, "You cannot use both --root and --sudo");
        return Ok(());
    }

    // Setup mods
    let mut mods: Vec<ModProvider> = Vec::new();
    if args.chroot.is_some() {
        mods.push(mods::ChrootMod::new_box);
    }
    if args.strace {
        mods.push(mods::StraceMod::new_box);
    }
    if args.root {
        mods.push(mods::SimpleRootMod::new_box);
    }
    if args.rootfs {
        mods.push(mods::RootfsMod::new_box);
    }
    if args.sudo {
        mods.push(mods::PermsMod::new_box);
    }

    let retcode = if args.fix_attach {
        let (ptrace_client, ptrace_loop) = executor::new_main_thread_executor();
        let join = actual_main(&args, mods, ptrace_client)?;
        ptrace_loop.serve()?;
        join.join().map_err(|_| CLIError::UnableToComplete)?
    } else {
        actual_main(&args, mods, executor::new_local_executor())?
            .join()
            .map_err(|_| CLIError::UnableToComplete)?
    };

    event!(Level::INFO, "Done. (all tracees exited)");
    std::process::exit(retcode.unwrap() as i32);
}

fn actual_main<PtraceClient: executor::PtraceClient>(
    args: &CLIArgs,
    mods: Vec<ModProvider>,
    ptrace_client: PtraceClient,
) -> Result<thread::JoinHandle<Option<u8>>, CLIError> {
    // Spawn first tracee
    let pid1 = {
        let mut cmd = std::process::Command::new(&args.cmd);
        ptrace::start(&mut cmd, args.fix_attach)?
    };
    event!(Level::INFO, "First tracee pid: {:?}", pid1);

    // Setup tracee handler states
    let states = sysaug::TraceeHandlerStates {
        fail_fast: args.fail_fast,
        path_prefix: RwLock::new(args.chroot.as_ref().map(|s| s.into())),
        root_pid: pid1,
        ..Default::default()
    };

    // Start tracee handler thread
    let ptrace_client2 = ptrace_client.clone();
    let new_tracee_handler =
        sysaug::TraceeHandler::new(pid1, ptrace_client.clone(), mods, Some(Arc::new(states)))?;
    Ok(new_tracee_handler.start(move || ptrace_client2.stop()))
}
