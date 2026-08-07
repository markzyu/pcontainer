// Copyright 2026 Zhongzhi Yu <7296488+markzyu@users.noreply.github.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.

use clap::Clap;
use executor::PtraceServer;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use sysaug::{display_err, ModProvider, PermsMode};
use thiserror::Error;
use tracing::{event, Level};

#[derive(Clap, Debug)]
pub struct CLIArgs {
    /// Trace syscalls like strace (slow). Not all syscalls are supported.
    #[clap(long)]
    pub strace: bool,

    /// Chroot to this path upon tracee startup. Implies --rootfs
    #[clap(long)]
    pub chroot: Option<PathBuf>,

    /// Only use this flag if you see "PTRACE_ATTACH error: EPERM: Permission denied".
    /// This will solve those permission errors, but will also cause slowdowns.
    /// (implies --fix-mmap)
    #[clap(long)]
    pub fix_attach: bool,

    /// If your tracee crashes due to SIGSYS, use this flag.
    #[clap(long)]
    pub fix_sigsys: bool,

    /// If your kernel is older than v3.17, then please use this flag to avoid mmap errors
    #[clap(long)]
    pub fix_mmap: bool,

    /// Make your applications think they are root when they are not.
    #[clap(long)]
    pub root: bool,

    /// You probably want --chroot instead. This simulates rootfs without chroot, for files in this folder.
    #[clap(long)]
    pub rootfs: Option<PathBuf>,

    /// Make your applications think they can sudo when they cannot. Not compatible with --root
    #[clap(long)]
    pub sudo: bool,

    /// Override the command to execute
    #[clap(long, default_value = "bash")]
    pub cmd: String,

    /// Quit as soon as any application fails
    #[clap(long)]
    pub fail_fast: bool,

    /// Try to attach GDB to applications that crashed
    #[clap(long)]
    pub gdb: bool,

    /// Attach GDB after X number of system calls
    #[clap(long)]
    pub gdb_at: Option<u64>,

    /// Use the host ld.so instead of the one from the chroot environment
    #[clap(long)]
    pub use_native_loader: bool,
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

    #[error("Unable to find the absolute path of {0:?}: {1}")]
    PathCanonicalization(PathBuf, std::io::Error),
}

fn init_logging() -> tracing_appender::non_blocking::WorkerGuard {
    if let Ok(filename) = std::env::var("RUST_LOG_DIR") {
        let appender = tracing_appender::rolling::minutely(filename, "main.log");
        let (non_blocking1, guard1) = tracing_appender::non_blocking(appender);
        tracing_subscriber::fmt()
            .with_writer(non_blocking1)
            .with_ansi(false)
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .try_init()
            .expect("Unable to setup logging");
        return guard1;
    }
    let (non_blocking2, guard2) = tracing_appender::non_blocking(std::io::stderr());
    tracing_subscriber::fmt()
        .with_writer(non_blocking2)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init()
        .expect("Unable to setup logging");
    return guard2;
}

fn main() {
    actual_main().map_err(display_err).unwrap();
}

fn actual_main() -> Result<(), CLIError> {
    // Initialize, parse args
    let _guard = init_logging();
    let args = CLIArgs::parse();

    if args.root && args.sudo {
        event!(Level::ERROR, "You cannot use both --root and --sudo");
        return Ok(());
    }
    if args.chroot.is_some() && args.rootfs.is_some() {
        event!(Level::ERROR, "You cannot use both --chroot and --rootfs");
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
    if args.chroot.is_some() || args.rootfs.is_some() {
        mods.push(mods::RootfsMod::new_box);
    }
    if args.sudo {
        mods.push(mods::PermsMod::new_box);
    }

    let retcode = if args.fix_attach {
        let (ptrace_client, ptrace_loop) = executor::new_main_thread_executor();
        let join = launch_ptrace(&args, mods, ptrace_client)?;
        ptrace_loop.serve()?;
        join.join().map_err(|_| CLIError::UnableToComplete)?
    } else {
        launch_ptrace(&args, mods, executor::new_local_executor())?
            .join()
            .map_err(|_| CLIError::UnableToComplete)?
    };

    event!(Level::INFO, "Done. (all tracees exited)");
    std::process::exit(retcode.unwrap() as i32);
}

fn canonicalize_clone(maybe_path: &Option<PathBuf>) -> Result<Option<PathBuf>, CLIError> {
    if let Some(path) = maybe_path {
        match path.canonicalize() {
            Ok(new_path) => Ok(Some(new_path)),
            Err(e) => Err(CLIError::PathCanonicalization(path.clone(), e)),
        }
    } else {
        Ok(None)
    }
}

fn launch_ptrace<PtraceClient: executor::PtraceClient>(
    args: &CLIArgs,
    mods: Vec<ModProvider>,
    ptrace_client: PtraceClient,
) -> Result<thread::JoinHandle<Option<u8>>, CLIError> {
    // Spawn first tracee
    let (pid1, shared_fd, mmap_addr) = {
        let mut cmd = std::process::Command::new(&args.cmd);
        ptrace::start(&mut cmd, args.fix_attach)?
    };
    event!(Level::INFO, "First tracee pid: {:?}", pid1);

    // Setup tracee handler states
    let args2 = sysaug::CLIArgs {
        chroot: canonicalize_clone(&args.chroot)?,
        rootfs: canonicalize_clone(&args.rootfs)?,
        perms_mode: if args.root {
            PermsMode::RootOnly
        } else if args.sudo {
            PermsMode::SudoOnly
        } else {
            PermsMode::Passthrough
        },
        fail_fast: args.fail_fast,
        fix_sigsys: args.fix_sigsys,
        fix_mmap: args.fix_mmap || args.fix_attach,
        gdb: args.gdb,
        gdb_at: args.gdb_at,
        use_native_loader: args.use_native_loader,
    };
    let states = sysaug::TraceeHandlerStates {
        args: args2,
        root_pid: pid1,
        ..Default::default()
    };

    // Start tracee handler thread
    let ptrace_client2 = ptrace_client.clone();
    let new_tracee_handler = sysaug::TraceeHandler::new(
        pid1,
        ptrace_client,
        mods,
        Some(Arc::new(states)),
        None,
        shared_fd,
        mmap_addr,
    )?;
    Ok(new_tracee_handler.start(move || ptrace_client2.stop()))
}
