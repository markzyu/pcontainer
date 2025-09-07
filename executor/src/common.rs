use nix::{sys, unistd};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvError, RecvTimeoutError, SendError, SyncSender};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use thiserror::Error;
use tracing::{event, Level};

pub type SharedBool = Arc<AtomicBool>;
pub type PtraceRequest = Box<dyn FnOnce() -> Result<(), PtraceExecutorError> + Send>;

#[derive(Debug, Error)]
pub enum PtraceExecutorError {
    #[error("Failed to enqueue ptrace() operation: {0}")]
    TaskEnqueue(#[from] SendError<PtraceRequest>),

    #[error("Failed to dequeue ptrace() operation: {0}")]
    TaskDequeue(RecvTimeoutError),

    #[error("Failed to dequeue ptrace() result: {0}")]
    ResultDequeue(RecvError),

    #[error("Failed to enqueue ptrace() result: {0}")]
    ResultEnqueue(String),

    #[error("PTRACE_ATTACH error: {0}")]
    Attach(nix::Error),

    #[error("{0}")]
    PtraceError(#[from] ptrace::PtraceError),

    #[error("Cannot transfer tracee. PTRACE_DETACH error: {0}")]
    TransferDetach(nix::Error),

    #[error("Cannot transfer tracee. Lock failure.")]
    TransferLock,

    #[error("Cannot transfer tracee. Waitpid error: {0:?}")]
    TransferWaitpid(sys::wait::WaitStatus),

    #[error("Internal error, async runtime detected invalid usage of external async library")]
    AsyncBanOfExternalCode,
}
