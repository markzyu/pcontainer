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

use nix::sys;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::{RecvError, RecvTimeoutError, SendError};
use thiserror::Error;

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
