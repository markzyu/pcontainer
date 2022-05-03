use nix::{sys, unistd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvError, RecvTimeoutError, SendError, SyncSender};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tracing::{event, Level};

pub type SharedBool = Arc<AtomicBool>;
pub type PtraceRequest = Box<dyn Fn() -> Result<(), PtraceExecutorError> + Send>;

pub trait PtraceServer {
    fn serve(&self) -> Result<(), PtraceExecutorError>;
}

pub trait PtraceClient: Clone + Send + Sync + 'static {
    fn attach_to(&self, _pid: unistd::Pid) -> Result<(), PtraceExecutorError> {
        Ok(())
    }

    fn prep_attach_to(&self, _pid: unistd::Pid) -> Result<(), PtraceExecutorError> {
        Ok(())
    }

    fn stop(&self);
    fn execute<T, F>(&self, f: F) -> Result<T, PtraceExecutorError>
    where
        F: Fn() -> T,
        F: Send + 'static,
        T: Send + 'static;
}

pub struct MainThreadServer {
    recv_req: Receiver<PtraceRequest>,
    should_serve: SharedBool,
}

pub struct MainThreadClient {
    send_req: SyncSender<PtraceRequest>,
    should_serve: SharedBool,
}

#[derive(Clone)]
pub struct LocalPtraceClient {}

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

    #[error("Cannot transfer tracee. Waitpid error: {0:?}")]
    TransferWaitpid(sys::wait::WaitStatus),
}

/// Run ptrace() syscalls on main thread only (requires tracees to be attached through PTRACE_TRACEME)
pub fn new_main_thread_executor() -> (MainThreadClient, MainThreadServer) {
    let (send, recv) = sync_channel(1);
    let should_serve = Arc::new(AtomicBool::new(false));
    let client = MainThreadClient {
        send_req: send,
        should_serve: Arc::clone(&should_serve),
    };
    let server = MainThreadServer {
        recv_req: recv,
        should_serve: Arc::clone(&should_serve),
    };
    (client, server)
}

/// Run ptrace() syscalls on any thread (requires tracees to be attached through PTRACE_ATTACH)
pub fn new_local_executor() -> LocalPtraceClient {
    LocalPtraceClient {}
}

impl MainThreadServer {
    fn read_should_serve(&self) -> bool {
        self.should_serve.load(Ordering::Relaxed)
    }
}

impl PtraceServer for MainThreadServer {
    fn serve(&self) -> Result<(), PtraceExecutorError> {
        self.should_serve.store(true, Ordering::Relaxed);
        while self.read_should_serve() {
            let item = self.recv_req.recv_timeout(Duration::from_millis(100));
            if matches!(item, Err(RecvTimeoutError::Timeout)) {
                continue;
            }
            if self.read_should_serve() {
                let task = item.map_err(PtraceExecutorError::TaskDequeue)?;
                task()?;
            } else if let Ok(req) = item {
                req()?;
            }
        }
        Ok(())
    }
}

impl Clone for MainThreadClient {
    fn clone(&self) -> MainThreadClient {
        MainThreadClient {
            send_req: self.send_req.clone(),
            should_serve: Arc::clone(&self.should_serve),
        }
    }
}

impl MainThreadClient {
    fn send(&self, req: PtraceRequest) -> Result<(), PtraceExecutorError> {
        Ok(self.send_req.clone().send(req)?)
    }
}

impl PtraceClient for MainThreadClient {
    fn stop(&self) {
        self.should_serve.store(false, Ordering::Relaxed);
    }

    fn execute<T, F>(&self, f: F) -> Result<T, PtraceExecutorError>
    where
        F: Fn() -> T,
        F: Send + 'static,
        T: Send + 'static,
    {
        let (send, recv) = sync_channel(1);
        let final_func = move || {
            let result = f();
            send.send(result)
                .map_err(|e| PtraceExecutorError::ResultEnqueue(e.to_string()))
        };

        // This must be replaced later
        self.send(Box::new(final_func))?;

        // Return results
        recv.recv().map_err(PtraceExecutorError::ResultDequeue)
    }
}

impl PtraceClient for LocalPtraceClient {
    fn attach_to(&self, pid: unistd::Pid) -> Result<(), PtraceExecutorError> {
        event!(Level::INFO, "LocalPtraceClient attaching to {:?}", pid);
        sys::ptrace::attach(pid).map_err(PtraceExecutorError::Attach)
    }

    fn prep_attach_to(&self, pid: unistd::Pid) -> Result<(), PtraceExecutorError> {
        event!(
            Level::INFO,
            "LocalPtraceClient prepping to attach to {:?}",
            pid
        );

        let status = ptrace::waitpid_hang(pid)?;
        event!(Level::INFO, "child status {:?}", &status);

        if !ptrace::is_trace_stop(&status) && !ptrace::is_still_alive(&status) {
            return Err(PtraceExecutorError::TransferWaitpid(status));
        }

        sys::ptrace::detach(pid, sys::signal::Signal::SIGSTOP)
            .map_err(PtraceExecutorError::TransferDetach)
    }

    fn stop(&self) {}

    #[inline(always)]
    fn execute<T, F>(&self, f: F) -> Result<T, PtraceExecutorError>
    where
        F: Fn() -> T,
        F: Send + 'static,
        T: Send + 'static,
    {
        Ok(f())
    }
}

#[cfg(test)]
mod tests {
    use crate::new_ptrace_executor;
    use std::thread;

    #[test]
    fn it_works() {
        let (client, server) = new_ptrace_executor();
        let client2 = client.clone();
        let join = thread::spawn(move || {
            let mut result = 0;
            for _i in 0..100 {
                for _j in 0..1000 {
                    result += client2.execute(|| 2 + 2).unwrap();
                }
            }
            client2.stop();
            result
        });

        server.serve().unwrap();

        let result = join.join().unwrap();
        assert_eq!(result, 4 * 1000 * 100);
    }
}
