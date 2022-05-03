use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvError, RecvTimeoutError, SendError, SyncSender};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

pub type SharedBool = Arc<AtomicBool>;
pub type PtraceRequest = Box<dyn Fn() -> Result<(), PtraceExecutorError> + Send>;

pub struct PtraceServer {
    recv_req: Receiver<PtraceRequest>,
    should_serve: SharedBool,
}

pub struct PtraceClient {
    send_req: SyncSender<PtraceRequest>,
    should_serve: SharedBool,
}

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
}

pub fn new_ptrace_executor() -> (PtraceClient, PtraceServer) {
    let (send, recv) = sync_channel(1);
    let should_serve = Arc::new(AtomicBool::new(false));
    let client = PtraceClient {
        send_req: send,
        should_serve: Arc::clone(&should_serve),
    };
    let server = PtraceServer {
        recv_req: recv,
        should_serve: Arc::clone(&should_serve),
    };
    (client, server)
}

impl PtraceServer {
    fn read_should_serve(&self) -> bool {
        self.should_serve.load(Ordering::Relaxed)
    }

    pub fn serve(&self) -> Result<(), PtraceExecutorError> {
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

impl Clone for PtraceClient {
    fn clone(&self) -> PtraceClient {
        PtraceClient {
            send_req: self.send_req.clone(),
            should_serve: Arc::clone(&self.should_serve),
        }
    }
}

impl PtraceClient {
    pub fn stop(&self) {
        self.should_serve.store(false, Ordering::Relaxed);
    }

    fn send(&self, req: PtraceRequest) -> Result<(), PtraceExecutorError> {
        Ok(self.send_req.clone().send(req)?)
    }

    pub fn execute<T, F>(&self, f: F) -> Result<T, PtraceExecutorError>
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
