use std::sync::{Arc, Mutex};
use std::sync::mpsc::{sync_channel, SyncSender, Receiver};
use std::time::Duration;

pub type SharedBool = Arc<Mutex<bool>>;
pub type PtraceRequest = Box<dyn Fn() + Send>;

pub struct PtraceServer {
    recv_req: Receiver<PtraceRequest>,
    should_serve: SharedBool,
}

pub struct PtraceClient {
    send_req: SyncSender<PtraceRequest>,
    should_serve: SharedBool,
}

pub fn new_ptrace_executor() -> (PtraceClient, PtraceServer) {
    let (send, recv) = sync_channel(1);
    let should_serve = Arc::new(Mutex::new(false));
    let client = PtraceClient {
        send_req: send,
        should_serve: Arc::clone(&should_serve),
    };
    let server = PtraceServer {
        recv_req: recv,
        should_serve: Arc::clone(&should_serve),
    };
    return (client, server);
}

impl PtraceServer {
    fn read_should_serve(&self) -> bool {
        let data = self.should_serve.lock().unwrap();
        data.clone()
    }

    pub fn serve(&self) {
        {
            let mut data = self.should_serve.lock().unwrap();
            *data = true;
        }
        while self.read_should_serve() {
            let item = self.recv_req.recv_timeout(Duration::from_millis(100));
            if let Ok(req) = item {
                req();
            }
        }
    }
}

impl PtraceClient {
    pub fn clone(&self) -> PtraceClient {
        PtraceClient {
            send_req: self.send_req.clone(),
            should_serve: Arc::clone(&self.should_serve),
        }
    }

    pub fn stop(&self) {
        let mut data = self.should_serve.lock().unwrap();
        *data = false;
    }

    fn send(&self, req: PtraceRequest) {
        self.send_req.clone().send(req).unwrap();
    }

    pub fn execute<T, F> (&self, f: F) -> T 
    where F: Fn() -> T,
          F: Send + 'static,
          T: Send + 'static {
        let (send, recv) = sync_channel(1);
        let final_func = move || {
            let result = f();
            send.send(result).unwrap();
        };

        // This must be replaced later
        self.send(Box::new(final_func));

        // Return results
        return recv.recv().unwrap();
    }
}

#[cfg(test)]
mod tests {
    use std::thread;
    use crate::new_ptrace_executor;

    #[test]
    fn it_works() {
        let (client, server) = new_ptrace_executor();
        let client2 = client.clone();
        let join = thread::spawn(move || {
            let mut result = 0;
            for _i in 0..100 {
                for _j in 0..1000 {
                    result += client2.execute(|| 2 + 2);
                }
            }
            client2.stop();
            result
        });

        server.serve();

        let result = join.join().unwrap();
        assert_eq!(result, 4 * 1000 * 100);
    }
}
