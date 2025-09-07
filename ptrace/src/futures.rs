use crate::common::PtraceError;
use nix::sys::wait::WaitStatus;
use std::cell::RefCell;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Wake};
use std::vec::Vec;

// TODO: Convert this to use futures_lite. 
//       Add unit tests
//       Move to ptrace crate

// Note: Important Caveat:
//
// We do not support tokio, async I/O, or most usual awaits.
//
// The use of async is purely to simplify the state machine spaghetti
// for managing the tracee states (for example when trying to force
// tracee to execute a series of system calls)
//
// You can await most functions we defined ourselves, but should not
// await on external library functions.

#[derive(Clone, Eq, Hash, PartialEq)]
pub enum PtraceFutureTypes {
    WaitForPtraceSyscall,
    WaitForPtraceEvent,
    WaitForSignal,
}

#[derive(Clone)]
pub struct PtraceStatus {
    pub wait_status: WaitStatus
}

#[derive(Default)]
pub struct PtraceAsyncRuntime {
    pending_futures: RefCell<HashMap<PtraceFutureTypes, Vec<Rc<RefCell<PtraceFuture>>>>>,
    has_new_future: AtomicBool,
}

/// Special PtraceFuture that yields back from "async" world to sync world
/// 
/// This is the only safe future object to await on, or wrap in async functions.
#[derive(Clone)]
pub enum PtraceFuture {
    Ready(Rc<PtraceStatus>),

    Pending,
}

impl PtraceFuture {
    fn new(runtime: &PtraceAsyncRuntime, future_type: PtraceFutureTypes) -> Rc<RefCell<Self>> {
        let result = Rc::new(RefCell::new(Self::Pending));
        runtime.register_pending(future_type, result.clone());
        result
    }

    fn resolve(&mut self, val: Rc<PtraceStatus>) {
        *self = PtraceFuture::Ready(val);
    }
}

// Backwards compatibility so that std Future can await PtraceFuture properly
impl Future for PtraceFuture {
    type Output = Rc<PtraceStatus>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.into_ref().get_ref().clone() {
            PtraceFuture::Ready(val) => Poll::Ready(val.clone()),
            PtraceFuture::Pending => Poll::Pending,
        }
    }
}

/// We don't need a real waker because we will run Future and PtraceFuture in a busy loop,
/// until we encounter a PtraceFuture::Pending.
#[derive(Default)]
struct DummyWaker {
    called: AtomicBool,
}
impl DummyWaker {
    fn has_been_called(&self) -> bool {
        self.called.load(Ordering::Relaxed)
    }
}
impl Wake for DummyWaker {
    fn wake(self: Arc<Self>) {
        self.called.store(true, Ordering::Relaxed);
        panic!("Internal error: Invalid async code.");
    }
}

/// The very simple async runtime for PtraceFuture
///
/// Requirement: the future object you pass in, must never be moved.
///
impl PtraceAsyncRuntime {
    
    fn register_pending(&self, future_type: PtraceFutureTypes, future: Rc<RefCell<PtraceFuture>>) {
        let has_key = {
            self.pending_futures.borrow().contains_key(&future_type)
        };
        if !has_key {
            self.pending_futures.borrow_mut().insert(future_type.clone(), Vec::new());
        }

        if let Some(futures) = self.pending_futures.borrow_mut().get_mut(&future_type) {
            futures.push(future);
            self.has_new_future.store(true, Ordering::Relaxed);
        }
    }

    /// Resolve currently pending PtraceFutures. Must call this at least once between run_async_step calls
    pub fn unblock_futures(&self, future_type: PtraceFutureTypes, status: PtraceStatus) {
        let rc = Rc::new(status);
        let futures = self.pending_futures.borrow_mut().remove(&future_type).unwrap_or(Vec::new());
        futures.into_iter().map(|f| f.borrow_mut().resolve(rc.clone()));
    }

    pub fn is_blocked_by(&self, future_type: PtraceFutureTypes) -> bool {
        self.pending_futures.borrow().contains_key(&future_type)
    }

    /// Helper function to create a new PtraceFuture, within async code, and await for its completion
    pub async fn new_ptrace_future(&self, future_type: PtraceFutureTypes) -> Rc<PtraceStatus> {
        let ref_cell = PtraceFuture::new(self, future_type);
        let fut_ref: &mut PtraceFuture = &mut *ref_cell.borrow_mut();
        std::pin::Pin::new(fut_ref).await
    }

    /// Returns: Ok(None) if pending PTRACE_SYSCALL, otherwise Ok(Some(async result))
    pub fn run_async_step<F: Future>(&self, future: &mut F) -> Result<Option<F::Output>, PtraceError> {
        let dummy_waker = Arc::new(DummyWaker::default());
        let waker = std::task::Waker::from(dummy_waker.clone());
        let mut cx = Context::from_waker(&waker);

        // Unsafely declare the future as pinned. (It will never be moved)
        let mut pinned_future = unsafe { Pin::new_unchecked(future) };

        // Poll main future once
        self.has_new_future.store(false, Ordering::Relaxed);
        let result = match pinned_future.as_mut().poll(&mut cx) {
            Poll::Ready(val) => Some(val),
            Poll::Pending => None,
        };

        if dummy_waker.has_been_called() {
            // This waker would only be used by external async library or async I/O
            // both of which are banned
            return Err(PtraceError::AsyncBanOfExternalCode);
        }

        Ok(result)
    }

    pub fn has_new_blockage(&self) -> bool {
        self.has_new_future.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use crate::futures;
    use nix::sys::wait::WaitStatus;
    use std::rc::Rc;

    #[test]
    fn test_basic_async_function() {
        let mut runtime = futures::PtraceAsyncRuntime::default();
        let mut test_future = futures_lite::future::ready(123);
        assert!(matches!(runtime.run_async_step(&mut test_future), Ok(Some(123))));
    }

    #[test]
    fn test_basic_blocking_on_ptrace_future() {
        let runtime = futures::PtraceAsyncRuntime::default();
        let mut test_future = runtime.new_ptrace_future(futures::PtraceFutureTypes::WaitForPtraceSyscall);
        assert!(matches!(runtime.run_async_step(&mut test_future), Ok(None)));
        assert!(runtime.has_new_blockage());

        // Unblock an irrelevant future
        let event1 = futures::PtraceStatus { wait_status: WaitStatus::StillAlive };
        runtime.unblock_futures(futures::PtraceFutureTypes::WaitForSignal, event1);
        assert!(matches!(runtime.run_async_step(&mut test_future), Ok(None)));
        assert!(!runtime.has_new_blockage());

        // Unblock the original future
        let event2 = futures::PtraceStatus { wait_status: WaitStatus::StillAlive };
        runtime.unblock_futures(futures::PtraceFutureTypes::WaitForPtraceSyscall, event2.clone());
        let output = runtime.run_async_step(&mut test_future).unwrap().unwrap();
        assert!(matches!(Rc::into_inner(output), Some(event2)));
        assert!(!runtime.has_new_blockage());
    }
}
