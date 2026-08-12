// Copyright 2026 Zhongzhi Yu <7296488+markzyu@users.noreply.github.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

use crate::common::PtraceExecutorError;
use nix::sys::wait::WaitStatus;
use std::cell::RefCell;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Wake};

// TODO: Move this to executor crate (Not ptrace crate...)

// Note: Important Caveat:
//
// We do not support tokio, async I/O, or external async utilities.
//
// We only support parts of futures_lite, these three helper functions:
//
// > `zip()`, `or()`, `poll_fn()`.
//
// Usage of unsupported external async utilities will cause an Err()
//
// You can await most async functions we defined ourselves, but should not
// await on external library functions.
//
// The use of async is purely to simplify the state machine spaghetti code,
// and to better manage the tracee states (for example when trying to force
// tracee to execute a series of system calls)

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum PtraceFutureTypes {
    WaitForPtraceSyscall,
    WaitForPtraceEvent,
    WaitForSignal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PtraceStatus {
    pub wait_status: WaitStatus,
}

#[derive(Default, Debug)]
pub struct PtraceAsyncRuntime {
    unblock_future_by_type: RefCell<Option<PtraceFutureTypes>>,
    unblock_with_status: RefCell<Option<Rc<PtraceStatus>>>,
    has_new_future: AtomicBool,
}

#[derive(Default)]
pub struct PtraceAsyncYielder {
    // When A yeilds to B, count the number of times B has been polled
    num_polls: RefCell<usize>,
}

/// We don't need a real waker because we will run Futures in a busy loop,
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
    }
}

/// The very simple async runtime for ptrace::futures
///
/// Requirement: the future object you pass in, must never be moved.
///
impl PtraceAsyncRuntime {
    /// Resolve currently pending PtraceFutures. Must call this at least once between run_async_step calls
    pub fn unblock_futures(&self, future_type: PtraceFutureTypes, status: PtraceStatus) {
        let rc = Rc::new(status);
        self.unblock_with_status.borrow_mut().replace(rc);
        self.unblock_future_by_type
            .borrow_mut()
            .replace(future_type);
    }

    /// Helper function to create a new PtraceFuture, within async code, and await for its completion
    pub async fn new_ptrace_future(&self, future_type: PtraceFutureTypes) -> Rc<PtraceStatus> {
        self.has_new_future.store(true, Ordering::Relaxed);
        let result = futures_lite::future::poll_fn(|_| {
            if self.unblock_future_by_type.borrow().as_ref() == Some(&future_type) {
                Poll::Ready(self.unblock_with_status.borrow_mut().take().unwrap())
            } else {
                Poll::Pending
            }
        })
        .await;
        self.unblock_future_by_type.borrow_mut().take();
        result
    }

    /// Returns: Ok(None) if pending PTRACE_SYSCALL, otherwise Ok(Some(async result))
    pub fn run_async_step<F: Future>(
        &self,
        future: &mut F,
    ) -> Result<Option<F::Output>, PtraceExecutorError> {
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
            return Err(PtraceExecutorError::AsyncBanOfExternalCode);
        }

        Ok(result)
    }

    pub fn has_new_blockage(&self) -> bool {
        self.has_new_future.load(Ordering::Relaxed)
    }
}

impl PtraceAsyncYielder {
    // Yield until another async loop has a chance to unblock us
    pub async fn yield_now(&self) {
        let original_poll_num = { *self.num_polls.borrow() };
        futures_lite::future::poll_fn(|_| {
            let new_poll_num = { *self.num_polls.borrow() };
            // To prevent overflow issues, do not compare with <= or >=
            if new_poll_num == original_poll_num {
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        })
        .await;
    }

    pub fn unblock(&self) {
        *self.num_polls.borrow_mut() += 1;
    }
}

#[cfg(test)]
mod tests {
    use crate::common::PtraceExecutorError;
    use crate::futures;
    use nix::sys::wait::WaitStatus;
    use nix::unistd::Pid;
    use std::rc::Rc;

    #[test]
    fn test_basic_async_function() {
        let runtime = futures::PtraceAsyncRuntime::default();
        let mut test_future = futures_lite::future::ready(123);
        assert!(matches!(
            runtime.run_async_step(&mut test_future),
            Ok(Some(123))
        ));
    }

    #[test]
    fn test_basic_blocking_on_ptrace_future() {
        let runtime = futures::PtraceAsyncRuntime::default();
        let mut test_future =
            runtime.new_ptrace_future(futures::PtraceFutureTypes::WaitForPtraceSyscall);
        assert!(matches!(runtime.run_async_step(&mut test_future), Ok(None)));
        assert!(runtime.has_new_blockage());

        // Unblock an irrelevant future
        let event1 = futures::PtraceStatus {
            wait_status: WaitStatus::StillAlive,
        };
        runtime.unblock_futures(futures::PtraceFutureTypes::WaitForSignal, event1);
        assert!(matches!(runtime.run_async_step(&mut test_future), Ok(None)));
        assert!(!runtime.has_new_blockage());

        // Unblock the original future
        let event2 = futures::PtraceStatus {
            wait_status: WaitStatus::StillAlive,
        };
        runtime.unblock_futures(
            futures::PtraceFutureTypes::WaitForPtraceSyscall,
            event2.clone(),
        );
        let output = runtime.run_async_step(&mut test_future).unwrap().unwrap();
        assert!(Rc::into_inner(output) == Some(event2));
        assert!(!runtime.has_new_blockage());
    }

    #[test]
    fn test_blocking_on_two_ptrace_futures() {
        let runtime = futures::PtraceAsyncRuntime::default();
        let mut test_future = async {
            runtime
                .new_ptrace_future(futures::PtraceFutureTypes::WaitForPtraceSyscall)
                .await;
            runtime
                .new_ptrace_future(futures::PtraceFutureTypes::WaitForSignal)
                .await;
            42
        };
        assert!(matches!(runtime.run_async_step(&mut test_future), Ok(None)));
        assert!(runtime.has_new_blockage());

        // Unblock an irrelevant future
        let event1 = futures::PtraceStatus {
            wait_status: WaitStatus::StillAlive,
        };
        runtime.unblock_futures(futures::PtraceFutureTypes::WaitForSignal, event1);
        assert!(matches!(runtime.run_async_step(&mut test_future), Ok(None)));
        assert!(!runtime.has_new_blockage());

        // Unblock the first future
        let event2 = futures::PtraceStatus {
            wait_status: WaitStatus::StillAlive,
        };
        runtime.unblock_futures(
            futures::PtraceFutureTypes::WaitForPtraceSyscall,
            event2.clone(),
        );
        assert!(matches!(runtime.run_async_step(&mut test_future), Ok(None)));
        assert!(runtime.has_new_blockage());

        // Unblock the second future (ignoring the first irrelevant unblock for WaitForSignal)
        let event3 = futures::PtraceStatus {
            wait_status: WaitStatus::StillAlive,
        };
        runtime.unblock_futures(futures::PtraceFutureTypes::WaitForSignal, event3.clone());
        let output = runtime.run_async_step(&mut test_future).unwrap().unwrap();
        assert!(output == 42);
        assert!(!runtime.has_new_blockage());
    }

    #[test]
    fn test_compatible_with_futures_lite_zip_in_order() {
        let runtime = futures::PtraceAsyncRuntime::default();
        let mut test_future = futures_lite::future::zip(
            runtime.new_ptrace_future(futures::PtraceFutureTypes::WaitForPtraceSyscall),
            runtime.new_ptrace_future(futures::PtraceFutureTypes::WaitForSignal),
        );
        assert!(matches!(runtime.run_async_step(&mut test_future), Ok(None)));
        assert!(runtime.has_new_blockage());

        // Unblock the first future
        let event2 = futures::PtraceStatus {
            wait_status: WaitStatus::StillAlive,
        };
        runtime.unblock_futures(
            futures::PtraceFutureTypes::WaitForPtraceSyscall,
            event2.clone(),
        );
        assert!(matches!(runtime.run_async_step(&mut test_future), Ok(None)));
        assert!(!runtime.has_new_blockage());

        // Unblock the second future
        let event3 = futures::PtraceStatus {
            wait_status: WaitStatus::Continued(Pid::from_raw(0.into())),
        };
        runtime.unblock_futures(futures::PtraceFutureTypes::WaitForSignal, event3.clone());
        let (output1, output2) = runtime.run_async_step(&mut test_future).unwrap().unwrap();
        assert!(Rc::into_inner(output1) == Some(event2));
        assert!(Rc::into_inner(output2) == Some(event3));
        assert!(!runtime.has_new_blockage());
    }

    #[test]
    fn test_compatible_with_futures_lite_zip_in_reversed_order() {
        let runtime = futures::PtraceAsyncRuntime::default();
        let mut test_future = futures_lite::future::zip(
            runtime.new_ptrace_future(futures::PtraceFutureTypes::WaitForPtraceSyscall),
            runtime.new_ptrace_future(futures::PtraceFutureTypes::WaitForSignal),
        );
        assert!(matches!(runtime.run_async_step(&mut test_future), Ok(None)));
        assert!(runtime.has_new_blockage());

        // Unblock the second future
        let event2 = futures::PtraceStatus {
            wait_status: WaitStatus::StillAlive,
        };
        runtime.unblock_futures(futures::PtraceFutureTypes::WaitForSignal, event2.clone());
        assert!(matches!(runtime.run_async_step(&mut test_future), Ok(None)));
        assert!(!runtime.has_new_blockage());

        // Unblock the first future
        let event3 = futures::PtraceStatus {
            wait_status: WaitStatus::Continued(Pid::from_raw(0.into())),
        };
        runtime.unblock_futures(
            futures::PtraceFutureTypes::WaitForPtraceSyscall,
            event3.clone(),
        );
        let (output1, output2) = runtime.run_async_step(&mut test_future).unwrap().unwrap();
        assert!(Rc::into_inner(output1) == Some(event3));
        assert!(Rc::into_inner(output2) == Some(event2));
        assert!(!runtime.has_new_blockage());
    }

    #[test]
    fn test_compatible_with_futures_lite_or_resolves_first() {
        let runtime = futures::PtraceAsyncRuntime::default();
        let mut test_future = futures_lite::future::or(
            async {
                runtime
                    .new_ptrace_future(futures::PtraceFutureTypes::WaitForPtraceSyscall)
                    .await;
                234
            },
            async {
                runtime
                    .new_ptrace_future(futures::PtraceFutureTypes::WaitForSignal)
                    .await;
                456
            },
        );
        assert!(matches!(runtime.run_async_step(&mut test_future), Ok(None)));
        assert!(runtime.has_new_blockage());

        // Unblock the first future
        let event = futures::PtraceStatus {
            wait_status: WaitStatus::StillAlive,
        };
        runtime.unblock_futures(
            futures::PtraceFutureTypes::WaitForPtraceSyscall,
            event.clone(),
        );
        let output = runtime.run_async_step(&mut test_future).unwrap().unwrap();
        assert!(output == 234);
        assert!(!runtime.has_new_blockage());
    }

    #[test]
    fn test_compatible_with_futures_lite_or_resolves_second() {
        let runtime = futures::PtraceAsyncRuntime::default();
        let mut test_future = futures_lite::future::or(
            async {
                runtime
                    .new_ptrace_future(futures::PtraceFutureTypes::WaitForPtraceSyscall)
                    .await;
                234
            },
            async {
                runtime
                    .new_ptrace_future(futures::PtraceFutureTypes::WaitForSignal)
                    .await;
                456
            },
        );
        assert!(matches!(runtime.run_async_step(&mut test_future), Ok(None)));
        assert!(runtime.has_new_blockage());

        // Unblock the second future
        let event = futures::PtraceStatus {
            wait_status: WaitStatus::StillAlive,
        };
        runtime.unblock_futures(futures::PtraceFutureTypes::WaitForSignal, event.clone());
        let output = runtime.run_async_step(&mut test_future).unwrap().unwrap();
        assert!(output == 456);
        assert!(!runtime.has_new_blockage());
    }

    #[test]
    fn test_incompatible_with_waker_such_as_futures_lite_yield_now() {
        // futures_lite::future::yield_now() uses a Waker.
        let runtime = futures::PtraceAsyncRuntime::default();
        let mut test_future = futures_lite::future::or(
            async {
                runtime
                    .new_ptrace_future(futures::PtraceFutureTypes::WaitForPtraceSyscall)
                    .await;
                futures_lite::future::yield_now().await;
                234
            },
            async {
                runtime
                    .new_ptrace_future(futures::PtraceFutureTypes::WaitForPtraceSyscall)
                    .await;
                456
            },
        );
        assert!(matches!(runtime.run_async_step(&mut test_future), Ok(None)));
        assert!(runtime.has_new_blockage());

        // Unblock the first await
        let event = futures::PtraceStatus {
            wait_status: WaitStatus::StillAlive,
        };
        runtime.unblock_futures(
            futures::PtraceFutureTypes::WaitForPtraceSyscall,
            event.clone(),
        );
        assert!(matches!(
            runtime.run_async_step(&mut test_future),
            Err(PtraceExecutorError::AsyncBanOfExternalCode)
        ));
    }
}
