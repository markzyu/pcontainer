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

use core::cell::RefCell;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
use std::fmt::Debug;

/// The KRSM async runtime
///
/// Note: Important Caveat:
///
/// We do not support tokio, async I/O, or external async utilities.
///
/// We only support parts of futures_lite, these three helper functions:
///
/// > `zip()`, `or()`, `poll_fn()`.
///
/// Usage of unsupported external async utilities will cause an Err()
///
/// The use of `async` is purely to avoid writing a state machine switch-case.
#[derive(Debug)]
pub struct AsyncRuntime<YieldReason: Eq + Debug, YieldResponse: PartialEq + Debug> {
    has_unblock: RefCell<Option<(YieldReason, YieldResponse)>>,
    has_new_future: AtomicBool,
}

/// This error type is for future proofing only. It will always implement Debug.
#[derive(Debug)]
pub struct AsyncRuntimeError();

/// AsyncYield is a helper for KRSM async loops.
/// 
/// This is useful when your async future contains two or more competing loops:
///      `futures_lite::or(loop1, loop2, loop3).await`
///
/// Futures lite's parallel `or()` function always runs the loops in the same order.
/// For loop2 to have a chance at executing, loop1 must yield, even when there isn't
/// a real `YieldReason`.
/// 
/// In that case, loop1 can use AsyncYielder to yield until the other loops get a chance
/// to run. But those other loops must also remember to `unblock()` us.
#[derive(Default)]
pub struct AsyncYielder {
    // When A yeilds to B, count the number of times B has been polled
    num_polls: RefCell<usize>,
}

const RAW_WAKER_SHOULD_NOT_BE_CALLED: &'static str =
    "Internal error, KRSM Async Runtime detected invalid usage of external async library";

/// This RawWaker is similar to core::task::RawWaker::NOOP, but with an assertion:
/// It panicks whenever any async code calls the waker at all.
const RAW_WAKER_WITH_ASSERTIONS: RawWaker = {
    const VTABLE: RawWakerVTable = RawWakerVTable::new(
        // clone
        |_| RAW_WAKER_WITH_ASSERTIONS,
        // wake
        |_| {
            panic!("{}", RAW_WAKER_SHOULD_NOT_BE_CALLED);
        },
        // wake_by_ref
        |_| {
            panic!("{}", RAW_WAKER_SHOULD_NOT_BE_CALLED);
        },
        // drop does nothing
        |_| {},
    );
    RawWaker::new(core::ptr::null(), &VTABLE)
};

impl<YieldReason: Eq + Debug, YieldResponse: PartialEq + Debug> AsyncRuntime<YieldReason, YieldResponse> {
    /// Resolve currently pending Futures. Must call this at least once between run_async_step calls
    pub fn unblock_futures(&self, future_type: YieldReason, status: YieldResponse) {
        self.has_unblock.borrow_mut().replace((future_type, status));
    }

    /// Helper function to create a new Future, within async code, and await for its completion
    pub async fn new_ptrace_future(&self, future_type: YieldReason) -> YieldResponse {
        self.has_new_future.store(true, Ordering::Relaxed);
        futures_lite::future::poll_fn(|_| {
            let matches = if let Some((curr_type, _)) = self.has_unblock.borrow().as_ref() {
                curr_type == &future_type
            } else {
                false
            };
            if matches && let Some((_, status)) = self.has_unblock.take() {
                return Poll::Ready(status);
            }
            Poll::Pending
        })
        .await
    }

    /// This call is unsafe because it doesn't check whether `future` is pinned.
    /// 
    /// You don't have to pass in a Pin<> but you have to make sure the pointer/reference is effectively
    /// pinned across all of your `run_async_step` calls.
    /// 
    /// This function returns a Result but currently has no error case.
    /// This return type is for future proofing only. (The Err type will always implement Debug.)
    /// 
    /// Returns: Ok(None) if the future is still incomplete, and has yielded.
    ///          Ok(Some(async result)) if the future has finished running.
    pub unsafe fn run_async_step<F: Future>(
        &self,
        future: &mut F,
    ) -> Result<Option<F::Output>, AsyncRuntimeError> {
        let waker = unsafe {
            Waker::from_raw(RAW_WAKER_WITH_ASSERTIONS)
        };
        let mut cx = Context::from_waker(&waker);

        // Unsafely declare the future as pinned. (the caller needs to make sure of that)
        let mut pinned_future = unsafe { Pin::new_unchecked(future) };

        // Poll the future exactly once
        self.has_new_future.store(false, Ordering::Relaxed);
        let result = match pinned_future.as_mut().poll(&mut cx) {
            Poll::Ready(val) => Some(val),
            Poll::Pending => None,
        };

        Ok(result)
    }

    /// This is a function used for unit testing only. It doesn't actually reflect all blockages.
    /// For example, AsyncYield's pending status won't be reflected here.
    pub fn _has_new_blockage(&self) -> bool {
        self.has_new_future.load(Ordering::Relaxed)
    }
}

impl<YieldReason: Eq + Debug, YieldResponse: PartialEq + Debug> Default for AsyncRuntime<YieldReason, YieldResponse> {
    fn default() -> Self {
        Self {
            has_unblock: RefCell::new(None),
            has_new_future: AtomicBool::default()
        }
    }
}

impl AsyncYielder {
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
    use crate::futures;

    /// This is just an example YieldReason.
    #[derive(Debug, Eq, PartialEq)]
    enum PtraceFutureTypes {
        WaitForPtraceSyscall,
        WaitForSignal,
    }

    #[derive(Clone, Debug, PartialEq)]
    /// This is just an example YieldResponse
    struct PtraceStatus {}

    type PtraceAsyncRuntime = futures::AsyncRuntime<PtraceFutureTypes, PtraceStatus>;

    #[test]
    fn test_basic_async_function() {
        let runtime = PtraceAsyncRuntime::default();
        let mut test_future = futures_lite::future::ready(123);
        assert!(matches!(
            unsafe { runtime.run_async_step(&mut test_future) },
            Ok(Some(123))
        ));
    }

    #[test]
    fn test_basic_blocking_on_ptrace_future() {
        let runtime = PtraceAsyncRuntime::default();
        let mut test_future =
            runtime.new_ptrace_future(PtraceFutureTypes::WaitForPtraceSyscall);
        assert!(matches!(unsafe { runtime.run_async_step(&mut test_future) }, Ok(None)));
        assert!(runtime._has_new_blockage());

        // Unblock an irrelevant future
        let event1 = PtraceStatus {};
        runtime.unblock_futures(PtraceFutureTypes::WaitForSignal, event1);
        assert!(matches!(unsafe { runtime.run_async_step(&mut test_future) }, Ok(None)));
        assert!(!runtime._has_new_blockage());

        // Unblock the original future
        let event2 = PtraceStatus {};
        runtime.unblock_futures(
            PtraceFutureTypes::WaitForPtraceSyscall,
            event2.clone(),
        );
        let output = unsafe { runtime.run_async_step(&mut test_future).unwrap().unwrap() };
        assert!(output == event2);
        assert!(!runtime._has_new_blockage());
    }

    #[test]
    fn test_blocking_on_two_ptrace_futures() {
        let runtime = PtraceAsyncRuntime::default();
        let mut test_future = async {
            runtime
                .new_ptrace_future(PtraceFutureTypes::WaitForPtraceSyscall)
                .await;
            runtime
                .new_ptrace_future(PtraceFutureTypes::WaitForSignal)
                .await;
            42
        };
        assert!(matches!(unsafe { runtime.run_async_step(&mut test_future) }, Ok(None)));
        assert!(runtime._has_new_blockage());

        // Unblock an irrelevant future
        let event1 = PtraceStatus {};
        runtime.unblock_futures(PtraceFutureTypes::WaitForSignal, event1);
        assert!(matches!(unsafe { runtime.run_async_step(&mut test_future) }, Ok(None)));
        assert!(!runtime._has_new_blockage());

        // Unblock the first future
        let event2 = PtraceStatus {};
        runtime.unblock_futures(
            PtraceFutureTypes::WaitForPtraceSyscall,
            event2.clone(),
        );
        assert!(matches!(unsafe { runtime.run_async_step(&mut test_future) }, Ok(None)));
        assert!(runtime._has_new_blockage());

        // Unblock the second future (ignoring the first irrelevant unblock for WaitForSignal)
        let event3 = PtraceStatus {};
        runtime.unblock_futures(PtraceFutureTypes::WaitForSignal, event3.clone());
        let output = unsafe { runtime.run_async_step(&mut test_future).unwrap().unwrap() };
        assert!(output == 42);
        assert!(!runtime._has_new_blockage());
    }

    #[test]
    fn test_compatible_with_futures_lite_zip_in_order() {
        let runtime = PtraceAsyncRuntime::default();
        let mut test_future = futures_lite::future::zip(
            runtime.new_ptrace_future(PtraceFutureTypes::WaitForPtraceSyscall),
            runtime.new_ptrace_future(PtraceFutureTypes::WaitForSignal),
        );
        assert!(matches!(unsafe { runtime.run_async_step(&mut test_future) }, Ok(None)));
        assert!(runtime._has_new_blockage());

        // Unblock the first future
        let event2 = PtraceStatus {};
        runtime.unblock_futures(
            PtraceFutureTypes::WaitForPtraceSyscall,
            event2.clone(),
        );
        assert!(matches!(unsafe { runtime.run_async_step(&mut test_future) }, Ok(None)));
        assert!(!runtime._has_new_blockage());

        // Unblock the second future
        let event3 = PtraceStatus {};
        runtime.unblock_futures(PtraceFutureTypes::WaitForSignal, event3.clone());
        let (output1, output2) = unsafe { runtime.run_async_step(&mut test_future).unwrap().unwrap() };
        assert!(output1 == event2);
        assert!(output2 == event3);
        assert!(!runtime._has_new_blockage());
    }

    #[test]
    fn test_compatible_with_futures_lite_zip_in_reversed_order() {
        let runtime = PtraceAsyncRuntime::default();
        let mut test_future = futures_lite::future::zip(
            runtime.new_ptrace_future(PtraceFutureTypes::WaitForPtraceSyscall),
            runtime.new_ptrace_future(PtraceFutureTypes::WaitForSignal),
        );
        assert!(matches!(unsafe { runtime.run_async_step(&mut test_future) }, Ok(None)));
        assert!(runtime._has_new_blockage());

        // Unblock the second future
        let event2 = PtraceStatus {};
        runtime.unblock_futures(PtraceFutureTypes::WaitForSignal, event2.clone());
        assert!(matches!(unsafe { runtime.run_async_step(&mut test_future) }, Ok(None)));
        assert!(!runtime._has_new_blockage());

        // Unblock the first future
        let event3 = PtraceStatus {};
        runtime.unblock_futures(
            PtraceFutureTypes::WaitForPtraceSyscall,
            event3.clone(),
        );
        let (output1, output2) = unsafe { runtime.run_async_step(&mut test_future).unwrap().unwrap() };
        assert!(output1 == event3);
        assert!(output2 == event2);
        assert!(!runtime._has_new_blockage());
    }

    #[test]
    fn test_compatible_with_futures_lite_or_resolves_first() {
        let runtime = PtraceAsyncRuntime::default();
        let mut test_future = futures_lite::future::or(
            async {
                runtime
                    .new_ptrace_future(PtraceFutureTypes::WaitForPtraceSyscall)
                    .await;
                234
            },
            async {
                runtime
                    .new_ptrace_future(PtraceFutureTypes::WaitForSignal)
                    .await;
                456
            },
        );
        assert!(matches!(unsafe { runtime.run_async_step(&mut test_future) }, Ok(None)));
        assert!(runtime._has_new_blockage());

        // Unblock the first future
        let event = PtraceStatus {};
        runtime.unblock_futures(
            PtraceFutureTypes::WaitForPtraceSyscall,
            event.clone(),
        );
        let output = unsafe { runtime.run_async_step(&mut test_future).unwrap().unwrap() };
        assert!(output == 234);
        assert!(!runtime._has_new_blockage());
    }

    #[test]
    fn test_compatible_with_futures_lite_or_resolves_second() {
        let runtime = PtraceAsyncRuntime::default();
        let mut test_future = futures_lite::future::or(
            async {
                runtime
                    .new_ptrace_future(PtraceFutureTypes::WaitForPtraceSyscall)
                    .await;
                234
            },
            async {
                runtime
                    .new_ptrace_future(PtraceFutureTypes::WaitForSignal)
                    .await;
                456
            },
        );
        assert!(matches!(unsafe { runtime.run_async_step(&mut test_future) }, Ok(None)));
        assert!(runtime._has_new_blockage());

        // Unblock the second future
        let event = PtraceStatus {};
        runtime.unblock_futures(PtraceFutureTypes::WaitForSignal, event.clone());
        let output = unsafe { runtime.run_async_step(&mut test_future).unwrap().unwrap() };
        assert!(output == 456);
        assert!(!runtime._has_new_blockage());
    }

    async fn _future_with_waker(runtime: &PtraceAsyncRuntime) {
        futures_lite::future::or(
            async {
                runtime
                    .new_ptrace_future(PtraceFutureTypes::WaitForPtraceSyscall)
                    .await;
                futures_lite::future::yield_now().await;
                234
            },
            async {
                runtime
                    .new_ptrace_future(PtraceFutureTypes::WaitForPtraceSyscall)
                    .await;
                456
            },
        ).await;
    }

    #[test]
    fn test_incompatible_with_waker_such_as_futures_lite_yield_now_step1() {
        // futures_lite::future::yield_now() uses a Waker.
        let runtime = PtraceAsyncRuntime::default();
        let mut test_future = _future_with_waker(&runtime);
        
        // Run the first async step, which should not panic
        assert!(matches!(unsafe { runtime.run_async_step(&mut test_future) }, Ok(None)));
        assert!(runtime._has_new_blockage());

        // Unblock the first await
        let event = PtraceStatus {};
        runtime.unblock_futures(
            PtraceFutureTypes::WaitForPtraceSyscall,
            event.clone(),
        );
    }

    #[test]
    #[should_panic(expected = "Internal error, KRSM Async Runtime detected invalid usage of external async library")]
    fn test_incompatible_with_waker_such_as_futures_lite_yield_now_step2() {
        // futures_lite::future::yield_now() uses a Waker.
        let runtime = PtraceAsyncRuntime::default();
        let mut test_future = _future_with_waker(&runtime);

        // Run the first async step, which should not panic
        assert!(matches!(unsafe { runtime.run_async_step(&mut test_future) }, Ok(None)));
        assert!(runtime._has_new_blockage());

        // Unblock the first await
        let event = PtraceStatus {};
        runtime.unblock_futures(
            PtraceFutureTypes::WaitForPtraceSyscall,
            event.clone(),
        );

        // Run the first async step, which should panic
        let _ = unsafe { runtime.run_async_step(&mut test_future) };
    }
}
