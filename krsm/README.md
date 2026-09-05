# KRSM: KRSM Rust State Machine

This crate is a simple, single threaded, pinned async runtime for futures. This runtime:

* Runs all async futures within the current thread
* Does not risk blocking the current thread permanently
* Does not include `std` as a dependency. (There are generic type parameters for your allocator, Arc, and Box)
* Does not interact with any system call through async I/O
* Does not rely on the wakers to determine when to wake up the polling thread.

Instead, KRSM lets the downstream define yields and take control of each individual polling step.


## Goal

This library aims to be a bare minimum abstraction of Rust compiler's ability to translate async functions into pollable state machines. The goal is to write huge, single-threaded, determinstic state machines using asynchronous descriptions.

Please check out the example state machines in `krsm/examples`.

## Caveat 1

Async code must be written as if it is a non-determinstics state machine (as if it's waiting on all "concurrent" branches of `futures_lite::future::or`).

But in reality, this async runtime is meant to **only execute one of those** possible transitions per turn.

As a result:

* Unblocking multiple futures in one turn can lead to undefined behaviors and is forbidden.
* The downstream caller must properly prioritize the pending futures, to choose only one when unblocking the state machine.
* The downstream caller might need to "filter" out expired futures which were not prioritized in time.

Thus, there is very little margin of error in the resulting code. And two versions code might look equivalent when only one of them is correct.

## Caveat 2

This crate is `no_std` and cannot allocate additional heap memory at runtime. And yet it provides tracking of the currently pending futures by reason type, which is an arbitrary enum provided by downstream.

At any moment of an async future's execution, there is a limit on the maximum number of pending futures that it's allowed to wait on.

This number is `MAX_PENDING` and can be controlled at compile time, through Rust const generics.

Upon hitting this limit, all further async calls will fail due to `AsyncRuntimeError::TooManyPending`

It's recommended that you minimize the number of possible `YieldReason` and cleanup any such reason that might expire using `AsyncRuntime.filter_valid_futures`

## License

Copyright (c) 2026 Zhongzhi Yu

This KRSM crate is dual licensed, under both the MIT License, and the GPLv3 License.
