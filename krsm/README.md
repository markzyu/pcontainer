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

## Caveat 1: Extra constraints on `async` syntax

Your async code must satisfy both of the following conditions:

1. It is written as if everything runs concurrently, like a non-determinstic state machine (through `futures_lite::future::or`)
2. And yet, it is executed deterministically: only one of those possible transitions can be taken, per async turn.

As a result:

* Unblocking multiple futures in one turn can lead to undefined behaviors and is forbidden.
* The downstream caller must properly prioritize the pending futures, to choose only one when unblocking the state machine.
* The downstream caller might need to "filter" out expired futures which were not prioritized in time.

Thus, there is very little margin of error in the resulting code. And two versions code might look equivalent when only one of them is correct.

## Caveat 2: If `YieldReason` is a Complex Enum:

This crate is `no_std` and cannot allocate additional heap memory at runtime. If your `YieldReason` is a simple, C-like Enum, this doesn't pose a problem until you have 1000+ variants of `YieldReason`.

However, if your YieldReason is a complex enum, then:

* At any moment of an async future's execution, there is a limit on the maximum number of pending futures that can be tracked by the runtime.
* This number is `MAX_PENDING` and can be controlled at compile time, through Rust const generics.

Upon hitting this limit, all further async calls will fail due to `AsyncRuntimeError::TooManyPending`

To avoid this scenario, it's recommended to

* Use a simple C-like Enum as `YieldReason` if possible.

Or, if it must be a complex enum:

* Minimize the possible `YieldReason` variants in flight during any single async step, and
* Cleanup any such reason that might expire using `AsyncRuntime.filter_valid_futures`

## License

Copyright (c) 2026 Zhongzhi Yu

This KRSM crate is dual licensed, under both the MIT License, and the GPLv3 License.
