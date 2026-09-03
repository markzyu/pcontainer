# KRSM: KRSM Rust State Machine

This crate is a simple, single threaded, pinned async runtime for futures. This runtime:

* Runs all async futures within the current thread
* Does not risk blocking the current thread permanently
* Does not include `std` as a dependency. (There are generic type parameters for your allocator, Arc, and Box)
* Does not interact with any system call through async I/O
* Does not rely on the wakers to determine when to wake up the polling thread.

Instead, KRSM lets the downstream define yields and wakers:

* The downstream supplies an `YieldReasons` type with `Eq` trait, whose different values describe different types of yields.
  * The async future can only yield due to one of these `YieldReasons`
* The downstream can choose to block itself if needed, but the runtime never blocks.
* The downstream **must** manage its own lifecycle for real suspends and real wakes. KRSM cannot enforce anything here.

And the downstream can define a state machine using asynchronous syntax:

* The async code can directly describe business logics using awaits
* The async code can create temporary states across awaits and reuse them within the scope of an async function
* The async code can define helper function and even recursive ones
* The async code can call basic `futures_lite` helpers such as `zip()` and `or()`, as long as they don't use the `std` feature.
* The async code must not make use of wakers, and thus, must not call real libraries with async I/O (such as `async_std` and `tokio`)

And the downstream can use the KRSM runtime to drive the state machine, no matter how large and convoluted, without a human ever needing to translate them into switch-cases:

1. The downstream polls an async logic for one single turn until it yields
2. The downstream examines which `YieldReasons` had been blocking the async code, and try to unblock at least one of them
3. The downstream notifie when such an unblock is completed, and loops back to step 1 

## License

Copyright (c) 2026 Zhongzhi Yu

This KRSM crate is dual licensed, under the MIT License, as well as the parent project's License.