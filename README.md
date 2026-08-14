## So this is just PRoot?

The fundamental idea is not that different from proot. In fact, it's inspiried by proot -- both make use of SECCOMP to improve performance. Both can intercept system calls through ptrace() and simulate the chroot() system call so that we can chroot into a different Linux Distro on a non-rooted phone. The main difference is this: This solution is multithreaded, while proot itself is single threaded.

You should just use PRoot instead. It has a history of proven stability and success.

My project is still in its early stage. And it barely works right now. Basic shell commands work but `apt-get` is broken.

Eventually, my goal is to be able to run Docker container on any mobile device, without needing root, by creating a configuration file that tells the ptrace how to glue the file system back together. But there is a long way to go.

## Multithreading model 

By default, pcontainer will try to run ptrace() syscalls on dedicated threads (one thread per tracee process)

But this requires the permission for PTRACE_ATTACH. And on some systems, this permission is blocked, and tracer can only attach to their direct children from main threads.

## Fallback model

If the host OS does not permit PTRACE_ATTACH, pcontainer will try to cumulate ptrace() syscalls on main thread from all tracee processes, and offload each tracee's own event loop and calculations to other threads. (Main thread is busy executing ptrace() calls while other threads queue ptrace actions)

![Fallback threading model](FallbackThreadingModel.png)

## Project structure

Sysaug crate contains the core logics of pconainer. The full name is System Augmentation, implying a backend, low level ability to modify specific syscalls (i.e. remapping path of openat())

Within `sysaug` crate, there are two major parts:

* `aug_*.rs` defines Augments which have separate concerns based on the type of syscalls they augment
* `handler.rs` defines the core "state machine" that translates TraceeHandlerConsts and various trackers of tracee's stack and hacky mmap injection addresses, into how exactly to rewrite every syscalls + followup on them in multi-step algorithms.

Additionally, 

* `ptrace` crate is responsible for abstracting away the low level pointer safety of translating tracee pointers to/from ptrace calls
* `executor` crate is responsible for abstracting away the low level thread safety of running ptrace calls across threads
* And, `executor` crate also implements a basic Thread-Per-Core "async" runtime that fits my realtime tracer needs better: `PtraceAsyncRuntime`


This `PtraceAsyncRuntime` is mostly an enabler of an anti-pattern: I chose to write the state machine of a tracer using async syntax sugar, instead of manually writing out the state machine as literal switch case listing and migrating between all checkpoint states. Another added benefit of `PtraceAsyncRuntime` is that all logics within it are forced to run on the same thread, so I can avoid `Arc<Mutex<>>` and use `RefCell` instead.

**Caveat**: this refactor from "synchronous spaghetti" to "async as a hacky state machine syntax" is still ongoing. You will see two hacky logics live next to each other. The synchronous logics use a ton of `Arc<Mutex<>>` types. And the async logics are always Pinned, not truly "async", and are more of a hacky use of the underlying state machine than a use of true async events

Right now the repo lives in a very bad state and has a lot more runtime overhead than needed. I intend to move fully into async in hope that removing Arc will fix some of the overhead. But I'm starting to think I misunderstood how Rust handles async, and how heavy it truly is.

## For Developers (Note: this might be outdated)

How to debug problems:

- `RUST_LOG=TRACE RUST_BACKTRACE=1 cargo run  -- --chroot xxx --root |& ansi2txt | tee ~/logfile | grep -v TRACE | grep -v DEBUG`

Overhead: Tested on Android Termux:

proot slows down `git status` to about 5x its original run time.

- original total wall time: about 10ms
- proot total wall time: about 50ms

As long as our parallel proot doesn't slow down the tracee by more than 5x. It should be fine.

It's highly recommended to simply install rust on Termux and perform native compilation.

Here are some (outdated) instructions about Android cross-compilation without Termux:

- Install GNU toolchains (`arm-linux-*-gcc` and `aarch64-linux-*-gcc`)
- Update your `~/.cargo/config`:
  ```
  [target.armv7-unknown-linux-gnueabihf]
  rustflags = ["-C", "target-feature=+crt-static"]
  linker = "arm-linux-foobar-gcc"
  ```
- Run `cargo build --target=armv7-unknown-linux-gnueabihf --release`
- **Android permissions**
  - The terminal emulator must request specific permissions to unlock the ability to execute `./dockify`. The exact permission name is unknown.
  - Older Android versions work better with https://f-droid.org/en/packages/org.galexander.sshd/
  - [Android 10 and above require executables to be codesigned](https://github.com/greenaddress/abcore/issues/97)
    - Termux is the only solution that works well in this situation. [Here is a page from their discussion.](https://github.com/termux/termux-app/issues/1072)
    - But apparently, IT'S EASIER IF `dockify` IS CODE SIGNED AS part of the readonly APK.

## AI Usage

I used AI to help review my code, especially during major updates like a Rust edition update.

I don't use AI to directly generate large chunks of code.

## License

Copyright (c) 2026 Zhongzhi Yu

This project is licensed under the GNU General Public License v3.0 (GPLv3) - 
see [COPYING](COPYING) for details
