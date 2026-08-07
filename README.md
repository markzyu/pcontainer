## So this is just PRoot?

The fundamental idea is not that different from proot. In fact, it's inspiried by proot -- both can intercept system calls through ptrace() and simulate the chroot() system call so that we can chroot into a different Linux Distro on a non-rooted phone. 

However, there are a few differences:

1. This solution is multithreaded, while proot itself is single threaded. (And yes, I know they also have a Rust version)
    - Multithreading mattered to me, more than the ptrace overhead. Because proot has a hardtime supporting heavy I/O from a multithreaded JVM running game servers, for example, to host Minecraft.
    - This project was an exploration of whether multithreading helps with heavy I/O. But I've been sidetracked by other issues like supporting `apt-get`.
2. PRoot uses GPL Licenses. This project uses MIT icensing to maximize software freedom.
3. PRoot has a longer history of proven success. But this project is still in its early stage. And it barely works right now. Basic shell commands work but `apt-get` is broken.

Eventually, my goal is to be able to run any Docker container on any mobile device, without needing root. But there is a long way to go.

## Warning: Outdated code (Don't use in prod)

In Cargo.toml, the Rust compiler edition and many dependencies are outdated. (I used very old versions of libc and nix. And there are a lot of dirty workarounds in my code to fix missing syscall constants)

The following designs are outdated:

* The "mods" crate is outdated. 
* The "procfs" crate is an empty placeholder for procfs simulation. It is not being used at all.

Regarding "mods" crate, the idea was to implement optional features and logics here. In reality, this proved unfit. Dynamically loading mods slows down Rust because it involves dyn pointers.

To actually achieve "turning on/off features at runtime", we should just create a better config schema so that we can customize "sysaug" crate behavior with a descriptive json config that's passed in during pcontainer initialization

## Multithreading model and Fallback model

By default, pcontainer will try to run ptrace() syscalls on dedicated threads (one thread per tracee process)

But this requires the permission for PTRACE_ATTACH. And on some systems, this permission is blocked, and tracer can only attach to their direct children from main threads.

In that case, pcontainer will try to cumulate ptrace() syscalls on main thread from all tracee processes, and offload each tracee's own event loop and calculations to other threads. (Main thread is busy executing ptrace() calls while other threads queue ptrace actions)

![Fallback threading model](FallbackThreadingModel.png)

## Project structure


Both sysaug and mods crates are supposed to modify the behavior of system calls. But here are the differences:

Sysaug is a backend while mods are the frontend.
- `sysaug` is a backend, low level ability to modify specific syscalls (i.e. remapping path of openat())
- `mods` are the fronted, high level features (provides chroot / root, without having root)

Mods are dynamic but sysaug isn't.
- `mods` can be imported, enabled, and disabled dynamically. Disabling mods should improve efficiency.
- `sysaug` is not dynamic and cannot be turned on/off or imported without rebuilding the binary, but frontend mods should eventually be able to.

Within `sysaug` crate, there are two major parts:

* `aug_*.rs` defines Augments which have separate concerns based on the type of syscalls they augment
* `handler.rs` defines the core "state machine" that translates TraceeHandlerStates and various trackers of tracee's stack and hacky mmap injection addresses, into how exactly to rewrite every syscalls + followup on them in multi-step algorithms.

Additionally, 

* `ptrace` crate is responsible for abstracting away the low level pointer safety of translating tracee pointers to/from ptrace calls
* `executor` crate is responsible for abstracting away the low level thread safety of running ptrace calls across threads
* And, `executor` crate also implements a basic Thread-Per-Core "async" runtime that fits my realtime tracer needs better: `PtraceAsyncRuntime`


This `PtraceAsyncRuntime` is mostly an enabler of an anti-pattern: I chose to write the state machine of a tracer using async syntax sugar, instead of manually writing out the state machine as literal switch case listing and migrating between all checkpoint states. Another added benefit of `PtraceAsyncRuntime` is that all logics within it are forced to run on the same thread, so I can avoid `Arc<Mutex<>>` and use `RefCell` instead.

**Caveat**: this refactor from "synchronous spaghetti" to "async as a hacky state machine syntax" is still ongoing. You will see two hacky logics live next to each other. The synchronous logics use a ton of `Arc<Mutex<>>` types. And the async logics are always Pinned, not truly "async", and are more of a hacky use of the underlying state machine than a use of true async events

Right now the repo lives in a very bad state and has a lot more runtime overhead than needed. I intend to move fully into async in hope that removing Arc will fix some of the overhead. But I'm starting to think I misunderstood how Rust handles async, and how heavy it truly is.

## License

Copyright (c) 2026 Zhongzhi Yu

This project is licensed under the GNU Lesser General Public License v3.0 (LGPLv3) - 
see [COPYING](COPYING) for details

## For Developers (Note: this might be outdated)

How to debug problems:

- `RUST_LOG=TRACE RUST_BACKTRACE=1 cargo run  -- --chroot xxx --root |& ansi2txt | tee ~/logfile | grep -v TRACE | grep -v DEBUG`

Overhead: Tested on Android Termux:

proot slows down `git status` to about 5x its original run time.

- original total wall time: about 10ms
- proot total wall time: about 50ms

As long as our parallel proot doesn't slow down the tracee by more than 5x. It should be fine.


How to cross-compile for Android:

- Install `arm-linux-*-gcc` and `aarch64-linux-*-gcc`
  - Depending on the license of these softwares, the `*` portion might differ
  - We prefer [Musl libc toolchains](https://musl.cc/).
- Update your `~/.cargo/config`:
  ```
  [target.armv7-unknown-linux-musleabihf]
  rustflags = ["-C", "target-feature=+crt-static"]
  linker = "arm-linux-foobar-gcc"

  [target.armv7-unknown-linux-musl]
  rustflags = ["-C", "target-feature=+crt-static"]
  linker = "aarch64-linux-foobar-gcc"
  ```
- Run `cargo build --target=armv7-unknown-linux-musleabihf --release`
- Or run `cargo build --target=aarch64-unknown-linux-musl --release`
- **Android permissions**
  - The terminal emulator must request specific permissions to unlock the ability to execute `./dockify`. The exact permission name is unknown.
  - Older Android versions work better with https://f-droid.org/en/packages/org.galexander.sshd/
  - [Android 10 and above require executables to be codesigned](https://github.com/greenaddress/abcore/issues/97)
    - Termux is the only solution that works well in this situation. [Here is a page from their discussion.](https://github.com/termux/termux-app/issues/1072)
    - But apparently, IT'S EASIER IF `dockify` IS CODE SIGNED AS part of the readonly APK.
