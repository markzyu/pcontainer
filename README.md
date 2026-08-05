## So this is just PRoot?

The fundamental idea is not that different from proot. In fact, it's inspiried by proot -- both can intercept system calls through ptrace() and simulate the chroot() system call so that we can chroot into a different Linux Distro on a non-rooted phone. 

However, there are a few differences:

1. This solution is multithreaded, while proot itself is single threaded. (And yes, I know they also have a Rust version)
    - Multithreading mattered to me, more than the ptrace overhead. Because proot has a hardtime supporting heavy I/O from a multithreaded JVM running game servers, for example, to host Minecraft.
    - This project was an exploration of whether multithreading helps with heavy I/O. But I've been sidetracked by other issues like supporting `apt-get`.
2. PRoot uses GPL Licenses. This project uses MIT icensing to maximize software freedom.
3. PRoot has a longer history of proven success. But this project is still in its early stage. This is both good and bad.
    - The Good: There are no rules for contributors. If you have a patch that helps, I'm willing to throw away existing code and use yours instead.
    - The Bad: This project barely works. Basic shell commands work but `apt-get` is broken.

Eventually, my goal is to be able to run any Docker container on any mobile device, without needing root. But there is a long way to go.

## Warning: Outdated code (Don't use in prod)

The Rust compiler version and many crates are outdated. (I used very old versions of libc and nix. And there are a lot of dirty workarounds in my code to fix missing syscall constants)

The following designs are outdated:

* The "mods" crate is outdated. 
* The "procfs" crate is an empty placeholder for procfs simulation. It is not being used at all.

Regarding "mods" crate, the idea was to implement optional features and logics here. In reality, this proved unfit. Dynamically loading mods slows down Rust because it involves dyn pointers.

To actually achieve "turning on/off features at runtime", we should just create a better config schema so that we can customize "sysaug" crate behavior with a descriptive json config that's passed in during pcontainer initialization

## Project structure


![project structure](ProjectStructure.png)

Both sysaug and mods crates are supposed to modify the behavior of system calls. But here are the differences:

Sysaug is a backend while mods are the frontend.
- `sysaug` is a backend, low level ability to modify specific syscalls (i.e. remapping path of openat())
- `mods` are the fronted, high level features (provides chroot / root, without having root)

Mods are dynamic but sysaug isn't.
- `mods` can be imported, enabled, and disabled dynamically. Disabling mods should improve efficiency.
- `sysaug` is not dynamic and cannot be turned on/off or imported without rebuilding the binary, but frontend mods should eventually be able to.

## Multithreading model

By default, pcontainer will try to run ptrace() syscalls on dedicated threads (one thread per tracee process)

But this requires the permission for PTRACE_ATTACH. And on some systems, this permission is blocked, and tracer can only attach to their direct children from main threads.

In that case, pcontainer will try to cumulate ptrace() syscalls on main thread from all tracee processes, and offload each tracee's own event loop and calculations to other threads. (Main thread is busy executing ptrace() calls while other threads queue ptrace actions)

## For Developers

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
