## Project structure

![project structure](ProjectStructure.png)

Both sysaug and mods crates are supposed to modify the behavior of system calls. But here are the differences:

Sysaug is a backend while mods are the frontend.
- `sysaug` is a backend, low level ability to modify specific syscalls (i.e. remapping path of openat())
- `mods` are the fronted, high level features (provides chroot / root, without having root)

Mods are dynamic but sysaug isn't.
- `mods` can be imported, enabled, and disabled dynamically. Disabling mods should improve efficiency.
- `sysaug` is not dynamic and cannot be turned on/off or imported without rebuilding the binary, but frontend mods should eventually be able to.

## What's a good performance overhead?

Tested on Android Termux:

proot slows down `git status` to about 5x its original run time.

- original total wall time: about 10ms
- proot total wall time: about 50ms

As long as our parallel proot doesn't slow down the tracee by more than 5x. It should be fine.
