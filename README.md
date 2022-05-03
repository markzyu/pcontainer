## What's a good performance overhead?

Tested on Android Termux:

proot slows down `git status` to about 5x its original run time.

- original total wall time: about 10ms
- proot total wall time: about 50ms

As long as our parallel proot doesn't slow down the tracee by more than 5x. It should be fine.

## Backend vs Frontend syscall mods

Frontend mods: provides chroot / root without having root

Backend mods: low level ability to modify specific syscalls (i.e. remapping path of openat())

Backend mods are not dynamic and cannot be turned on/off or imported without rebuilding the binary, but frontend mods should eventually be able to.
