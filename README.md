## Backend vs Frontend syscall mods

Frontend mods: provides chroot / root without having root

Backend mods: low level ability to modify specific syscalls (i.e. remapping path of openat())

Backend mods are not dynamic and cannot be turned on/off or imported without rebuilding the binary, but frontend mods should eventually be able to.
