use crate::common::{Augments, SyscallInfo, NO_MOD_SYSCALL};
use lazy_static::lazy_static;
use std::collections::HashMap;

macro_rules! define_syscall {
    ($name:expr, $augment:expr, $ans:ident) => {
        $ans.insert(
            $name as usize,
            SyscallInfo {
                augment: $augment,
                name: stringify!($name),
                num: $name as usize,
                ..Default::default()
            },
        )
    };
}

macro_rules! define_perms_syscall {
    ($name:expr, $is_setter:expr, $type:expr, $ans:ident) => {
        $ans.insert(
            $name as usize,
            SyscallInfo {
                augment: Augments::Perms,
                name: stringify!($name),
                num: $name as usize,
                is_setter: $is_setter,
                is_uid: $type == "uid",
                is_gid: $type == "gid",
                ..Default::default()
            },
        )
    };
}

macro_rules! define_paths_syscall {
    ($name:expr, $path_positions:expr, $ans:ident) => {
        $ans.insert(
            $name as usize,
            SyscallInfo {
                augment: Augments::Paths,
                name: stringify!($name),
                num: $name as usize,
                path_positions: $path_positions,
                getdents_bits: None,
                ..Default::default()
            },
        )
    };
}

macro_rules! define_dirfd_syscall {
    ($name:expr, $path_positions:expr, $dirfd_position:expr, $ans:ident) => {
        $ans.insert(
            $name as usize,
            SyscallInfo {
                augment: Augments::Paths,
                name: stringify!($name),
                num: $name as usize,
                path_positions: $path_positions,
                dirfd_position: Some($dirfd_position),
                getdents_bits: None,
                ..Default::default()
            },
        )
    };
}

macro_rules! define_getdents_syscall {
    ($name:expr, $getdents_bits:expr, $ans:ident) => {
        $ans.insert(
            $name as usize,
            SyscallInfo {
                augment: Augments::Paths,
                name: stringify!($name),
                num: $name as usize,
                path_positions: 0,
                getdents_bits: Some($getdents_bits),
                ..Default::default()
            },
        )
    };
}

// ----------------- DEFINE ALL KNOWN SYSCALLS ------------------

lazy_static! {
    pub static ref SYSCALL_INFOS: HashMap<usize, SyscallInfo> = {
        let mut ans = HashMap::new();
        define_syscall!(libc::SYS_clone, Augments::Clone, ans);
        define_syscall!(libc::SYS_wait4, Augments::Waitpid, ans);
        define_perms_syscall!(libc::SYS_getuid, false, "uid", ans);
        define_perms_syscall!(libc::SYS_geteuid, false, "uid", ans);
        define_perms_syscall!(libc::SYS_setuid, true, "uid", ans);
        define_perms_syscall!(libc::SYS_getgid, false, "gid", ans);
        // define_perms_syscall!(libc::SYS_getegid, false, "gid", ans);
        define_perms_syscall!(libc::SYS_setgid, true, "gid", ans);
        define_perms_syscall!(libc::SYS_setgroups, true, "unknown", ans);
        define_perms_syscall!(libc::SYS_setregid, true, "unknown", ans);
        define_perms_syscall!(libc::SYS_setreuid, true, "unknown", ans);
        define_perms_syscall!(libc::SYS_setresgid, true, "unknown", ans);
        define_perms_syscall!(libc::SYS_setresuid, true, "unknown", ans);
        define_perms_syscall!(libc::SYS_setfsgid, true, "unknown", ans);
        define_perms_syscall!(libc::SYS_setfsuid, true, "unknown", ans);
        define_paths_syscall!(libc::SYS_acct, 1, ans);
        define_paths_syscall!(libc::SYS_chdir, 1, ans);
        define_paths_syscall!(libc::SYS_chroot, 1, ans);
        define_paths_syscall!(libc::SYS_getxattr, 1, ans);
        define_paths_syscall!(libc::SYS_listxattr, 1, ans);
        define_paths_syscall!(libc::SYS_removexattr, 1, ans);
        define_paths_syscall!(libc::SYS_setxattr, 1, ans);
        define_paths_syscall!(libc::SYS_statfs, 1, ans);
        define_paths_syscall!(libc::SYS_swapoff, 1, ans);
        define_paths_syscall!(libc::SYS_swapon, 1, ans);
        define_paths_syscall!(libc::SYS_truncate, 1, ans);
        define_paths_syscall!(libc::SYS_umount2, 1, ans);
        define_paths_syscall!(libc::SYS_lgetxattr, 1, ans);
        define_paths_syscall!(libc::SYS_llistxattr, 1, ans);
        define_paths_syscall!(libc::SYS_execve, 1, ans);

        define_dirfd_syscall!(libc::SYS_openat, 2, 0, ans);
        define_dirfd_syscall!(libc::SYS_name_to_handle_at, 2, 0, ans);
        define_dirfd_syscall!(libc::SYS_faccessat, 2, 0, ans);
        define_dirfd_syscall!(libc::SYS_mkdirat, 2, 0, ans);
        define_dirfd_syscall!(libc::SYS_utimensat, 2, 0, ans);
        define_getdents_syscall!(libc::SYS_getdents64, 64, ans);
        add_xplat_syscalls(&mut ans);
        ans.remove(&NO_MOD_SYSCALL);
        ans
    };
}

#[cfg(target_arch = "arm")]
fn add_xplat_syscalls(ans: &mut HashMap<usize, SyscallInfo>) {
    define_paths_syscall!(libc::SYS_chown32, 1, ans);
    define_paths_syscall!(libc::SYS_stat64, 1, ans);
    define_paths_syscall!(libc::SYS_statfs64, 1, ans);
    define_paths_syscall!(libc::SYS_truncate64, 1, ans);
    define_paths_syscall!(libc::SYS_lchown32, 1, ans);
    define_paths_syscall!(libc::SYS_lstat64, 1, ans);
    add_xplat_syscalls2(ans);
}

#[cfg(target_arch = "aarch64")]
fn add_xplat_syscalls(ans: &mut HashMap<usize, SyscallInfo>) {
    define_dirfd_syscall!(libc::SYS_newfstatat, 2, 0, ans);
}

#[cfg(target_arch = "x86_64")]
fn add_xplat_syscalls(ans: &mut HashMap<usize, SyscallInfo>) {
    define_dirfd_syscall!(libc::SYS_newfstatat, 2, 0, ans);
    define_paths_syscall!(libc::SYS_utime, 1, ans);
    define_getdents_syscall!(libc::SYS_getdents, 32, ans);
    add_xplat_syscalls2(ans);
}

#[cfg(any(target_arch = "x86_64", target_arch = "arm"))]
fn add_xplat_syscalls2(ans: &mut HashMap<usize, SyscallInfo>) {
    define_paths_syscall!(libc::SYS_access, 1, ans);
    define_paths_syscall!(libc::SYS_chmod, 1, ans);
    define_paths_syscall!(libc::SYS_chown, 1, ans);
    define_paths_syscall!(libc::SYS_mknod, 1, ans);
    define_paths_syscall!(libc::SYS_creat, 1, ans);
    define_paths_syscall!(libc::SYS_stat, 1, ans);
    define_paths_syscall!(libc::SYS_uselib, 1, ans);
    define_paths_syscall!(libc::SYS_utimes, 1, ans);
    define_paths_syscall!(libc::SYS_open, 1, ans);
    define_paths_syscall!(libc::SYS_readlink, 1, ans);
    define_paths_syscall!(libc::SYS_lchown, 1, ans);
    define_paths_syscall!(libc::SYS_lstat, 1, ans);
    define_paths_syscall!(libc::SYS_unlink, 1, ans);
    define_paths_syscall!(libc::SYS_rmdir, 1, ans);
    define_paths_syscall!(libc::SYS_mkdir, 1, ans);
}
