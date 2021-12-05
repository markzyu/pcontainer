use crate::common::{Augments, DelType, PermType, SyscallInfo, NO_MOD_SYSCALL};
use lazy_static::lazy_static;
use std::collections::HashMap;

macro_rules! define_syscall {
    ($name:expr, $augment:expr, $ans:ident) => {
        $ans.insert(
            $name as usize,
            SyscallInfo {
                augment: $augment,
                name: stringify!($name),
                num: $name,
                ..Default::default()
            },
        )
    };
}

macro_rules! define_setperms_syscall {
    ($name:expr, $perm_type:expr, $ans:ident) => {
        $ans.insert(
            $name as usize,
            SyscallInfo {
                name: stringify!($name),
                num: $name,
                sets_file_perms: Some($perm_type),
                ..Default::default()
            },
        )
    };
}

macro_rules! define_perms_syscall {
    ($name:expr, $is_setter:expr, $res_bits:expr, $resf_bit:expr, $ans:ident) => {
        $ans.insert(
            $name as usize,
            SyscallInfo {
                augment: Augments::Perms,
                name: stringify!($name),
                num: $name,
                is_setter: $is_setter,
                res_bits: $res_bits,
                resf_bit: $resf_bit,
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
                num: $name,
                path_positions: $path_positions,
                getdents_bits: None,
                ..Default::default()
            },
        )
    };
}

macro_rules! define_paths_deletion_syscall {
    ($name:expr, $path_positions:expr, $type:expr, $ans:ident) => {
        $ans.insert(
            $name as usize,
            SyscallInfo {
                augment: Augments::Paths,
                name: stringify!($name),
                num: $name,
                path_positions: $path_positions,
                getdents_bits: None,
                deletion_type: Some($type),
                ..Default::default()
            },
        )
    };
}

macro_rules! define_paths_setperms_syscall {
    ($name:expr, $path_positions:expr, $perm_type:expr, $ans:ident) => {
        $ans.insert(
            $name as usize,
            SyscallInfo {
                augment: Augments::Paths,
                name: stringify!($name),
                num: $name,
                path_positions: $path_positions,
                getdents_bits: None,
                sets_file_perms: Some($perm_type),
                ..Default::default()
            },
        )
    };
}

// In this version, all paths share the same dirfd
macro_rules! define_dirfd_syscall {
    ($name:expr, $path_positions:expr, $dirfd_position:expr, $ans:ident) => {
        $ans.insert(
            $name as usize,
            SyscallInfo {
                augment: Augments::Paths,
                name: stringify!($name),
                num: $name,
                path_positions: $path_positions,
                dirfd_position: Some($dirfd_position),
                getdents_bits: None,
                ..Default::default()
            },
        )
    };
}

// In this version, the dirfd for each path is the argument immediately preceding it.
macro_rules! define_dirfd2_syscall {
    ($name:expr, $path_positions:expr, $ans:ident) => {
        $ans.insert(
            $name as usize,
            SyscallInfo {
                augment: Augments::Paths,
                name: stringify!($name),
                num: $name,
                path_positions: $path_positions,
                dirfd_precedes_path: true,
                dirfd_position: None,
                getdents_bits: None,
                ..Default::default()
            },
        )
    };
}

macro_rules! define_dirfd_deletion_syscall {
    ($name:expr, $path_positions:expr, $dirfd_position:expr, $type:expr, $ans:ident) => {
        $ans.insert(
            $name as usize,
            SyscallInfo {
                augment: Augments::Paths,
                name: stringify!($name),
                num: $name,
                path_positions: $path_positions,
                dirfd_position: Some($dirfd_position),
                getdents_bits: None,
                deletion_type: Some($type),
                ..Default::default()
            },
        )
    };
}

macro_rules! define_dirfd_setperms_syscall {
    ($name:expr, $path_positions:expr, $dirfd_position:expr, $perm_type:expr, $ans:ident) => {
        $ans.insert(
            $name as usize,
            SyscallInfo {
                augment: Augments::Paths,
                name: stringify!($name),
                num: $name,
                path_positions: $path_positions,
                dirfd_position: Some($dirfd_position),
                getdents_bits: None,
                sets_file_perms: Some($perm_type),
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
                num: $name,
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
        define_perms_syscall!(libc::SYS_getuid, false, 0, 17, ans);
        define_perms_syscall!(libc::SYS_geteuid, false, 0, 18, ans);
        define_perms_syscall!(libc::SYS_getgid, false, 0, 1, ans);
        define_perms_syscall!(libc::SYS_getegid, false, 0, 2, ans);
        define_perms_syscall!(libc::SYS_getgroups, false, 0, 0, ans);
        define_perms_syscall!(libc::SYS_setuid, true, 0, 18, ans);
        define_perms_syscall!(libc::SYS_setgid, true, 0, 2, ans);
        define_perms_syscall!(libc::SYS_setgroups, true, 0, 0, ans);
        define_perms_syscall!(libc::SYS_setregid, true, 3, 0, ans);
        define_perms_syscall!(libc::SYS_setreuid, true, 19, 0, ans);
        define_perms_syscall!(libc::SYS_setresgid, true, 7, 0, ans);
        define_perms_syscall!(libc::SYS_setresuid, true, 23, 0, ans);
        define_perms_syscall!(libc::SYS_setfsgid, true, 0, 8, ans);
        define_perms_syscall!(libc::SYS_setfsuid, true, 0, 24, ans);
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
        define_syscall!(libc::SYS_execve, Augments::Exec, ans);

        define_dirfd_syscall!(libc::SYS_openat, 2, 0, ans);
        define_dirfd_syscall!(libc::SYS_name_to_handle_at, 2, 0, ans);
        define_dirfd_syscall!(libc::SYS_faccessat, 2, 0, ans);
        define_dirfd_setperms_syscall!(libc::SYS_fchmodat, 2, 0, PermType::Chmod, ans);
        define_dirfd_setperms_syscall!(libc::SYS_fchownat, 2, 0, PermType::Chown, ans);
        define_dirfd2_syscall!(libc::SYS_linkat, 10, ans);
        define_dirfd_syscall!(libc::SYS_mkdirat, 2, 0, ans);
        define_dirfd2_syscall!(libc::SYS_renameat, 10, ans);
        define_dirfd_syscall!(libc::SYS_symlinkat, 4, 1, ans);
        define_dirfd_syscall!(libc::SYS_utimensat, 2, 0, ans);
        define_dirfd_deletion_syscall!(libc::SYS_unlinkat, 2, 0, DelType::File, ans);
        define_dirfd_syscall!(libc::SYS_statx, 2, 0, ans);
        define_getdents_syscall!(libc::SYS_getdents64, 64, ans);

        define_setperms_syscall!(libc::SYS_fchmod, PermType::Chmod, ans);
        define_setperms_syscall!(libc::SYS_fchown, PermType::Chown, ans);

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
    define_dirfd_syscall!(libc::SYS_faccessat, 2, 0, ans);
}

#[cfg(target_arch = "x86_64")]
fn add_xplat_syscalls(ans: &mut HashMap<usize, SyscallInfo>) {
    define_dirfd_syscall!(libc::SYS_newfstatat, 2, 0, ans);
    define_paths_syscall!(libc::SYS_rename, 3, ans);
    define_paths_syscall!(libc::SYS_utime, 1, ans);
    define_getdents_syscall!(libc::SYS_getdents, 32, ans);
    add_xplat_syscalls2(ans);
}

#[cfg(any(target_arch = "x86_64", target_arch = "arm"))]
fn add_xplat_syscalls2(ans: &mut HashMap<usize, SyscallInfo>) {
    define_paths_syscall!(libc::SYS_access, 1, ans);
    define_paths_setperms_syscall!(libc::SYS_chmod, 1, PermType::Chmod, ans);
    define_paths_setperms_syscall!(libc::SYS_chown, 1, PermType::Chown, ans);
    define_paths_syscall!(libc::SYS_mknod, 1, ans);
    define_paths_syscall!(libc::SYS_creat, 1, ans);
    define_paths_syscall!(libc::SYS_stat, 1, ans);
    define_paths_syscall!(libc::SYS_uselib, 1, ans);
    define_paths_syscall!(libc::SYS_utimes, 1, ans);
    define_dirfd_syscall!(libc::SYS_futimesat, 2, 0, ans);
    define_paths_syscall!(libc::SYS_open, 1, ans);
    define_paths_syscall!(libc::SYS_readlink, 1, ans);
    define_paths_setperms_syscall!(libc::SYS_lchown, 1, PermType::Chown, ans);
    define_paths_syscall!(libc::SYS_lstat, 1, ans);
    define_paths_syscall!(libc::SYS_symlink, 2, ans);
    define_paths_syscall!(libc::SYS_link, 3, ans);
    define_paths_deletion_syscall!(libc::SYS_unlink, 1, DelType::File, ans);
    define_paths_deletion_syscall!(libc::SYS_rmdir, 1, DelType::Dir, ans);
    define_paths_syscall!(libc::SYS_mkdir, 1, ans);
}
