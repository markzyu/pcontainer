use crate::common::{Augments, DelType, PermType, SyscallInfo, NO_MOD_SYSCALL};
use lazy_static::lazy_static;
use std::collections::HashMap;

/**
TODO: a simple refactor (just move definitions to jsons so this looks more declarative):
{
    SYS_chmod: {
        type: Paths,
        config: {
            path_positions: $path_positions,
            dirfd_position: Some($dirfd_position),
            getdents_bits: None,
            sets_file_perms: Some($perm_type),
        },
    }
}
**/

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

macro_rules! update_syscall {
    ($ans:ident, $name:expr, $func:expr) => {
        $ans.get_mut(&($name as usize)).map($func)
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

        #[cfg(any(target_arch = "arm", target_arch = "x86"))]
        {
            define_perms_syscall!(libc::SYS_getuid32, false, 0, 17, ans);
            define_perms_syscall!(libc::SYS_geteuid32, false, 0, 18, ans);
            define_perms_syscall!(libc::SYS_getgid32, false, 0, 1, ans);
            define_perms_syscall!(libc::SYS_getegid32, false, 0, 2, ans);
            define_perms_syscall!(libc::SYS_getgroups32, false, 0, 0, ans);
            define_perms_syscall!(libc::SYS_setuid32, true, 0, 18, ans);
            define_perms_syscall!(libc::SYS_setgid32, true, 0, 2, ans);
            define_perms_syscall!(libc::SYS_setgroups32, true, 0, 0, ans);
            define_perms_syscall!(libc::SYS_setregid32, true, 3, 0, ans);
            define_perms_syscall!(libc::SYS_setreuid32, true, 19, 0, ans);
            define_perms_syscall!(libc::SYS_setresgid32, true, 7, 0, ans);
            define_perms_syscall!(libc::SYS_setresuid32, true, 23, 0, ans);
            define_perms_syscall!(libc::SYS_setfsgid32, true, 0, 8, ans);
            define_perms_syscall!(libc::SYS_setfsuid32, true, 0, 24, ans);
        }

        define_paths_syscall!(libc::SYS_acct, 1, ans);
        define_paths_syscall!(libc::SYS_chdir, 1, ans);
        define_paths_syscall!(libc::SYS_chroot, 1, ans);
        define_paths_syscall!(libc::SYS_getxattr, 1, ans);
        define_paths_syscall!(libc::SYS_listxattr, 1, ans);
        define_paths_syscall!(libc::SYS_removexattr, 1, ans);
        define_paths_syscall!(libc::SYS_setxattr, 1, ans);
        define_paths_syscall!(libc::SYS_swapoff, 1, ans);
        define_paths_syscall!(libc::SYS_swapon, 1, ans);
        define_paths_syscall!(libc::SYS_umount2, 1, ans);
        define_syscall!(libc::SYS_execve, Augments::Exec, ans);

        define_dirfd_syscall!(libc::SYS_openat, 2, 0, ans);
        define_dirfd_syscall!(libc::SYS_name_to_handle_at, 2, 0, ans);
        define_dirfd_syscall!(libc::SYS_faccessat, 2, 0, ans);
        define_dirfd_setperms_syscall!(libc::SYS_fchmodat, 2, 0, PermType::Chmod, ans);
        define_dirfd_setperms_syscall!(libc::SYS_fchownat, 2, 0, PermType::Chown, ans);
        define_dirfd2_syscall!(libc::SYS_linkat, 10, ans);
        define_dirfd_syscall!(libc::SYS_mkdirat, 2, 0, ans);

        define_dirfd_syscall!(libc::SYS_readlinkat, 2, 0, ans);
        define_dirfd2_syscall!(libc::SYS_renameat, 10, ans);
        define_dirfd_syscall!(libc::SYS_symlinkat, 4, 1, ans);
        define_dirfd_deletion_syscall!(libc::SYS_unlinkat, 2, 0, DelType::File, ans);
        define_paths_syscall!(libc::SYS_lgetxattr, 1, ans);
        define_paths_syscall!(libc::SYS_llistxattr, 1, ans);
        update_syscall!(ans, libc::SYS_readlinkat, |x| x.dont_follow_symlink = true);
        update_syscall!(ans, libc::SYS_renameat, |x| x.dont_follow_symlink = true);
        update_syscall!(ans, libc::SYS_symlinkat, |x| x.dont_follow_symlink = true);
        update_syscall!(ans, libc::SYS_unlinkat, |x| x.dont_follow_symlink = true);
        update_syscall!(ans, libc::SYS_lgetxattr, |x| x.dont_follow_symlink = true);
        update_syscall!(ans, libc::SYS_llistxattr, |x| x.dont_follow_symlink = true);

        #[cfg(not(all(target_os = "android", target_arch = "aarch64")))]
        {
            define_paths_syscall!(libc::SYS_truncate, 1, ans);
            define_paths_syscall!(libc::SYS_statfs, 1, ans);
        }
        #[cfg(not(target_os = "android"))]
        {
            define_dirfd_syscall!(libc::SYS_statx, 2, 0, ans);
            update_syscall!(ans, libc::SYS_statx, |x| {
                x.flags = Some(2);
                x.flag_dont_follow_symlink = Some(libc::AT_SYMLINK_NOFOLLOW as usize);
            });
        }

        define_dirfd_syscall!(libc::SYS_utimensat, 2, 0, ans);
        update_syscall!(ans, libc::SYS_utimensat, |x| {
            x.flags = Some(3);
            x.flag_dont_follow_symlink = Some(libc::AT_SYMLINK_NOFOLLOW as usize);
        });

        define_getdents_syscall!(libc::SYS_getdents64, 64, ans);

        define_setperms_syscall!(libc::SYS_fchmod, PermType::Chmod, ans);
        define_setperms_syscall!(libc::SYS_fchown, PermType::Chown, ans);

        #[cfg(target_arch = "arm")]
        {
            define_paths_syscall!(libc::SYS_chown32, 1, ans);
            define_paths_syscall!(libc::SYS_stat64, 1, ans);
            define_paths_syscall!(libc::SYS_statfs64, 1, ans);
            define_paths_syscall!(libc::SYS_truncate64, 1, ans);

            define_paths_syscall!(libc::SYS_lchown32, 1, ans);
            define_paths_syscall!(libc::SYS_lstat64, 1, ans);
            update_syscall!(ans, libc::SYS_lchown32, |x| x.dont_follow_symlink = true);
            update_syscall!(ans, libc::SYS_lstat64, |x| x.dont_follow_symlink = true);
        }

        #[cfg(all(target_arch = "aarch64", not(target_os = "android")))]
        {
            define_dirfd_syscall!(libc::SYS_newfstatat, 2, 0, ans);
            update_syscall!(ans, libc::SYS_newfstatat, |x| {
                x.flags = Some(3);
                x.flag_dont_follow_symlink = Some(libc::AT_SYMLINK_NOFOLLOW as usize);
            });
        }

        #[cfg(target_arch = "x86_64")]
        {
            define_dirfd_syscall!(libc::SYS_faccessat2, 2, 0, ans);
            define_dirfd_syscall!(libc::SYS_newfstatat, 2, 0, ans);
            define_paths_syscall!(libc::SYS_rename, 3, ans);
            update_syscall!(ans, libc::SYS_rename, |x| x.dont_follow_symlink = true);
            update_syscall!(ans, libc::SYS_newfstatat, |x| {
                x.flags = Some(3);
                x.flag_dont_follow_symlink = Some(libc::AT_SYMLINK_NOFOLLOW as usize);
            });

            define_paths_syscall!(libc::SYS_utime, 1, ans);
            define_getdents_syscall!(libc::SYS_getdents, 32, ans);
        }

        #[cfg(any(target_arch = "x86_64", target_arch = "arm"))]
        {
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
            define_paths_syscall!(libc::SYS_link, 3, ans);

            define_paths_syscall!(libc::SYS_readlink, 1, ans);
            define_paths_setperms_syscall!(libc::SYS_lchown, 1, PermType::Chown, ans);
            define_paths_syscall!(libc::SYS_lstat, 1, ans);
            define_paths_syscall!(libc::SYS_symlink, 2, ans);
            update_syscall!(ans, libc::SYS_readlink, |x| x.dont_follow_symlink = true);
            update_syscall!(ans, libc::SYS_lchown, |x| x.dont_follow_symlink = true);
            update_syscall!(ans, libc::SYS_lstat, |info| info.dont_follow_symlink = true);
            update_syscall!(ans, libc::SYS_symlink, |x| x.dont_follow_symlink = true);

            define_paths_deletion_syscall!(libc::SYS_unlink, 1, DelType::File, ans);
            update_syscall!(ans, libc::SYS_unlink, |x| x.dont_follow_symlink = true);
            define_paths_deletion_syscall!(libc::SYS_rmdir, 1, DelType::Dir, ans);

            define_paths_syscall!(libc::SYS_mkdir, 1, ans);
        }

        ans.remove(&NO_MOD_SYSCALL);
        ans
    };
}

#[cfg(any(target_arch = "aarch64"))]
pub const SYSCALL_INSTRUCTION_SIZE: usize = 4;

#[cfg(not(any(target_arch = "aarch64")))]
pub const SYSCALL_INSTRUCTION_SIZE: usize = 2;

pub fn get_syscall(syscall_num: &usize) -> (Option<&SyscallInfo>, String) {
    let syscall_info = SYSCALL_INFOS.get(syscall_num);
    let syscall_num_str = syscall_num.to_string();
    let syscall_name = syscall_info
        .map(|x| format!("{}({})", x.name(), &syscall_num_str))
        .unwrap_or(syscall_num_str);
    (syscall_info, syscall_name)
}
