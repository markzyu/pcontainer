// Copyright 2026 Zhongzhi Yu <7296488+markzyu@users.noreply.github.comter>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.

#![allow(non_snake_case)]
#![allow(unused_macros)]
use crate::common::{Augments, DelType, NO_MOD_SYSCALL, PermType, SyscallInfo, default_syscall_info};
use lazy_static::lazy_static;
use std::collections::HashMap;
use tracing::{Level, event};

const MAX_RAW_SYSCALL_INFOS: usize = (u8::MAX as usize) - 4;

macro_rules! define_syscall {
    ($name:expr, $augment:expr, $iter:ident, $next:ident) => {
        $next += 1;
        if $next >= MAX_RAW_SYSCALL_INFOS {
            panic!("No more space for ptrace-eligible syscalls");
        }
        if ($name as usize) == NO_MOD_SYSCALL {
            panic!("Syscall list should not include NO_MOD_SYSCALL");
        }
        $iter[$next] = Some(SyscallInfo {
            augment: $augment,
            name: stringify!($name),
            num: $name,
            ..default_syscall_info()
        });
    };
}

macro_rules! define_setperms_syscall {
    ($name:expr, $perm_type:expr, $iter:ident, $next:ident) => {
        $next += 1;
        if $next >= MAX_RAW_SYSCALL_INFOS {
            panic!("No more space for syscalls");
        }
        if ($name as usize) == NO_MOD_SYSCALL {
            panic!("Syscall list should not include NO_MOD_SYSCALL");
        }
        $iter[$next] = Some(SyscallInfo {
            name: stringify!($name),
            num: $name,
            sets_file_perms: Some($perm_type),
            ..default_syscall_info()
        });
    };
}

macro_rules! define_perms_syscall {
    ($name:expr, $is_setter:expr, $res_bits:expr, $resf_bit:expr, $iter:ident, $next:ident) => {
        $next += 1;
        if $next >= MAX_RAW_SYSCALL_INFOS {
            panic!("No more space for syscalls");
        }
        if ($name as usize) == NO_MOD_SYSCALL {
            panic!("Syscall list should not include NO_MOD_SYSCALL");
        }
        $iter[$next] = Some(SyscallInfo {
            augment: Augments::Perms,
            name: stringify!($name),
            num: $name,
            is_setter: $is_setter,
            res_bits: $res_bits,
            resf_bit: $resf_bit,
            ..default_syscall_info()
        });
    };
}

macro_rules! define_paths_syscall {
    ($name:expr, $path_positions:expr, $iter:ident, $next:ident) => {
        $next += 1;
        if $next >= MAX_RAW_SYSCALL_INFOS {
            panic!("No more space for syscalls");
        }
        if ($name as usize) == NO_MOD_SYSCALL {
            panic!("Syscall list should not include NO_MOD_SYSCALL");
        }
        $iter[$next] = Some(SyscallInfo {
            augment: Augments::Paths,
            name: stringify!($name),
            num: $name,
            path_positions: $path_positions,
            getdents_bits: None,
            ..default_syscall_info()
        });
    };
}

macro_rules! define_paths_deletion_syscall {
    ($name:expr, $path_positions:expr, $type:expr, $iter:ident, $next:ident) => {
        $next += 1;
        if $next >= MAX_RAW_SYSCALL_INFOS {
            panic!("No more space for syscalls");
        }
        if ($name as usize) == NO_MOD_SYSCALL {
            panic!("Syscall list should not include NO_MOD_SYSCALL");
        }
        $iter[$next] = Some(SyscallInfo {
            augment: Augments::Paths,
            name: stringify!($name),
            num: $name,
            path_positions: $path_positions,
            getdents_bits: None,
            deletion_type: Some($type),
            ..default_syscall_info()
        });
    };
}

macro_rules! define_paths_setperms_syscall {
    ($name:expr, $path_positions:expr, $perm_type:expr, $iter:ident, $next:ident) => {
        $next += 1;
        if $next >= MAX_RAW_SYSCALL_INFOS {
            panic!("No more space for syscalls");
        }
        if ($name as usize) == NO_MOD_SYSCALL {
            panic!("Syscall list should not include NO_MOD_SYSCALL");
        }
        $iter[$next] = Some(SyscallInfo {
            augment: Augments::Paths,
            name: stringify!($name),
            num: $name,
            path_positions: $path_positions,
            getdents_bits: None,
            sets_file_perms: Some($perm_type),
            ..default_syscall_info()
        });
    };
}

// In this version, all paths share the same dirfd
macro_rules! define_dirfd_syscall {
    ($name:expr, $path_positions:expr, $dirfd_position:expr, $iter:ident, $next:ident) => {
        $next += 1;
        if $next >= MAX_RAW_SYSCALL_INFOS {
            panic!("No more space for syscalls");
        }
        if ($name as usize) == NO_MOD_SYSCALL {
            panic!("Syscall list should not include NO_MOD_SYSCALL");
        }
        $iter[$next] = Some(SyscallInfo {
            augment: Augments::Paths,
            name: stringify!($name),
            num: $name,
            path_positions: $path_positions,
            dirfd_position: Some($dirfd_position),
            getdents_bits: None,
            ..default_syscall_info()
        });
    };
}

// In this version, the dirfd for each path is the argument immediately preceding it.
macro_rules! define_dirfd2_syscall {
    ($name:expr, $path_positions:expr, $iter:ident, $next:ident) => {
        $next += 1;
        if $next >= MAX_RAW_SYSCALL_INFOS {
            panic!("No more space for syscalls");
        }
        if ($name as usize) == NO_MOD_SYSCALL {
            panic!("Syscall list should not include NO_MOD_SYSCALL");
        }
        $iter[$next] = Some(SyscallInfo {
            augment: Augments::Paths,
            name: stringify!($name),
            num: $name,
            path_positions: $path_positions,
            dirfd_precedes_path: true,
            dirfd_position: None,
            getdents_bits: None,
            ..default_syscall_info()
        });
    };
}

macro_rules! define_dirfd_deletion_syscall {
    ($name:expr, $path_positions:expr, $dirfd_position:expr, $type:expr, $iter:ident, $next:ident) => {
        $next += 1;
        if $next >= MAX_RAW_SYSCALL_INFOS {
            panic!("No more space for syscalls");
        }
        if ($name as usize) == NO_MOD_SYSCALL {
            panic!("Syscall list should not include NO_MOD_SYSCALL");
        }
        $iter[$next] = Some(SyscallInfo {
            augment: Augments::Paths,
            name: stringify!($name),
            num: $name,
            path_positions: $path_positions,
            dirfd_position: Some($dirfd_position),
            getdents_bits: None,
            deletion_type: Some($type),
            ..default_syscall_info()
        });
    };
}

macro_rules! define_dirfd_setperms_syscall {
    ($name:expr, $path_positions:expr, $dirfd_position:expr, $perm_type:expr, $iter:ident, $next:ident) => {
        $next += 1;
        if $next >= MAX_RAW_SYSCALL_INFOS {
            panic!("No more space for syscalls");
        }
        if ($name as usize) == NO_MOD_SYSCALL {
            panic!("Syscall list should not include NO_MOD_SYSCALL");
        }
        $iter[$next] = Some(SyscallInfo {
            augment: Augments::Paths,
            name: stringify!($name),
            num: $name,
            path_positions: $path_positions,
            dirfd_position: Some($dirfd_position),
            getdents_bits: None,
            sets_file_perms: Some($perm_type),
            ..default_syscall_info()
        });
    };
}

macro_rules! define_getdents_syscall {
    ($name:expr, $getdents_bits:expr, $iter:ident, $next:ident) => {
        $next += 1;
        if $next >= MAX_RAW_SYSCALL_INFOS {
            panic!("No more space for syscalls");
        }
        if ($name as usize) == NO_MOD_SYSCALL {
            panic!("Syscall list should not include NO_MOD_SYSCALL");
        }
        $iter[$next] = Some(SyscallInfo {
            augment: Augments::Paths,
            name: stringify!($name),
            num: $name,
            path_positions: 0,
            getdents_bits: Some($getdents_bits),
            ..default_syscall_info()
        });
    };
}

// ----------------- DEFINE ALL KNOWN SYSCALLS ------------------

pub const RAW_SYSCALL_INFOS: [Option<SyscallInfo>; MAX_RAW_SYSCALL_INFOS] = {
    let mut iter = [const { None }; MAX_RAW_SYSCALL_INFOS];
    let mut next: usize = 0;

    define_syscall!(libc::SYS_clone, Augments::Clone, iter, next);
    define_syscall!(libc::SYS_wait4, Augments::Waitpid, iter, next);
    define_perms_syscall!(libc::SYS_getuid, false, 0, Some(4), iter, next);
    define_perms_syscall!(libc::SYS_geteuid, false, 0, Some(5), iter, next);
    define_perms_syscall!(libc::SYS_getgid, false, 0, Some(0), iter, next);
    define_perms_syscall!(libc::SYS_getegid, false, 0, Some(1), iter, next);
    define_perms_syscall!(libc::SYS_getgroups, false, 0, None, iter, next);
    define_perms_syscall!(libc::SYS_setuid, true, 0, Some(4), iter, next);
    define_perms_syscall!(libc::SYS_setgid, true, 0, Some(0), iter, next);
    define_perms_syscall!(libc::SYS_setgroups, true, 0, None, iter, next);
    define_perms_syscall!(libc::SYS_setregid, true, 3, None, iter, next);
    define_perms_syscall!(libc::SYS_setreuid, true, 19, None, iter, next);
    define_perms_syscall!(libc::SYS_setresgid, true, 7, None, iter, next);
    define_perms_syscall!(libc::SYS_setresuid, true, 23, None, iter, next);
    define_perms_syscall!(libc::SYS_setfsgid, true, 0, Some(3), iter, next);
    define_perms_syscall!(libc::SYS_setfsuid, true, 0, Some(7), iter, next);

    #[cfg(any(target_arch = "arm", target_arch = "x86"))]
    {
        define_perms_syscall!(libc::SYS_getuid32, false, 0, Some(4), iter, next);
        define_perms_syscall!(libc::SYS_geteuid32, false, 0, Some(5), iter, next);
        define_perms_syscall!(libc::SYS_getgid32, false, 0, Some(0), iter, next);
        define_perms_syscall!(libc::SYS_getegid32, false, 0, Some(1), iter, next);
        define_perms_syscall!(libc::SYS_getgroups32, false, 0, None, iter, next);
        define_perms_syscall!(libc::SYS_setuid32, true, 0, Some(4), iter, next);
        define_perms_syscall!(libc::SYS_setgid32, true, 0, Some(0), iter, next);
        define_perms_syscall!(libc::SYS_setgroups32, true, 0, None, iter, next);
        define_perms_syscall!(libc::SYS_setregid32, true, 3, None, iter, next);
        define_perms_syscall!(libc::SYS_setreuid32, true, 19, None, iter, next);
        define_perms_syscall!(libc::SYS_setresgid32, true, 7, None, iter, next);
        define_perms_syscall!(libc::SYS_setresuid32, true, 23, None, iter, next);
        define_perms_syscall!(libc::SYS_setfsgid32, true, 0, Some(3), iter, next);
        define_perms_syscall!(libc::SYS_setfsuid32, true, 0, Some(7), iter, next);
    }

    define_paths_syscall!(libc::SYS_acct, 1, iter, next);
    define_paths_syscall!(libc::SYS_chdir, 1, iter, next);
    define_paths_syscall!(libc::SYS_chroot, 1, iter, next);
    define_paths_syscall!(libc::SYS_getxattr, 1, iter, next);
    define_paths_syscall!(libc::SYS_listxattr, 1, iter, next);
    define_paths_syscall!(libc::SYS_removexattr, 1, iter, next);
    define_paths_syscall!(libc::SYS_setxattr, 1, iter, next);
    define_paths_syscall!(libc::SYS_swapoff, 1, iter, next);
    define_paths_syscall!(libc::SYS_swapon, 1, iter, next);
    define_paths_syscall!(libc::SYS_umount2, 1, iter, next);
    define_syscall!(libc::SYS_execve, Augments::Exec, iter, next);

    define_dirfd_syscall!(libc::SYS_openat, 2, 0, iter, next);
    define_dirfd_syscall!(libc::SYS_name_to_handle_at, 2, 0, iter, next);
    define_dirfd_syscall!(libc::SYS_faccessat, 2, 0, iter, next);
    define_dirfd_setperms_syscall!(libc::SYS_fchmodat, 2, 0, PermType::Chmod, iter, next);
    define_dirfd_setperms_syscall!(libc::SYS_fchownat, 2, 0, PermType::Chown, iter, next);
    define_dirfd2_syscall!(libc::SYS_linkat, 10, iter, next);
    define_dirfd_syscall!(libc::SYS_mkdirat, 2, 0, iter, next);

    define_dirfd_syscall!(libc::SYS_readlinkat, 2, 0, iter, next);
    if let Some(val) = iter[next].as_mut() {
        val.dont_follow_symlink = true;
    }

    define_dirfd2_syscall!(libc::SYS_renameat, 10, iter, next);
    if let Some(val) = iter[next].as_mut() {
        val.dont_follow_symlink = true;
    }

    define_dirfd2_syscall!(libc::SYS_renameat2, 10, iter, next);
    if let Some(val) = iter[next].as_mut() {
        val.dont_follow_symlink = true;
    }

    define_dirfd_syscall!(libc::SYS_symlinkat, 4, 1, iter, next);
    if let Some(val) = iter[next].as_mut() {
        val.dont_follow_symlink = true;
    }

    define_dirfd_deletion_syscall!(libc::SYS_unlinkat, 2, 0, DelType::File, iter, next);
    if let Some(val) = iter[next].as_mut() {
        val.dont_follow_symlink = true;
    }

    define_paths_syscall!(libc::SYS_lgetxattr, 1, iter, next);
    if let Some(val) = iter[next].as_mut() {
        val.dont_follow_symlink = true;
    }

    define_paths_syscall!(libc::SYS_llistxattr, 1, iter, next);
    if let Some(val) = iter[next].as_mut() {
        val.dont_follow_symlink = true;
    }

    #[cfg(not(all(target_os = "android", target_arch = "aarch64")))]
    {
        define_paths_syscall!(libc::SYS_truncate, 1, iter, next);
        define_paths_syscall!(libc::SYS_statfs, 1, iter, next);
    }
    #[cfg(not(target_os = "android"))]
    {
        define_dirfd_syscall!(libc::SYS_statx, 2, 0, iter, next);
        if let Some(val) = iter[next].as_mut() {
            val.flags = Some(2);
            val.flag_dont_follow_symlink = Some(libc::AT_SYMLINK_NOFOLLOW as usize);
        }
    }

    define_dirfd_syscall!(libc::SYS_utimensat, 2, 0, iter, next);
    if let Some(val) = iter[next].as_mut() {
        val.flags = Some(3);
        val.flag_dont_follow_symlink = Some(libc::AT_SYMLINK_NOFOLLOW as usize);
    }

    define_getdents_syscall!(libc::SYS_getdents64, 64, iter, next);

    define_setperms_syscall!(libc::SYS_fchmod, PermType::Chmod, iter, next);
    define_setperms_syscall!(libc::SYS_fchown, PermType::Chown, iter, next);

    #[cfg(target_arch = "arm")]
    {
        define_paths_syscall!(libc::SYS_chown32, 1, iter, next);
        define_paths_syscall!(libc::SYS_stat64, 1, iter, next);
        define_paths_syscall!(libc::SYS_statfs64, 1, iter, next);
        define_paths_syscall!(libc::SYS_truncate64, 1, iter, next);

        define_paths_syscall!(libc::SYS_lchown32, 1, iter, next);
        if let Some(val) = iter[next].as_mut() {
            val.dont_follow_symlink = true;
        }

        define_paths_syscall!(libc::SYS_lstat64, 1, iter, next);
        if let Some(val) = iter[next].as_mut() {
            val.dont_follow_symlink = true;
        }
    }

    #[cfg(target_arch = "x86_64")]
    {
        define_dirfd_syscall!(libc::SYS_faccessat2, 2, 0, iter, next);
        define_paths_syscall!(libc::SYS_rename, 3, iter, next);
        if let Some(val) = iter[next].as_mut() {
            val.dont_follow_symlink = true;
        }

        define_paths_syscall!(libc::SYS_utime, 1, iter, next);
        define_getdents_syscall!(libc::SYS_getdents, 32, iter, next);
    }

    #[cfg(target_arch = "x86_64")]
    let SYS_newfstatat: i64 = libc::SYS_newfstatat;

    #[cfg(target_arch = "aarch64")]
    let SYS_newfstatat: i64 = 79;

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        define_dirfd_syscall!(SYS_newfstatat, 2, 0, iter, next);
        if let Some(val) = iter[next].as_mut() {
            val.flags = Some(3);
            val.flag_dont_follow_symlink = Some(libc::AT_SYMLINK_NOFOLLOW as usize);
        }
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "arm"))]
    {
        define_paths_syscall!(libc::SYS_access, 1, iter, next);
        define_paths_setperms_syscall!(libc::SYS_chmod, 1, PermType::Chmod, iter, next);
        define_paths_setperms_syscall!(libc::SYS_chown, 1, PermType::Chown, iter, next);
        define_paths_syscall!(libc::SYS_mknod, 1, iter, next);
        define_paths_syscall!(libc::SYS_creat, 1, iter, next);
        define_paths_syscall!(libc::SYS_stat, 1, iter, next);
        define_paths_syscall!(libc::SYS_uselib, 1, iter, next);
        define_paths_syscall!(libc::SYS_utimes, 1, iter, next);
        define_dirfd_syscall!(libc::SYS_futimesat, 2, 0, iter, next);
        define_paths_syscall!(libc::SYS_open, 1, iter, next);
        define_paths_syscall!(libc::SYS_link, 3, iter, next);

        define_paths_syscall!(libc::SYS_readlink, 1, iter, next);
        if let Some(val) = iter[next].as_mut() {
            val.dont_follow_symlink = true;
        }

        define_paths_setperms_syscall!(libc::SYS_lchown, 1, PermType::Chown, iter, next);
        if let Some(val) = iter[next].as_mut() {
            val.dont_follow_symlink = true;
        }

        define_paths_syscall!(libc::SYS_lstat, 1, iter, next);
        if let Some(val) = iter[next].as_mut() {
            val.dont_follow_symlink = true;
        }

        define_paths_syscall!(libc::SYS_symlink, 2, iter, next);
        if let Some(val) = iter[next].as_mut() {
            val.dont_follow_symlink = true;
        }

        define_paths_deletion_syscall!(libc::SYS_unlink, 1, DelType::File, iter, next);
        if let Some(val) = iter[next].as_mut() {
            val.dont_follow_symlink = true;
        }

        define_paths_deletion_syscall!(libc::SYS_rmdir, 1, DelType::Dir, iter, next);

        define_paths_syscall!(libc::SYS_mkdir, 1, iter, next);
    }
    iter
};


lazy_static! {
    pub static ref SYSCALL_INFOS: HashMap<usize, SyscallInfo> = {
        let mut ans = HashMap::<usize, SyscallInfo>::new();
        RAW_SYSCALL_INFOS.iter().for_each(|x| {
            if let Some(val) = x {
                ans.insert(val.num as usize, val.clone());
            }
        });
        event!(Level::INFO, "Defined {} syscalls", ans.len());
        ans
    };

}
    /** TODO: This fails to compile because libc doesn't define BPF_* for android
    pub static ref SECCOMP_PROGRAM: Vec<libc::sock_filter> = {
        if (SYSCALL_INFOS.len() > MAX_RAW_SYSCALL_INFOS) {
            panic!("Too many ptrace-eligible syscalls to fit in SECCOMP BPF filter");
        }

        let end_of_syscalls: u8 = (SYSCALL_INFOS.len() + 1) as u8;
        let mut program = Vec::new();
        program.push(libc::BPF_STMT(libc::BPF_LD + libc::BPF_W + libc::BPF_ABS, 2));
        SYSCALL_INFOS.keys().for_each(|num| unsafe {
            program.push(libc::BPF_JUMP(libc::BPF_JMP + libc::BPF_JEQ + libc::BPF_K, *num as u32, end_of_syscalls, 1));
        });
        program
    };
    */

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
