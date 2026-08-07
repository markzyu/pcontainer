// Copyright 2026 Zhongzhi Yu <7296488+markzyu@users.noreply.github.com>
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

use crate::handler::TraceeHandlerStates;
use crate::mods;
use executor::{PtraceFutureTypes, PtraceStatus};
use std::collections::HashMap;
use std::fmt::Display;
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use thiserror::Error;
use tracing::{event, Level};

#[derive(Debug, Error)]
pub enum SysAugError {
    #[error("Unexpected internal error from ptrace() executor: {0}")]
    InternalExecutor(#[from] executor::PtraceExecutorError),

    #[error("Failed to parse waitpid result: {0}")]
    ParseWaitStatus(nix::Error),

    #[error("Procfs error: {0}")]
    Procfs(#[from] procfs::ProcfsError),

    #[error("Ptrace error: {0}")]
    Ptrace(#[from] ptrace::PtraceError),

    #[error("PTRACE_DETACH error")]
    PtraceDetach(nix::Error),

    #[error("PTRACE_GETSIGINFO error")]
    PtraceGetSigInfo,

    #[error("PTRACE_GETSIGINFO error: {0}")]
    PtraceGetSigInfo2(nix::Error),

    #[error("PTRACE_PEEKDATA error: {0}")]
    PtraceRead(nix::Error),

    #[error("PTRACE_SETOPTIONS error: {0}")]
    PtraceSetOptions(nix::Error),

    #[error("PTRACE_SYSCALL error: {0}")]
    PtraceSyscall(nix::Error),

    #[error("Not a valid absolute path: {0}")]
    AbsolutePath(std::path::PathBuf),

    #[error("Cannot convert to absolute path: {0}")]
    ConvertAbsolutePath(std::io::Error),

    #[error("Cannot convert to absolute path: prefix did not match chroot path")]
    ConvertAbsolutePathPrefix,

    #[error("Unable to find tracee's dirfd directory")]
    DirfdReg,

    #[error("Unable to detach tracee for gdb to attach: {0}")]
    GDBDetach(nix::Error),

    #[error("Unable to run gdb: {0}")]
    GDB(std::io::Error),

    #[error("Interger conversion error")]
    IntoInt,

    #[error("Cannot list metadata files in folder, because: {0}")]
    ListMetadata(std::io::Error),

    #[error("Cannot lock/unlock tracee handler")]
    LockTraceeHandler,

    #[error("Tracee process exited/crashed unexpectedly")]
    TraceeCrashed,

    #[error("Failed to write metadata: {0}")]
    WriteMetadata(String),

    #[error("Failed to create .metadata folder: {0}")]
    MetadataDir(std::io::Error),

    #[error("Failed to delete metadata: {0}")]
    DeleteMetadata(std::io::Error),

    #[error("Unexpected null value for {0}")]
    NullValue(String),

    #[error("Unimplemented system call")]
    UnimplementedAugment,

    #[error("Unable to read binary file: {0}")]
    ReadBin(std::io::Error),

    #[error("Unable to read symlink: {0}")]
    ReadSymlink(std::io::Error),

    #[error("{kind} error from '{mod_name}' mod: {message}")]
    Mod {
        kind: String,
        message: String,
        mod_name: String,
    },

    #[error("Internal error, tracee initializing but missing original regs")]
    InitMissingSavedRegs,

    #[error(
        "Internal error, ptrace async executor unblocked without correct status: {0:?} vs {1:?}"
    )]
    AsyncMismatch(PtraceFutureTypes, PtraceStatus),

    #[error("Internal error, weak reference is no longer valid")]
    WeakReference,
}

// ------------------- MODS -------------------

pub type ModProvider = fn(Arc<TraceeHandlerStates>) -> Box<dyn mods::Mod>;
pub type ModBox = Box<dyn mods::Mod + Send + Sync>;
pub type ModsByFeature = HashMap<mods::ModFeature, Vec<ModBox>>;

#[allow(dead_code)]
pub fn clone_mods_by_feature(src: &ModsByFeature) -> ModsByFeature {
    let mut ans: ModsByFeature = HashMap::new();
    for (feature, arr) in src.iter() {
        let mut arr2 = Vec::new();
        for m in arr.iter() {
            arr2.push(m.clone_box());
        }
        ans.insert(feature.clone(), arr2);
    }
    ans
}

// ------------------- AUGMENTS -------------------

#[derive(Debug, PartialEq)]
pub enum Augments {
    Clone,
    Exec,
    Paths,
    Perms,
    Waitpid,
    None,
    Unimplemented,
}

impl Default for Augments {
    fn default() -> Augments {
        Augments::None
    }
}

// ------------------- SYSCALLS -------------------

#[derive(Debug, PartialEq)]
pub enum DelType {
    File,
    Dir,
}

#[derive(Debug, PartialEq)]
pub enum PermType {
    Chmod,
    Chown,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum PermsMode {
    #[default]
    Passthrough,
    RootOnly,
    SudoOnly,
}

#[derive(Debug, Default)]
pub struct SyscallInfo {
    /// The type of augment that will handle this syscall
    pub augment: Augments,
    /// The syscall argument that stores flags like AT_SYMLINK_NOFOLLOW
    pub flags: Option<usize>,

    /// Bitwise representation. Bit0: arg0 is path. Bit1 = arg1 ...
    pub path_positions: usize,
    pub dirfd_position: Option<u8>,
    pub dirfd_precedes_path: bool,
    pub getdents_bits: Option<u8>,
    pub sets_file_perms: Option<PermType>,
    pub deletion_type: Option<DelType>,
    pub dont_follow_symlink: bool,
    pub flag_dont_follow_symlink: Option<usize>,

    /// true -> setuid/setgid, false -> getuid/getgid
    pub is_setter: bool,
    /// a bitmask of Real/Effective/SavedSet/FileSystem/IsUid flags (from 0 to 31). One call can set multiple flags at once.
    pub res_bits: u8,
    /// the direct index of the perms_ids slot (from 0 to 8: rgid, egid, ssgid, fsgid, ruid, euid, ssuid, fsuid)
    pub resf_bit: Option<u8>,

    pub num: libc::c_long,
    pub name: &'static str,
}

impl SyscallInfo {
    pub fn name(&self) -> &str {
        &self.name[10..]
    }
}

// We promise not to modify this system call
pub const NO_MOD_SYSCALL: usize = libc::SYS_getpid as usize;

// ------------------- MISC -------------------

pub fn display_err<E: Display>(e: E) -> E {
    event!(Level::ERROR, "Error: {}", e);
    e
}

pub fn rwlock_read<T>(lock: &RwLock<T>) -> Result<RwLockReadGuard<'_, T>, SysAugError> {
    lock.read().or(Err(SysAugError::LockTraceeHandler))
}

pub fn rwlock_write<T>(lock: &RwLock<T>) -> Result<RwLockWriteGuard<'_, T>, SysAugError> {
    lock.write().or(Err(SysAugError::LockTraceeHandler))
}

pub fn rwlock_replace<T>(lock: &RwLock<T>, val: T) -> Result<(), SysAugError> {
    let mut guard = rwlock_write(lock)?;
    *guard = val;
    Ok(())
}

pub fn rwoption_replace<T>(lock: &RwLock<Option<T>>, val: T) -> Result<Option<T>, SysAugError> {
    let mut guard = rwlock_write(lock)?;
    Ok(guard.replace(val))
}

pub fn rwoption_setdefault<T>(lock: &RwLock<Option<T>>, val: T) -> Result<(), SysAugError> {
    let mut guard = rwlock_write(lock)?;
    if guard.is_none() {
        guard.replace(val);
    }
    Ok(())
}

pub fn rwoption_take<T>(lock: &RwLock<Option<T>>) -> Result<Option<T>, SysAugError> {
    let mut guard = rwlock_write(lock)?;
    Ok(guard.take())
}

#[macro_export]
macro_rules! rwoptions_replace {
    ($name:expr, $idx:expr, $val:expr) => {{
        $name.write().or(Err(SysAugError::LockTraceeHandler))?[$idx].replace($val)
    }};
}

#[macro_export]
macro_rules! rwoptions_setdefault {
    ($name:expr, $idx:expr, $val:expr) => {{
        let mut guard = $name.write().or(Err(SysAugError::LockTraceeHandler))?;
        if guard[$idx].is_none() {
            guard[$idx].replace($val);
        }
    }};
}

#[macro_export]
macro_rules! rwoption_take_ok {
    ($name:expr) => {
        crate::common::rwoption_take(&$name)?
            .ok_or(SysAugError::NullValue(stringify!($name).to_string()))
    };
}
