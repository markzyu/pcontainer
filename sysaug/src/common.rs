use crate::handler::TraceeHandlerStates;
use crate::mods;
use ptrace::GenericPurposeRegs;
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

    #[error("Internal error, Invalid TraceeInitStage: {0}")]
    BadInitStage(u8),

    #[error("Internal error, tracee initializing but missing original regs")]
    InitMissingSavedRegs,
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

pub trait AugmentSyscall {
    fn before_call(
        &self,
        regs: GenericPurposeRegs,
        syscall: &SyscallInfo,
    ) -> Result<(), SysAugError>;
    fn after_call(
        &self,
        regs: GenericPurposeRegs,
        syscall: &SyscallInfo,
    ) -> Result<(), SysAugError>;

    fn dispatch(
        &self,
        last_syscall: &SyscallCounter,
        regs: GenericPurposeRegs,
    ) -> Result<(), SysAugError> {
        let syscall_info = last_syscall.syscall_info.unwrap();
        if last_syscall.times % 2 == 1 {
            self.before_call(regs, syscall_info)
        } else {
            self.after_call(regs, syscall_info)
        }
    }
}

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

#[derive(Debug)]
pub struct SyscallCounter {
    pub syscall: Option<usize>,
    pub syscall_info: Option<&'static SyscallInfo>,
    pub times: u64,
    pub total_times: u64,
}

impl SyscallCounter {
    pub fn count(&mut self, syscall_name: usize, syscall_info: Option<&'static SyscallInfo>) {
        let curr_syscall = Some(syscall_name);
        if self.syscall != curr_syscall {
            self.syscall = curr_syscall;
            self.syscall_info = syscall_info;
            self.times = 1;
        } else {
            self.times += 1;
        }
        self.total_times += 1;
    }

    pub fn new() -> SyscallCounter {
        SyscallCounter {
            syscall: None,
            syscall_info: None,
            times: 0,
            total_times: 0,
        }
    }
}

// pub const PERMS_IDBIT_R: u8 = 1;
// pub const PERMS_IDBIT_E: u8 = 2;
// pub const PERMS_IDBIT_S: u8 = 4;
// pub const PERMS_IDBIT_F: u8 = 8;
/// True = uid, False = gid.
pub const PERMS_IDBIT_UG: u8 = 16;
pub const PERMS_IDS_SIZE: usize = 32;

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
    /// 0 -> see resf_bit, 3 -> reuid/regid, 7 -> resuid/resgid
    ///     + check PERMS_IDBIT_UG for uid/gid
    pub res_bits: u8,
    /// 2 -> gid, 24 -> fsuid
    pub resf_bit: u8,

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
