/// See "../mods/src/lib.rs" for more details
use crate::common::{SysAugError, SyscallInfo};
use lazy_static::lazy_static;
use std::any::type_name;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[derive(Clone, PartialEq, Eq, Hash)]
pub enum ModFeature {
    OnFilePath,
    OnFileRealPath,
    OnChroot,
    OnCloneComplete,
    OnSetuid,
    OnTraceeStartup,
    OverrideFileFakePath,
    OverrideFileRealPath,
    ResolveMetadataPath,
}

#[derive(Debug, PartialEq)]
pub enum PathAction {
    None,
    HidePath,
    Override(PathBuf),
}

pub enum ModAction {
    // Skip current syscall and return {0}
    SkipSyscall(usize),

    // No need to do anything
    None,
}

lazy_static! {
    static ref DEFAULT_LISTENER_SPEC: HashSet<ModFeature> = HashSet::new();
}

pub trait Mod {
    fn err(&self, kind: &str, msg: &str) -> SysAugError {
        SysAugError::Mod {
            kind: kind.into(),
            message: msg.into(),
            mod_name: type_name::<Self>().to_string(),
        }
    }

    fn on_init_tracee(&self) -> Result<ModAction, SysAugError> {
        Ok(ModAction::None)
    }

    fn get_features(&self) -> &'static HashSet<ModFeature> {
        &*DEFAULT_LISTENER_SPEC
    }

    // Return None if we don't want to keep metadata around for a specific path
    fn resolve_metadata_path(
        &self,
        _path: &Path,
        _dirfd_path: &Path,
    ) -> Result<Option<PathBuf>, SysAugError> {
        Ok(None)
    }

    fn on_chroot(&self, _raw_path: &Path) -> Result<ModAction, SysAugError> {
        Ok(ModAction::None)
    }

    fn on_clone_complete(&self, _raw_pid: isize) -> Result<ModAction, SysAugError> {
        Ok(ModAction::None)
    }

    // Don't use this to override/change paths.
    // Instead, set TraceeHandlerStates.path_prefix, or use override_file_real_path
    fn on_file_path(
        &self,
        _raw_path: &Path,
        _syscall: &SyscallInfo,
    ) -> Result<ModAction, SysAugError> {
        Ok(ModAction::None)
    }

    // Don't use this to override/change paths.
    // Instead, set TraceeHandlerStates.path_prefix, or use override_file_real_path
    fn on_file_real_path(
        &self,
        _raw_path: &Path,
        _syscall: &SyscallInfo,
    ) -> Result<ModAction, SysAugError> {
        Ok(ModAction::None)
    }

    fn override_file_real_path(
        &self,
        _curr_path: &Path,
        _syscall: &SyscallInfo,
    ) -> Result<PathAction, SysAugError> {
        Ok(PathAction::None)
    }

    fn override_file_fake_path(
        &self,
        _curr_path: &Path,
        _syscall: &SyscallInfo,
    ) -> Result<PathAction, SysAugError> {
        Ok(PathAction::None)
    }

    fn on_setuid(&self, _uid: usize, _syscall: &SyscallInfo) -> Result<ModAction, SysAugError> {
        Ok(ModAction::None)
    }

    fn on_tracee_startup(&self) -> Result<ModAction, SysAugError> {
        Ok(ModAction::None)
    }

    fn clone_box(&self) -> Box<dyn Mod + Send + Sync>;
}
