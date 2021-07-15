/// See "../mods/src/lib.rs" for more details
use crate::common::SysAugError;
use lazy_static::lazy_static;
use std::collections::HashSet;
use std::path::Path;

#[derive(Clone, PartialEq, Eq, Hash)]
pub enum ModFeature {
    OnFilePath,
    OnFileRealPath,
    OnChroot,
    OnCloneComplete,
    OnSetuid,
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
    fn on_init_tracee(&self) -> Result<ModAction, SysAugError> {
        Ok(ModAction::None)
    }

    fn get_features(&self) -> &'static HashSet<ModFeature> {
        &*DEFAULT_LISTENER_SPEC
    }

    fn on_chroot(&self, _raw_path: &Path) -> Result<ModAction, SysAugError> {
        Ok(ModAction::None)
    }

    fn on_clone_complete(&self, _raw_pid: isize) -> Result<ModAction, SysAugError> {
        Ok(ModAction::None)
    }

    // Don't use this to override/change paths.
    // Instead, set TraceeHandlerStates.path_prefix
    fn on_file_path(&self, _raw_path: &Path, _syscall: usize) -> Result<ModAction, SysAugError> {
        Ok(ModAction::None)
    }

    // Don't use this to override/change paths.
    // Instead, set TraceeHandlerStates.path_prefix
    fn on_file_real_path(
        &self,
        _raw_path: &Path,
        _syscall: usize,
    ) -> Result<ModAction, SysAugError> {
        Ok(ModAction::None)
    }

    fn on_setuid(&self, _uid: usize, _syscall: usize) -> Result<ModAction, SysAugError> {
        Ok(ModAction::None)
    }

    fn clone_box(&self) -> Box<dyn Mod + Send + Sync>;
}
