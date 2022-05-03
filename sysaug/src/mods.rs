/// See "../mods/src/lib.rs" for more details
use crate::common::SysAugError;
use lazy_static::lazy_static;
use std::collections::HashSet;
use std::path::Path;

#[derive(Clone, PartialEq, Eq, Hash)]
pub enum ModFeature {
    OnFilePath,
    OnChroot,
    OnCloneComplete,
}

lazy_static! {
    static ref DEFAULT_LISTENER_SPEC: HashSet<ModFeature> = HashSet::new();
}

pub trait Mod {
    fn on_init_tracee(&self) -> Result<(), SysAugError> {
        Ok(())
    }

    fn get_features(&self) -> &'static HashSet<ModFeature> {
        &*DEFAULT_LISTENER_SPEC
    }

    fn on_chroot(&self, _raw_path: &Path) -> Result<(), SysAugError> {
        Ok(())
    }

    fn on_clone_complete(&self, _raw_pid: isize) -> Result<(), SysAugError> {
        Ok(())
    }

    // Don't use this to override/change paths.
    // TraceeHandler should provide a setter for path_prefix.
    fn on_file_path(&self, _raw_path: &[u8]) -> Result<(), SysAugError> {
        Ok(())
    }

    fn clone_box(&self) -> Box<dyn Mod + Send + Sync>;
}
