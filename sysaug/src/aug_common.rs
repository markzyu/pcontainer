use crate::common;
use crate::common::{SysAugError, SyscallInfo};
use crate::handler::TraceeHandler;
use crate::mods;
use crate::mods::PathAction;
use std::cell::RefCell;
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{event, Level};

// Common helper functions used by aug_*.rs
type HandlerArc<T> = Arc<TraceeHandler<T>>;

// Calculate real path of file based on its path in rootfs
pub fn calc_real_path_simple<T: executor::PtraceClient>(
    handler: &HandlerArc<T>,
    orig_path: &Path,
    syscall: &SyscallInfo,
) -> Result<PathAction, SysAugError> {
    let mut new_path = PathAction::None;
    let prefix_maybe = common::rwlock_read(&handler.states.path_prefix)?;
    if let Some(prefix) = prefix_maybe.as_ref() {
        if orig_path.is_absolute() {
            let val = prefix.as_path().join(orig_path.strip_prefix("/").unwrap());
            new_path = PathAction::Override(val);
        }
    }

    get_mod_path(handler, syscall, orig_path, new_path, false)
}

// Calculate real path of file + following symlinks that use fake paths
pub fn calc_real_path<T: executor::PtraceClient>(
    handler: &HandlerArc<T>,
    orig_path: &Path,
    syscall: &SyscallInfo,
) -> Result<PathAction, SysAugError> {
    let action = calc_real_path_simple(handler, orig_path, syscall)?;
    if let PathAction::Override(real_path) = &action {
        if let Ok(metadata) = std::fs::symlink_metadata(real_path) {
            if !metadata.file_type().is_symlink() {
                return Ok(action);
            }
            let link = real_path.read_link().map_err(SysAugError::ReadSymlink)?;
            if link.is_relative() {
                return Ok(action);
            }
            calc_real_path(handler, link.as_path(), syscall)
        } else {
            Ok(action)
        }
    } else {
        Ok(action)
    }
}

// Ask every mod to translate a path from rootfs point of view to real paths
// reverse: false = generating real paths on disk, true = generating fake paths from container
// perspective
pub fn get_mod_path<T: executor::PtraceClient>(
    handler: &HandlerArc<T>,
    syscall: &SyscallInfo,
    orig_path: &Path,
    initial_override: PathAction,
    reverse: bool,
) -> Result<PathAction, SysAugError> {
    let override_path: RefCell<PathAction> = RefCell::new(initial_override);
    let feature = if reverse {
        mods::ModFeature::OverrideFileFakePath
    } else {
        mods::ModFeature::OverrideFileRealPath
    };
    handler.call_mods(feature, |m| {
        let old_override = override_path.replace(PathAction::None);
        let curr_path = match &old_override {
            PathAction::Override(path) => path.as_path(),
            _ => orig_path,
        };
        let new_override = if reverse {
            m.override_file_fake_path(curr_path, syscall)?
        } else {
            m.override_file_real_path(curr_path, syscall)?
        };
        override_path.replace(if new_override == PathAction::None {
            old_override
        } else {
            new_override
        });
        Ok(mods::ModAction::None)
    })?;
    Ok(override_path.into_inner())
}

pub fn notify_mods_about_path<T: executor::PtraceClient>(
    handler: &HandlerArc<T>,
    syscall: &SyscallInfo,
    orig_path: &Path,
    path_action: &PathAction,
) -> Result<(), SysAugError> {
    handler.call_mods(mods::ModFeature::OnFilePath, |m| {
        m.on_file_path(orig_path, syscall)
    })?;
    let notify_path = match path_action {
        PathAction::Override(path) => path.as_path(),
        _ => orig_path,
    };
    event!(
        Level::DEBUG,
        "Translate {} -> {}",
        orig_path.to_string_lossy(),
        notify_path.to_string_lossy()
    );
    handler.call_mods(mods::ModFeature::OnFileRealPath, |m| {
        m.on_file_real_path(notify_path, syscall)
    })?;
    Ok(())
}

pub fn path_from_bytes(mut path_bytes: Vec<u8>) -> Result<PathBuf, SysAugError> {
    while path_bytes.last() == Some(&0) {
        path_bytes.pop();
    }
    let path_osstr: OsString = OsStringExt::from_vec(path_bytes);
    Ok(path_osstr.into())
}
