use crate::common;
use crate::common::{SysAugError, SyscallInfo};
use crate::handler::AsyncTraceeHandler;
use crate::mods;
use crate::mods::PathAction;
use std::cell::RefCell;
use std::collections::HashSet;
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{event, Level};

// Common helper functions used by aug_*.rs
// Calculate real path of file based on its path in rootfs
impl<PtraceClient: executor::PtraceClient> AsyncTraceeHandler<'_, PtraceClient> {

pub async fn calc_real_path_simple(
    &self,
    orig_path: &Path,
    syscall: &SyscallInfo,
) -> Result<PathAction, SysAugError> {
    let mut new_path = PathAction::None;
    let prefix_maybe = common::rwlock_read(&self.states.path_prefix)?;
    let exclude_list = common::rwlock_read(&self.states.path_prefix_excludes)?;
    if !exclude_list.iter().any(|x| orig_path.starts_with(x)) {
        if let Some(prefix) = prefix_maybe.as_ref() {
            if orig_path.is_absolute() {
                let val = prefix.as_path().join(orig_path.strip_prefix("/").unwrap());
                new_path = PathAction::Override(val);
            }
        }
    }

    self.get_mod_path(syscall, orig_path, new_path, false).await
}

// Calculate real path of file + following symlinks that use fake paths
pub async fn calc_real_path_recurse(
    &self,
    orig_path: &Path,
    syscall: &SyscallInfo,
    mut visited: HashSet<PathBuf>,
    args: &[usize],
) -> Result<PathAction, SysAugError> {
    event!(Level::DEBUG, "Following symlink {:?}", orig_path);
    visited.insert(orig_path.into());
    let action = self.calc_real_path_simple(orig_path, syscall).await?;
    if let PathAction::Override(real_path) = &action {
        if syscall.dont_follow_symlink {
            return Ok(action);
        } else if let (Some(flag), Some(flag_reg)) =
            (syscall.flag_dont_follow_symlink, syscall.flags)
        {
            if args[flag_reg] | flag != 0 {
                return Ok(action);
            }
        }
        if let Ok(metadata) = std::fs::symlink_metadata(real_path) {
            if !metadata.file_type().is_symlink() {
                return Ok(action);
            }
            let link = real_path.read_link().map_err(SysAugError::ReadSymlink)?;
            if link.is_relative() {
                return Ok(action);
            }
            if visited.contains(&link) {
                return Ok(PathAction::ELOOP);
            }
            return Box::pin(self.calc_real_path_recurse(link.as_path(), syscall, visited, args)).await;
        }
    }
    Ok(action)
}

// Same as calc_real_path_recurse
pub async fn calc_real_path(
    &self,
    orig_path: &Path,
    syscall: &SyscallInfo,
    args: &[usize],
) -> Result<PathAction, SysAugError> {
    self.calc_real_path_recurse(orig_path, syscall, HashSet::new(), args).await
}

// Ask every mod to translate a path from rootfs point of view to real paths
// reverse: false = generating real paths on disk, true = generating fake paths from container
// perspective
pub async fn get_mod_path(
    &self,
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
    self.call_mods(feature, |m| {
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
    }).await?;
    Ok(override_path.into_inner())
}

pub async fn notify_mods_about_path(
    &self,
    syscall: &SyscallInfo,
    orig_path: &Path,
    path_action: &PathAction,
) -> Result<(), SysAugError> {
    self.call_mods(mods::ModFeature::OnFilePath, |m| {
        m.on_file_path(orig_path, syscall)
    }).await?;
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
    self.call_mods(mods::ModFeature::OnFileRealPath, |m| {
        m.on_file_real_path(notify_path, syscall)
    }).await?;
    Ok(())
}

pub fn path_from_bytes(mut path_bytes: Vec<u8>) -> Result<PathBuf, SysAugError> {
    while path_bytes.last() == Some(&0) {
        path_bytes.pop();
    }
    let path_osstr: OsString = OsStringExt::from_vec(path_bytes);
    Ok(path_osstr.into())
}

}
