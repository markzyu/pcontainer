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

use crate::common;
use crate::common::{PathAction, SysAugError, SyscallInfo};
use crate::handler::AsyncTraceeHandler;
use std::cell::RefCell;
use std::collections::HashSet;
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};
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
                return Box::pin(self.calc_real_path_recurse(
                    link.as_path(),
                    syscall,
                    visited,
                    args,
                ))
                .await;
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
        self.calc_real_path_recurse(orig_path, syscall, HashSet::new(), args)
            .await
    }

    // There are SysAugConfig configurations that can "modify" a guest/host path. This function applies them.
    // reverse: false = generating real paths on disk, true = generating fake paths from container
    // perspective
    pub async fn get_mod_path(
        &self,
        syscall: &SyscallInfo,
        orig_path: &Path,
        initial_override: PathAction,
        reverse: bool,
    ) -> Result<PathAction, SysAugError> {
        let rename_map = if reverse {
            &self.states.config.rootfs.rename_guest_paths
        } else {
            &self.states.config.rootfs.rename_host_paths
        };
        for config in rename_map {
            let bytes_str = orig_path.as_os_str().as_encoded_bytes();
            if config.regex.is_match(bytes_str) {
                let Some(ref replacement) = config.replacement else {
                    return Ok(PathAction::HidePath);
                };
                let replacement_bytes = replacement.as_bytes();
                let replacement = if config.should_replace_all {
                    config.regex.replace_all(bytes_str, replacement_bytes)
                } else {
                    config.regex.replace(bytes_str, replacement_bytes)
                };
                let os_str = OsString::from_vec(replacement.into());
                return Ok(PathAction::Override(os_str.into()));
            }
        }
        Ok(PathAction::None)
    }

    pub fn path_from_bytes(mut path_bytes: Vec<u8>) -> Result<PathBuf, SysAugError> {
        while path_bytes.last() == Some(&0) {
            path_bytes.pop();
        }
        let path_osstr: OsString = OsStringExt::from_vec(path_bytes);
        Ok(path_osstr.into())
    }
}
