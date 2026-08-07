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

use lazy_static::lazy_static;
use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use sysaug::mods::{Mod, ModAction, ModFeature};
use sysaug::{PermType, SysAugError, SyscallInfo, TraceeHandlerStates};

lazy_static! {
    static ref DEFAULT_LISTENER_SPEC: HashSet<ModFeature> = {
        let mut ans = HashSet::new();
        ans.insert(ModFeature::DeleteMetaDir);
        ans.insert(ModFeature::OnSetsPerms);
        ans.insert(ModFeature::ResolveMetadataPath);
        ans
    };
}

pub struct RootfsMod {
    states: Arc<TraceeHandlerStates>,
}

impl RootfsMod {
    pub fn new_box(states: Arc<TraceeHandlerStates>) -> Box<dyn Mod> {
        Box::new(RootfsMod { states })
    }
}

impl Mod for RootfsMod {
    fn clone_box(&self) -> Box<dyn Mod + Send + Sync> {
        Box::new(RootfsMod {
            states: Arc::clone(&self.states),
        })
    }

    fn get_features(&self) -> &'static HashSet<ModFeature> {
        &*DEFAULT_LISTENER_SPEC
    }

    fn resolve_metadata_path(&self, path: &Path) -> Result<Option<PathBuf>, SysAugError> {
        let args = &self.states.args;
        let rootfs = args
            .rootfs
            .as_ref()
            .or_else(|| args.chroot.as_ref())
            .unwrap();
        if rootfs == Path::new("/") {
            // If setting real root as chroot/rootfs, don't create metadata
            return Ok(None);
        }
        if !path.exists() {
            return Ok(None);
        }
        let canonical_path = path.canonicalize();
        if canonical_path.is_err() {
            return Ok(None);
        }
        let canonical_path_unwrap = canonical_path.unwrap();

        let mut metaname = rootfs.file_name().unwrap().to_os_string();
        metaname.push(".metadata");
        let mut metadir = rootfs.with_file_name(metaname);
        metadir.push("rootfs");

        let relative_path = canonical_path_unwrap.strip_prefix(rootfs);
        if relative_path.is_err() {
            return Ok(None);
        }
        let relative_path_unwrap = relative_path.unwrap();

        metadir.push("chld");
        for component in relative_path_unwrap.components() {
            if component == Component::CurDir {
                continue;
            }
            if component == Component::RootDir {
                continue;
            }
            if let Component::Normal(part) = component {
                metadir.push(part);
                metadir.push("chld");
            } else {
                return Ok(None);
            }
        }
        metadir.pop();
        Ok(Some(metadir.join("meta")))
    }

    fn delete_meta_dir(&self, path: &Path) -> Result<(), SysAugError> {
        if let Some(mut meta_path) = self.resolve_metadata_path(path)? {
            meta_path.pop();
            let _ = std::fs::remove_dir_all(meta_path);
        }
        Ok(())
    }

    fn on_sets_perms(&self, syscall: &SyscallInfo) -> Result<ModAction, SysAugError> {
        if syscall.sets_file_perms == Some(PermType::Chown) {
            return Ok(ModAction::SkipSyscall(0));
        }
        Ok(ModAction::None)
    }
}
