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

// Make sure children of tracees are also traced.
use lazy_static::lazy_static;
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use sysaug::mods::{Mod, ModAction, ModFeature};
use sysaug::{rwoptions_replace, SysAugError, SyscallInfo, TraceeHandlerStates};
use tracing::{event, Level};

lazy_static! {
    static ref DEFAULT_LISTENER_SPEC: HashSet<ModFeature> = {
        let mut ans = HashSet::new();
        ans.insert(ModFeature::OnFileRealPath);
        ans.insert(ModFeature::OnSetid);
        ans
    };
}

macro_rules! exec_setid {
    ($perms_ids:expr, $which:expr, $path:expr, $id: expr) => {
        event!(
            Level::INFO,
            "Execve real path: {:?} set {} to {:?}",
            $path,
            $which,
            $id,
        );
        rwoptions_replace!(&$perms_ids, $which as usize, $id as usize);
    };
}

pub struct PermsMod {
    states: Arc<TraceeHandlerStates>,
}

impl PermsMod {
    pub fn new_box(states: Arc<TraceeHandlerStates>) -> Box<dyn Mod> {
        Box::new(PermsMod { states })
    }
}

impl Mod for PermsMod {
    fn clone_box(&self) -> Box<dyn Mod + Send + Sync> {
        Box::new(PermsMod {
            states: Arc::clone(&self.states),
        })
    }

    fn get_features(&self) -> &'static HashSet<ModFeature> {
        &*DEFAULT_LISTENER_SPEC
    }

    fn on_file_real_path(
        &self,
        path: &Path,
        syscall: &SyscallInfo,
    ) -> Result<ModAction, SysAugError> {
        if syscall.num == libc::SYS_execve {
            if let Ok(stat) = nix::sys::stat::stat(path) {
                let setuid = stat.st_mode & nix::sys::stat::Mode::S_ISUID.bits();
                let setgid = stat.st_mode & nix::sys::stat::Mode::S_ISGID.bits();
                if setuid != 0 {
                    exec_setid!(self.states.perms_ids, 18, path, stat.st_uid);
                }
                if setgid != 0 {
                    exec_setid!(self.states.perms_ids, 2, path, stat.st_gid);
                }
            }
        }
        Ok(ModAction::None)
    }

    fn on_setid(
        &self,
        which: u8,
        uid: usize,
        _syscall: &SyscallInfo,
    ) -> Result<ModAction, SysAugError> {
        event!(
            Level::INFO,
            "Setting {:b} id to {}",
            which,
            uid as libc::uid_t
        );
        rwoptions_replace!(&self.states.perms_ids, which as usize, uid);
        Ok(ModAction::SkipSyscall(0))
    }
}
