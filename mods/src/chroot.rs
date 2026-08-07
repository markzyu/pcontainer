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
use std::sync::Arc;
use sysaug::mods::{Mod, ModAction, ModFeature};
use sysaug::{rwlock_replace, rwlock_write, SysAugError, TraceeHandlerStates};

lazy_static! {
    static ref DEFAULT_LISTENER_SPEC: HashSet<ModFeature> = {
        let mut ans = HashSet::new();
        ans.insert(ModFeature::OnTraceeStartup);
        ans
    };
}

pub struct ChrootMod {
    states: Arc<TraceeHandlerStates>,
}

impl ChrootMod {
    pub fn new_box(states: Arc<TraceeHandlerStates>) -> Box<dyn Mod> {
        Box::new(ChrootMod { states })
    }
}

impl Mod for ChrootMod {
    fn clone_box(&self) -> Box<dyn Mod + Send + Sync> {
        Box::new(ChrootMod {
            states: Arc::clone(&self.states),
        })
    }

    fn get_features(&self) -> &'static HashSet<ModFeature> {
        &*DEFAULT_LISTENER_SPEC
    }

    fn on_tracee_startup(&self) -> Result<ModAction, SysAugError> {
        rwlock_replace(&self.states.path_prefix, self.states.args.chroot.clone())?;
        let mut excludes = rwlock_write(&self.states.path_prefix_excludes)?;
        // Linux systems require real versions of the following files
        excludes.push("/dev".into());
        excludes.push("/proc".into());
        excludes.push("/sys".into());

        // Android systems require real versions of the following files
        excludes.push("/system/lib64".into());
        excludes.push("/system/lib".into());
        Ok(ModAction::None)
    }
}
