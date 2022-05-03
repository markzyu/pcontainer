// Make sure children of tracees are also traced.
use lazy_static::lazy_static;
use std::collections::HashSet;
use std::sync::Arc;
use sysaug::mods::{Mod, ModAction, ModFeature};
use sysaug::{SysAugError, TraceeHandlerStates};

lazy_static! {
    static ref DEFAULT_LISTENER_SPEC: HashSet<ModFeature> = {
        let mut ans = HashSet::new();
        ans.insert(ModFeature::OnSetuid);
        ans
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

    fn on_setuid(&self, uid: usize, _syscall: usize) -> Result<ModAction, SysAugError> {
        let mut maybe_uid = self
            .states
            .override_uid
            .write()
            .or(Err(SysAugError::LockTraceeHandler))?;
        maybe_uid.replace(uid);
        Ok(ModAction::SkipSyscall(0))
    }
}
