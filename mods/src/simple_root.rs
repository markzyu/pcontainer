// Make sure children of tracees are also traced.
use lazy_static::lazy_static;
use std::collections::HashSet;
use std::sync::Arc;
use sysaug::mods::{Mod, ModAction, ModFeature};
use sysaug::{SysAugError, TraceeHandlerStates};

lazy_static! {
    static ref DEFAULT_LISTENER_SPEC: HashSet<ModFeature> = {
        let mut ans = HashSet::new();
        ans.insert(ModFeature::OnTraceeStartup);
        ans
    };
}

pub struct SimpleRootMod {
    states: Arc<TraceeHandlerStates>,
}

impl SimpleRootMod {
    pub fn new_box(states: Arc<TraceeHandlerStates>) -> Box<dyn Mod> {
        Box::new(SimpleRootMod { states })
    }

    fn setuid(&self, uid: usize) -> Result<(), SysAugError> {
        let mut maybe_uid = self
            .states
            .override_uid
            .write()
            .or(Err(SysAugError::LockTraceeHandler))?;
        maybe_uid.replace(uid);
        Ok(())
    }
}

impl Mod for SimpleRootMod {
    fn clone_box(&self) -> Box<dyn Mod + Send + Sync> {
        Box::new(SimpleRootMod {
            states: Arc::clone(&self.states),
        })
    }

    fn get_features(&self) -> &'static HashSet<ModFeature> {
        &*DEFAULT_LISTENER_SPEC
    }

    fn on_tracee_startup(&self) -> Result<ModAction, SysAugError> {
        self.setuid(0)?;
        Ok(ModAction::None)
    }
}
