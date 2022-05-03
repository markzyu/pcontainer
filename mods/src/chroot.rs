// Make sure children of tracees are also traced.
use lazy_static::lazy_static;
use std::collections::HashSet;
use std::sync::Arc;
use sysaug::mods::{Mod, ModAction, ModFeature};
use sysaug::{rwlock_replace, SysAugError, TraceeHandlerStates};

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
        Ok(ModAction::None)
    }
}
