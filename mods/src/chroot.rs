// Make sure children of tracees are also traced.
use lazy_static::lazy_static;
use std::collections::HashSet;
use std::sync::Arc;
use sysaug::mods::{Mod, ModFeature};
use sysaug::TraceeHandlerStates;

lazy_static! {
    static ref DEFAULT_LISTENER_SPEC: HashSet<ModFeature> = {
        let ans = HashSet::new();
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
}
