// Make sure children of tracees are also traced.
use lazy_static::lazy_static;
use std::collections::HashSet;
use std::sync::Arc;
use sysaug::mods::{Mod, ModFeature};
use sysaug::{SysAugError, TraceeHandlerStates};
use tracing::{event, Level};

lazy_static! {
    static ref DEFAULT_LISTENER_SPEC: HashSet<ModFeature> = {
        let mut ans = HashSet::new();
        ans.insert(ModFeature::OnCloneComplete);
        ans
    };
}

pub struct TraceChildMod {
    states: Arc<TraceeHandlerStates>,
}

impl TraceChildMod {
    pub fn new_box(states: Arc<TraceeHandlerStates>) -> Box<dyn Mod> {
        Box::new(TraceChildMod { states })
    }
}

impl Mod for TraceChildMod {
    fn clone_box(&self) -> Box<dyn Mod + Send + Sync> {
        Box::new(TraceChildMod {
            states: Arc::clone(&self.states),
        })
    }

    fn get_features(&self) -> &'static HashSet<ModFeature> {
        &*DEFAULT_LISTENER_SPEC
    }

    fn on_clone_complete(&self, child_pid: isize) -> Result<(), SysAugError> {
        event!(Level::INFO, "Clone pid {}", child_pid);
        Ok(())
    }
}
