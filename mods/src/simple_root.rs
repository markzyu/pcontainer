// Make sure children of tracees are also traced.
use lazy_static::lazy_static;
use std::collections::HashSet;
use std::sync::Arc;
use sysaug::mods::{Mod, ModAction, ModFeature};
use sysaug::{rwoption_replace, SysAugError, SyscallInfo, TraceeHandlerStates};
use tracing::{event, Level};

lazy_static! {
    static ref DEFAULT_LISTENER_SPEC: HashSet<ModFeature> = {
        let mut ans = HashSet::new();
        ans.insert(ModFeature::OnTraceeStartup);
        ans.insert(ModFeature::OnSetuid);
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
        rwoption_replace(&self.states.override_uid, 0)?;
        rwoption_replace(&self.states.override_gid, 0)?;
        Ok(ModAction::None)
    }

    fn on_setuid(&self, _uid: usize, _syscall: &SyscallInfo) -> Result<ModAction, SysAugError> {
        event!(Level::INFO, "Skipping setuid");
        Ok(ModAction::SkipSyscall(0))
    }
}
