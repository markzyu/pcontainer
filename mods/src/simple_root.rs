// Make sure children of tracees are also traced.
use lazy_static::lazy_static;
use std::collections::HashSet;
use std::sync::Arc;
use sysaug::mods::{Mod, ModAction, ModFeature};
use sysaug::{
    rwoptions_replace, rwoptions_setdefault, SysAugError, SyscallInfo, TraceeHandlerStates,
};
use tracing::{event, Level};

lazy_static! {
    static ref DEFAULT_LISTENER_SPEC: HashSet<ModFeature> = {
        let mut ans = HashSet::new();
        ans.insert(ModFeature::OnTraceeStartup);
        ans.insert(ModFeature::OnSetid);
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
        rwoptions_setdefault!(&self.states.perms_ids, 19, 0);
        rwoptions_setdefault!(&self.states.perms_ids, 18, 0);
        rwoptions_setdefault!(&self.states.perms_ids, 17, 0);
        rwoptions_setdefault!(&self.states.perms_ids, 3, 0);
        rwoptions_setdefault!(&self.states.perms_ids, 2, 0);
        rwoptions_setdefault!(&self.states.perms_ids, 1, 0);
        Ok(ModAction::None)
    }

    fn on_setid(
        &self,
        which: u8,
        uid: usize,
        syscall: &SyscallInfo,
    ) -> Result<ModAction, SysAugError> {
        if uid as i32 == -1 {
            if syscall.res_bits != 0 {
                // These system calls ignore setting -1 as id
                return Ok(ModAction::SkipSyscall(0));
            } else {
                // Otherwise, system call fails
                return Ok(ModAction::SkipSyscall((-libc::EINVAL) as usize));
            }
        }
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
