// Make sure children of tracees are also traced.
use lazy_static::lazy_static;
use std::collections::HashSet;
use std::convert::TryInto;
use std::sync::Arc;
use sysaug::mods::{Mod, ModFeature};
use sysaug::{display_err, SysAugError, TraceeHandler};
use tracing::{event, Level};

lazy_static! {
    static ref DEFAULT_LISTENER_SPEC: HashSet<ModFeature> = {
        let mut ans = HashSet::new();
        ans.insert(ModFeature::OnCloneComplete);
        ans
    };
}

pub struct TraceChildMod {
    handler: Arc<TraceeHandler>,
}

impl TraceChildMod {
    pub fn new_box(handler: Arc<TraceeHandler>) -> Box<dyn Mod> {
        Box::new(TraceChildMod { handler })
    }
}

impl Mod for TraceChildMod {
    fn clone_box(&self) -> Box<dyn Mod + Send + Sync> {
        Box::new(TraceChildMod {
            handler: Arc::clone(&self.handler),
        })
    }

    fn get_features(&self) -> &'static HashSet<ModFeature> {
        &*DEFAULT_LISTENER_SPEC
    }

    fn on_clone_complete(&self, raw_pid: isize) -> Result<(), SysAugError> {
        if raw_pid > 0 {
            let child_pid: nix::unistd::Pid =
                nix::unistd::Pid::from_raw(raw_pid.try_into().or(Err(SysAugError::IntoInt))?);
            event!(Level::INFO, "Clone pid {}", child_pid);

            let new_tracee_handler = self.handler.fork(child_pid)?;
            std::thread::spawn(move || {
                new_tracee_handler
                    .event_loop()
                    .map_err(display_err)
                    .unwrap();
            });
        }
        Ok(())
    }
}
