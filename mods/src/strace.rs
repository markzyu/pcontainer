use lazy_static::lazy_static;
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use sysaug::mods::{Mod, ModAction, ModFeature};
use sysaug::{SysAugError, TraceeHandlerStates};
use tracing::{event, Level};

lazy_static! {
    static ref DEFAULT_LISTENER_SPEC: HashSet<ModFeature> = {
        let mut ans = HashSet::new();
        ans.insert(ModFeature::OnFilePath);
        ans.insert(ModFeature::OnFileRealPath);
        ans
    };
}

pub struct StraceMod {
    states: Arc<TraceeHandlerStates>,
}

impl StraceMod {
    pub fn new_box(states: Arc<TraceeHandlerStates>) -> Box<dyn Mod> {
        Box::new(StraceMod { states })
    }
}

impl Mod for StraceMod {
    fn clone_box(&self) -> Box<dyn Mod + Send + Sync> {
        Box::new(StraceMod {
            states: Arc::clone(&self.states),
        })
    }

    fn get_features(&self) -> &'static HashSet<ModFeature> {
        &*DEFAULT_LISTENER_SPEC
    }

    fn on_file_path(&self, path: &Path, syscall: usize) -> Result<ModAction, SysAugError> {
        if syscall == libc::SYS_execve as usize {
            event!(
                Level::INFO,
                "Execve pid {:?} input Path: {:?}",
                self.states.pid,
                path
            );
        } else {
            event!(Level::DEBUG, "Input Path: {:?}", path);
        }
        Ok(ModAction::None)
    }

    fn on_file_real_path(&self, path: &Path, syscall: usize) -> Result<ModAction, SysAugError> {
        if syscall == libc::SYS_execve as usize {
            event!(
                Level::INFO,
                "Execve pid {:?} real Path: {:?}",
                self.states.pid,
                path
            );
        } else {
            event!(Level::DEBUG, "Real Path: {:?}", path);
        }
        Ok(ModAction::None)
    }
}
