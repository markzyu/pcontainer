use lazy_static::lazy_static;
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use sysaug::mods::{Mod, ModFeature};
use sysaug::{SysAugError, TraceeHandler};
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
    handler: Arc<TraceeHandler>,
}

impl StraceMod {
    pub fn new_box(handler: Arc<TraceeHandler>) -> Box<dyn Mod> {
        Box::new(StraceMod { handler })
    }
}

impl Mod for StraceMod {
    fn clone_box(&self) -> Box<dyn Mod + Send + Sync> {
        Box::new(StraceMod {
            handler: Arc::clone(&self.handler),
        })
    }

    fn get_features(&self) -> &'static HashSet<ModFeature> {
        &*DEFAULT_LISTENER_SPEC
    }

    fn on_file_path(&self, path: &Path) -> Result<(), SysAugError> {
        event!(Level::INFO, "Input Path: {:?}", path,);
        Ok(())
    }

    fn on_file_real_path(&self, path: &Path) -> Result<(), SysAugError> {
        event!(Level::INFO, "Real Path: {:?}", path,);
        Ok(())
    }
}
