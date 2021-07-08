// Make sure children of tracees are also traced.
use lazy_static::lazy_static;
use std::collections::HashSet;
use std::sync::Arc;
use sysaug::mods::{Mod, ModFeature};
use sysaug::{SysAugError, TraceeHandler};
use tracing::{event, Level};

lazy_static! {
    static ref DEFAULT_LISTENER_SPEC: HashSet<ModFeature> = {
        let mut ans = HashSet::new();
        ans.insert(ModFeature::OnFilePath);
        ans
    };
}

pub struct ChrootMod {
    handler: Arc<TraceeHandler>,
}

impl ChrootMod {
    pub fn new_box(handler: Arc<TraceeHandler>) -> Box<dyn Mod> {
        Box::new(ChrootMod { handler })
    }
}

impl Mod for ChrootMod {
    fn clone_box(&self) -> Box<dyn Mod + Send + Sync> {
        Box::new(ChrootMod {
            handler: Arc::clone(&self.handler),
        })
    }

    fn get_features(&self) -> &'static HashSet<ModFeature> {
        &*DEFAULT_LISTENER_SPEC
    }

    fn on_file_path(&self, raw_path: &[u8]) -> Result<(), SysAugError> {
        event!(
            Level::INFO,
            "Input Path: {:?}",
            String::from_utf8_lossy(raw_path)
        );
        Ok(())
    }
}
