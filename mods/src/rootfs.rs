use lazy_static::lazy_static;
use std::collections::HashSet;
use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use sysaug::mods::{Mod, ModFeature, PathAction};
use sysaug::{SysAugError, TraceeHandlerStates};

lazy_static! {
    static ref DEFAULT_LISTENER_SPEC: HashSet<ModFeature> = {
        let mut ans = HashSet::new();
        ans.insert(ModFeature::OnTraceeStartup);
        ans.insert(ModFeature::OverrideFileRealPath);
        ans.insert(ModFeature::OverrideFileFakePath);
        ans.insert(ModFeature::ResolveMetadataPath);
        ans
    };
}

pub struct RootfsMod {
    states: Arc<TraceeHandlerStates>,
}

impl RootfsMod {
    pub fn new_box(states: Arc<TraceeHandlerStates>) -> Box<dyn Mod> {
        Box::new(RootfsMod { states })
    }

    fn map_components(
        &self,
        path: &Path,
        mapper: fn(&[u8]) -> PathAction,
    ) -> Result<PathAction, SysAugError> {
        let mut buf = PathBuf::new();
        let mut changed = false;
        for component in path.components() {
            let result = mapper(component.as_os_str().as_bytes());
            match result {
                PathAction::Override(override_path) => {
                    buf.push(override_path);
                    changed = true;
                }
                PathAction::HidePath => return Ok(PathAction::HidePath),
                PathAction::None => {
                    buf.push(component);
                }
            }
        }
        if changed {
            Ok(PathAction::Override(buf))
        } else {
            Ok(PathAction::None)
        }
    }
}

impl Mod for RootfsMod {
    fn clone_box(&self) -> Box<dyn Mod + Send + Sync> {
        Box::new(RootfsMod {
            states: Arc::clone(&self.states),
        })
    }

    fn get_features(&self) -> &'static HashSet<ModFeature> {
        &*DEFAULT_LISTENER_SPEC
    }

    fn override_file_real_path(
        &self,
        curr_path: &Path,
        _syscall: usize,
    ) -> Result<PathAction, SysAugError> {
        self.map_components(curr_path, |bytes| {
            if bytes == b"." {
                return PathAction::None;
            }
            let maybe_n_dots = bytes.iter().position(|&x| x != b'.');
            if let Some(n_dots) = maybe_n_dots {
                let mut result = b".".repeat(n_dots * 2);
                result.extend_from_slice(&bytes[n_dots..]);
                let osstring = OsString::from_vec(result);
                return PathAction::Override(osstring.into());
            }
            PathAction::None
        })
    }

    fn resolve_metadata_path(&self, path: &Path) -> Result<Option<PathBuf>, SysAugError> {
        let path_str = path.to_string_lossy();
        if !path.exists() {
            return Ok(None);
        }
        if path.is_dir() {
            Ok(Some(path.join("...")))
        } else {
            let parent = path
                .parent()
                .ok_or(self.err("FileWithoutParent", &path_str))?;
            let filename = path
                .file_name()
                .ok_or(self.err("FailedToReadFilename", &path_str))?;
            let mut new_filename = OsString::from(".");
            new_filename.push(filename);
            Ok(Some(parent.join(new_filename)))
        }
    }

    fn override_file_fake_path(
        &self,
        curr_path: &Path,
        _syscall: usize,
    ) -> Result<PathAction, SysAugError> {
        self.map_components(curr_path, |bytes| {
            if bytes == b"." {
                return PathAction::None;
            }
            let maybe_n_dots = bytes.iter().position(|&x| x != b'.');
            if let Some(n_dots) = maybe_n_dots {
                if n_dots % 2 == 1 {
                    return PathAction::HidePath;
                }
                let mut result = b".".repeat(n_dots / 2);
                result.extend_from_slice(&bytes[n_dots..]);
                let osstring = OsString::from_vec(result);
                return PathAction::Override(osstring.into());
            }
            PathAction::None
        })
    }
}
