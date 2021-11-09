use lazy_static::lazy_static;
use std::collections::HashSet;
use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use sysaug::mods::{Mod, ModAction, ModFeature, PathAction};
use sysaug::{SysAugError, SyscallInfo, TraceeHandlerStates};

lazy_static! {
    static ref DEFAULT_LISTENER_SPEC: HashSet<ModFeature> = {
        let mut ans = HashSet::new();
        ans.insert(ModFeature::OverrideFileRealPath);
        ans.insert(ModFeature::OverrideFileFakePath);
        ans.insert(ModFeature::OnFileRealPath);
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
        _syscall: &SyscallInfo,
    ) -> Result<PathAction, SysAugError> {
        self.map_components(curr_path, |bytes| {
            if bytes == b"." || bytes == b".." {
                return PathAction::None;
            }
            let maybe_n_dots = bytes.iter().position(|&x| x != b'.');
            if maybe_n_dots != Some(0) {
                let n_dots = maybe_n_dots.unwrap_or(bytes.len());
                let mut result = b".".repeat(n_dots * 2);
                result.extend_from_slice(&bytes[n_dots..]);
                let osstring = OsString::from_vec(result);
                return PathAction::Override(osstring.into());
            }
            PathAction::None
        })
    }

    fn resolve_metadata_path(
        &self,
        rel_path: &Path,
        dirfd_path: &Path,
    ) -> Result<Option<PathBuf>, SysAugError> {
        let path = dirfd_path.join(rel_path);
        let path_str = path.to_string_lossy();
        let args = &self.states.args;
        let maybe_rootfs = args.rootfs.as_ref().or_else(|| args.chroot.as_ref());
        if !path.exists() {
            return Ok(None);
        }
        let canonical_path = path.canonicalize();
        if canonical_path.is_err() {
            return Ok(None);
        }
        if !canonical_path.unwrap().starts_with(maybe_rootfs.unwrap()) {
            return Ok(None);
        }
        if path.is_dir() {
            Ok(Some(path.join("...")))
        } else {
            let filename = path
                .file_name()
                .ok_or_else(|| self.err("FailedToReadFilename", &path_str))?;
            let mut new_filename = OsString::from(".");
            new_filename.push(filename);
            Ok(Some(path.with_file_name(new_filename)))
        }
    }

    fn override_file_fake_path(
        &self,
        curr_path: &Path,
        _syscall: &SyscallInfo,
    ) -> Result<PathAction, SysAugError> {
        self.map_components(curr_path, |bytes| {
            if bytes == b"." || bytes == b".." {
                return PathAction::None;
            }
            let maybe_n_dots = bytes.iter().position(|&x| x != b'.');
            if maybe_n_dots != Some(0) {
                let n_dots = maybe_n_dots.unwrap_or(bytes.len());
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

    fn on_file_real_path(
        &self,
        _raw_path: &Path,
        syscall: &SyscallInfo,
    ) -> Result<ModAction, SysAugError> {
        if syscall.sets_file_perms {
            return Ok(ModAction::SkipSyscall(0));
        }
        Ok(ModAction::None)
    }
}
