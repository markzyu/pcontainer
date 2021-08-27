// Make sure children of tracees are also traced.
use lazy_static::lazy_static;
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use sysaug::mods::{Mod, ModAction, ModFeature};
use sysaug::{SysAugError, SyscallInfo, TraceeHandlerStates};
use tracing::{event, Level};

lazy_static! {
    static ref DEFAULT_LISTENER_SPEC: HashSet<ModFeature> = {
        let mut ans = HashSet::new();
        ans.insert(ModFeature::OnFileRealPath);
        ans.insert(ModFeature::OnSetuid);
        ans
    };
}

pub struct PermsMod {
    states: Arc<TraceeHandlerStates>,
}

impl PermsMod {
    pub fn new_box(states: Arc<TraceeHandlerStates>) -> Box<dyn Mod> {
        Box::new(PermsMod { states })
    }

    fn setuid(&self, uid: usize) -> Result<(), SysAugError> {
        let mut maybe_uid = self
            .states
            .override_uid
            .write()
            .or(Err(SysAugError::LockTraceeHandler))?;
        maybe_uid.replace(uid);
        Ok(())
    }
}

impl Mod for PermsMod {
    fn clone_box(&self) -> Box<dyn Mod + Send + Sync> {
        Box::new(PermsMod {
            states: Arc::clone(&self.states),
        })
    }

    fn get_features(&self) -> &'static HashSet<ModFeature> {
        &*DEFAULT_LISTENER_SPEC
    }

    fn on_file_real_path(
        &self,
        path: &Path,
        syscall: &SyscallInfo,
    ) -> Result<ModAction, SysAugError> {
        if syscall.num == libc::SYS_execve as usize {
            if let Some(stat) = nix::sys::stat::stat(path).ok() {
                let setuid = stat.st_mode & nix::sys::stat::Mode::S_ISUID.bits();
                if setuid != 0 {
                    event!(
                        Level::INFO,
                        "Execve real path: {:?} setuid to {:?}",
                        path,
                        stat.st_uid,
                    );
                    self.setuid(stat.st_uid as usize)?;
                }
            }
        }
        Ok(ModAction::None)
    }

    fn on_setuid(&self, uid: usize, _syscall: &SyscallInfo) -> Result<ModAction, SysAugError> {
        self.setuid(uid)?;
        Ok(ModAction::SkipSyscall(0))
    }
}
