use crate::aug_clone::AugmentClone;
use crate::aug_paths::AugmentPaths;
use crate::aug_waitpid::AugmentWaitpid;
use crate::common::{
    AugmentSyscall, ModBox, ModProvider, ModsByFeature, SysAugError, SyscallCounter,
};
use crate::mods::ModFeature;
use nix::sys;
use ptrace::GenericPurposeRegs;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use tracing::{event, span, Level};

pub struct TraceeHandlerStates {
    pub path_prefix: RwLock<Option<PathBuf>>,
    pub pid: nix::unistd::Pid,
}

pub struct TraceeHandler<PtraceClient: executor::PtraceClient> {
    pub mods: RwLock<ModsByFeature>,
    mod_providers: Vec<ModProvider>,
    pub pid: nix::unistd::Pid,
    pub ptrace_client: PtraceClient,
    pub states: Arc<TraceeHandlerStates>,

    // ignore the next sigstop for the following pids
    pub orig_request_regs: RwLock<Option<GenericPurposeRegs>>,
    pub ignore_sigstops: RwLock<HashSet<nix::unistd::Pid>>,
}

macro_rules! new_augment {
    ($type:ty, $self:ident) => {
        <$type>::new(Arc::clone(&$self))
    };
}

impl<PtraceClient: executor::PtraceClient> TraceeHandler<PtraceClient> {
    pub fn new(
        pid: nix::unistd::Pid,
        ptrace_client: PtraceClient,
        mods: Vec<ModProvider>,
        states: Option<Arc<TraceeHandlerStates>>,
    ) -> Result<Arc<TraceeHandler<PtraceClient>>, SysAugError> {
        let default_states = states.unwrap_or_default();
        let ans = Arc::new(TraceeHandler {
            pid,
            ptrace_client,
            mods: RwLock::new(HashMap::new()),
            mod_providers: mods,
            orig_request_regs: RwLock::new(None),
            ignore_sigstops: RwLock::new(HashSet::new()),
            states: Arc::new(TraceeHandlerStates {
                path_prefix: clone_locked(&default_states.path_prefix)?,
                pid,
            }),
        });

        let mut mod_map: ModsByFeature = HashMap::new();
        for provider in ans.mod_providers.iter() {
            let m = provider(Arc::clone(&ans.states));
            for feature in m.get_features().iter() {
                if !mod_map.contains_key(feature) {
                    mod_map.insert(feature.clone(), Vec::new());
                }
                let vec = mod_map.get_mut(feature).unwrap();
                vec.push(m.clone_box());
            }
        }

        let ans2 = Arc::clone(&ans);
        let mut ans_mods = ans2.mods.write().or(Err(SysAugError::LockTraceeHandler))?;
        *ans_mods = mod_map;
        Ok(ans)
    }

    /// Create a new TraceeHandler for a child, without starting event loop
    pub fn fork(
        &self,
        child_pid: nix::unistd::Pid,
    ) -> Result<Arc<TraceeHandler<PtraceClient>>, SysAugError> {
        TraceeHandler::new(
            child_pid,
            self.ptrace_client.clone(),
            self.mod_providers.clone(),
            Some(self.states.clone()),
        )
    }

    pub fn call_mods<F>(&self, feature: ModFeature, func: F) -> Result<(), SysAugError>
    where
        F: Fn(&ModBox) -> Result<(), SysAugError>,
    {
        let mod_map = self.mods.read().or(Err(SysAugError::LockTraceeHandler))?;
        if let Some(mods_) = mod_map.get(&feature) {
            for m in mods_.iter() {
                func(m)?;
            }
        }
        Ok(())
    }

    pub fn event_loop(self: Arc<TraceeHandler<PtraceClient>>) -> Result<(), SysAugError> {
        let augment_clone = new_augment!(AugmentClone<PtraceClient>, self);
        let augment_paths = new_augment!(AugmentPaths<PtraceClient>, self);
        let augment_waitpid = new_augment!(AugmentWaitpid<PtraceClient>, self);

        let mut did_set_options = false;
        let mut last_syscall = SyscallCounter::new();
        let pid = self.pid;

        self.ptrace_client.attach_to(pid)?;
        loop {
            let span = span!(Level::TRACE, "event_loop", ?pid);
            let _span_enter = span.enter();

            if did_set_options {
                self.ptrace_client
                    .execute(move || sys::ptrace::syscall(pid, None))?
                    .map_err(SysAugError::PtraceSyscall)?;
            }

            let status = ptrace::waitpid_hang(pid)?;
            event!(Level::TRACE, "child status {:?}", &status);

            if !ptrace::is_trace_stop(&status) && !ptrace::is_still_alive(&status) {
                break;
            }

            if !did_set_options {
                self.ptrace_client
                    .execute(move || {
                        sys::ptrace::setoptions(pid, sys::ptrace::Options::PTRACE_O_TRACESYSGOOD)
                    })?
                    .map_err(SysAugError::PtraceSetOptions)?;
                did_set_options = true;
                continue;
            }

            if !ptrace::is_syscall_stop(&status) {
                event!(Level::INFO, "Non-syscall ptrace stop: child status {:?}", &status);
                continue;
            }

            let mut regs = self.ptrace_client.execute(move || ptrace::getregs(pid))??;
            last_syscall.count(regs.syscall_num);

            if last_syscall.times % 2 == 1 {
                event!(
                    Level::DEBUG,
                    "Syscall {:x} #{} ({:x}, {:x}, {:x})",
                    regs.syscall_num,
                    times = &last_syscall.times,
                    arg0 = regs.arg0,
                    arg1 = regs.arg1,
                    arg2 = regs.arg2,
                );
            }

            // TODO: precalculate HashMap.get to determine:
            //  (1) Whether any augment supports this syscall. If not, skip it
            //  (2) Which augment supports this sycall. !!! No two augments can share the same syscall
            //  (3) Which "SyscallInfo" to use. (instead of being specific to AugmentPaths, share it)
            augment_clone.dispatch(&last_syscall, &mut regs)?;
            augment_paths.dispatch(&last_syscall, &mut regs)?;
            augment_waitpid.dispatch(&last_syscall, &mut regs)?;
        }
        Ok(())
    }
}

fn clone_locked<T: Clone>(lock: &RwLock<T>) -> Result<RwLock<T>, SysAugError> {
    let val = lock.read().or(Err(SysAugError::LockTraceeHandler))?;
    Ok(RwLock::new(val.clone()))
}

impl Default for TraceeHandlerStates {
    fn default() -> TraceeHandlerStates {
        TraceeHandlerStates {
            path_prefix: RwLock::default(),
            pid: nix::unistd::Pid::from_raw(0),
        }
    }
}

impl TraceeHandlerStates {
    pub fn clone(&self) -> Result<TraceeHandlerStates, SysAugError> {
        Ok(TraceeHandlerStates {
            path_prefix: clone_locked(&self.path_prefix)?,
            pid: self.pid,
        })
    }
}
