use crate::clone::AugmentClone;
use crate::common::{
    AugmentSyscall, ModBox, ModProvider, ModsByFeature, SysAugError, SyscallCounter,
};
use crate::mods::ModFeature;
use crate::paths::AugmentPaths;
use nix::sys;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;
use tracing::{event, span, Level};

pub struct TraceeHandler {
    pub mods: RwLock<ModsByFeature>,
    mod_providers: Vec<ModProvider>,
    pub pid: nix::unistd::Pid,
    pub ptrace_client: executor::PtraceClient,
}

macro_rules! new_augment {
    ($type:ty, $self:ident) => {
        <$type>::new(Arc::clone(&$self))
    };
}

impl TraceeHandler {
    pub fn new(
        pid: nix::unistd::Pid,
        ptrace_client: executor::PtraceClient,
        mods: Vec<ModProvider>,
    ) -> Result<Arc<TraceeHandler>, SysAugError> {
        let ans = Arc::new(TraceeHandler {
            pid,
            ptrace_client,
            mods: RwLock::new(HashMap::new()),
            mod_providers: mods,
        });

        let mut mod_map: ModsByFeature = HashMap::new();
        for provider in ans.mod_providers.iter() {
            let m = provider(Arc::clone(&ans));
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
    pub fn fork(&self, child_pid: nix::unistd::Pid) -> Result<Arc<TraceeHandler>, SysAugError> {
        TraceeHandler::new(
            child_pid,
            self.ptrace_client.clone(),
            self.mod_providers.clone(),
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

    pub fn event_loop(self: Arc<TraceeHandler>) -> Result<(), SysAugError> {
        let pid = self.pid;

        thread::sleep(Duration::from_millis(1));
        self.ptrace_client.execute(move || {
            sys::ptrace::setoptions(pid, sys::ptrace::Options::PTRACE_O_TRACESYSGOOD)
        })??;

        let augment_clone = new_augment!(AugmentClone, self);
        let augment_paths = new_augment!(AugmentPaths, self);

        let mut last_syscall = SyscallCounter::new();
        loop {
            let span = span!(Level::TRACE, "event_loop", ?pid);
            let _span_enter = span.enter();

            self.ptrace_client
                .execute(move || sys::ptrace::syscall(pid, None))??;
            let status = ptrace::waitpid_hang(pid)?;
            event!(Level::TRACE, "child status {:?}", &status);

            if !ptrace::is_trace_stop(&status) && !ptrace::is_still_alive(&status) {
                break;
            }

            if !ptrace::is_syscall_stop(&status) {
                continue;
            }

            let regs = self.ptrace_client.execute(move || ptrace::getregs(pid))??;
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
            augment_clone.dispatch(&last_syscall, &regs)?;
            augment_paths.dispatch(&last_syscall, &regs)?;
        }
        Ok(())
    }
}
