use crate::aug_clone::AugmentClone;
use crate::aug_paths::AugmentPaths;
use crate::aug_perms::AugmentPerms;
use crate::aug_waitpid::AugmentWaitpid;
use crate::common::{
    AugmentSyscall, Augments, ModBox, ModProvider, ModsByFeature, SysAugError, SyscallCounter,
};
use crate::mods::{ModAction, ModFeature};
use lazy_static::lazy_static;
use nix::sys;
use nix::sys::wait::WaitStatus;
use ptrace::GenericPurposeRegs;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use tracing::{event, info, span, Level};

pub struct TraceeHandlerStates {
    pub override_uid: RwLock<Option<usize>>,
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
    pub signal_tracee: RwLock<Option<sys::signal::Signal>>,
    pub skip_syscall_retval: RwLock<Option<usize>>,
}

// We promise not to modify this system call
const NO_MOD_SYSCALL: usize = libc::SYS_getpid as usize;

lazy_static! {
    static ref SYSCALL_TO_AUG: HashMap<&'static usize, &'static Augments> = {
        let mut ans = HashMap::new();
        ans.extend(AugmentClone::<executor::LocalPtraceClient>::valid_calls());
        ans.extend(AugmentPaths::<executor::LocalPtraceClient>::valid_calls());
        ans.extend(AugmentWaitpid::<executor::LocalPtraceClient>::valid_calls());
        ans.remove(&NO_MOD_SYSCALL);
        ans
    };
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
            orig_request_regs: RwLock::default(),
            ignore_sigstops: RwLock::default(),
            signal_tracee: RwLock::default(),
            skip_syscall_retval: RwLock::default(),
            states: Arc::new((*default_states).clone()?),
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
        F: Fn(&ModBox) -> Result<ModAction, SysAugError>,
    {
        let mod_map = self.mods.read().or(Err(SysAugError::LockTraceeHandler))?;
        if let Some(mods_) = mod_map.get(&feature) {
            for m in mods_.iter() {
                match func(m)? {
                    ModAction::SkipSyscall(retval) => {
                        let mut maybe_retval = self
                            .skip_syscall_retval
                            .write()
                            .or(Err(SysAugError::LockTraceeHandler))?;
                        maybe_retval.replace(retval);
                    }
                    ModAction::None => (),
                }
            }
        }
        Ok(())
    }

    fn set_ptrace_options(&self) -> Result<(), SysAugError> {
        let pid = self.pid;
        let status = ptrace::waitpid_hang(pid)?;
        event!(Level::TRACE, "child status {:?}", &status);
        if !ptrace::is_trace_stop(&status) && !ptrace::is_still_alive(&status) {
            return Err(SysAugError::TraceeCrashed);
        }
        self.ptrace_client
            .execute(move || {
                sys::ptrace::setoptions(pid, sys::ptrace::Options::PTRACE_O_TRACESYSGOOD)
            })?
            .map_err(SysAugError::PtraceSetOptions)?;
        Ok(())
    }

    pub fn event_loop(self: Arc<TraceeHandler<PtraceClient>>) -> Result<(), SysAugError> {
        let augment_clone = new_augment!(AugmentClone<PtraceClient>, self);
        let augment_paths = new_augment!(AugmentPaths<PtraceClient>, self);
        let augment_perms = new_augment!(AugmentPerms<PtraceClient>, self);
        let augment_waitpid = new_augment!(AugmentWaitpid<PtraceClient>, self);

        let mut last_syscall = SyscallCounter::new();
        let pid = self.pid;

        self.ptrace_client.attach_to(pid)?;
        self.set_ptrace_options()?;
        loop {
            let span = span!(Level::TRACE, "event_loop", ?pid);
            let _span_enter = span.enter();

            let maybe_signal = {
                let mut lock = self
                    .signal_tracee
                    .write()
                    .or(Err(SysAugError::LockTraceeHandler))?;
                lock.take()
            };
            self.ptrace_client
                .execute(move || sys::ptrace::syscall(pid, maybe_signal))?
                .map_err(SysAugError::PtraceSyscall)?;

            let status = ptrace::waitpid_hang(pid)?;
            event!(Level::TRACE, "child status {:?}", &status);

            if !ptrace::is_trace_stop(&status) && !ptrace::is_still_alive(&status) {
                return Ok(());
            }
            match &status {
                // Decide whether to deliver signal to tracee
                &WaitStatus::Stopped(pid2, signal) => {
                    if pid2 != pid || signal == sys::signal::Signal::SIGTRAP {
                        continue;
                    }
                    info!("Will deliver signal {:?} to {:?}", &signal, &pid);
                    let mut maybe_signal = self
                        .signal_tracee
                        .write()
                        .or(Err(SysAugError::LockTraceeHandler))?;
                    maybe_signal.replace(signal);
                }
                // Killed by signal
                &WaitStatus::Signaled(pid2, signal, _) => {
                    if pid2 != pid {
                        continue;
                    }
                    info!("Process {:?} killed by signal {:?}", &pid, &signal);
                    return Ok(());
                }
                // SYSTEM CALL
                &WaitStatus::PtraceEvent(_, _, _) | &WaitStatus::PtraceSyscall(_) => {
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

                    match SYSCALL_TO_AUG.get(&regs.syscall_num) {
                        Some(Augments::Clone) => augment_clone.dispatch(&last_syscall, regs)?,
                        Some(Augments::Paths) => augment_paths.dispatch(&last_syscall, regs)?,
                        Some(Augments::Perms) => augment_perms.dispatch(&last_syscall, regs)?,
                        Some(Augments::Waitpid) => augment_waitpid.dispatch(&last_syscall, regs)?,
                        None => (),
                    }
                    self.maybe_skip_syscall(&mut last_syscall)?;
                }
                _ => {
                    event!(Level::INFO, "Unexpected ptrace stop: {:?}", &status);
                }
            }
        }
    }

    fn maybe_skip_syscall(&self, last_syscall: &mut SyscallCounter) -> Result<(), SysAugError> {
        let pid = self.pid;
        if last_syscall.times % 2 == 1 {
            let maybe_skip = self
                .skip_syscall_retval
                .read()
                .or(Err(SysAugError::LockTraceeHandler))?;
            if maybe_skip.is_some() {
                let mut regs = self.ptrace_client.execute(move || ptrace::getregs(pid))??;
                regs.syscall_num = NO_MOD_SYSCALL;
                self.ptrace_client
                    .execute(move || ptrace::setregs(pid, regs))??;
                last_syscall.count(NO_MOD_SYSCALL);
            }
        } else if last_syscall.syscall == Some(NO_MOD_SYSCALL) {
            let mut maybe_skip = self
                .skip_syscall_retval
                .write()
                .or(Err(SysAugError::LockTraceeHandler))?;
            if let Some(retval) = maybe_skip.take() {
                let mut regs = self.ptrace_client.execute(move || ptrace::getregs(pid))??;
                regs.set_syscall_retval(retval);
                self.ptrace_client
                    .execute(move || ptrace::setregs(pid, regs))??;
            }
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
            override_uid: RwLock::default(),
            path_prefix: RwLock::default(),
            pid: nix::unistd::Pid::from_raw(0),
        }
    }
}

impl TraceeHandlerStates {
    pub fn clone(&self) -> Result<TraceeHandlerStates, SysAugError> {
        Ok(TraceeHandlerStates {
            override_uid: clone_locked(&self.override_uid)?,
            path_prefix: clone_locked(&self.path_prefix)?,
            pid: self.pid,
        })
    }
}
