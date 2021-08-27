use crate::aug_clone::AugmentClone;
use crate::aug_paths::AugmentPaths;
use crate::aug_perms::AugmentPerms;
use crate::aug_waitpid::AugmentWaitpid;
use crate::common::{
    display_err, AugmentSyscall, Augments, ModBox, ModProvider, ModsByFeature, SysAugError,
    SyscallCounter, NO_MOD_SYSCALL,
};
use crate::mods::{ModAction, ModFeature};
use crate::syscalls::SYSCALL_INFOS;
use nix::sys;
use nix::sys::wait::WaitStatus;
use ptrace::GenericPurposeRegs;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use tracing::{event, info, span, Level};

pub struct TraceeHandlerStates {
    pub fail_fast: bool,
    pub failed: AtomicBool,
    pub override_uid: RwLock<Option<usize>>,
    pub override_gid: RwLock<Option<usize>>,
    pub path_prefix: RwLock<Option<PathBuf>>,
    pub pid: nix::unistd::Pid,
    pub root_pid: nix::unistd::Pid,
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
            signal_tracee: RwLock::default(), // new(Some(sys::signal::Signal::SIGCONT)),
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

    pub fn skip_syscall(&self, retval: usize) -> Result<(), SysAugError> {
        let mut maybe_retval = self
            .skip_syscall_retval
            .write()
            .or(Err(SysAugError::LockTraceeHandler))?;
        maybe_retval.replace(retval);
        Ok(())
    }

    pub fn call_first_mod<F, T>(
        &self,
        feature: ModFeature,
        func: F,
    ) -> Result<Option<T>, SysAugError>
    where
        F: Fn(&ModBox) -> Result<T, SysAugError>,
    {
        let mod_map = self.mods.read().or(Err(SysAugError::LockTraceeHandler))?;
        if let Some(mods_) = mod_map.get(&feature) {
            if let Some(m) = mods_.iter().nth(0) {
                return Ok(Some(func(m)?));
            }
        }
        Ok(None)
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
                        self.skip_syscall(retval)?;
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
                sys::ptrace::setoptions(
                    pid,
                    sys::ptrace::Options::PTRACE_O_TRACESYSGOOD
                        | sys::ptrace::Options::PTRACE_O_TRACEEXIT,
                )
            })?
            .map_err(SysAugError::PtraceSetOptions)?;
        Ok(())
    }

    pub fn handle_exit(&self, pid: nix::unistd::Pid) -> Result<(), SysAugError> {
        info!("Process {:?} exited.", &pid);
        self.ptrace_client
            .execute(move || sys::ptrace::detach(pid, None))?
            .map_err(SysAugError::PtraceDetach)
    }

    pub fn trace_span(&self) -> tracing::Span {
        return span!(Level::ERROR, "event_loop", "{:?}", self.pid);
    }

    pub fn start<F>(
        self: Arc<TraceeHandler<PtraceClient>>,
        callback: F,
    ) -> thread::JoinHandle<Option<u8>>
    where
        F: FnOnce() -> () + Send + 'static,
    {
        thread::spawn(move || {
            let self2 = Arc::clone(&self);
            let _span = self.trace_span().entered();
            let result = self.event_loop().map_err(display_err);
            if result.is_err() {
                let _ = sys::signal::kill(self2.pid, Some(sys::signal::Signal::SIGKILL))
                    .map_err(display_err);
                self2.states.failed.store(true, Ordering::Relaxed);
            }
            callback();
            result.ok()
        })
    }

    pub fn failed(&self) -> bool {
        self.states.failed.load(Ordering::Relaxed)
    }

    pub fn event_loop(self: Arc<TraceeHandler<PtraceClient>>) -> Result<u8, SysAugError> {
        let augment_clone = new_augment!(AugmentClone<PtraceClient>, self);
        let augment_paths = new_augment!(AugmentPaths<PtraceClient>, self);
        let augment_perms = new_augment!(AugmentPerms<PtraceClient>, self);
        let augment_waitpid = new_augment!(AugmentWaitpid<PtraceClient>, self);

        let mut last_syscall = SyscallCounter::new();
        let pid = self.pid;

        self.ptrace_client.attach_to(pid)?;
        self.set_ptrace_options()?;
        self.call_mods(ModFeature::OnTraceeStartup, |m| m.on_tracee_startup())?;
        loop {
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
            if !ptrace::is_trace_stop(&status) && !ptrace::is_still_alive(&status) {
                info!("Process {:?} crashed: {:?}.", &pid, &status);
                self.handle_exit(pid)?;
                return Err(SysAugError::TraceeCrashed);
            }
            match &status {
                // Decide whether to deliver signal to tracee
                &WaitStatus::Stopped(pid2, signal) => {
                    event!(Level::INFO, "child stopped, status {:?}", &status);
                    if pid2 != pid || signal == sys::signal::Signal::SIGTRAP {
                        continue;
                    }
                    let getsig_err = self
                        .ptrace_client
                        .execute(move || sys::ptrace::getsiginfo(pid))?
                        .err();
                    if getsig_err == Some(nix::Error::Sys(nix::errno::Errno::EINVAL)) {
                        continue;
                    }
                    info!("Will deliver signal {:?} to {:?}", &signal, &pid);
                    let mut maybe_signal = self
                        .signal_tracee
                        .write()
                        .or(Err(SysAugError::LockTraceeHandler))?;
                    maybe_signal.replace(signal);
                }
                // Tracee Exits
                &WaitStatus::PtraceEvent(pid2, _, libc::PTRACE_EVENT_EXIT) => {
                    if pid2 != pid {
                        continue;
                    }
                    let rawret = self
                        .ptrace_client
                        .execute(move || ptrace::getevent(pid))??;
                    let retcode = (rawret as u32) >> 8;
                    info!("Exit status = {}", retcode);
                    self.handle_exit(pid)?;
                    return Ok(retcode as u8);
                }
                // SYSTEM CALL
                &WaitStatus::PtraceEvent(_, _, _) | &WaitStatus::PtraceSyscall(_) => {
                    let regs = self.ptrace_client.execute(move || ptrace::getregs(pid))??;
                    let syscall_info = SYSCALL_INFOS.get(&regs.syscall_num);
                    let syscall_name = syscall_info.map(|x| x.name()).unwrap_or("??");
                    last_syscall.count(regs.syscall_num, syscall_info);

                    let _span = if last_syscall.times % 2 == 1 {
                        span!(
                            Level::DEBUG,
                            "before",
                            "syscall {} args {:#x} {:#x} {:#x}",
                            syscall_name,
                            regs.arg0,
                            regs.arg1,
                            regs.arg2
                        )
                    } else {
                        span!(
                            Level::DEBUG,
                            "after",
                            "syscall {} args {:#x} {:#x} {:#x}",
                            syscall_name,
                            regs.arg0,
                            regs.arg1,
                            regs.arg2
                        )
                    }
                    .entered();
                    event!(Level::TRACE, "syscall event");

                    let which_aug = syscall_info.map(|x| &x.augment);
                    let _span2 = span!(
                        Level::INFO,
                        "sysaug",
                        "{:?},{}",
                        which_aug.unwrap_or(&Augments::None),
                        syscall_name
                    )
                    .entered();
                    match which_aug {
                        Some(Augments::Clone) => augment_clone.dispatch(&last_syscall, regs),
                        Some(Augments::Paths) => augment_paths.dispatch(&last_syscall, regs),
                        Some(Augments::Perms) => augment_perms.dispatch(&last_syscall, regs),
                        Some(Augments::Waitpid) => augment_waitpid.dispatch(&last_syscall, regs),
                        _ => Ok(()),
                    }
                    .map_err(display_err)?;
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
        if last_syscall.syscall == Some(NO_MOD_SYSCALL) {
            let mut maybe_skip = self
                .skip_syscall_retval
                .write()
                .or(Err(SysAugError::LockTraceeHandler))?;
            event!(
                Level::INFO,
                "In NO_MOD_SYSCALL, times: {}",
                &last_syscall.times,
            );
            if last_syscall.times % 2 == 1 {
                return Ok(());
            }
            if let Some(retval) = maybe_skip.take() {
                let mut regs = self.ptrace_client.execute(move || ptrace::getregs(pid))??;

                event!(
                    Level::INFO,
                    "Replacing syscall return value {} with {}",
                    regs.syscall_retval(),
                    retval
                );
                regs.set_syscall_retval(retval);
                self.ptrace_client
                    .execute(move || ptrace::setregs(pid, regs))??;
            }
        } else if last_syscall.times % 2 == 1 {
            let maybe_skip = self
                .skip_syscall_retval
                .read()
                .or(Err(SysAugError::LockTraceeHandler))?;
            if maybe_skip.is_some() {
                event!(Level::INFO, "Attempting to skip syscall");
                self.ptrace_client
                    .execute(move || ptrace::set_syscall_num(pid, NO_MOD_SYSCALL))??;
                last_syscall.count(NO_MOD_SYSCALL, None);
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
            fail_fast: true,
            failed: AtomicBool::new(false),
            override_uid: RwLock::default(),
            override_gid: RwLock::default(),
            path_prefix: RwLock::default(),
            pid: nix::unistd::Pid::from_raw(0),
            root_pid: nix::unistd::Pid::from_raw(0),
        }
    }
}

impl TraceeHandlerStates {
    pub fn clone(&self) -> Result<TraceeHandlerStates, SysAugError> {
        Ok(TraceeHandlerStates {
            fail_fast: self.fail_fast,
            failed: AtomicBool::new(false),
            override_uid: clone_locked(&self.override_uid)?,
            override_gid: clone_locked(&self.override_gid)?,
            path_prefix: clone_locked(&self.path_prefix)?,
            pid: self.pid,
            root_pid: self.root_pid,
        })
    }
}
