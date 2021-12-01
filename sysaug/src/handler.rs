use crate::aug_clone::AugmentClone;
use crate::aug_exec::AugmentExec;
use crate::aug_paths::AugmentPaths;
use crate::aug_perms::AugmentPerms;
use crate::aug_waitpid::AugmentWaitpid;
use crate::common::{
    display_err, rwlock_read, rwlock_replace, rwlock_write, rwoption_replace, rwoption_take,
    AugmentSyscall, Augments, ModBox, ModProvider, ModsByFeature, SysAugError, SyscallCounter,
    NO_MOD_SYSCALL, PERMS_IDS_SIZE,
};
use crate::mods::{ModAction, ModFeature};
use crate::syscalls::SYSCALL_INFOS;
use nix::sys;
use nix::sys::wait::WaitStatus;
use ptrace::GenericPurposeRegs;
use std::collections::{HashMap, HashSet};
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use tracing::{event, info, span, Level};

#[derive(Clone, Debug, Default)]
pub struct CLIArgs {
    pub chroot: Option<PathBuf>,
    pub rootfs: Option<PathBuf>,
    pub fail_fast: bool,
    pub gdb: bool,
    pub gdb_at: Option<u64>,
}

#[derive(Debug)]
pub struct TraceeHandlerStates {
    pub args: CLIArgs,
    pub failed: AtomicBool,
    pub perms_ids: RwLock<[Option<usize>; PERMS_IDS_SIZE]>,
    pub path_prefix: RwLock<Option<PathBuf>>,
    pub path_prefix_excludes: RwLock<Vec<PathBuf>>,
    pub pid: nix::unistd::Pid,
    pub root_pid: nix::unistd::Pid,
}

pub struct TraceeHandler<PtraceClient: executor::PtraceClient> {
    pub mods: RwLock<ModsByFeature>,
    mod_providers: Vec<ModProvider>,
    pub pid: nix::unistd::Pid,
    pub ptrace_client: PtraceClient,
    pub states: Arc<TraceeHandlerStates>,
    pub parent: Option<Arc<TraceeHandler<PtraceClient>>>,

    pub curr_paths: RwLock<Option<[Option<PathBuf>; 3]>>,
    pub curr_dirfd_path: RwLock<Option<PathBuf>>,
    pub orig_request_regs: RwLock<Option<GenericPurposeRegs>>,
    // ignore the next sigstop for the following pids
    pub ignore_sigstops: RwLock<HashSet<nix::unistd::Pid>>,
    pub signal_tracee: RwLock<Option<sys::signal::Signal>>,
    pub skip_syscall_retval: RwLock<Option<usize>>,
    pub tracee_stack_offset: RwLock<usize>,
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
        parent: Option<Arc<TraceeHandler<PtraceClient>>>,
    ) -> Result<Arc<TraceeHandler<PtraceClient>>, SysAugError> {
        let default_states = states.unwrap_or_default();
        let ans = Arc::new(TraceeHandler {
            pid,
            ptrace_client,
            mods: RwLock::new(HashMap::new()),
            mod_providers: mods,
            curr_paths: RwLock::default(),
            curr_dirfd_path: RwLock::default(),
            orig_request_regs: RwLock::default(),
            ignore_sigstops: RwLock::default(),
            signal_tracee: RwLock::default(), // new(Some(sys::signal::Signal::SIGCONT)),
            skip_syscall_retval: RwLock::default(),
            tracee_stack_offset: RwLock::default(),
            states: Arc::new((*default_states).try_clone()?),
            parent: parent,
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
        rwlock_replace(&ans2.mods, mod_map)?;
        Ok(ans)
    }

    /// Create a new TraceeHandler for a child, without starting event loop
    pub fn fork(
        self: &Arc<TraceeHandler<PtraceClient>>,
        child_pid: nix::unistd::Pid,
    ) -> Result<Arc<TraceeHandler<PtraceClient>>, SysAugError> {
        TraceeHandler::new(
            child_pid,
            self.ptrace_client.clone(),
            self.mod_providers.clone(),
            Some(self.states.clone()),
            Some(Arc::clone(self)),
        )
    }

    pub fn skip_syscall(&self, retval: usize) -> Result<(), SysAugError> {
        rwoption_replace(&self.skip_syscall_retval, retval)?;
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
        let mod_map = rwlock_read(&self.mods)?;
        if let Some(mods_) = mod_map.get(&feature) {
            if let Some(m) = mods_.get(0) {
                return Ok(Some(func(m)?));
            }
        }
        Ok(None)
    }

    pub fn call_mods<F>(&self, feature: ModFeature, func: F) -> Result<(), SysAugError>
    where
        F: Fn(&ModBox) -> Result<ModAction, SysAugError>,
    {
        let mod_map = rwlock_read(&self.mods)?;
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
        F: FnOnce() + Send + 'static,
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

    // Send the content of `bytes` to tracee's stack, and return its address.
    // This can be called multiple times and will add new content to the end of
    // previous contents.
    pub fn tracee_stack_append(&self, bytes: Vec<u8>) -> Result<usize, SysAugError> {
        let pid = self.pid;
        let mut offset = rwlock_write(&self.tracee_stack_offset)?;
        let old_offset = *offset;
        let (addr, new_offset) = self.ptrace_client.execute(move || {
            let final_bytes = bytes.as_slice();
            unsafe { ptrace::bytes_to_stack(pid, old_offset, final_bytes) }
        })??;
        *offset = new_offset;
        Ok(addr)
    }

    pub fn tracee_stack_append_path(&self, path: PathBuf) -> Result<usize, SysAugError> {
        let bytes = path.into_os_string().into_vec();
        self.tracee_stack_append(bytes)
    }

    // Change the address, to which the next tracee_stack_append will write contents.
    // offset = how many bytes of previously written contents will stay after this
    pub fn tracee_stack_seek(&self, offset: usize) -> Result<(), SysAugError> {
        let mut ref_offset = rwlock_write(&self.tracee_stack_offset)?;
        *ref_offset = offset;
        Ok(())
    }

    pub fn event_loop(self: Arc<TraceeHandler<PtraceClient>>) -> Result<u8, SysAugError> {
        let augment_clone = new_augment!(AugmentClone<PtraceClient>, self);
        let augment_exec = new_augment!(AugmentExec<PtraceClient>, self);
        let augment_paths = new_augment!(AugmentPaths<PtraceClient>, self);
        let augment_perms = new_augment!(AugmentPerms<PtraceClient>, self);
        let augment_waitpid = new_augment!(AugmentWaitpid<PtraceClient>, self);

        let mut last_syscall = SyscallCounter::new();
        let pid = self.pid;

        self.ptrace_client.attach_to(pid)?;
        self.set_ptrace_options()?;
        self.call_mods(ModFeature::OnTraceeStartup, |m| m.on_tracee_startup())?;
        loop {
            let maybe_signal = rwoption_take(&self.signal_tracee)?;
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
                    event!(Level::DEBUG, "child stopped, status {:?}", &status);
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
                    if signal == sys::signal::Signal::SIGSTOP {
                        if let Some(parent) = self.parent.as_ref() {
                            let ignore_sigstops = rwlock_read(&parent.ignore_sigstops)?;
                            if ignore_sigstops.contains(&pid) {
                                continue;
                            }
                        }
                    }
                    if signal == sys::signal::Signal::SIGSEGV && self.states.args.gdb {
                        info!("Tracee segfault. Starting gdb");
                        return self.transfer_to_gdb();
                    }
                    info!("Will deliver signal {:?} to {:?}", &signal, &pid);
                    rwoption_replace(&self.signal_tracee, signal)?;
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
                    let syscall_num_str = regs.syscall_num.to_string();
                    let syscall_name = syscall_info.map(|x| x.name()).unwrap_or(&syscall_num_str);
                    last_syscall.count(regs.syscall_num, syscall_info);

                    let _span = if last_syscall.times % 2 == 1 {
                        span!(
                            Level::INFO,
                            "before",
                            "syscall {} args {:#x} {:#x} {:#x}",
                            syscall_name,
                            regs.arg0,
                            regs.arg1,
                            regs.arg2
                        )
                    } else {
                        span!(
                            Level::INFO,
                            "after",
                            "syscall {} return {:#x} args {:#x} {:#x} {:#x}",
                            syscall_name,
                            regs.syscall_retval(),
                            regs.arg0,
                            regs.arg1,
                            regs.arg2
                        )
                    }
                    .entered();
                    let which_aug = syscall_info.map(|x| &x.augment);
                    let _span2 = span!(
                        Level::INFO,
                        "sysaug",
                        "{:?},{},{}",
                        which_aug.unwrap_or(&Augments::None),
                        syscall_name,
                        last_syscall.total_times
                    )
                    .entered();
                    event!(Level::TRACE, "syscall event");
                    if self.states.args.gdb_at == Some(last_syscall.total_times) {
                        return self.transfer_to_gdb();
                    }
                    match which_aug {
                        Some(Augments::Clone) => augment_clone.dispatch(&last_syscall, regs),
                        Some(Augments::Exec) => augment_exec.dispatch(&last_syscall, regs),
                        Some(Augments::Paths) => augment_paths.dispatch(&last_syscall, regs),
                        Some(Augments::Perms) => augment_perms.dispatch(&last_syscall, regs),
                        Some(Augments::Waitpid) => augment_waitpid.dispatch(&last_syscall, regs),
                        Some(Augments::Unimplemented) => Err(SysAugError::UnimplementedAugment),
                        _ => Ok(()),
                    }
                    .map_err(display_err)?;
                    if let Some(info) = syscall_info {
                        if info.sets_file_perms {
                            self.call_mods(ModFeature::OnSetsPerms, |m| m.on_sets_perms(info))?;
                        }
                    }
                    self.maybe_skip_syscall(&mut last_syscall)?;
                }
                _ => {
                    event!(Level::INFO, "Unexpected ptrace stop: {:?}", &status);
                }
            }
        }
    }

    fn transfer_to_gdb(&self) -> Result<u8, SysAugError> {
        let pid = self.pid;
        self.ptrace_client
            .execute(move || sys::ptrace::detach(pid, sys::signal::Signal::SIGSTOP))?
            .map_err(SysAugError::GDBDetach)?;
        let mut cmd = std::process::Command::new("gdb");
        cmd.arg("-p").arg(pid.as_raw().to_string());
        let status = cmd.status().map_err(SysAugError::GDB)?;
        Ok(status.code().unwrap_or(-1) as u8)
    }

    fn maybe_skip_syscall(&self, last_syscall: &mut SyscallCounter) -> Result<(), SysAugError> {
        let pid = self.pid;
        if last_syscall.syscall == Some(NO_MOD_SYSCALL) {
            let mut maybe_skip = rwlock_write(&self.skip_syscall_retval)?;
            event!(
                Level::DEBUG,
                "In NO_MOD_SYSCALL, times: {}",
                &last_syscall.times,
            );
            if last_syscall.times % 2 == 1 {
                return Ok(());
            }
            if let Some(retval) = maybe_skip.take() {
                let mut regs = self.ptrace_client.execute(move || ptrace::getregs(pid))??;

                event!(
                    Level::DEBUG,
                    "Replacing syscall return value {} with {}",
                    regs.syscall_retval(),
                    retval
                );
                regs.set_syscall_retval(retval);
                self.ptrace_client
                    .execute(move || ptrace::setregs(pid, regs))??;
            }
        } else if last_syscall.times % 2 == 1 {
            let maybe_skip = rwlock_read(&self.skip_syscall_retval)?;
            if maybe_skip.is_some() {
                event!(Level::DEBUG, "Attempting to skip syscall");
                self.ptrace_client
                    .execute(move || ptrace::set_syscall_num(pid, NO_MOD_SYSCALL))??;
                last_syscall.count(NO_MOD_SYSCALL, None);
            }
        }
        Ok(())
    }
}

fn clone_locked<T: Clone>(lock: &RwLock<T>) -> Result<RwLock<T>, SysAugError> {
    let val = rwlock_read(lock)?;
    Ok(RwLock::new(val.clone()))
}

impl Default for TraceeHandlerStates {
    fn default() -> TraceeHandlerStates {
        TraceeHandlerStates {
            args: CLIArgs::default(),
            failed: AtomicBool::new(false),
            perms_ids: RwLock::default(),
            path_prefix: RwLock::default(),
            path_prefix_excludes: RwLock::default(),
            pid: nix::unistd::Pid::from_raw(0),
            root_pid: nix::unistd::Pid::from_raw(0),
        }
    }
}

impl TraceeHandlerStates {
    pub fn try_clone(&self) -> Result<TraceeHandlerStates, SysAugError> {
        Ok(TraceeHandlerStates {
            args: self.args.clone(),
            failed: AtomicBool::new(false),
            perms_ids: clone_locked(&self.perms_ids)?,
            path_prefix: clone_locked(&self.path_prefix)?,
            path_prefix_excludes: clone_locked(&self.path_prefix_excludes)?,
            pid: self.pid,
            root_pid: self.root_pid,
        })
    }
}
