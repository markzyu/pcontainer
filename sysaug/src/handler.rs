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
use nix::unistd::Pid;
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

struct AugmentContainer<PtraceClient: executor::PtraceClient> {
    clone: AugmentClone<PtraceClient>,
    exec: AugmentExec<PtraceClient>,
    paths: AugmentPaths<PtraceClient>,
    perms: AugmentPerms<PtraceClient>,
    waitpid: AugmentWaitpid<PtraceClient>,
}

pub struct TraceeHandler<PtraceClient: executor::PtraceClient> {
    pub mods: RwLock<ModsByFeature>,
    mod_providers: Vec<ModProvider>,
    pub pid: nix::unistd::Pid,
    pub ptrace_client: PtraceClient,
    pub states: Arc<TraceeHandlerStates>,
    pub parent: Option<Arc<TraceeHandler<PtraceClient>>>,

    pub curr_paths: RwLock<Option<[Option<PathBuf>; 4]>>,
    pub orig_request_regs: RwLock<Option<GenericPurposeRegs>>,
    pub orig_wait_status: RwLock<usize>,
    // ignore the next sigstop for the following pids
    pub ignore_sigstops: RwLock<HashSet<nix::unistd::Pid>>,
    pub signal_tracee: RwLock<Option<sys::signal::Signal>>,
    pub skip_syscall_retval: RwLock<Option<usize>>,
    pub tracee_stack_offset: RwLock<usize>,

    augments: RwLock<Option<AugmentContainer<PtraceClient>>>,
    last_syscall: RwLock<SyscallCounter>,
}

type BoolResult = Result<bool, SysAugError>;

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
            augments: RwLock::default(),
            last_syscall: RwLock::new(SyscallCounter::new()),
            mods: RwLock::new(HashMap::new()),
            mod_providers: mods,
            curr_paths: RwLock::default(),
            orig_request_regs: RwLock::default(),
            orig_wait_status: RwLock::default(),
            ignore_sigstops: RwLock::default(),
            signal_tracee: RwLock::default(), // new(Some(sys::signal::Signal::SIGCONT)),
            skip_syscall_retval: RwLock::default(),
            tracee_stack_offset: RwLock::default(),
            states: Arc::new((*default_states).try_clone()?),
            parent,
        });

        let augments = AugmentContainer::<PtraceClient> {
            clone: new_augment!(AugmentClone<PtraceClient>, ans),
            exec: new_augment!(AugmentExec<PtraceClient>, ans),
            paths: new_augment!(AugmentPaths<PtraceClient>, ans),
            perms: new_augment!(AugmentPerms<PtraceClient>, ans),
            waitpid: new_augment!(AugmentWaitpid<PtraceClient>, ans),
        };
        rwoption_replace(&ans.augments, augments)?;

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
    fn fork_alloc(
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

    /// Create a new TraceeHandler for a child, and start event loop
    fn fork(
        self: &Arc<TraceeHandler<PtraceClient>>,
        child_pid: nix::unistd::Pid,
    ) -> Result<(), SysAugError> {
        self.ptrace_client
            .prep_attach_to(child_pid, &self.ignore_sigstops)?;
        let new_tracee_handler = self.fork_alloc(child_pid)?;
        let new_tracee_handler2 = Arc::clone(&new_tracee_handler);
        let root_pid = self.states.root_pid;
        let fail_fast = self.states.args.fail_fast;
        new_tracee_handler.start(move || {
            if fail_fast && new_tracee_handler2.failed() {
                let _ = sys::signal::kill(root_pid, Some(sys::signal::Signal::SIGKILL))
                    .map_err(display_err);
            }
        });

        self.call_mods(ModFeature::OnCloneComplete, |m| {
            m.on_clone_complete(child_pid.as_raw() as isize)
        })?;
        Ok(())
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
        span!(Level::ERROR, "event_loop", "{:?}", self.pid)
    }

    pub fn start<F>(
        self: Arc<TraceeHandler<PtraceClient>>,
        callback: F,
    ) -> thread::JoinHandle<Option<u8>>
    where
        F: FnOnce() + Send + 'static,
    {
        let thread_name = format!("tracer-{}", self.pid);
        let new_thread = thread::Builder::new().name(thread_name);
        new_thread
            .spawn(move || {
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
            .unwrap()
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

    pub fn ptrace_syscall(&self) -> Result<(), SysAugError> {
        let pid = self.pid;
        let maybe_signal = rwoption_take(&self.signal_tracee)?;
        event!(Level::TRACE, "PTRACE_SYSCALL");
        self.ptrace_client
            .execute(move || sys::ptrace::syscall(pid, maybe_signal))?
            .map_err(SysAugError::PtraceSyscall)?;
        Ok(())
    }

    pub fn event_loop(self: Arc<TraceeHandler<PtraceClient>>) -> Result<u8, SysAugError> {
        let pid = self.pid;

        self.ptrace_client.attach_to(pid)?;
        self.set_ptrace_options()?;
        self.call_mods(ModFeature::OnTraceeStartup, |m| m.on_tracee_startup())?;
        self.ptrace_syscall()?; // Because we did waitpid in self.set_ptrace_options

        loop {
            let status = ptrace::waitpid_hang(Pid::from_raw(-1 as i32))?;
            let pid2 = status.pid();

            if !ptrace::is_trace_stop(&status) && !ptrace::is_still_alive(&status) {
                info!("Process {:?} crashed: {:?}.", &pid, &status);
                self.handle_exit(pid)?;
                return Err(SysAugError::TraceeCrashed);
            }

            if let (Some(child_pid), true) = (pid2, pid2 != Some(pid)) {
                if !matches!(&status, &WaitStatus::Stopped(_, _)) {
                    event!(Level::DEBUG, "ignoring grandchild event {:?}", &status);
                    continue;
                }

                // This is a new tracee, create a new tracer thread.
                event!(Level::INFO, "new child, status {:?}", &status);
                self.fork(child_pid)?;
                continue;
            }

            let mut maybe_exit: Option<u8> = None;
            let _ = self.on_tracee_stopped(&status, &mut maybe_exit)?
                && self.on_tracee_exited(&status, &mut maybe_exit)?
                && self.on_tracee_syscall(&status, &mut maybe_exit)?;

            if let Some(exit_code) = maybe_exit {
                return Ok(exit_code);
            }
            self.ptrace_syscall()?;
        }
    }

    fn on_tracee_stopped(&self, s: &WaitStatus, exit: &mut Option<u8>) -> BoolResult {
        let pid = self.pid;
        if let &WaitStatus::Stopped(_, signal) = &s {
            event!(Level::DEBUG, "child stopped, status {:?}", &s);
            if signal == &sys::signal::Signal::SIGTRAP {
                return Ok(false);
            }
            let getsig_err = self
                .ptrace_client
                .execute(move || sys::ptrace::getsiginfo(pid))?
                .err();
            if getsig_err == Some(nix::Error::Sys(nix::errno::Errno::EINVAL)) {
                return Ok(false);
            }
            if signal == &sys::signal::Signal::SIGSTOP {
                if let Some(parent) = self.parent.as_ref() {
                    let ignore_sigstops = rwlock_read(&parent.ignore_sigstops)?;
                    if ignore_sigstops.contains(&pid) {
                        return Ok(false);
                    }
                }
            }
            if signal == &sys::signal::Signal::SIGSEGV && self.states.args.gdb {
                info!("Tracee segfault. Starting gdb");
                exit.replace(self.transfer_to_gdb()?);
                return Ok(false);
            }
            info!("Will deliver signal {:?} to {:?}", &signal, &pid);
            rwoption_replace(&self.signal_tracee, *signal)?;
            return Ok(false);
        }
        Ok(true)
    }

    fn on_tracee_exited(&self, s: &WaitStatus, exit: &mut Option<u8>) -> BoolResult {
        let pid = self.pid;
        if let &WaitStatus::PtraceEvent(_, _, libc::PTRACE_EVENT_EXIT) = &s {
            let rawret = self
                .ptrace_client
                .execute(move || ptrace::getevent(pid))??;
            let retcode = (rawret as u32) >> 8;
            info!("Exit status = {}", retcode);
            self.handle_exit(pid)?;
            exit.replace(retcode as u8);
            return Ok(false);
        }
        Ok(true)
    }

    fn on_tracee_syscall(&self, s: &WaitStatus, exit: &mut Option<u8>) -> BoolResult {
        let pid = self.pid;
        if ptrace::is_syscall_stop(&s) {
            let regs = self.ptrace_client.execute(move || ptrace::getregs(pid))??;
            let syscall_info = SYSCALL_INFOS.get(&regs.syscall_num);
            let syscall_num_str = regs.syscall_num.to_string();
            let syscall_name = syscall_info.map(|x| x.name()).unwrap_or(&syscall_num_str);
            {
                let mut last_syscall = rwlock_write(&self.last_syscall)?;
                last_syscall.count(regs.syscall_num, syscall_info);
            }

            let last_syscall = rwlock_read(&self.last_syscall)?;
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
            event!(
                Level::TRACE,
                "syscall event, stack@{:x}",
                ptrace::stack_ptr()
            );
            if self.states.args.gdb_at == Some(last_syscall.total_times) {
                exit.replace(self.transfer_to_gdb()?);
                return Ok(false);
            }

            // For maximum performance, we hardcode the jump table.
            let maybe_augments = rwlock_read(&self.augments)?;
            let augments = maybe_augments.as_ref().unwrap();
            match which_aug {
                Some(Augments::Clone) => augments.clone.dispatch(&last_syscall, regs),
                Some(Augments::Exec) => augments.exec.dispatch(&last_syscall, regs),
                Some(Augments::Paths) => augments.paths.dispatch(&last_syscall, regs),
                Some(Augments::Perms) => augments.perms.dispatch(&last_syscall, regs),
                Some(Augments::Waitpid) => augments.waitpid.dispatch(&last_syscall, regs),
                Some(Augments::Unimplemented) => Err(SysAugError::UnimplementedAugment),
                _ => Ok(()),
            }
            .map_err(display_err)?;
            if let Some(info) = syscall_info {
                if info.sets_file_perms.is_some() {
                    self.call_mods(ModFeature::OnSetsPerms, |m| m.on_sets_perms(info))?;
                }
            }

            drop(last_syscall); // Otherwise, deadlock.
            self.maybe_skip_syscall()?;
            return Ok(false);
        }
        Ok(true)
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

    fn maybe_skip_syscall(&self) -> Result<(), SysAugError> {
        let pid = self.pid;
        let mut last_syscall = rwlock_write(&self.last_syscall)?;
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
