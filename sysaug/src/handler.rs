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
use executor::{PtraceAsyncRuntime, PtraceAsyncYielder, PtraceFutureTypes, PtraceStatus};
use nix::sys;
use nix::sys::wait::WaitStatus;
use nix::unistd::Pid;
use ptrace::{GenericPurposeRegs, SHARED_MMAP_SIZE};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::convert::{TryFrom, TryInto};
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use sys::signal::Signal;
use tracing::{event, info, span, Level};

#[derive(Clone, Debug, Default)]
pub struct CLIArgs {
    pub chroot: Option<PathBuf>,
    pub rootfs: Option<PathBuf>,
    pub fail_fast: bool,
    pub fix_sigsys: bool,
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
    pub pid: Pid,
    pub root_pid: Pid,
}

struct AugmentContainer<PtraceClient: executor::PtraceClient> {
    clone: AugmentClone<PtraceClient>,
    exec: AugmentExec<PtraceClient>,
    paths: AugmentPaths<PtraceClient>,
    perms: AugmentPerms<PtraceClient>,
    waitpid: AugmentWaitpid<PtraceClient>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u8)]
pub enum TraceeInitStage {
    /// Waiting for Exec
    Begin = 0,
    /// Intercepted exec
    ExecSeen = 1,
    /// Intercepted first call
    FirstCallSeen = 2,
    /// Intercepted the mmap call that replaced the first call
    FirstCallReplacedWithMmap = 3,
    /// Intercepted the final actual first call
    FirstCallActuallyDone = 4,
}

impl TryFrom<u8> for TraceeInitStage {
    type Error = SysAugError;
    fn try_from(val: u8) -> Result<Self, Self::Error> {
        match val {
            0 => Ok(TraceeInitStage::Begin),
            1 => Ok(TraceeInitStage::ExecSeen),
            2 => Ok(TraceeInitStage::FirstCallSeen),
            3 => Ok(TraceeInitStage::FirstCallReplacedWithMmap),
            4 => Ok(TraceeInitStage::FirstCallActuallyDone),
            _ => Err(SysAugError::BadInitStage(val)),
        }
    }
}

pub struct TraceeHandler<PtraceClient: executor::PtraceClient> {
    pub mods: RwLock<ModsByFeature>,
    mod_providers: Vec<ModProvider>,
    pub pid: Pid,
    pub ptrace_client: PtraceClient,
    pub states: Arc<TraceeHandlerStates>,
    pub parent: Option<Arc<TraceeHandler<PtraceClient>>>,

    pub curr_paths: RwLock<Option<[Option<PathBuf>; 4]>>,
    pub orig_request_regs: RwLock<Option<GenericPurposeRegs>>,
    pub orig_wait_status: RwLock<usize>,
    // ignore the next sigstop for the following pids
    pub ignore_sigstops: RwLock<HashSet<Pid>>,
    pub signal_tracee: RwLock<Option<Signal>>,
    pub skip_syscall_retval: RwLock<Option<usize>>,
    pub nosys_syscall_retval: RwLock<Option<usize>>,
    pub tracee_stack_offset: RwLock<usize>,
    pub mmap_tracee_addr: RwLock<usize>,
    pub tracee_init_stage: RwLock<TraceeInitStage>,

    augments: RwLock<Option<AugmentContainer<PtraceClient>>>,
    last_syscall: RwLock<SyscallCounter>,

    /// Readonly, Copy on Move, values
    pub shared_fd: RawFd,
    pub mmap_tracer_addr: usize,
}

/// Events reported from async loop back to the Runtime without resolving async loop
#[derive(Default)]
struct AsyncNotifications {
    signal_tracee: RefCell<Option<Signal>>,
    transfer_to_gdb: RefCell<bool>,
}

struct AsyncTraceeHandler<'a, PtraceClient: executor::PtraceClient> {
    async_runtime: &'a PtraceAsyncRuntime,
    cli_args: CLIArgs,
    pid: Pid,
    ptrace_client: PtraceClient,

    notifiers: AsyncNotifications,

    /// Yield until the next syscall poll has happened
    yielder_syscall: PtraceAsyncYielder,
}

impl<PtraceClient: executor::PtraceClient> AsyncTraceeHandler<'_, PtraceClient> {
    /// Returns: the tracee exit code
    async fn all_tracee_loops(&self) -> Result<u8, SysAugError> {
        futures_lite::future::or(
            futures_lite::future::or(
                self.loop_handle_tracee_signals(),
                self.loop_handle_tracee_exit(),
            ),
            self.loop_handle_tracee_syscalls(),
        )
        .await
    }

    /// Creates a future from raw PtraceFuture to wait for any signal
    async fn wait_for_any_signal(&self) -> Result<Signal, SysAugError> {
        let status = self
            .async_runtime
            .new_ptrace_future(PtraceFutureTypes::WaitForSignal)
            .await;
        if let WaitStatus::Stopped(_, signal) = status.wait_status {
            return Ok(signal);
        }
        Err(SysAugError::AsyncMismatch(
            PtraceFutureTypes::WaitForSignal,
            (*status).clone(),
        ))
    }

    /// Wait for a specific signal
    async fn wait_for_signal(&self, signal: Signal) -> Result<(), SysAugError> {
        loop {
            let signal2 = self.wait_for_any_signal().await?;
            if signal == signal2 {
                return Ok(());
            }
        }
    }

    async fn loop_handle_tracee_signals(&self) -> Result<u8, SysAugError> {
        let pid = self.pid;
        loop {
            let signal = self.wait_for_any_signal().await?;
            let getsig_ans = self
                .ptrace_client
                .execute(move || sys::ptrace::getsiginfo(pid))?;
            if getsig_ans.err() == Some(nix::errno::Errno::EINVAL) {
                continue;
            }
            if signal == Signal::SIGSYS && self.cli_args.fix_sigsys {
                // Android sometimes kills a process for using privileged syscalls like sysinfo()
                // Instead of killing tracee, return -ENOSYS and let it resume
                let siginfo = getsig_ans.map_err(SysAugError::PtraceGetSigInfo2)?;
                let mut regs = self.ptrace_client.execute(move || ptrace::getregs(pid))??;
                if siginfo.si_code > 0 {
                    // Signal was sent by kernel, so it's safe to assume a syscall just happened.
                    let mut retval = (-libc::ENOSYS) as usize;

                    // TODO: This is bad for security. OTher processes can replace register by running
                    //              kill -NOSYS <tracee pid>
                    event!(
                        Level::WARN,
                        "blocking SIGSYS and returning ENOSYS instead (UNSAFE)",
                    );

                    // If we were trying to override a syscall, follow that override.
                    if regs.syscall_num == NO_MOD_SYSCALL {
                        self.yielder_syscall.yield_now().await;
                        continue;
                    }

                    // Otherwise, override return value to -ENOSYS
                    regs.set_syscall_retval(retval);
                    self.ptrace_client
                        .execute(move || ptrace::setregs(pid, regs))??;

                    continue;
                }
            }
            if signal == Signal::SIGSEGV && self.cli_args.gdb {
                info!("Tracee segfault. Starting gdb");
                *self.notifiers.transfer_to_gdb.borrow_mut() = true;
                return Ok(0);
            }
            info!("Will deliver signal {:?} to {:?}", &signal, &pid);
            self.notifiers.signal_tracee.borrow_mut().replace(signal);
        }
        Ok(0)
    }

    async fn loop_handle_tracee_exit(&self) -> Result<u8, SysAugError> {
        loop {
            futures_lite::future::pending::<()>().await;
        }
        Ok(0)
    }

    async fn loop_handle_tracee_syscalls(&self) -> Result<u8, SysAugError> {
        // lookup the correct syscall handler, call it as an async func
        //
        // Then, within this  async func, we can do things like
        //
        // if (needs_mmap_init)
        // await tracee_init_mmap()
        //
        // or even, within the mod async func
        //
        // await tracee_memcpy_from_mmap()
        //
        // So that the async logics themselves are fluid.
        loop {
            let status = self
                .async_runtime
                .new_ptrace_future(PtraceFutureTypes::WaitForPtraceSyscall)
                .await;
            self.yielder_syscall.unblock();
        }
        Ok(0)
    }
}

type BoolResult = Result<bool, SysAugError>;

macro_rules! new_augment {
    ($type:ty, $self:ident) => {
        <$type>::new(Arc::clone(&$self))
    };
}

impl<PtraceClient: executor::PtraceClient> TraceeHandler<PtraceClient> {
    pub fn new(
        pid: Pid,
        ptrace_client: PtraceClient,
        mods: Vec<ModProvider>,
        states: Option<Arc<TraceeHandlerStates>>,
        parent: Option<Arc<TraceeHandler<PtraceClient>>>,
        shared_fd: RawFd,
        mmap_addr: usize,
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
            signal_tracee: RwLock::default(),
            skip_syscall_retval: RwLock::default(),
            nosys_syscall_retval: RwLock::default(),
            tracee_stack_offset: RwLock::default(),
            tracee_init_stage: RwLock::new(TraceeInitStage::Begin),
            mmap_tracee_addr: RwLock::default(),
            mmap_tracer_addr: mmap_addr,
            shared_fd,
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
    fn fork(
        self: &Arc<TraceeHandler<PtraceClient>>,
        child_pid: Pid,
    ) -> Result<Arc<TraceeHandler<PtraceClient>>, SysAugError> {
        TraceeHandler::new(
            child_pid,
            self.ptrace_client.clone(),
            self.mod_providers.clone(),
            Some(self.states.clone()),
            Some(Arc::clone(self)),
            self.shared_fd,
            self.mmap_tracer_addr,
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
                        | sys::ptrace::Options::PTRACE_O_TRACEEXIT
                        | sys::ptrace::Options::PTRACE_O_TRACECLONE
                        | sys::ptrace::Options::PTRACE_O_TRACEFORK
                        | sys::ptrace::Options::PTRACE_O_TRACEVFORK,
                )
            })?
            .map_err(SysAugError::PtraceSetOptions)?;
        Ok(())
    }

    pub fn handle_exit(&self, pid: Pid) -> Result<(), SysAugError> {
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
                    let _ =
                        sys::signal::kill(self2.pid, Some(Signal::SIGKILL)).map_err(display_err);
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
            unsafe { ptrace::write_bytes_to_tracee(pid, old_offset, final_bytes) }
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

    pub fn ptrace_syscall(&self, maybe_signal: Option<Signal>) -> Result<(), SysAugError> {
        let pid = self.pid;
        event!(Level::TRACE, "PTRACE_SYSCALL");
        self.ptrace_client
            .execute(move || sys::ptrace::syscall(pid, maybe_signal))?
            .map_err(SysAugError::PtraceSyscall)?;
        Ok(())
    }

    pub fn event_loop(self: Arc<TraceeHandler<PtraceClient>>) -> Result<u8, SysAugError> {
        let pid = self.pid;

        // Initialize and store async loops and futures
        let async_runtime = PtraceAsyncRuntime::default();
        let async_handlers = AsyncTraceeHandler {
            async_runtime: &async_runtime,
            cli_args: self.states.args.clone(),
            pid: pid.clone(),
            ptrace_client: self.ptrace_client.clone(),
            notifiers: AsyncNotifications::default(),
            yielder_syscall: PtraceAsyncYielder::default(),
        };
        let mut main_loop_future = async_handlers.all_tracee_loops();

        // Attach ptrace to tracee
        self.ptrace_client.attach_to(pid)?;
        self.set_ptrace_options()?;
        self.call_mods(ModFeature::OnTraceeStartup, |m| m.on_tracee_startup())?;

        loop {
            // Drive async logic until it waits for PtraceFutureTypes
            if let Some(exit_code) = async_runtime.run_async_step(&mut main_loop_future)? {
                return Ok(exit_code?);
            }

            // Handle special crashes, signals, etc
            if *async_handlers.notifiers.transfer_to_gdb.borrow() {
                return Ok(self.transfer_to_gdb()?);
            }
            let mut maybe_signal = { async_handlers.notifiers.signal_tracee.borrow_mut().take() };

            loop {
                // Wait for tracee updates, until we have unblocked a future
                // Also, use maybe_signal.take() so that the signal is only sent once
                self.ptrace_syscall(maybe_signal.take())?;
                let wait_status = ptrace::waitpid_hang(pid)?;
                event!(Level::TRACE, "child status {:?}", &wait_status);

                let status = PtraceStatus {
                    wait_status: wait_status.clone(),
                };

                // Unblock different PtraceFutureTypes in the proper order
                if let Some(..) = self.get_tracee_maybe_signal(&wait_status)? {
                    async_runtime.unblock_futures(PtraceFutureTypes::WaitForSignal, status);
                    break;
                } else if let WaitStatus::PtraceEvent(..) = &wait_status {
                    async_runtime.unblock_futures(PtraceFutureTypes::WaitForPtraceEvent, status);
                    break;
                } else if let WaitStatus::PtraceSyscall(..) = &wait_status {
                    async_runtime.unblock_futures(PtraceFutureTypes::WaitForPtraceSyscall, status);
                    break;
                } else {
                    event!(Level::INFO, "Unknown ptrace event: {:?}", &wait_status);
                }
            }

            // Old async logic:
            // if !ptrace::is_trace_stop(&status) && !ptrace::is_still_alive(&status) {
            //     info!("Process {:?} crashed: {:?}.", &pid, &status);
            //     self.handle_exit(pid)?;
            //     return Err(SysAugError::TraceeCrashed);
            // }

            // let mut maybe_exit: Option<u8> = None;
            // let _ = self.on_tracee_signaled(&status, &mut maybe_exit)?
            //     && self.on_tracee_exited(&status, &mut maybe_exit)?
            //     && self.on_tracee_init_syscalls(&status, &mut maybe_exit)?
            //     && self.on_tracee_syscall(&status, &mut maybe_exit)?
            //     && self.on_tracee_clone(&status, &mut maybe_exit)?
            //     && self.on_tracee_unknown_event(&status, &mut maybe_exit)?;

            // if let Some(exit_code) = maybe_exit {
            //     return Ok(exit_code);
            // }
        }
    }

    fn get_tracee_maybe_signal<'a>(
        &self,
        s: &'a WaitStatus,
    ) -> Result<Option<&'a Signal>, SysAugError> {
        let pid = self.pid;
        if let WaitStatus::Stopped(_, signal) = s {
            event!(Level::DEBUG, "child stopped, status {:?}", &s);
            if signal == &Signal::SIGTRAP {
                return Ok(None);
            }
            let getsig_ans = self
                .ptrace_client
                .execute(move || sys::ptrace::getsiginfo(pid))?;
            if getsig_ans.err() == Some(nix::errno::Errno::EINVAL) {
                return Ok(None);
            }
            return Ok(Some(signal));
        }
        Ok(None)
    }

    fn on_tracee_signaled(&self, s: &WaitStatus, exit: &mut Option<u8>) -> BoolResult {
        let pid = self.pid;
        if let WaitStatus::Stopped(_, signal) = s {
            event!(Level::DEBUG, "child stopped, status {:?}", &s);
            if signal == &Signal::SIGTRAP {
                return Ok(false);
            }
            let getsig_ans = self
                .ptrace_client
                .execute(move || sys::ptrace::getsiginfo(pid))?;
            if getsig_ans.err() == Some(nix::errno::Errno::EINVAL) {
                return Ok(false);
            }
            if signal == &Signal::SIGSTOP {
                if let Some(parent) = self.parent.as_ref() {
                    let ignore_sigstops = rwlock_read(&parent.ignore_sigstops)?;
                    if ignore_sigstops.contains(&pid) {
                        return Ok(false);
                    }
                }
            }
            if signal == &Signal::SIGSYS && self.states.args.fix_sigsys {
                // Android sometimes kills a process for using privileged syscalls like sysinfo()
                // Instead of killing tracee, return -ENOSYS and let it resume
                let siginfo = getsig_ans.map_err(SysAugError::PtraceGetSigInfo2)?;
                let mut regs = self.ptrace_client.execute(move || ptrace::getregs(pid))??;
                if siginfo.si_code > 0 {
                    // Signal was sent by kernel, so it's safe to assume a syscall just happened.
                    let mut retval = (-libc::ENOSYS) as usize;

                    // TODO: This is bad for security. OTher processes can replace register by running
                    //              kill -NOSYS <tracee pid>
                    event!(
                        Level::WARN,
                        "blocking SIGSYS and returning ENOSYS instead (UNSAFE)",
                    );

                    // If we were trying to override a syscall, follow that override.
                    if regs.syscall_num == NO_MOD_SYSCALL {
                        let mut maybe_skip = rwlock_write(&self.nosys_syscall_retval)?;
                        if let Some(new_retval) = maybe_skip.take() {
                            event!(
                                Level::DEBUG,
                                "Replacing syscall return value {} with {}",
                                retval,
                                new_retval
                            );
                            retval = new_retval;
                        }
                    }

                    // Otherwise, override return value to -ENOSYS
                    regs.set_syscall_retval(retval);
                    self.ptrace_client
                        .execute(move || ptrace::setregs(pid, regs))??;

                    return Ok(false);
                }
            }
            if signal == &Signal::SIGSEGV && self.states.args.gdb {
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
        if let WaitStatus::PtraceEvent(_, _, libc::PTRACE_EVENT_EXIT) = s {
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

    /// This should cover all cases of clone, fork, vfork, etc.
    fn on_tracee_clone(
        self: &Arc<TraceeHandler<PtraceClient>>,
        s: &WaitStatus,
        _exit: &mut Option<u8>,
    ) -> BoolResult {
        let pid = self.pid;
        if matches!(
            s,
            WaitStatus::PtraceEvent(_, _, libc::PTRACE_EVENT_CLONE)
                | WaitStatus::PtraceEvent(_, _, libc::PTRACE_EVENT_FORK)
                | WaitStatus::PtraceEvent(_, _, libc::PTRACE_EVENT_VFORK)
        ) {
            let raw_pid = self
                .ptrace_client
                .execute(move || ptrace::getevent(pid))?? as isize;
            if raw_pid > 0 {
                let child_pid: Pid = Pid::from_raw(raw_pid as i32);

                self.ptrace_client
                    .prep_attach_to(child_pid, &self.ignore_sigstops)?;

                let new_tracee_handler = self.fork(child_pid)?;
                let new_tracee_handler2 = Arc::clone(&new_tracee_handler);
                let root_pid = self.states.root_pid;
                let fail_fast = self.states.args.fail_fast;
                new_tracee_handler.start(move || {
                    if fail_fast && new_tracee_handler2.failed() {
                        let _ =
                            sys::signal::kill(root_pid, Some(Signal::SIGKILL)).map_err(display_err);
                    }
                });

                self.call_mods(ModFeature::OnCloneComplete, |m| {
                    m.on_clone_complete(raw_pid as isize)
                })?;
            }
            return Ok(false);
        }
        Ok(true)
    }

    /// This should cover all cases of clone, fork, vfork, etc.
    fn on_tracee_unknown_event(&self, s: &WaitStatus, _exit: &mut Option<u8>) -> BoolResult {
        event!(Level::INFO, "Unknown ptrace event: {:?}", s);
        Ok(true)
    }

    fn on_tracee_syscall(&self, s: &WaitStatus, exit: &mut Option<u8>) -> BoolResult {
        let pid = self.pid;
        if ptrace::is_syscall_stop(s) {
            let regs = self.ptrace_client.execute(move || ptrace::getregs(pid))??;
            let syscall_info = SYSCALL_INFOS.get(&regs.syscall_num);
            let syscall_num_str = regs.syscall_num.to_string();
            let syscall_name = syscall_info.map(|x| x.name()).unwrap_or(&syscall_num_str);
            {
                let mut last_syscall = rwlock_write(&self.last_syscall)?;
                last_syscall.count(regs.syscall_num, syscall_info);
            }

            let last_syscall = rwlock_read(&self.last_syscall)?;
            let tracee_init_stage = { *(rwlock_read(&self.tracee_init_stage)?) };
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

            if tracee_init_stage != TraceeInitStage::FirstCallActuallyDone
                && which_aug == Some(&Augments::Exec)
            {
                rwlock_replace(&self.tracee_init_stage, TraceeInitStage::ExecSeen)?;
                return Ok(true);
            }
            return Ok(false);
        }
        Ok(true)
    }

    fn on_tracee_init_syscalls(&self, s: &WaitStatus, exit: &mut Option<u8>) -> BoolResult {
        let pid = self.pid;
        let mut last_stage = { *(rwlock_read(&self.tracee_init_stage)?) };
        if last_stage == TraceeInitStage::Begin {
            // Waiting for exec (which will be marked by on_tracee_syscall)
            return Ok(true);
        }
        if last_stage == TraceeInitStage::FirstCallActuallyDone {
            return Ok(true);
        }
        if ptrace::is_syscall_stop(s) {
            let mut regs = self.ptrace_client.execute(move || ptrace::getregs(pid))??;
            let syscall_info = SYSCALL_INFOS.get(&regs.syscall_num);
            if regs.syscall_num == NO_MOD_SYSCALL {
                // If we are trying to skip a syscall, allow that to go through
                return Ok(true);
            }
            if syscall_info.map(|x| &x.augment) == Some(&Augments::Exec) {
                return Ok(true);
            }

            if last_stage == TraceeInitStage::ExecSeen {
                // Last stage is ExecSeen and we are no longer seeing Exec syscall
                last_stage = TraceeInitStage::FirstCallSeen;
            }

            // Make sure we bookkeep the value of tracee_init_stage for next round
            let new_stage: TraceeInitStage = (last_stage as u8 + 1).try_into().unwrap();
            rwlock_replace(&self.tracee_init_stage, new_stage)?;
            event!(
                Level::INFO,
                "TraceeInitStage: {:?} syscall {:?}",
                &last_stage,
                &regs.syscall_num
            );

            // Handle a few special stages for the current round
            match last_stage {
                TraceeInitStage::FirstCallSeen => {
                    rwoption_replace(&self.orig_request_regs, regs.clone())?;

                    // TODO: Block Tracee from accessing the entire MMAP. Expose only its own.
                    regs.arg0 = 0;
                    regs.arg1 = SHARED_MMAP_SIZE;
                    regs.arg2 = libc::PROT_READ as usize;
                    regs.arg3 = libc::MAP_SHARED as usize;
                    regs.arg4 = self.shared_fd as usize;
                    regs.arg5 = 0;

                    self.ptrace_client
                        .execute(move || ptrace::setregs(pid, regs))??;
                    self.ptrace_client
                        .execute(move || ptrace::set_syscall_num(pid, libc::SYS_mmap as usize))??;
                    return Ok(false);
                }
                TraceeInitStage::FirstCallReplacedWithMmap => {
                    let orig_regs = rwoption_take(&self.orig_request_regs)?
                        .ok_or(SysAugError::InitMissingSavedRegs)?;
                    let orig_syscall_num = orig_regs.syscall_num;
                    let mut tracee_addr = rwlock_write(&self.mmap_tracee_addr)?;
                    *tracee_addr = regs.syscall_retval();

                    event!(
                        Level::INFO,
                        "Tracee mounted mmap address: {:x}",
                        regs.syscall_retval()
                    );
                    self.ptrace_client
                        .execute(move || ptrace::setregs(pid, orig_regs))??;
                    self.ptrace_client
                        .execute(move || ptrace::set_syscall_num(pid, orig_syscall_num))??;
                    return Ok(false);
                }
                _ => {}
            }
        }
        Ok(true)
    }

    fn transfer_to_gdb(&self) -> Result<u8, SysAugError> {
        let pid = self.pid;
        self.ptrace_client
            .execute(move || sys::ptrace::detach(pid, Signal::SIGSTOP))?
            .map_err(SysAugError::GDBDetach)?;
        let mut cmd = std::process::Command::new("gdb");
        cmd.arg("-p").arg(pid.as_raw().to_string());
        let status = cmd.status().map_err(SysAugError::GDB)?;
        Ok(status.code().unwrap_or(-1) as u8)
    }

    fn maybe_skip_syscall(&self) -> Result<(), SysAugError> {
        {
            let mut maybe_nosys = rwlock_write(&self.nosys_syscall_retval)?;
            let _ = maybe_nosys.take();
        }

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
                rwoption_replace(&self.nosys_syscall_retval, retval)?;
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
            pid: Pid::from_raw(0),
            root_pid: Pid::from_raw(0),
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
