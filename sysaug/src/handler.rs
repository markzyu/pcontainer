// Copyright 2026 Zhongzhi Yu <7296488+markzyu@users.noreply.github.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.

use crate::common::{
    display_err, rwlock_read, rwlock_replace, Augments, ModBox, ModProvider, ModsByFeature,
    PermsMode, SysAugError, NO_MOD_SYSCALL,
};
use crate::config::{init_passthroughs_from_config, init_perms_ids_from_config, SysAugConfig, PERMS_IDS_SIZE};
use crate::mods::{ModAction, ModFeature};
use crate::rwlock_write;
use crate::syscalls::{get_syscall, SYSCALL_INSTRUCTION_SIZE};
use executor::{PtraceAsyncRuntime, PtraceAsyncYielder, PtraceFutureTypes, PtraceStatus};
use nix::sys;
use nix::sys::wait::WaitStatus;
use nix::unistd::Pid;
use ptrace::{
    get_own_region_id, set_tracee_write_region_addr, GenericPurposeRegs, MemHelpers,
    DIRECT_MEM_HELPERS, SLOW_MEM_HELPERS, STACK_SAFE_ZONE_SIZE,
};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock, Weak};
use std::thread;
use sys::signal::Signal;
use tracing::{event, info, span, Level};

#[cfg(not(target_arch = "arm"))]
const SYS_mmap: usize = libc::SYS_mmap as usize;
#[cfg(target_arch = "arm")]
const SYS_mmap: usize = libc::SYS_mmap2 as usize;

#[cfg(not(target_arch = "arm"))]
const SYS_mmap_pgoffset_block: usize = 1;
#[cfg(target_arch = "arm")]
const SYS_mmap_pgoffset_block: usize = 4096;

thread_local! {
    static MEM: RefCell<MemHelpers> = RefCell::new(SLOW_MEM_HELPERS.clone());
}

pub fn get_mem_helper() -> MemHelpers {
    MEM.with_borrow(|cell| cell.clone())
}

#[derive(Clone, Debug, Default)]
pub struct CLIArgs {
    pub chroot: Option<PathBuf>,
    pub rootfs: Option<PathBuf>,
    pub perms_mode: PermsMode,
    pub fail_fast: bool,
    pub fix_sigsys: bool,
    pub fix_mmap: bool,
    pub gdb: bool,
    pub gdb_at: Option<u64>,

    /// Use the host ld.so instead of the one from the chroot environment
    pub use_native_loader: bool,
}

#[derive(Debug)]
pub struct TraceeHandlerStates {
    pub args: CLIArgs,
    pub config: SysAugConfig,
    pub failed: AtomicBool,
    pub perms_ids: RwLock<[Option<usize>; PERMS_IDS_SIZE]>,
    pub path_prefix: RwLock<Option<PathBuf>>,
    pub path_prefix_excludes: RwLock<Vec<PathBuf>>,
    pub pid: Pid,
    pub root_pid: Pid,
}

/// Call augment without having to rely on the slow dyn Boxes
macro_rules! call_augment {
    ($self: ident, $augment: expr, $regs: expr, $syscall: expr) => {
        match $augment {
            Some(Augments::Clone) => $self.augment_sys_clone($regs, $syscall).await,
            Some(Augments::Exec) => $self.augment_sys_exec($regs, $syscall).await,
            Some(Augments::Paths) => $self.augment_sys_paths($regs, $syscall).await,
            Some(Augments::Perms) => $self.augment_sys_perms($regs, $syscall).await,
            Some(Augments::Waitpid) => $self.augment_sys_waitpid($regs, $syscall).await,
            Some(Augments::Unimplemented) => Err(SysAugError::UnimplementedAugment),
            _ => Ok(()),
        }
        .map_err(display_err)?;
    };
}

pub struct TraceeHandler<PtraceClient: executor::PtraceClient> {
    mod_providers: Vec<ModProvider>,
    pub pid: Pid,
    pub ptrace_client: PtraceClient,
    pub states: Arc<TraceeHandlerStates>,
    pub parent: Option<Arc<TraceeHandler<PtraceClient>>>,

    // ignore the next sigstop for the following pids
    pub ignore_sigstops: Arc<RwLock<HashSet<Pid>>>,

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

pub struct AsyncTraceeHandler<'a, PtraceClient: executor::PtraceClient> {
    // Readonly, Copy on Move, values
    pub async_runtime: &'a PtraceAsyncRuntime,
    pub cli_args: CLIArgs,
    pub pid: Pid,
    pub shared_fd: RawFd,

    // References to other helpers
    pub mods: ModsByFeature,
    pub states: Arc<TraceeHandlerStates>,
    pub parent: Option<Arc<TraceeHandler<PtraceClient>>>,
    pub sync_handler: Weak<TraceeHandler<PtraceClient>>,
    pub ptrace_client: PtraceClient,
    pub ignore_sigstops: Arc<RwLock<HashSet<Pid>>>,

    /// Yield until the next syscall poll has happened
    pub yielder_syscall: PtraceAsyncYielder,

    // Actual shared states that are owned by this AsyncTraceeHandler
    pub mmap_tracee_addr: RefCell<usize>,
    notifiers: AsyncNotifications,
    pub tracee_stack_offset: RefCell<usize>,
}

impl<PtraceClient: executor::PtraceClient> AsyncTraceeHandler<'_, PtraceClient> {
    /// Returns: the tracee exit code
    async fn all_tracee_loops(&self) -> Result<u8, SysAugError> {
        // Initialize
        init_perms_ids_from_config(&self.states.perms_ids, &self.states.config.perms)?;
        if self.states.args.chroot.is_some() {
            let mut path_prefix_excludes = rwlock_write(&self.states.path_prefix_excludes)?;
            init_passthroughs_from_config(&mut *path_prefix_excludes, &self.states.config.rootfs);
        }

        // Event loops
        // (The order here matters. It's the order of polling precedence.)
        let result = futures_lite::future::or(
            futures_lite::future::or(
                self.loop_handle_tracee_signals(),
                self.loop_handle_tracee_syscalls(),
            ),
            self.loop_handle_tracee_other_events(),
        )
        .await;

        // Cleanup
        let pid = self.pid;
        let MemHelpers { close_tracee, .. } = get_mem_helper();
        (close_tracee)(&pid)?;
        result
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

    async fn wait_for_syscall(&self) -> Result<PtraceStatus, SysAugError> {
        let status = self
            .async_runtime
            .new_ptrace_future(PtraceFutureTypes::WaitForPtraceSyscall)
            .await;
        if !ptrace::is_syscall_stop(&status.wait_status) {
            return Err(SysAugError::AsyncMismatch(
                PtraceFutureTypes::WaitForSignal,
                (*status).clone(),
            ));
        }
        Ok((*status).clone())
    }

    pub fn call_first_mod<F, T>(
        &self,
        feature: ModFeature,
        func: F,
    ) -> Result<Option<T>, SysAugError>
    where
        F: Fn(&ModBox) -> Result<T, SysAugError>,
    {
        let mod_map = &self.mods;
        if let Some(mods_) = mod_map.get(&feature) {
            if let Some(m) = mods_.get(0) {
                return Ok(Some(func(m)?));
            }
        }
        Ok(None)
    }

    pub async fn call_mods<F>(&self, feature: ModFeature, func: F) -> Result<(), SysAugError>
    where
        F: Fn(&ModBox) -> Result<ModAction, SysAugError>,
    {
        let mod_map = &self.mods;
        if let Some(mods_) = mod_map.get(&feature) {
            for m in mods_.iter() {
                match func(m)? {
                    ModAction::SkipSyscall(retval) => {
                        self.do_skip_syscall(retval).await?;
                    }
                    ModAction::None => (),
                }
            }
        }
        Ok(())
    }

    // Send the content of `bytes` to tracee's stack, and return its address.
    // This can be called multiple times and will add new content to the end of
    // previous contents.
    pub fn tracee_stack_append(&self, bytes: Vec<u8>) -> Result<usize, SysAugError> {
        let MemHelpers {
            write_bytes_to_tracee,
            ..
        } = get_mem_helper();
        let pid = self.pid;
        let mut offset = self.tracee_stack_offset.borrow_mut();
        let old_offset = *offset;
        let (addr, new_offset) = self.ptrace_client.execute(move || {
            let final_bytes = bytes.as_slice();
            unsafe { (write_bytes_to_tracee)(pid, old_offset, final_bytes) }
        })??;
        *offset = new_offset;
        Ok(addr)
    }

    pub fn tracee_stack_append_str(&self, val: String) -> Result<usize, SysAugError> {
        let mut bytes: Vec<u8> = val.into();
        bytes.push(0);
        self.tracee_stack_append(bytes)
    }

    pub fn tracee_stack_append_path(&self, path: PathBuf) -> Result<usize, SysAugError> {
        let mut bytes = path.into_os_string().into_vec();
        bytes.push(0);
        self.tracee_stack_append(bytes)
    }

    // Change the address, to which the next tracee_stack_append will write contents.
    // offset = how many bytes of previously written contents will stay after this
    //
    // Note: By default, this is called upon every syscall entry
    pub fn tracee_stack_seek(&self, offset: usize) -> Result<(), SysAugError> {
        let mut ref_offset = self.tracee_stack_offset.borrow_mut();
        *ref_offset = offset;
        Ok(())
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
            if signal == Signal::SIGSTOP {
                if let Some(parent) = self.parent.as_ref() {
                    let ignore_sigstops = rwlock_read(parent.ignore_sigstops.as_ref())?;
                    if ignore_sigstops.contains(&pid) {
                        continue;
                    }
                }
            }
            if signal == Signal::SIGSYS && self.cli_args.fix_sigsys {
                // Android sometimes kills a process for using privileged syscalls like sysinfo()
                // Instead of killing tracee, return -ENOSYS and let it resume
                let siginfo = getsig_ans.map_err(SysAugError::PtraceGetSigInfo2)?;
                let mut regs = self.ptrace_client.execute(move || ptrace::getregs(pid))??;
                if siginfo.si_code > 0 {
                    // Signal was sent by kernel, so it's safe to assume a syscall just happened.
                    let retval = (-libc::ENOSYS) as usize;

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
    }

    async fn loop_handle_tracee_other_events(&self) -> Result<u8, SysAugError> {
        let pid = self.pid;
        loop {
            let status = self
                .async_runtime
                .new_ptrace_future(PtraceFutureTypes::WaitForPtraceEvent)
                .await;

            // Tracee is being cloned or forked
            if matches!(
                status.wait_status,
                WaitStatus::PtraceEvent(_, _, libc::PTRACE_EVENT_CLONE)
                    | WaitStatus::PtraceEvent(_, _, libc::PTRACE_EVENT_FORK)
                    | WaitStatus::PtraceEvent(_, _, libc::PTRACE_EVENT_VFORK)
            ) {
                let raw_pid =
                    self.ptrace_client
                        .execute(move || ptrace::getevent(pid))?? as isize;
                if raw_pid > 0 {
                    let child_pid: Pid = Pid::from_raw(raw_pid as i32);

                    self.ptrace_client
                        .prep_attach_to(child_pid, self.ignore_sigstops.as_ref())?;

                    let new_tracee_handler = self
                        .sync_handler
                        .upgrade()
                        .ok_or(SysAugError::WeakReference)?
                        .fork(child_pid)?;
                    let new_tracee_handler2 = Arc::clone(&new_tracee_handler);
                    let root_pid = self.states.root_pid;
                    let fail_fast = self.states.args.fail_fast;
                    new_tracee_handler.start(move || {
                        if fail_fast && new_tracee_handler2.failed() {
                            let _ = sys::signal::kill(root_pid, Some(Signal::SIGKILL))
                                .map_err(display_err);
                        }
                    });

                    self.call_mods(ModFeature::OnCloneComplete, |m| {
                        m.on_clone_complete(raw_pid as isize)
                    })
                    .await?;
                }
                continue;
            }

            // Tracee exited normally
            if let WaitStatus::PtraceEvent(_, _, libc::PTRACE_EVENT_EXIT) = status.wait_status {
                let rawret = self
                    .ptrace_client
                    .execute(move || ptrace::getevent(pid))??;
                let retcode = (rawret as u32) >> 8;
                info!("Exit status = {}", retcode);
                self.ptrace_client
                    .execute(move || sys::ptrace::detach(pid, None))?
                    .map_err(SysAugError::PtraceDetach)?;
                return Ok(retcode as u8);
            }
        }
    }

    /// Resume the system call as is (using the current tracee register states)
    /// But only wait for this one system call to go through, and
    /// Return just early enough to override system call return value.
    pub async fn do_resume_syscall(&self) -> Result<GenericPurposeRegs, SysAugError> {
        let pid = self.pid;
        self.wait_for_syscall().await?;
        let regs = self.ptrace_client.execute(move || ptrace::getregs(pid))??;
        event!(
            Level::TRACE,
            "syscall exit event, stack@{:x}, return {:#x} args {:#x} {:#x} {:#x}",
            ptrace::stack_ptr(),
            regs.syscall_retval(),
            regs.arg0,
            regs.arg1,
            regs.arg2
        );

        // Note: It might be wise to double check we got the expected augment
        //       But, it might also overcomplicate the do_skip_syscall logic
        Ok(regs)
    }

    /// Skip the system call (clobbering current tracee register states, setting sysret=0)
    pub async fn do_skip_syscall(&self, syscall_retval: usize) -> Result<(), SysAugError> {
        let pid = self.pid;
        event!(Level::DEBUG, "Attempting to skip syscall");
        self.ptrace_client
            .execute(move || ptrace::set_syscall_num(pid, NO_MOD_SYSCALL))??;
        let mut regs = self.do_resume_syscall().await?;

        event!(
            Level::DEBUG,
            "Returning {} for skipped syscall, originally {}",
            syscall_retval,
            regs.syscall_retval()
        );
        regs.set_syscall_retval(syscall_retval);
        self.ptrace_client
            .execute(move || ptrace::setregs(pid, regs))??;
        Ok(())
    }

    async fn loop_handle_tracee_syscalls(&self) -> Result<u8, SysAugError> {
        let pid = self.pid;
        let mut total_times: u64 = 0;
        loop {
            // We just finished one round of syscall. Unblock any signal handler that yielded to us
            self.yielder_syscall.unblock();
            total_times += 1;

            // Wait for System Call Entry
            self.wait_for_syscall().await?;
            let regs = self.ptrace_client.execute(move || ptrace::getregs(pid))??;
            let (maybe_syscall_info, syscall_name) = get_syscall(&regs.syscall_num);
            let which_aug = maybe_syscall_info.map(|x| &x.augment);
            let _span1 = span!(
                Level::DEBUG,
                "syscall",
                "{:?} syscall {} id {} args {:#x} {:#x} {:#x} {:#x} {:#x} {:#x}",
                which_aug.unwrap_or(&Augments::None),
                syscall_name,
                total_times,
                regs.arg0,
                regs.arg1,
                regs.arg2,
                regs.arg3,
                regs.arg4,
                regs.arg5
            )
            .entered();
            event!(
                Level::TRACE,
                "syscall entry event, stack@{:x}",
                ptrace::stack_ptr()
            );

            self.tracee_stack_seek(0)?;

            if self.cli_args.gdb_at == Some(total_times) {
                info!(
                    "Reached {:?}-th system call. Starting gdb",
                    self.cli_args.gdb_at
                );
                *self.notifiers.transfer_to_gdb.borrow_mut() = true;
                return Ok(0);
            }

            // Check how we should augment the syscall
            if let Some(syscall_info) = maybe_syscall_info {
                call_augment!(self, which_aug, regs.clone(), &syscall_info);
            } else {
                self.do_resume_syscall().await?;
            }

            // aarch64 doesn't work if we read regs right after execve()
            // Yet, x86_64 requires it...
            let _new_regs = self.ptrace_client.execute(move || ptrace::getregs(pid))??;
            let (_new_syscall_info, _) = get_syscall(&_new_regs.syscall_num);
            #[cfg(not(any(target_arch = "aarch64")))]
            let which_aug = _new_syscall_info.map(|x| &x.augment);

            if which_aug == Some(&Augments::Exec) {
                self.initialize_tracee_mmaps().await?;
            }
        }
    }

    async fn _insert_syscall(
        &self,
        syscall_name: &'static str,
        syscall_num: usize,
        args: [usize; 6],
    ) -> Result<GenericPurposeRegs, SysAugError> {
        // Note: This function must call self.yielder_syscall.unblock() manually
        //       We are not trying to override any system during this time, so,
        //       We should unblock yields whenever we await
        let pid = self.pid;

        // Wait the next system call entry, could be anything, including NO_MOD_SYSCALL
        // (Because we know for sure our own code did not trigger it)
        self.yielder_syscall.unblock();
        self.wait_for_syscall().await?;

        let orig_regs = self.ptrace_client.execute(move || ptrace::getregs(pid))??;
        let mut regs = orig_regs.clone();
        let (_, orig_syscall_name) = get_syscall(&regs.syscall_num);
        event!(
            Level::INFO,
            "TraceeInit: Overriding first syscall after exec, was {:?}",
            orig_syscall_name
        );

        // TODO: rename the fd to something much larger than 3. fd3 is often used in bash scripts
        //       (cannot really remap all fds because thats too many syscalls)

        // Override that system call to run mmap instead
        regs.arg0 = args[0];
        regs.arg1 = args[1];
        regs.arg2 = args[2];
        regs.arg3 = args[3];
        regs.arg4 = args[4];
        regs.arg5 = args[5];

        self.ptrace_client
            .execute(move || ptrace::setregs(pid, regs))??;
        self.ptrace_client
            .execute(move || ptrace::set_syscall_num(pid, syscall_num))??;

        // Wait for mmap to return
        event!(
            Level::DEBUG,
            "TraceeInit: replaced first syscall with {}",
            syscall_name
        );
        self.yielder_syscall.unblock();
        self.wait_for_syscall().await?;
        let result_regs = self.ptrace_client.execute(move || ptrace::getregs(pid))??;

        // Reset tracee to register state before system call
        // and decrement PC pointer to immediately rerun system call
        let mut new_regs = orig_regs;
        new_regs.pc -= SYSCALL_INSTRUCTION_SIZE;
        event!(
            Level::DEBUG,
            "TraceeInit: Continuing syscall {} from {:x}",
            new_regs.syscall_num,
            new_regs.pc
        );
        self.ptrace_client
            .execute(move || ptrace::setregs(pid, new_regs))??;
        Ok(result_regs)
    }

    /// Take over the syscall async loop, right after execve() to establish mmap
    async fn initialize_tracee_mmaps(&self) -> Result<(), SysAugError> {
        let pid = self.pid;
        let region_id = get_own_region_id(&pid)?;
        let mmap_regs = self
            ._insert_syscall(
                "SYS_mmap",
                SYS_mmap,
                [
                    0,
                    STACK_SAFE_ZONE_SIZE,
                    libc::PROT_READ as usize,
                    libc::MAP_SHARED as usize,
                    self.shared_fd as usize,
                    region_id * STACK_SAFE_ZONE_SIZE / SYS_mmap_pgoffset_block,
                ],
            )
            .await?;

        let mut tracee_addr = self.mmap_tracee_addr.borrow_mut();
        *tracee_addr = mmap_regs.syscall_retval();

        set_tracee_write_region_addr(mmap_regs.syscall_retval())?;
        if !self.cli_args.fix_mmap {
            MEM.with_borrow_mut(|cell| *cell = DIRECT_MEM_HELPERS);
        }

        event!(
            Level::INFO,
            "Tracee mounted mmap address: {:x}",
            mmap_regs.syscall_retval()
        );
        Ok(())
    }
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
        Ok(Arc::new(TraceeHandler {
            pid,
            ptrace_client,
            mod_providers: mods,
            ignore_sigstops: Arc::new(RwLock::default()),
            mmap_tracer_addr: mmap_addr,
            shared_fd,
            states: Arc::new((*default_states).try_clone()?),
            parent,
        }))
    }

    /// Create a new TraceeHandler for a child, without starting event loop
    pub fn fork(
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

        // Initialize Mods
        let mut mod_map: ModsByFeature = HashMap::new();
        for provider in self.mod_providers.iter() {
            let m = provider(Arc::clone(&self.states));
            for feature in m.get_features().iter() {
                if !mod_map.contains_key(feature) {
                    mod_map.insert(feature.clone(), Vec::new());
                }
                let vec = mod_map.get_mut(feature).unwrap();
                vec.push(m.clone_box());
            }
        }

        // Initialize and store async loops and futures
        let async_runtime = PtraceAsyncRuntime::default();
        let async_handlers = AsyncTraceeHandler {
            async_runtime: &async_runtime,
            cli_args: self.states.args.clone(),
            pid: pid.clone(),
            shared_fd: self.shared_fd.clone(),

            mods: mod_map,
            states: self.states.clone(),
            parent: self.parent.clone(),
            sync_handler: Arc::downgrade(&self),
            ptrace_client: self.ptrace_client.clone(),
            ignore_sigstops: self.ignore_sigstops.clone(),

            yielder_syscall: PtraceAsyncYielder::default(),

            mmap_tracee_addr: RefCell::default(),
            notifiers: AsyncNotifications::default(),
            tracee_stack_offset: RefCell::default(),
        };
        let mut main_loop_future = async_handlers.all_tracee_loops();

        // Attach ptrace to tracee
        self.ptrace_client.attach_to(pid)?;
        self.set_ptrace_options()?;

        loop {
            // Drive async logic until it is pending on a future by resuming from where we left off
            if let Some(exit_code) = async_runtime.run_async_step(&mut main_loop_future)? {
                // Handle signals, special gdb exit, etc
                if *async_handlers.notifiers.transfer_to_gdb.borrow() {
                    return Ok(self.transfer_to_gdb()?);
                }

                return Ok(exit_code?);
            }

            let mut maybe_signal = { async_handlers.notifiers.signal_tracee.borrow_mut().take() };

            loop {
                // Send ptrace calls, resume tracee, until we have unblocked a future
                // Also, use maybe_signal.take() so that the signal is only sent once
                self.ptrace_syscall(maybe_signal.take())?;
                let wait_status = ptrace::waitpid_hang(pid)?;
                event!(Level::TRACE, "child status {:?}", &wait_status);

                let status = PtraceStatus {
                    wait_status: wait_status.clone(),
                };

                // Handle unexpected crashes
                if !ptrace::is_trace_stop(&wait_status) && !ptrace::is_still_alive(&wait_status) {
                    info!("Process {:?} crashed: {:?}.", &pid, &wait_status);
                    self.ptrace_client
                        .execute(move || sys::ptrace::detach(pid, None))?
                        .map_err(SysAugError::PtraceDetach)?;
                    return Err(SysAugError::TraceeCrashed);
                }

                // Unblock different futures in the proper order
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
}

fn clone_locked<T: Clone>(lock: &RwLock<T>) -> Result<RwLock<T>, SysAugError> {
    let val = rwlock_read(lock)?;
    Ok(RwLock::new(val.clone()))
}

impl Default for TraceeHandlerStates {
    fn default() -> TraceeHandlerStates {
        TraceeHandlerStates {
            args: CLIArgs::default(),
            config: SysAugConfig::default(),
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
            config: self.config.clone(),
            failed: AtomicBool::new(false),
            perms_ids: clone_locked(&self.perms_ids)?,
            path_prefix: clone_locked(&self.path_prefix)?,
            path_prefix_excludes: clone_locked(&self.path_prefix_excludes)?,
            pid: self.pid,
            root_pid: self.root_pid,
        })
    }
}
