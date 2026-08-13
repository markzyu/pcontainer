// Copyright 2026 Zhongzhi Yu <7296488+markzyu@users.noreply.github.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

use crate::common::{
    Augments, NO_MOD_SYSCALL, PR_SET_NO_NEW_PRIVS, PermsMode, SECCOMP_FILTER_FLAG_TSYNC,
    SECCOMP_SET_MODE_FILTER, SysAugError, display_err, rwlock_read,
};
use crate::config::{
    PERMS_IDS_SIZE, SysAugConfig, init_passthroughs_from_config, init_perms_ids_from_config,
};
use crate::rwlock_write;
use crate::syscalls::{BpfProgram, SECCOMP_FILTERS, SYSCALL_INSTRUCTION_SIZE, get_syscall};
use executor::{PtraceAsyncRuntime, PtraceAsyncYielder, PtraceFutureTypes, PtraceStatus};
use nix::sys;
use nix::sys::utsname::uname;
use nix::sys::wait::WaitStatus;
use nix::unistd::Pid;
use ptrace::{
    DIRECT_MEM_HELPERS, GenericPurposeRegs, MemHelpers, SLOW_MEM_HELPERS, STACK_SAFE_ZONE_SIZE,
    get_own_region_id, set_tracee_write_region_addr,
};
use std::cell::RefCell;
use std::collections::HashSet;
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock, Weak};
use std::thread;
use sys::signal::Signal;
use tracing::{Level, event, info, span};

#[cfg(not(target_arch = "arm"))]
const SYS_MMAP: usize = libc::SYS_mmap as usize;
#[cfg(target_arch = "arm")]
const SYS_MMAP: usize = libc::SYS_mmap2 as usize;

#[cfg(not(target_arch = "arm"))]
const SYS_MMAP_PGOFFSET_BLOCK: usize = 1;
#[cfg(target_arch = "arm")]
const SYS_MMAP_PGOFFSET_BLOCK: usize = 4096;

const PTRACE_EVENT_SECCOMP: libc::c_int = sys::ptrace::Event::PTRACE_EVENT_SECCOMP as libc::c_int;

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
            Some(Augments::Seccomp) => $self.augment_sys_seccomp($regs, $syscall).await,
            Some(Augments::Unimplemented) => Err(SysAugError::UnimplementedAugment),
            _ => Ok(()),
        }
        .map_err(display_err)?;
    };
}

pub struct TraceeHandler<PtraceClient: executor::PtraceClient> {
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
    /// Whether to resume through a PTRACE_CONT or PTRACE_SYSCALL (see `wait_for_syscall()`)
    resume_through_syscall: RefCell<bool>,
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
    /// This tracks completion of either syscall-entry-stop or seccomp-stop
    pub is_after_syscall_entry: RefCell<bool>,

    /// Whether kernel version is < 4.8
    pub is_legacy_seccomp: RefCell<bool>,
    /// Whether seccomp has been initialized
    /// (note: this only matters for the root process. all children processes will already have seccomp initialized)
    pub tracee_seccomp_init_complete: RefCell<bool>,
    pub orig_syscall_num: RefCell<Option<usize>>,
}

impl<PtraceClient: executor::PtraceClient> AsyncTraceeHandler<'_, PtraceClient> {
    /// Returns: the tracee exit code
    async fn all_tracee_loops(&self) -> Result<u8, SysAugError> {
        // Initialize
        init_perms_ids_from_config(&self.states.perms_ids, &self.states.config.perms)?;
        if self.states.args.chroot.is_some() {
            let mut path_prefix = rwlock_write(&self.states.path_prefix)?;
            let mut path_prefix_excludes = rwlock_write(&self.states.path_prefix_excludes)?;
            init_passthroughs_from_config(&mut *path_prefix_excludes, &self.states.config.rootfs);
            *path_prefix = self.states.args.chroot.clone();
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
    #[allow(dead_code)]
    async fn wait_for_signal(&self, signal: Signal) -> Result<(), SysAugError> {
        loop {
            let signal2 = self.wait_for_any_signal().await?;
            if signal == signal2 {
                return Ok(());
            }
        }
    }

    /// This function is used to wait for both syscall-entry-stop and syscall-exit-stop
    /// (This needs to handle the special case that seccomp has extra syscall-entry-stop for some kernel versions)
    /// Possibile starting states:
    ///    * Starts from seccomp            (yields until syscall-exit-stop)
    ///    * Starts from syscall-exit-stop  (yields until seccomp)
    ///
    /// Assupmtions:
    ///    * We will never start from syscall-entry-stop
    ///    * All injected system calls are also SECCOMP_RET_TRACE
    ///    * Nobody directly calls ptrace::syscall() to step through one syscall at a time
    ///    * We don't have access to PTRACE_GET_SYSCALL_INFO (kernel < 5.4)
    async fn wait_for_syscall(&self) -> Result<PtraceStatus, SysAugError> {
        let is_legacy = { *self.is_legacy_seccomp.borrow() };
        let is_seccomp_ready = { *self.tracee_seccomp_init_complete.borrow() };
        let expects_syscall_exit = self.is_after_syscall_entry.replace(false);
        let expects_syscall_stop = !is_seccomp_ready || expects_syscall_exit;

        // Run PTRACE_CONT / PTRACE_SYSCALL
        self.notifiers
            .resume_through_syscall
            .replace(expects_syscall_stop);

        // Wait for one round of syscall-*-stop OR seccomp-stop
        let future_type = if expects_syscall_stop {
            PtraceFutureTypes::WaitForPtraceSyscall
        } else {
            PtraceFutureTypes::WaitForPtraceSeccomp
        };
        let mut status = self.async_runtime.new_ptrace_future(future_type).await;

        if !is_seccomp_ready {
            if !ptrace::is_syscall_stop(&status.wait_status) {
                return Err(SysAugError::AsyncMisMatchSyscall(
                    "non-syscall stop while initializing seccomp",
                    (*status).clone(),
                ));
            }
            return Ok((*status).clone());
        }

        if let WaitStatus::PtraceEvent(_, _, PTRACE_EVENT_SECCOMP) = &status.wait_status {
            if expects_syscall_exit {
                return Err(SysAugError::AsyncMisMatchSyscall(
                    "seccomp stop right after seccomp stop",
                    (*status).clone(),
                ));
            }
            self.is_after_syscall_entry.replace(true);
            return Ok((*status).clone());
        } else if ptrace::is_syscall_stop(&status.wait_status) && expects_syscall_exit {
            if !is_legacy {
                self.is_after_syscall_entry.replace(false);
                return Ok((*status).clone());
            }

            // We are in kernel version < 4.8 and need to do an extra round of ptrace_syscall (through async)
            self.is_after_syscall_entry.replace(false);
            self.notifiers.resume_through_syscall.replace(true);
            status = self
                .async_runtime
                .new_ptrace_future(PtraceFutureTypes::WaitForPtraceSyscall)
                .await;

            if ptrace::is_syscall_stop(&status.wait_status) {
                self.is_after_syscall_entry.replace(false);
                return Ok((*status).clone());
            }
        }
        Err(SysAugError::AsyncMismatch(
            PtraceFutureTypes::WaitForPtraceSyscall,
            (*status).clone(),
        ))
    }

    /// Send the content of `bytes` to tracee's stack, and return its address.
    /// This can be called multiple times and will add new content to the end of
    /// previous contents.
    ///
    /// Note: By default, you don't need to clean up this stack, because the
    ///    `loop_handle_tracee_syscalls` function will cleanup before each syscall.
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

    /// This is similar to tracee_stack_append, but it **destructs** an object into bytes and appends them.
    pub fn tracee_stack_append_fixed_size_obj<T: Sized>(
        &self,
        obj: T,
    ) -> Result<usize, SysAugError> {
        let bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(&obj as *const _ as *const u8, std::mem::size_of::<T>())
        };
        self.tracee_stack_append(bytes.to_vec())
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

    /// Change the address, to which the next tracee_stack_append will write contents.
    /// offset = how many bytes of previously written contents will stay after this
    ///
    /// Note: By default, this is called upon every syscall entry
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
        let mut is_first_loop_after_init: bool = false;
        loop {
            // We just finished one round of syscall. Unblock any signal handler that yielded to us
            self.yielder_syscall.unblock();
            total_times += 1;

            // Wait for System Call Entry
            self.wait_for_syscall().await?;
            self.orig_syscall_num.replace(None);
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

            // AFTER System Call Entry:
            // Update tracee_seccomp_init_complete when init is complete & when orig syscall completes
            if is_first_loop_after_init {
                self.tracee_seccomp_init_complete.replace(true);
                self.is_after_syscall_entry.replace(true);
                is_first_loop_after_init = false;
            }

            // Augment the system call or resume (This will yield AFTER System Call Exit)
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
                if !self.cli_args.fix_mmap {
                    self.initialize_tracee_mmaps().await?;
                }
                if self.parent.is_none() {
                    self.initialize_tracee_seccomp().await?;
                }
                is_first_loop_after_init = true;
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
        //       So that signal handlers and non-syscall ptrace code can still run.
        let pid = self.pid;

        // Wait for the next system call entry, could be anything, including NO_MOD_SYSCALL
        // (This won't cause a race on tracer side because:)
        //    1. Tracee has not yet run the inserted syscall
        //    2. Tracer loop_handle_tracee_syscalls() will not see any syscall until _insert_syscall() yields.
        //    3. The syscall we get from wait_for_syscall() will not complete until _insert_syscall() yields.
        //    4. When _insert_syscall() yields, both tracer and tracee will see the same syscall instead of the inserted one.
        self.yielder_syscall.unblock();
        self.wait_for_syscall().await?;

        let orig_regs = self.ptrace_client.execute(move || ptrace::getregs(pid))??;
        let mut regs = orig_regs.clone();

        let clone_orig_syscall_num = { self.orig_syscall_num.borrow().clone() };
        let orig_syscall_num = if let Some(val) = clone_orig_syscall_num {
            val
        } else {
            let (_, orig_syscall_name) = get_syscall(&regs.syscall_num);
            self.orig_syscall_num.replace(Some(regs.syscall_num));
            event!(
                Level::INFO,
                "TraceeInit: Overriding first syscall, was {:?}",
                orig_syscall_name
            );
            regs.syscall_num
        };

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
            "TraceeInit: executing replacement syscall {}",
            syscall_name
        );
        self.yielder_syscall.unblock();
        self.wait_for_syscall().await?;
        let result_regs = self.ptrace_client.execute(move || ptrace::getregs(pid))??;

        // Reset tracee to register state before system call
        // and decrement PC pointer to immediately rerun system call
        // (Note: This doesn't actually resume the syscall, so it's ok to call _insert_syscall() again)
        let mut new_regs = orig_regs;
        new_regs.syscall_num = orig_syscall_num;
        new_regs.pc -= SYSCALL_INSTRUCTION_SIZE;
        event!(
            Level::DEBUG,
            "TraceeInit: Continuing syscall {} from {:x}",
            new_regs.syscall_num,
            new_regs.pc
        );
        self.ptrace_client
            .execute(move || ptrace::setregs(pid, new_regs))??;
        self.ptrace_client
            .execute(move || ptrace::set_syscall_num(pid, orig_syscall_num))??;
        Ok(result_regs)
    }

    /// Take over the syscall async loop, right after execve() to establish mmap
    async fn initialize_tracee_mmaps(&self) -> Result<(), SysAugError> {
        let pid = self.pid;
        let region_id = get_own_region_id(&pid)?;
        let mmap_regs = self
            ._insert_syscall(
                "SYS_mmap",
                SYS_MMAP,
                [
                    0,
                    STACK_SAFE_ZONE_SIZE,
                    libc::PROT_READ as usize,
                    libc::MAP_SHARED as usize,
                    self.shared_fd as usize,
                    region_id * STACK_SAFE_ZONE_SIZE / SYS_MMAP_PGOFFSET_BLOCK,
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

    async fn initialize_tracee_seccomp(&self) -> Result<(), SysAugError> {
        let prctl_regs = self
            ._insert_syscall(
                "SYS_prctl",
                libc::SYS_prctl as usize,
                [PR_SET_NO_NEW_PRIVS as usize, 1, 0, 0, 0, 0],
            )
            .await?;
        if prctl_regs.syscall_retval() != 0 {
            return Err(SysAugError::SeccompInit);
        }

        let filters_len = SECCOMP_FILTERS.actual_len;
        let filters_addr = self.tracee_stack_append_fixed_size_obj(SECCOMP_FILTERS.filters)?;

        let program = BpfProgram {
            len: filters_len as u16,
            filters_ptr: filters_addr,
        };
        let program_addr = self.tracee_stack_append_fixed_size_obj(program)?;

        let seccomp_regs = self
            ._insert_syscall(
                "SYS_seccomp",
                libc::SYS_seccomp as usize,
                [
                    SECCOMP_SET_MODE_FILTER as usize,
                    SECCOMP_FILTER_FLAG_TSYNC as usize,
                    program_addr,
                    0,
                    0,
                    0,
                ],
            )
            .await?;
        if seccomp_regs.syscall_retval() != 0 {
            event!(
                Level::ERROR,
                "Tracee failed to initialize seccomp, syscall retval: {:x}",
                seccomp_regs.syscall_retval()
            );
            return Err(SysAugError::SeccompInit);
        }
        event!(
            Level::INFO,
            "Tracee initialized seccomp with default filters, length {}",
            filters_len
        );
        Ok(())
    }
}

impl<PtraceClient: executor::PtraceClient> TraceeHandler<PtraceClient> {
    pub fn new(
        pid: Pid,
        ptrace_client: PtraceClient,
        states: Option<Arc<TraceeHandlerStates>>,
        parent: Option<Arc<TraceeHandler<PtraceClient>>>,
        shared_fd: RawFd,
        mmap_addr: usize,
    ) -> Result<Arc<TraceeHandler<PtraceClient>>, SysAugError> {
        let default_states = states.unwrap_or_default();
        Ok(Arc::new(TraceeHandler {
            pid,
            ptrace_client,
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
                        | sys::ptrace::Options::PTRACE_O_TRACEVFORK
                        | sys::ptrace::Options::PTRACE_O_TRACESECCOMP,
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

    fn _ptrace_request_next_syscall(
        &self,
        maybe_signal: Option<Signal>,
        notifiers: &AsyncNotifications,
    ) -> Result<(), SysAugError> {
        let pid = self.pid;
        let is_single_syscall = { *notifiers.resume_through_syscall.borrow() };
        if is_single_syscall {
            event!(Level::DEBUG, "PTRACE_SYSCALL");
            self.ptrace_client
                .execute(move || sys::ptrace::syscall(pid, maybe_signal))?
                .map_err(SysAugError::PtraceSyscall)?;
        } else {
            event!(Level::DEBUG, "PTRACE_CONT");
            self.ptrace_client
                .execute(move || sys::ptrace::cont(pid, maybe_signal))?
                .map_err(SysAugError::PtraceContinue)?;
        }
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
            shared_fd: self.shared_fd.clone(),

            states: self.states.clone(),
            parent: self.parent.clone(),
            sync_handler: Arc::downgrade(&self),
            ptrace_client: self.ptrace_client.clone(),
            ignore_sigstops: self.ignore_sigstops.clone(),

            yielder_syscall: PtraceAsyncYielder::default(),

            mmap_tracee_addr: RefCell::default(),
            notifiers: AsyncNotifications::default(),
            tracee_stack_offset: RefCell::default(),
            is_after_syscall_entry: RefCell::default(),
            is_legacy_seccomp: RefCell::new({
                let uname_result = uname().map_err(SysAugError::ReadKernelVersion)?;
                let kernel_version = uname_result.release().to_string_lossy();
                let version_parts = kernel_version.split('.').collect::<Vec<&str>>();
                let maybe_error =
                    SysAugError::ParseKernelVersion(kernel_version.clone().to_string());
                let maybe_error2 =
                    SysAugError::ParseKernelVersion(kernel_version.clone().to_string());
                let major = version_parts[0].parse::<usize>().map_err(|_| maybe_error)?;
                let minor = version_parts[1]
                    .parse::<usize>()
                    .map_err(|_| maybe_error2)?;
                major <= 4 && minor <= 7
            }),
            tracee_seccomp_init_complete: RefCell::new(false),
            orig_syscall_num: RefCell::new(None),
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
                self._ptrace_request_next_syscall(maybe_signal.take(), &async_handlers.notifiers)?;
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
                } else if let WaitStatus::PtraceEvent(_, _, PTRACE_EVENT_SECCOMP) = &wait_status {
                    async_runtime.unblock_futures(PtraceFutureTypes::WaitForPtraceSeccomp, status);
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
