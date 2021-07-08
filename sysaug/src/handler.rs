use crate::clone::AugmentClone;
use crate::common::{AugmentSyscall, SysAugError, SyscallCounter};
use crate::paths::AugmentPaths;
use lazy_static::lazy_static;
use nix::sys;
use std::collections::HashMap;
use std::thread;
use std::time::Duration;
use tracing::{event, span, Level};

lazy_static! {
    static ref SYSCALL_NAMES: HashMap<ptrace::SysNum, String> = {
        let mut map = HashMap::new();
        map.insert(libc::SYS_openat as usize, "openat".into());
        map.insert(libc::SYS_close as usize, "close".into());
        map.insert(libc::SYS_read as usize, "read".into());
        map.insert(libc::SYS_write as usize, "write".into());
        map.insert(libc::SYS_clone as usize, "clone".into());
        map
    };
}

pub struct TraceeHandler {
    pid: nix::unistd::Pid,
    ptrace_client: executor::PtraceClient,
}

impl TraceeHandler {
    pub fn new(pid: nix::unistd::Pid, ptrace_client: executor::PtraceClient) -> TraceeHandler {
        TraceeHandler { pid, ptrace_client }
    }

    pub fn event_loop(&self) -> Result<(), SysAugError> {
        let pid = self.pid;

        thread::sleep(Duration::from_millis(1));
        self.ptrace_client.execute(move || {
            sys::ptrace::setoptions(pid, sys::ptrace::Options::PTRACE_O_TRACESYSGOOD)
        })??;

        let augment_clone = AugmentClone {
            pid,
            ptrace_client: self.ptrace_client.clone(),
        };
        let augment_paths = AugmentPaths::new(pid, self.ptrace_client.clone());

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
            let unknown: String = "Unknown syscall".into();
            let name = SYSCALL_NAMES.get(&regs.syscall_num).unwrap_or(&unknown);

            last_syscall.count(regs.syscall_num);
            if last_syscall.times % 2 == 1 {
                event!(
                    Level::DEBUG,
                    "Syscall {} {} ({:x}, {:x}, {:x})",
                    name,
                    times = &last_syscall.times,
                    arg0 = regs.arg0,
                    arg1 = regs.arg1,
                    arg2 = regs.arg2,
                );
            }
            augment_clone.dispatch(&last_syscall, &regs)?;
            augment_paths.dispatch(&last_syscall, &regs)?;
        }
        Ok(())
    }
}
