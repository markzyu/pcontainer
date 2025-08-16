mod common;
mod mem_slow;

pub use crate::common::{
    getregs, setregs, CHeader, CStruct, GenericPurposeRegs, NixISize, PtraceError,
    PTRACE_GETEVENTMSG, SHARED_MMAP_SIZE, USIZE_SIZE,
};
pub use crate::mem_slow::{
    read, read_bytes_to_structs, read_bytes_until_num_zeroes, read_bytes_until_zero, write,
    write_bytes_to_tracee, write_structs_to_tracee,
};

use nix::sys;
use nix::sys::memfd;
use nix::sys::mman;
use nix::sys::wait;
use nix::unistd;
use std::convert::TryInto;
use std::os::fd::AsRawFd;
use std::os::fd::RawFd;
use std::os::unix::process::CommandExt;
use std::process;
use tracing::{event, Level};

pub fn is_trace_stop(status: &wait::WaitStatus) -> bool {
    matches!(
        status,
        wait::WaitStatus::PtraceEvent(_, _, _)
            | wait::WaitStatus::Stopped(_, nix::sys::signal::Signal::SIGTRAP)
    )
}

pub fn is_syscall_stop(status: &wait::WaitStatus) -> bool {
    matches!(status, wait::WaitStatus::PtraceSyscall(_))
}

pub fn is_still_alive(status: &wait::WaitStatus) -> bool {
    !matches!(status, wait::WaitStatus::Exited(_, _))
}

pub fn start(
    cmd: &mut process::Command,
    no_attach: bool,
) -> Result<(unistd::Pid, RawFd, usize), PtraceError> {
    let shared_fd = memfd::memfd_create("shared_from_tracer", memfd::MFdFlags::empty())
        .map_err(PtraceError::CreateMemoryFile)?;
    unistd::ftruncate(&shared_fd, SHARED_MMAP_SIZE as NixISize)
        .map_err(PtraceError::CreateMemoryFile)?;
    let mmap_addr = unsafe {
        mman::mmap(
            None,
            SHARED_MMAP_SIZE.try_into().unwrap(),
            mman::ProtFlags::PROT_READ | mman::ProtFlags::PROT_WRITE,
            mman::MapFlags::MAP_SHARED,
            &shared_fd,
            0,
        )
        .map_err(PtraceError::CreateMemoryFile)?
        .as_ptr() as usize
    };
    event!(
        Level::INFO,
        "Created shared mmap fd {:?} addr {:x}",
        shared_fd,
        mmap_addr
    );
    match unsafe { unistd::fork() } {
        Ok(unistd::ForkResult::Parent { child, .. }) => {
            Ok((child, shared_fd.as_raw_fd(), mmap_addr))
        }
        Ok(unistd::ForkResult::Child) => {
            if no_attach {
                // Use PTRACE_TRACEME, and wait for tracer's main thread
                nix::sys::ptrace::traceme().unwrap();
            } else {
                // Pause child execution and wait for tracer to PTRACE_ATTACH
                sys::signal::raise(sys::signal::Signal::SIGSTOP).unwrap();
            }
            let e = cmd.exec();
            println!("[ERROR] Unexpected exec failure, returned {:?}", &e);
            Err(PtraceError::InitCmdFailed(e))
        }
        Err(e) => Err(PtraceError::StartInitCmd(e)),
    }
}

pub fn pid(child: &process::Child) -> Result<nix::unistd::Pid, PtraceError> {
    let raw_id: u64 = child.id().into();
    let pid: libc::pid_t = raw_id
        .try_into()
        .map_err(|e| PtraceError::ParsePid(raw_id, e))?;
    Ok(nix::unistd::Pid::from_raw(pid))
}

pub fn waitpid(pid: nix::unistd::Pid) -> Result<wait::WaitStatus, PtraceError> {
    wait::waitpid(pid, Some(wait::WaitPidFlag::WNOHANG)).map_err(PtraceError::Waitpid)
}

pub fn wait(child: &process::Child) -> Result<wait::WaitStatus, PtraceError> {
    waitpid(pid(child)?)
}

pub fn waitpid_hang(pid: nix::unistd::Pid) -> Result<wait::WaitStatus, PtraceError> {
    wait::waitpid(pid, None).map_err(PtraceError::Waitpid)
}

pub fn wait_hang(child: &process::Child) -> Result<wait::WaitStatus, PtraceError> {
    waitpid_hang(pid(child)?)
}

pub fn getevent(pid: nix::unistd::Pid) -> Result<libc::c_ulong, PtraceError> {
    let mut data = std::mem::MaybeUninit::uninit();
    let res = unsafe {
        libc::ptrace(
            PTRACE_GETEVENTMSG,
            libc::pid_t::from(pid),
            std::ptr::null_mut::<libc::c_void>(),
            data.as_mut_ptr() as *mut libc::c_void,
        )
    };
    nix::errno::Errno::result(res).map_err(PtraceError::GetEventMsg)?;
    Ok(unsafe { data.assume_init() })
}

pub fn set_syscall_num(pid: nix::unistd::Pid, val: usize) -> Result<(), PtraceError> {
    let mut regs = getregs(pid)?;
    event!(
        Level::DEBUG,
        "Replacing syscall {} with {}",
        regs.syscall_num,
        val,
    );

    regs.syscall_num = val;
    setregs(pid, regs)?;

    let regs2 = getregs(pid)?;
    event!(
        Level::TRACE,
        "Confirm regs: syscall {} with {:x} {:x} {:x}",
        regs2.syscall_num,
        regs2.arg0,
        regs2.arg1,
        regs2.arg2,
    );
    Ok(())
}

pub fn stack_ptr() -> usize {
    let mut ans: Option<usize> = None;
    backtrace::trace(|frame| {
        ans.replace(frame.sp() as usize);
        false
    });
    ans.unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use nix::sys::ptrace;
    use nix::sys::wait;
    use nix::unistd;
    use ntest::timeout;
    use std::thread;
    use std::time::Duration;

    fn _start_cmd() -> unistd::Pid {
        let mut cmd = std::process::Command::new("ls");
        crate::start(&mut cmd, false).unwrap()
    }

    #[test]
    #[timeout(100)]
    fn test_start_cmd_does_wait_and_child_is_stopped() {
        let pid = _start_cmd();
        let status = crate::waitpid(pid.clone()).unwrap();
        assert!(matches!(status, wait::WaitStatus::StillAlive));
        assert!(!crate::is_trace_stop(&status));
        assert!(crate::is_still_alive(&status));
    }

    #[test]
    #[timeout(100)]
    fn test_is_trace_stop_and_is_still_alive() {
        let pid = _start_cmd();
        ptrace::setoptions(pid.clone(), ptrace::Options::PTRACE_O_TRACEEXIT).unwrap();
        ptrace::cont(pid.clone(), None).unwrap();

        thread::sleep(Duration::from_millis(20)); // Note: without sleep, wait will return StillAlive instead.
        let status = crate::waitpid(pid.clone()).unwrap();
        assert!(matches!(status, wait::WaitStatus::PtraceEvent(_, _, _)));
        assert!(crate::is_trace_stop(&status));
        assert!(crate::is_still_alive(&status));
    }

    #[test]
    #[timeout(100)]
    fn test_child_finished_and_is_not_still_alive() {
        let pid = _start_cmd();
        let mut status = crate::waitpid(pid.clone()).unwrap();
        assert!(matches!(status, wait::WaitStatus::StillAlive));
        assert!(!crate::is_trace_stop(&status));
        assert!(crate::is_still_alive(&status));

        ptrace::detach(pid.clone(), None).unwrap();
        status = crate::waitpid_hang(pid.clone()).unwrap();
        assert!(!crate::is_trace_stop(&status));
        assert!(!crate::is_still_alive(&status));
    }
}
