use lazy_static::lazy_static;
use nix::sys;
use nix::sys::wait;
use nix::unistd;
use std::convert::TryInto;
use std::os::unix::process::CommandExt;
use std::process;
use thiserror::Error;
use tracing::{event, Level};

const NT_PRSTATUS: libc::c_int = 1;
const STACK_SAFE_ZONE_SIZE: usize = 16 * 1024;

lazy_static! {
    static ref USIZE_SIZE: usize = std::mem::size_of::<usize>();
}

#[derive(Debug, Error)]
pub enum PtraceError {
    #[error("Cannot run initial command: {0}")]
    StartInitCmd(nix::Error),

    #[error("Failed to parse pid {0}: {1}")]
    ParsePid(u64, <u64 as TryInto<libc::pid_t>>::Error),

    #[error("Cannot get tracee's CPU registers: {0}")]
    GetRegs(nix::Error),

    #[error("Cannot set tracee's CPU registers: {0}")]
    SetRegs(nix::Error),

    #[error("Cannot read tracee memory: {0}")]
    Read(nix::Error),

    #[error("Cannot write tracee memory: {0}")]
    Write(nix::Error),

    #[error("Failed to wait/waitpid for tracee: {0}")]
    Waitpid(nix::Error),

    #[error("Integer overflow: {0} {1} {2}")]
    IntOverflow(usize, &'static str, usize),
}

pub fn is_trace_stop(status: &wait::WaitStatus) -> bool {
    matches!(
        status,
        wait::WaitStatus::PtraceEvent(_, _, _)
            | wait::WaitStatus::Stopped(_, nix::sys::signal::Signal::SIGTRAP)
    )
}

pub fn is_syscall_stop(status: &wait::WaitStatus) -> bool {
    matches!(
        status,
        wait::WaitStatus::PtraceEvent(_, _, _) | wait::WaitStatus::PtraceSyscall(_)
    )
}

pub fn is_still_alive(status: &wait::WaitStatus) -> bool {
    !matches!(status, wait::WaitStatus::Exited(_, _))
}

pub fn start(cmd: &mut process::Command, no_attach: bool) -> Result<unistd::Pid, PtraceError> {
    match unsafe { unistd::fork() } {
        Ok(unistd::ForkResult::Parent { child, .. }) => Ok(child),
        Ok(unistd::ForkResult::Child) => {
            if no_attach {
                // Use PTRACE_TRACEME, and wait for tracer's main thread
                nix::sys::ptrace::traceme().unwrap();
            } else {
                // Pause child execution and wait for tracer to PTRACE_ATTACH
                sys::signal::raise(sys::signal::Signal::SIGSTOP).unwrap();
            }
            cmd.exec();
            Ok(unistd::Pid::from_raw(0))
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
    Ok(wait::waitpid(pid, Some(wait::WaitPidFlag::WNOHANG)).map_err(PtraceError::Waitpid)?)
}

pub fn wait(child: &process::Child) -> Result<wait::WaitStatus, PtraceError> {
    waitpid(pid(&child)?)
}

pub fn waitpid_hang(pid: nix::unistd::Pid) -> Result<wait::WaitStatus, PtraceError> {
    Ok(wait::waitpid(pid, None).map_err(PtraceError::Waitpid)?)
}

pub fn wait_hang(child: &process::Child) -> Result<wait::WaitStatus, PtraceError> {
    waitpid_hang(pid(&child)?)
}

/// For Android, See https://android.googlesource.com/platform/prebuilts/ndk/+/1b55d7b281f282232ee58da5d09d3da5969ff11d/9/platforms/android-19/arch-arm64/usr/include/sys/user.h
/// https://android.googlesource.com/kernel/common/+/60ffc30d5652810dd34ea2eec41504222f5d5791/arch/arm64/include/asm/ptrace.h (user_pt_regs)
#[cfg(target_arch = "aarch64")]
#[derive(Debug, Clone)]
#[repr(C)]
#[allow(dead_code)]
pub struct GenericPurposeRegs {
    pub arg0: usize,
    pub arg1: usize,
    pub arg2: usize,
    unknown_x3: usize,
    unknown_x4: usize,
    unknown_x5: usize,
    unknown_x6: usize,
    unknown_x7: usize,
    pub syscall_num: usize,
    unknown_x9: usize,
    unknown_x10: usize,
    unknown_x11: usize,
    unknown_x12: usize,
    unknown_x13: usize,
    unknown_x14: usize,
    unknown_x15: usize,
    unknown_x16: usize,
    unknown_x17: usize,
    unknown_x18: usize,
    unknown_x19: usize,
    unknown_x20: usize,
    unknown_x21: usize,
    unknown_x22: usize,
    unknown_x23: usize,
    unknown_x24: usize,
    unknown_x25: usize,
    unknown_x26: usize,
    unknown_x27: usize,
    unknown_x28: usize,
    unknown_x29: usize,
    unknown_x30: usize,
    pub sp: usize,
    pub pc: usize,
    pstate: usize,
}

#[cfg(target_arch = "arm")]
#[derive(Debug, Clone)]
#[repr(C)]
#[allow(dead_code)]
pub struct GenericPurposeRegs {
    pub arg0: usize,
    pub arg1: usize,
    pub arg2: usize,
    unknown_x3: usize,
    unknown_x4: usize,
    unknown_x5: usize,
    unknown_x6: usize,
    pub syscall_num: usize,
    unknown_x8: usize,
    unknown_x9: usize,
    unknown_x10: usize,
    unknown_x11: usize,
    unknown_x12: usize,
    pub sp: usize,
    unknown_x14: usize,
    pub pc: usize,
    unknown_x16: usize,
    pub orig_r0: usize,
}

#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
impl GenericPurposeRegs {
    pub fn syscall_retval(&self) -> usize {
        self.arg0
    }

    pub fn set_syscall_retval(&mut self, val: usize) {
        self.arg0 = val
    }
}

/// Use this as reference: https://android.googlesource.com/platform/system/core/+/59d16c9e9171f4367ad3a0516e7000c0d95e89cf/debuggerd/arm64/machine.cpp
#[cfg(target_arch = "aarch64")]
pub fn getregs(pid: nix::unistd::Pid) -> Result<GenericPurposeRegs, PtraceError> {
    let mut data = std::mem::MaybeUninit::uninit();
    let res = unsafe {
        let mut iov = libc::iovec {
            iov_base: data.as_mut_ptr() as *mut _ as *mut libc::c_void,
            iov_len: std::mem::size_of::<GenericPurposeRegs>(),
        };
        libc::ptrace(
            sys::ptrace::Request::PTRACE_GETREGSET as u32,
            libc::pid_t::from(pid),
            NT_PRSTATUS as *mut libc::c_void,
            &mut iov as *mut _ as *mut libc::c_void,
        )
    };
    nix::errno::Errno::result(res).map_err(PtraceError::GetRegs)?;
    Ok(unsafe { data.assume_init() })
}

/// Use this as reference: https://android.googlesource.com/platform/prebuilts/ndk/+/refs/heads/lollipop-dev/9/platforms/android-5/arch-arm/usr/include/asm/ptrace.h
#[cfg(target_arch = "arm")]
pub fn getregs(pid: nix::unistd::Pid) -> Result<GenericPurposeRegs, PtraceError> {
    let mut data = std::mem::MaybeUninit::uninit();
    let res = unsafe {
        libc::ptrace(
            12_u32,
            libc::pid_t::from(pid),
            std::ptr::null_mut::<i32>(),
            data.as_mut_ptr() as *mut _ as *mut libc::c_void,
        )
    };
    nix::errno::Errno::result(res).map_err(PtraceError::GetRegs)?;
    Ok(unsafe { data.assume_init() })
}

/// Use this as reference: https://android.googlesource.com/platform/system/core/+/59d16c9e9171f4367ad3a0516e7000c0d95e89cf/debuggerd/arm64/machine.cpp
#[cfg(target_arch = "aarch64")]
pub fn setregs(pid: nix::unistd::Pid, mut data: GenericPurposeRegs) -> Result<(), PtraceError> {
    let res = unsafe {
        let mut iov = libc::iovec {
            iov_base: &mut data as *mut _ as *mut libc::c_void,
            iov_len: std::mem::size_of::<GenericPurposeRegs>(),
        };
        libc::ptrace(
            sys::ptrace::Request::PTRACE_SETREGSET as u32,
            libc::pid_t::from(pid),
            NT_PRSTATUS as *mut libc::c_void,
            &mut iov as *mut _ as *mut libc::c_void,
        )
    };
    nix::errno::Errno::result(res).map_err(PtraceError::SetRegs)?;
    Ok(())
}

/// Use this as reference: https://android.googlesource.com/platform/prebuilts/ndk/+/refs/heads/lollipop-dev/9/platforms/android-5/arch-arm/usr/include/asm/ptrace.h
#[cfg(target_arch = "arm")]
pub fn setregs(pid: nix::unistd::Pid, mut data: GenericPurposeRegs) -> Result<(), PtraceError> {
    let res = unsafe {
        libc::ptrace(
            13_u32,
            libc::pid_t::from(pid),
            std::ptr::null_mut::<i32>(),
            &mut data as *mut _ as *mut libc::c_void,
        )
    };
    nix::errno::Errno::result(res).map_err(PtraceError::SetRegs)?;
    Ok(())
}

#[inline]
fn checked_add(a: usize, b: usize) -> Result<usize, PtraceError> {
    a.checked_add(b).ok_or(PtraceError::IntOverflow(a, "+", b))
}

#[inline]
fn checked_sub(a: usize, b: usize) -> Result<usize, PtraceError> {
    a.checked_sub(b).ok_or(PtraceError::IntOverflow(a, "-", b))
}

#[inline]
fn checked_mul(a: usize, b: usize) -> Result<usize, PtraceError> {
    a.checked_mul(b).ok_or(PtraceError::IntOverflow(a, "*", b))
}

pub fn bytes_to_usizes(bytes: &[u8]) -> Result<Vec<usize>, PtraceError> {
    let mut result: Vec<usize> = Vec::new();
    let iter = bytes.chunks_exact(*USIZE_SIZE);
    for chunk in iter {
        result.push(usize::from_ne_bytes(chunk.try_into().unwrap()));
    }

    let remainder_pos = checked_mul(result.len(), *USIZE_SIZE)?;
    let mut remainder_vec: Vec<u8> = Vec::new();
    remainder_vec.resize(*USIZE_SIZE, 0);

    for (i, byte) in bytes.iter().skip(remainder_pos).enumerate() {
        remainder_vec[i] = *byte;
    }
    result.push(usize::from_ne_bytes(
        (&remainder_vec[..]).try_into().unwrap(),
    ));
    Ok(result)
}

pub fn bytes_to_stack(pid: nix::unistd::Pid, bytes: &[u8]) -> Result<usize, PtraceError> {
    let usizes = bytes_to_usizes(bytes)?;
    let size = checked_mul(usizes.len(), *USIZE_SIZE)?;
    let regs = getregs(pid)?;
    let start: usize = checked_sub(regs.sp, checked_add(STACK_SAFE_ZONE_SIZE, size)?)?;
    let mut addr = start;
    for value in usizes.iter() {
        unsafe {
            sys::ptrace::write(pid, addr as *mut libc::c_void, *value as *mut libc::c_void)
                .map_err(PtraceError::Write)?;
        }
        addr = checked_add(addr, *USIZE_SIZE)?;
    }
    Ok(start)
}

pub fn read_bytes_until_zero(pid: nix::unistd::Pid, addr: usize) -> Result<Vec<u8>, PtraceError> {
    let mut result: Vec<u8> = Vec::new();
    let mut curr_addr = addr;
    loop {
        event!(Level::DEBUG, "PTRACE_READ addr: {:x}", curr_addr);
        let machine_word =
            sys::ptrace::read(pid, curr_addr as *mut libc::c_void).map_err(PtraceError::Read)?;
        for byte in machine_word.to_ne_bytes().iter() {
            if *byte == b'\0' {
                return Ok(result);
            }
            result.push(*byte);
        }
        curr_addr = checked_add(curr_addr, *USIZE_SIZE)?;
    }
}

#[cfg(test)]
mod tests {
    use nix::sys::ptrace;
    use nix::sys::wait;
    use ntest::timeout;
    use std::thread;
    use std::time::Duration;

    fn _start_cmd() -> std::process::Child {
        let mut cmd = std::process::Command::new("ls");
        crate::start(&mut cmd).unwrap()
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn test_convert_bytes_to_usizes_exact() {
        let bytes: &[u8] = b"abcdefghijklmnop";
        let _expect: Vec<usize> = vec![7523094288207667809, 8101815670912281193];
        assert!(matches!(crate::bytes_to_usizes(bytes), Ok(_expect)));
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn test_convert_bytes_to_usizes_remainder() {
        let bytes: &[u8] = b"abcdefghijklmnop9";
        let _expect: Vec<usize> = vec![7523094288207667809, 8101815670912281193, 57];
        assert!(matches!(crate::bytes_to_usizes(bytes), Ok(_expect)));
    }

    #[test]
    #[timeout(100)]
    fn test_start_cmd_does_wait_and_child_is_stopped() {
        let child = _start_cmd();
        let status = crate::wait(&child).unwrap();
        assert!(matches!(status, wait::WaitStatus::StillAlive));
        assert!(!crate::is_trace_stop(&status));
        assert!(crate::is_still_alive(&status));
    }

    #[test]
    #[timeout(100)]
    fn test_is_trace_stop_and_is_still_alive() {
        let child = _start_cmd();
        let pid = crate::pid(&child).unwrap();
        ptrace::setoptions(pid.clone(), ptrace::Options::PTRACE_O_TRACEEXIT).unwrap();
        ptrace::cont(pid.clone(), None).unwrap();

        thread::sleep(Duration::from_millis(20)); // Note: without sleep, wait will return StillAlive instead.
        let status = crate::wait(&child).unwrap();
        assert!(matches!(status, wait::WaitStatus::PtraceEvent(_, _, _)));
        assert!(crate::is_trace_stop(&status));
        assert!(crate::is_still_alive(&status));
    }

    #[test]
    #[timeout(100)]
    fn test_child_finished_and_is_not_still_alive() {
        let child = _start_cmd();
        let pid = crate::pid(&child).unwrap();
        let mut status = crate::wait(&child).unwrap();
        assert!(matches!(status, wait::WaitStatus::StillAlive));
        assert!(!crate::is_trace_stop(&status));
        assert!(crate::is_still_alive(&status));

        ptrace::detach(pid.clone(), None).unwrap();
        status = crate::wait_hang(&child).unwrap();
        assert!(!crate::is_trace_stop(&status));
        assert!(!crate::is_still_alive(&status));
    }
}
