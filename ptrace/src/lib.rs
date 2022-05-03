use nix::sys;
use nix::sys::wait;
use spawn_ptrace::CommandPtraceSpawn;
use std::convert::TryInto;
use std::fmt;
use std::process;

type AnyErr = Box<dyn std::error::Error>;
type AnyResult<V> = Result<V, AnyErr>;

#[derive(Debug, Clone)]
pub struct PTraceError {
    reason: String,
}
impl fmt::Display for PTraceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PTrace Error: {}", self.reason)
    }
}
impl std::error::Error for PTraceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

#[cfg(target_arch = "aarch64")]
pub type SysNum = i64;
#[cfg(target_arch = "arm")]
pub type SysNum = i32;

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

pub fn start(cmd: &mut process::Command) -> AnyResult<process::Child> {
    Ok(cmd.spawn_ptrace()?)
}

pub fn pid(child: &process::Child) -> AnyResult<nix::unistd::Pid> {
    let pid: i32 = child.id().try_into()?;
    Ok(nix::unistd::Pid::from_raw(pid))
}

pub fn waitpid(pid: nix::unistd::Pid) -> AnyResult<wait::WaitStatus> {
    Ok(wait::waitpid(pid, Some(wait::WaitPidFlag::WNOHANG))?)
}

pub fn wait(child: &process::Child) -> AnyResult<wait::WaitStatus> {
    waitpid(pid(&child)?)
}

pub fn waitpid_hang(pid: nix::unistd::Pid) -> AnyResult<wait::WaitStatus> {
    Ok(wait::waitpid(pid, None)?)
}

pub fn wait_hang(child: &process::Child) -> AnyResult<wait::WaitStatus> {
    waitpid_hang(pid(&child)?)
}

bitflags::bitflags! {
    pub struct LibcConst: libc::c_int {
        const NT_PRSTATUS = 1 as libc::c_int;
    }
}

/// This is copied from https://github.com/nix-rust/nix/blob/master/src/sys/ptrace/linux.rs
/// Function for ptrace requests that return values from the data field.
/// Some ptrace get requests populate structs or larger elements than `c_long`
/// and therefore use the data field to return values. This function handles these
/// requests.
pub fn ptrace_get_data<T>(request: sys::ptrace::Request, pid: nix::unistd::Pid) -> AnyResult<T> {
    let mut data = std::mem::MaybeUninit::uninit();
    let res = unsafe {
        libc::ptrace(
            request as sys::ptrace::RequestType,
            libc::pid_t::from(pid),
            LibcConst::NT_PRSTATUS.bits() as *mut libc::c_void,
            data.as_mut_ptr() as *mut _ as *mut libc::c_void,
        )
    };
    nix::errno::Errno::result(res)?;
    Ok(unsafe { data.assume_init() })
}

/// For Android, See https://android.googlesource.com/platform/prebuilts/ndk/+/1b55d7b281f282232ee58da5d09d3da5969ff11d/9/platforms/android-19/arch-arm64/usr/include/sys/user.h
#[cfg(target_arch = "aarch64")]
#[derive(Debug, Clone)]
#[repr(C)]
#[allow(dead_code)]
pub struct GenericPurposeRegs {
    pub arg0: i64,
    pub arg1: i64,
    pub arg2: i64,
    unknown_x3: i64,
    unknown_x4: i64,
    unknown_x5: i64,
    unknown_x6: i64,
    unknown_x7: i64,
    pub syscall_num: i64,
    unknown_x9: i64,
    unknown_x10: i64,
    unknown_x11: i64,
    unknown_x12: i64,
    unknown_x13: i64,
    unknown_x14: i64,
    unknown_x15: i64,
    unknown_x16: i64,
    unknown_x17: i64,
    unknown_x18: i64,
}

#[cfg(target_arch = "arm")]
#[derive(Debug, Clone)]
#[repr(C)]
#[allow(dead_code)]
pub struct GenericPurposeRegs {
    pub arg0: i32,
    pub arg1: i32,
    pub arg2: i32,
    unknown_x3: i32,
    unknown_x4: i32,
    unknown_x5: i32,
    unknown_x6: i32,
    pub syscall_num: i32,
    unknown_x8: i32,
    unknown_x9: i32,
    unknown_x10: i32,
    unknown_x11: i32,
    unknown_x12: i32,
    unknown_x13: i32,
    unknown_x14: i32,
    unknown_x15: i32,
    unknown_x16: i32,
    unknown_x17: i32,
}

#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
impl GenericPurposeRegs {
    pub fn syscall_retval(&self) -> SysNum {
        self.arg0
    }
}

/// Use this as reference: https://android.googlesource.com/platform/system/core/+/59d16c9e9171f4367ad3a0516e7000c0d95e89cf/debuggerd/arm64/machine.cpp
#[cfg(target_arch = "aarch64")]
pub fn getregs(pid: nix::unistd::Pid) -> AnyResult<GenericPurposeRegs> {
    let mut data = std::mem::MaybeUninit::uninit();
    let res = unsafe {
        let mut iov = libc::iovec {
            iov_base: data.as_mut_ptr() as *mut _ as *mut libc::c_void,
            iov_len: std::mem::size_of::<GenericPurposeRegs>(),
        };
        libc::ptrace(
            sys::ptrace::Request::PTRACE_GETREGSET as u32,
            libc::pid_t::from(pid),
            LibcConst::NT_PRSTATUS.bits() as *mut libc::c_void,
            &mut iov as *mut _ as *mut libc::c_void,
        )
    };
    nix::errno::Errno::result(res)?;
    Ok(unsafe { data.assume_init() })
}

/// Use this as reference: https://android.googlesource.com/platform/prebuilts/ndk/+/refs/heads/lollipop-dev/9/platforms/android-5/arch-arm/usr/include/asm/ptrace.h
#[cfg(target_arch = "arm")]
pub fn getregs(pid: nix::unistd::Pid) -> AnyResult<GenericPurposeRegs> {
    let mut data = std::mem::MaybeUninit::uninit();
    let res = unsafe {
        libc::ptrace(
            12 as u32,
            libc::pid_t::from(pid),
            std::ptr::null_mut::<i32>(),
            data.as_mut_ptr() as *mut _ as *mut libc::c_void,
        )
    };
    nix::errno::Errno::result(res)?;
    Ok(unsafe { data.assume_init() })
}

/// Use this as reference: https://android.googlesource.com/platform/system/core/+/59d16c9e9171f4367ad3a0516e7000c0d95e89cf/debuggerd/arm64/machine.cpp
#[cfg(target_arch = "aarch64")]
pub fn setregs(pid: nix::unistd::Pid, mut data: GenericPurposeRegs) -> AnyResult<()> {
    let res = unsafe {
        let mut iov = libc::iovec {
            iov_base: &mut data as *mut _ as *mut libc::c_void,
            iov_len: std::mem::size_of::<GenericPurposeRegs>(),
        };
        libc::ptrace(
            sys::ptrace::Request::PTRACE_SETREGSET as u32,
            libc::pid_t::from(pid),
            LibcConst::NT_PRSTATUS.bits() as *mut libc::c_void,
            &mut iov as *mut _ as *mut libc::c_void,
        )
    };
    nix::errno::Errno::result(res)?;
    Ok(())
}

/// Use this as reference: https://android.googlesource.com/platform/prebuilts/ndk/+/refs/heads/lollipop-dev/9/platforms/android-5/arch-arm/usr/include/asm/ptrace.h
#[cfg(target_arch = "arm")]
pub fn setregs(pid: nix::unistd::Pid, mut data: GenericPurposeRegs) -> AnyResult<()> {
    let res = unsafe {
        libc::ptrace(
            13 as u32,
            libc::pid_t::from(pid),
            std::ptr::null_mut::<i32>(),
            &mut data as *mut _ as *mut libc::c_void,
        )
    };
    nix::errno::Errno::result(res)?;
    Ok(())
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
