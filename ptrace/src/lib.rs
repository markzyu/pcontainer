use nix::sys;
use nix::sys::wait;
use spawn_ptrace::CommandPtraceSpawn;
use std::collections::HashMap;
use std::convert::TryInto;
use std::fmt;
use std::process;
use std::sync::{Arc, RwLock};

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

pub trait SysOverride {
    fn get_syscalls(&self) -> &[SysNum];
    fn on_syscall(&self, n: &SysNum, child: Option<i32>) -> AnyResult<()>;
}

type SysOverrideBox = Box<dyn SysOverride>;
type Lock<T> = Arc<RwLock<T>>;
type OverrideBySysNum = Vec<Lock<SysOverrideBox>>;

#[derive(Default)]
pub struct SysOverrideList {
    overrides: HashMap<SysNum, OverrideBySysNum>,
}

impl SysOverrideList {
    pub fn add_override(&mut self, val: SysOverrideBox) -> Lock<SysOverrideBox> {
        let mut old_vec: OverrideBySysNum;
        let mut new_vec: OverrideBySysNum = Vec::new();
        let override_arc = Arc::new(RwLock::new(val));
        let override_arc2 = Arc::clone(&override_arc);
        let override_ref = override_arc2.read().unwrap();
        for n in override_ref.get_syscalls().iter() {
            if !self.overrides.contains_key(&n) {
                old_vec = new_vec;
                new_vec = Vec::new();
                self.overrides.insert(*n, old_vec);
            }

            self.overrides
                .get_mut(&n)
                .unwrap()
                .push(Arc::clone(&override_arc));
        }
        override_arc
    }

    pub fn _summarize_errors(&self, errors: Vec<AnyErr>, msg: String) -> AnyResult<()> {
        if errors.is_empty() {
            Ok(())
        } else {
            Err(Box::new(PTraceError {
                reason: format!("{}: {:?}", msg, errors),
            }))
        }
    }

    pub fn on_syscall(&mut self, n: &SysNum, child: Option<i32>) -> AnyResult<()> {
        if let Some(vec) = self.overrides.get(&n) {
            let results = vec
                .iter()
                .map(|val| val.read().unwrap().on_syscall(&n, child));
            self._summarize_errors(
                results.filter_map(|x| x.err()).collect(),
                format!("Errors(s) starting syscall {}", n),
            )
        } else {
            Ok(())
        }
    }
}

pub fn is_trace_stop(status: &wait::WaitStatus) -> bool {
    match status {
        wait::WaitStatus::PtraceEvent(_, _, _) => true,
        wait::WaitStatus::Stopped(_, nix::sys::signal::Signal::SIGTRAP) => true,
        _ => false,
    }
}

pub fn is_still_alive(status: &wait::WaitStatus) -> bool {
    matches!(status, wait::WaitStatus::StillAlive)
}

pub fn start(cmd: &mut process::Command) -> AnyResult<process::Child> {
    Ok(cmd.spawn_ptrace()?)
}

pub fn pid(child: &process::Child) -> AnyResult<nix::unistd::Pid> {
    let pid: i32 = child.id().try_into()?;
    Ok(nix::unistd::Pid::from_raw(pid))
}

pub fn wait(child: &process::Child) -> AnyResult<wait::WaitStatus> {
    Ok(wait::waitpid(
        pid(&child)?,
        Some(wait::WaitPidFlag::WNOHANG),
    )?)
}

pub fn wait_hang(child: &process::Child) -> AnyResult<wait::WaitStatus> {
    Ok(wait::waitpid(
        pid(&child)?,
        None,
    )?)
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
        libc::ptrace(request as sys::ptrace::RequestType,
                     libc::pid_t::from(pid),
                     LibcConst::NT_PRSTATUS.bits() as *mut libc::c_void,
                     data.as_mut_ptr() as *mut _ as *mut libc::c_void)
    };
    nix::errno::Errno::result(res)?;
    Ok(unsafe{ data.assume_init() })
}

/// For Android, See https://android.googlesource.com/platform/prebuilts/ndk/+/1b55d7b281f282232ee58da5d09d3da5969ff11d/9/platforms/android-19/arch-arm64/usr/include/sys/user.h
#[cfg(target_arch = "aarch64")]
#[derive(Debug)]
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
#[derive(Debug)]
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

/// Use this as reference: https://android.googlesource.com/platform/system/core/+/59d16c9e9171f4367ad3a0516e7000c0d95e89cf/debuggerd/arm64/machine.cpp
#[cfg(target_arch = "aarch64")]
pub fn getregs(pid: nix::unistd::Pid) -> AnyResult<GenericPurposeRegs> {
    let mut data = std::mem::MaybeUninit::uninit();
    let res = unsafe {
        let mut iov = libc::iovec {
            iov_base: data.as_mut_ptr() as *mut _ as *mut libc::c_void,
            iov_len: std::mem::size_of::<GenericPurposeRegs>(),
        };
        libc::ptrace(sys::ptrace::Request::PTRACE_GETREGSET as u32,
                     libc::pid_t::from(pid),
                     LibcConst::NT_PRSTATUS.bits() as *mut libc::c_void,
                     &mut iov as *mut _ as *mut libc::c_void)
    };
    nix::errno::Errno::result(res)?;
    Ok(unsafe{ data.assume_init() })
}

/// Use this as reference: https://android.googlesource.com/platform/prebuilts/ndk/+/refs/heads/lollipop-dev/9/platforms/android-5/arch-arm/usr/include/asm/ptrace.h
#[cfg(target_arch = "arm")]
pub fn getregs(pid: nix::unistd::Pid) -> AnyResult<GenericPurposeRegs> {
    let mut data = std::mem::MaybeUninit::uninit();
    let res = unsafe {
        libc::ptrace(12 as u32,
                     libc::pid_t::from(pid),
                     std::ptr::null_mut::<i32>(),
                     data.as_mut_ptr() as *mut _ as *mut libc::c_void)
    };
    nix::errno::Errno::result(res)?;
    Ok(unsafe{ data.assume_init() })
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
        assert!(!crate::is_still_alive(&status));
    }

    const MOCK_SYSCALLS1: &'static [crate::SysNum] = &[libc::SYS_read, libc::SYS_write];
    use std::sync::{Arc, RwLock};

    struct TestSysOverride {
        result: Arc<RwLock<Option<crate::SysNum>>>,
    }
    impl crate::SysOverride for TestSysOverride {
        fn get_syscalls(&self) -> &[crate::SysNum] {
            MOCK_SYSCALLS1
        }
        fn on_syscall(&self, n: &crate::SysNum, _child: Option<i32>) -> crate::AnyResult<()> {
            let mut maybe = self.result.write().unwrap();
            maybe.replace(n.clone());
            Ok(())
        }
    }

    fn _reset_syscall_result(result: Arc<RwLock<Option<crate::SysNum>>>) {
        let mut maybe = result.write().unwrap();
        maybe.take();
    }

    fn _run_syscall_and_assert(
        result: Arc<RwLock<Option<crate::SysNum>>>,
        call_num: &crate::SysNum,
        want_sys_num: Option<crate::SysNum>,
        list: &mut crate::SysOverrideList,
    ) {
        list.on_syscall(&call_num, None).unwrap();
        let maybe = result.read().unwrap();
        assert!(*maybe == want_sys_num);
    }

    #[test]
    fn test_add_override_and_call() {
        let result = Arc::new(RwLock::new(None));
        let fake = TestSysOverride {
            result: result.clone(),
        };
        let mut list = crate::SysOverrideList::default();

        list.add_override(Box::new(fake));
        _reset_syscall_result(result.clone());
        _run_syscall_and_assert(result.clone(), &libc::SYS_openat, None, &mut list);

        _reset_syscall_result(result.clone());
        _run_syscall_and_assert(
            result.clone(),
            &libc::SYS_write,
            Some(libc::SYS_write.clone()),
            &mut list,
        );
        _run_syscall_and_assert(
            result.clone(),
            &libc::SYS_read,
            Some(libc::SYS_read.clone()),
            &mut list,
        );
    }
}
