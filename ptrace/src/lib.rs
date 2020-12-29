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

type SysNum = libc::c_long;

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
    matches!(status, wait::WaitStatus::PtraceEvent(_, _, _))
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
