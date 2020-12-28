use nix::sys::wait;
use spawn_ptrace::CommandPtraceSpawn;
use std::collections::HashMap;
use std::convert::TryInto;
use std::fmt;
use std::process;
use std::sync::Arc;

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

#[cfg_attr(test, mockall::automock)]
pub trait SysOverride : std::any::Any {
    fn get_syscalls(&self) -> &[SysNum];
    fn on_syscall<'a>(&self, n: &SysNum, child: Option<&'a process::Child>) -> AnyResult<()>;
}

type SysOverrideBox = Box<dyn SysOverride>;
type OverrideBySysNum = Vec<Arc<SysOverrideBox>>;

pub struct SysOverrideList {
    overrides: HashMap<SysNum, OverrideBySysNum>,
}
impl SysOverrideList {
    pub fn new() -> SysOverrideList {
        SysOverrideList{overrides: HashMap::new()}
    }

    pub fn add_override(&mut self, val: SysOverrideBox) -> Arc<SysOverrideBox> {
        let mut old_vec: OverrideBySysNum;
        let mut new_vec: OverrideBySysNum = Vec::new();
        let mut override_arc = Arc::new(val);
        let mut override_arc2 = Arc::clone(&override_arc);
        let override_ref = Arc::get_mut(&mut override_arc2).unwrap();
        for n in override_ref.get_syscalls().iter() {
            if !self.overrides.contains_key(&n) {
                old_vec = new_vec;
                new_vec = Vec::new();
                self.overrides.insert(n.clone(), old_vec);
            }

            self.overrides.get_mut(&n).unwrap().push(Arc::clone(&override_arc));
        }
        override_arc
    }

    pub fn _summarize_errors(&self, errors: Vec<AnyErr>, msg: String) -> AnyResult<()> {
        if errors.len() == 0 {
            Ok(())
        } else {
            Err(Box::new(PTraceError{reason: format!("{}: {:?}", msg, errors)}))
        }
    }

    pub fn on_syscall(&mut self, n: &SysNum, child: Option<&process::Child>) -> AnyResult<()> {
        if let Some(vec) = self.overrides.get(&n) {
            let results = vec.iter().map(|val| val.on_syscall(&n, child.clone()));
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
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;
    use mockall::Sequence;

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

    #[test]
    #[timeout(100)]
    fn test_add_override_and_call() {
        let mut mock = Box::new(crate::MockSysOverride::new());
        let mut list = crate::SysOverrideList::new();

        let mut mock_arc = list.add_override(mock);
        list.on_syscall(&libc::SYS_openat, None);
        {
					let mut value_any = Arc::get_mut(&mut mock_arc).unwrap() as &mut dyn std::any::Any;
					let mock: &mut crate::MockSysOverride = value_any.downcast_mut().unwrap();
          mock.checkpoint();
        }

        let mut seq = Sequence::new();
        {
					let mut value_any = Arc::get_mut(&mut mock_arc).unwrap() as &mut dyn std::any::Any;
					let mock: &mut crate::MockSysOverride = value_any.downcast_mut().unwrap();
          mock.expect_get_syscalls().times(2).return_const(MOCK_SYSCALLS1.to_vec());
          mock.expect_on_syscall()
            .times(1).in_sequence(&mut seq)
            .withf(|n, _| n == &libc::SYS_write).return_once(move |_, _| Ok(()));
          mock.expect_on_syscall()
            .times(1).in_sequence(&mut seq)
            .withf(|n, _| n == &libc::SYS_read).return_once(move |_, _| Ok(()));
        }
        list.on_syscall(&libc::SYS_write, None);
        list.on_syscall(&libc::SYS_read, None);
        {
					let mut value_any = Arc::get_mut(&mut mock_arc).unwrap() as &mut dyn std::any::Any;
					let mock: &mut crate::MockSysOverride = value_any.downcast_mut().unwrap();
          mock.checkpoint();
        }
    }
}
