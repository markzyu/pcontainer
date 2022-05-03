use nix::sys::wait;
use spawn_ptrace::CommandPtraceSpawn;
use std::convert::TryInto;
use std::fmt;
use std::process;

type AnyResult<V> = Result<V, Box<dyn std::error::Error>>;

#[derive(Debug, Clone)]
pub struct PTraceError<'a> {
    reason: &'a str,
}
impl<'a> fmt::Display for PTraceError<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PTrace Error: {}", self.reason)
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
}
