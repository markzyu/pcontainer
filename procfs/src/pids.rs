use crate::common::ProcfsError;
use std::path::PathBuf;

pub fn getcwd(pid: nix::unistd::Pid) -> Result<PathBuf, ProcfsError> {
    let mut path = pid_path(pid);
    path.push("cwd");
    path.read_link().map_err(ProcfsError::IO)
}

pub fn getfd_path(pid: nix::unistd::Pid, fd: isize) -> Result<PathBuf, ProcfsError> {
    let mut path = pid_path(pid);
    path.push("fd");
    path.push(fd.to_string());
    path.read_link().map_err(ProcfsError::IO)
}

fn pid_path(pid: nix::unistd::Pid) -> PathBuf {
    let mut path = PathBuf::new();
    path.push("/proc");
    path.push(pid.as_raw().to_string());
    path
}
