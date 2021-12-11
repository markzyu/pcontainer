use crate::common::ProcfsError;
use std::io::ErrorKind;
use std::path::PathBuf;

pub fn getcwd(pid: nix::unistd::Pid) -> Result<PathBuf, ProcfsError> {
    let mut path = pid_path(pid);
    path.push("cwd");
    path.read_link().map_err(ProcfsError::IO)
}

pub fn getfd_path(pid: nix::unistd::Pid, fd: isize) -> Result<Option<PathBuf>, ProcfsError> {
    let mut path = pid_path(pid);
    path.push("fd");
    path.push(fd.to_string());
    match path.read_link() {
        Ok(ans) => Ok(Some(ans)),
        Err(ref e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(ProcfsError::IO(e)),
    }
}

fn pid_path(pid: nix::unistd::Pid) -> PathBuf {
    let mut path = PathBuf::new();
    path.push("/proc");
    path.push(pid.as_raw().to_string());
    path
}
