use procfs::config_gz;
use ptrace;
use nix::sys;
use std::time::Duration;
use std::thread;

fn main() {
    let mut config = config_gz::ConfigGz {lines: vec![]};
    config.init_from_host_os().unwrap();
    for line in config.lines() {
      if let Some((name, _)) = line.maybeName() {
        if let Some((value, _)) = line.maybeValue() {
          println!("{:?} = {:?}", std::str::from_utf8(name), std::str::from_utf8(value));
        }
      }
    }

    let mut cmd = std::process::Command::new("ls");
    let child = ptrace::start(&mut cmd).unwrap();
    let pid = ptrace::pid(&child).unwrap();
    sys::ptrace::setoptions(pid.clone(), sys::ptrace::Options::PTRACE_O_TRACEEXIT).unwrap();
    sys::ptrace::cont(pid.clone(), None).unwrap();
    thread::sleep(Duration::from_millis(20));  // Note: without sleep, wait will return StillAlive instead.
    let status = ptrace::wait(&child).unwrap();
    dbg!(status);
}
