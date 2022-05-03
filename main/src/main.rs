use nix::sys;
use std::thread;
use std::time::Duration;

use std::collections::HashMap;

fn syscall_names() -> HashMap<ptrace::SysNum, String> {
    let mut map = HashMap::new();
    map.insert(libc::SYS_openat, "openat".into());
    map.insert(libc::SYS_close, "close".into());
    map.insert(libc::SYS_read, "read".into());
    map.insert(libc::SYS_write, "write".into());
    map
}

fn main() {
    let names = syscall_names();

    let mut cmd = std::process::Command::new("ls");
    let child = ptrace::start(&mut cmd).unwrap();
    let pid = ptrace::pid(&child).unwrap();
    dbg!(pid);
    loop {
        sys::ptrace::syscall(pid, None).unwrap();
        let status = ptrace::wait_hang(&child).unwrap();
        dbg!(status);

        if !ptrace::is_trace_stop(&status) && !ptrace::is_still_alive(&status) {
            break;
        }
        let regs = ptrace::getregs(pid).unwrap();
        let unknown: String = "Unknown syscall".into();
        let name = names.get(&regs.syscall_num).unwrap_or(&unknown);
        dbg!(name);
    }
    thread::sleep(Duration::from_millis(10));
    dbg!("Done");
}
