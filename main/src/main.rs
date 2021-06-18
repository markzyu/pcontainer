use lazy_static::lazy_static;
use nix::sys;
use std::thread;

use std::collections::HashMap;

lazy_static! {
    static ref SYSCALL_NAMES: HashMap<ptrace::SysNum, String> = {
        let mut map = HashMap::new();
        map.insert(libc::SYS_openat, "openat".into());
        map.insert(libc::SYS_close, "close".into());
        map.insert(libc::SYS_read, "read".into());
        map.insert(libc::SYS_write, "write".into());
        map.insert(libc::SYS_clone, "clone".into());
        map
    };
}

pub fn event_thread(pid: nix::unistd::Pid, ptrace_client: executor::PtraceClient) {
    loop {
        ptrace_client.execute(move || sys::ptrace::syscall(pid, None).unwrap());
        let status = ptrace::waitpid_hang(pid).unwrap();
        dbg!(status);

        if !ptrace::is_trace_stop(&status) && !ptrace::is_still_alive(&status) {
            break;
        }
        let regs = ptrace_client.execute(move || ptrace::getregs(pid).unwrap());
        let unknown: String = "Unknown syscall".into();
        let name = SYSCALL_NAMES.get(&regs.syscall_num).unwrap_or(&unknown);
        dbg!(name);
    }
}

fn main() {
    let (proc1_client, ptrace_loop) = executor::new_ptrace_executor();

    let mut cmd = std::process::Command::new("bash");
    let child = ptrace::start(&mut cmd).unwrap();

    let pid1 = ptrace::pid(&child).unwrap();
    dbg!(pid1);
    thread::spawn(move || {
        let proc1_client2 = proc1_client.clone();
        event_thread(pid1, proc1_client);
        proc1_client2.stop();
    });

    ptrace_loop.serve();
    dbg!("Done");
}
