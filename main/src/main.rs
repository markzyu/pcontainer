use nix::sys;
use procfs::config_gz;
use std::thread;
use std::time::Duration;

macro_rules! seq {
    // Sequences
    ($($v:expr,)*) => {
        std::array::IntoIter::new([$($v,)*]).collect()
    };
    ($($v:expr),*) => {
        std::array::IntoIter::new([$($v,)*]).collect()
    };

    // Maps
    ($($k:expr => $v:expr,)*) => {
        std::array::IntoIter::new([$(($k, $v),)*]).collect()
    };
    ($($k:expr => $v:expr),*) => {
        std::array::IntoIter::new([$(($k, $v),)*]).collect()
    };
}

use std::collections::HashMap;

fn syscall_names() -> HashMap<libc::c_long, String> { 
    let mut map = HashMap::new();
    map.insert(libc::SYS_openat, "openat".into());
    map.insert(libc::SYS_close, "close".into());
    map.insert(libc::SYS_read, "read".into());
    map.insert(libc::SYS_write, "write".into());
    map
}

fn main() {
    let mut config = config_gz::ConfigGz::default();
    config.init_from_host_os().unwrap();
    for line in config.lines() {
        if let Some((name, _)) = line.maybe_name() {
            if let Some((value, _)) = line.maybe_value() {
                println!(
                    "{:?} = {:?}",
                    std::str::from_utf8(name),
                    std::str::from_utf8(value)
                );
            }
        }
    }

    let overrides = ptrace::SysOverrideList::default();
    let names = syscall_names();

    let mut cmd = std::process::Command::new("ls");
    let child = ptrace::start(&mut cmd).unwrap();
    let pid = ptrace::pid(&child).unwrap();
    dbg!(pid);
    loop {
				dbg!("before syscall");
        sys::ptrace::syscall(pid, None).unwrap();
				dbg!("after syscall");
        let status = ptrace::wait_hang(&child).unwrap();
				dbg!(status);
				let regs = ptrace::getregset1(pid).unwrap();
        let unknown: String = "Unknown syscall".into();
				let name = names.get(&regs.syscall_num).unwrap_or(&unknown);
        dbg!(name);
        /*
        if ptrace::is_trace_stop(&status) {
            let regs = ptrace::getregset1(pid).unwrap();
            dbg!(regs);
            //overrides.on_syscall(&mut regs);
        } else if !ptrace::is_still_alive(&status) {
            break
        }
        */
    }
    thread::sleep(Duration::from_millis(10));
}
