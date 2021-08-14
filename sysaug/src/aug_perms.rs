use crate::common;
use crate::common::SysAugError;
use crate::handler::TraceeHandler;
use crate::mods;
use lazy_static::lazy_static;
use ptrace::GenericPurposeRegs;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tracing::{event, Level};

struct SyscallInfo {
    // true -> setuid/setgid, false -> getuid/getgid
    is_setter: bool,

    // true -> setuid/getuid, false -> setgid/getgid
    is_uid: bool,

    is_gid: bool,
}

macro_rules! define_syscall {
    ($name:expr, $is_setter:expr, $type:expr, $ans:ident) => {
        $ans.insert(
            $name as usize,
            SyscallInfo {
                is_setter: $is_setter,
                is_uid: $type == "uid",
                is_gid: $type == "gid",
            },
        )
    };
}

lazy_static! {
    static ref SYSCALL_INFOS: HashMap<usize, SyscallInfo> = {
        let mut ans = HashMap::new();
        define_syscall!(libc::SYS_getuid, false, "uid", ans);
        define_syscall!(libc::SYS_geteuid, false, "uid", ans);
        define_syscall!(libc::SYS_setuid, true, "uid", ans);
        define_syscall!(libc::SYS_getgid, false, "gid", ans);
        // define_syscall!(libc::SYS_getegid, false, "gid", ans);
        define_syscall!(libc::SYS_setgid, true, "gid", ans);
        define_syscall!(libc::SYS_setgroups, true, "unknown", ans);
        define_syscall!(libc::SYS_setresgid, true, "unknown", ans);
        define_syscall!(libc::SYS_setresuid, true, "unknown", ans);
        ans
    };
    static ref VALID_SYSCALLS: HashMap<usize, common::Augments> = {
        let mut ans = HashMap::new();
        for key in SYSCALL_INFOS.keys() {
            ans.insert(*key, common::Augments::Perms);
        }
        ans
    };
}

pub struct AugmentPerms<PtraceClient: executor::PtraceClient> {
    pub handler: Arc<TraceeHandler<PtraceClient>>,
}

impl<PtraceClient: executor::PtraceClient> common::AugmentSyscall for AugmentPerms<PtraceClient> {
    fn valid_calls() -> &'static HashMap<usize, common::Augments> {
        &*VALID_SYSCALLS
    }

    fn before_call(&self, regs: GenericPurposeRegs) -> Result<(), SysAugError> {
        let info = SYSCALL_INFOS.get(&regs.syscall_num).unwrap();
        if regs.syscall_num == libc::SYS_setuid as usize {
            self.handler.call_mods(mods::ModFeature::OnSetuid, |m| {
                m.on_setuid(regs.arg0, regs.syscall_num)
            })?;
        } else if info.is_setter {
            event!(
                Level::INFO,
                "Attempting to skip syscall {}",
                regs.syscall_num
            );
            self.handler.skip_syscall(0)?;
        }
        Ok(())
    }

    fn after_call(&self, regs: GenericPurposeRegs) -> Result<(), SysAugError> {
        let info = SYSCALL_INFOS.get(&regs.syscall_num).unwrap();
        if !info.is_setter && info.is_uid {
            self.write_retval(regs, &self.handler.states.override_uid)?;
        } else if !info.is_setter && info.is_gid {
            self.write_retval(regs, &self.handler.states.override_gid)?;
        }
        Ok(())
    }
}

impl<PtraceClient: executor::PtraceClient> AugmentPerms<PtraceClient> {
    pub fn new(handler: Arc<TraceeHandler<PtraceClient>>) -> Self {
        AugmentPerms { handler }
    }

    fn write_retval(
        &self,
        mut regs: GenericPurposeRegs,
        maybe_override_val: &RwLock<Option<usize>>,
    ) -> Result<(), SysAugError> {
        let maybe_override = maybe_override_val
            .read()
            .or(Err(SysAugError::LockTraceeHandler))?;
        if let Some(val) = &*maybe_override {
            regs.set_syscall_retval(*val);
            let pid = self.handler.pid;
            self.handler
                .ptrace_client
                .execute(move || ptrace::setregs(pid, regs))??;
        }
        Ok(())
    }
}
