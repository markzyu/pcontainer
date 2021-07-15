use crate::common;
use crate::common::SysAugError;
use crate::handler::TraceeHandler;
use crate::mods;
use lazy_static::lazy_static;
use ptrace::GenericPurposeRegs;
use std::collections::HashMap;
use std::sync::Arc;

struct SyscallInfo {
    // true -> setuid/setgid, false -> getuid/getgid
    is_setter: bool,

    // true -> setuid/getuid, false -> setgid/getgid
    is_uid: bool,
}

macro_rules! define_syscall {
    ($name:expr, $is_setter:expr, $is_uid:expr, $ans:ident) => {
        $ans.insert(
            $name as usize,
            SyscallInfo {
                is_setter: $is_setter,
                is_uid: $is_uid,
            },
        )
    };
}

lazy_static! {
    static ref SYSCALL_INFOS: HashMap<usize, SyscallInfo> = {
        let mut ans = HashMap::new();
        define_syscall!(libc::SYS_getuid, false, true, ans);
        // define_syscall!(libc::SYS_geteuid, false, true, ans);
        define_syscall!(libc::SYS_setuid, true, true, ans);
        define_syscall!(libc::SYS_getgid, false, false, ans);
        // define_syscall!(libc::SYS_getegid, false, false, ans);
        define_syscall!(libc::SYS_setgid, true, false, ans);
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
        if regs.syscall_num == libc::SYS_setuid as usize {
            self.handler.call_mods(mods::ModFeature::OnSetuid, |m| {
                m.on_setuid(regs.arg0, regs.syscall_num)
            })?;
        }
        Ok(())
    }

    fn after_call(&self, mut regs: GenericPurposeRegs) -> Result<(), SysAugError> {
        if regs.syscall_num == libc::SYS_getuid as usize {
            let maybe_override = self
                .handler
                .states
                .override_uid
                .read()
                .or(Err(SysAugError::LockTraceeHandler))?;
            if let Some(uid) = *maybe_override {
                regs.set_syscall_retval(uid);
            }
        }
        Ok(())
    }
}

impl<PtraceClient: executor::PtraceClient> AugmentPerms<PtraceClient> {
    pub fn new(handler: Arc<TraceeHandler<PtraceClient>>) -> Self {
        AugmentPerms { handler }
    }
}
