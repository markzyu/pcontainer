use crate::common;
use crate::common::{SysAugError, SyscallInfo};
use crate::handler::TraceeHandler;
use crate::mods;
use ptrace::GenericPurposeRegs;
use std::sync::{Arc, RwLock};

pub struct AugmentPerms<PtraceClient: executor::PtraceClient> {
    pub handler: Arc<TraceeHandler<PtraceClient>>,
}

impl<PtraceClient: executor::PtraceClient> common::AugmentSyscall for AugmentPerms<PtraceClient> {
    fn before_call(
        &self,
        regs: GenericPurposeRegs,
        syscall: &SyscallInfo,
    ) -> Result<(), SysAugError> {
        if regs.syscall_num == libc::SYS_setuid as usize {
            self.handler.call_mods(mods::ModFeature::OnSetuid, |m| {
                m.on_setuid(regs.arg0, syscall)
            })?;
        } else if syscall.is_setter {
            self.handler.skip_syscall(0)?;
        }
        Ok(())
    }

    fn after_call(
        &self,
        regs: GenericPurposeRegs,
        syscall: &SyscallInfo,
    ) -> Result<(), SysAugError> {
        if !syscall.is_setter && syscall.is_uid {
            self.write_retval(regs, &self.handler.states.override_uid)?;
        } else if !syscall.is_setter && syscall.is_gid {
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
