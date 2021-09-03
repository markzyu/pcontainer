use crate::common;
use crate::common::{SysAugError, SyscallInfo, PERMS_IDBIT_UG};
use crate::handler::TraceeHandler;
use crate::mods;
use ptrace::GenericPurposeRegs;
use std::sync::Arc;
use tracing::{event, Level};

pub struct AugmentPerms<PtraceClient: executor::PtraceClient> {
    pub handler: Arc<TraceeHandler<PtraceClient>>,
}

impl<PtraceClient: executor::PtraceClient> common::AugmentSyscall for AugmentPerms<PtraceClient> {
    fn before_call(
        &self,
        regs: GenericPurposeRegs,
        syscall: &SyscallInfo,
    ) -> Result<(), SysAugError> {
        if !syscall.is_setter {
            return Ok(());
        }
        if syscall.num == libc::SYS_setgroups {
            return self.handler.skip_syscall(0);
        }

        let res_bits = syscall.res_bits;
        if res_bits == 0 {
            self.handler.call_mods(mods::ModFeature::OnSetid, |m| {
                m.on_setid(syscall.resf_bit, regs.arg0, syscall)
            })?;
        } else {
            let ug_bit = res_bits & PERMS_IDBIT_UG;
            let possible_args = &[regs.arg0, regs.arg1, regs.arg2];
            for i in 0..3 {
                let match_bit = res_bits & (1 << i);
                if match_bit == 0 {
                    continue;
                }

                self.handler.call_mods(mods::ModFeature::OnSetid, |m| {
                    m.on_setid(match_bit | ug_bit, possible_args[i], syscall)
                })?;
            }
        }
        Ok(())
    }

    fn after_call(
        &self,
        regs: GenericPurposeRegs,
        syscall: &SyscallInfo,
    ) -> Result<(), SysAugError> {
        if syscall.is_setter {
            return Ok(());
        }
        if syscall.num == libc::SYS_getgroups {
            return self.write_retval(regs, 0);
        }

        let res_bits = syscall.res_bits;
        if res_bits == 0 {
            let maybe_override = common::rwlock_read(&self.handler.states.perms_ids)?;
            if let Some(val) = maybe_override[syscall.resf_bit as usize].as_ref() {
                self.write_retval(regs, *val)?;
            }
        } else {
            return Err(SysAugError::UnimplementedAugment);
        }
        Ok(())
    }
}

impl<PtraceClient: executor::PtraceClient> AugmentPerms<PtraceClient> {
    pub fn new(handler: Arc<TraceeHandler<PtraceClient>>) -> Self {
        AugmentPerms { handler }
    }

    fn write_retval(&self, mut regs: GenericPurposeRegs, val: usize) -> Result<(), SysAugError> {
        event!(Level::INFO, "Setting return value: {}", val);
        regs.set_syscall_retval(val);
        let pid = self.handler.pid;
        self.handler
            .ptrace_client
            .execute(move || ptrace::setregs(pid, regs))??;
        Ok(())
    }
}
