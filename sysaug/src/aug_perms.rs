// Copyright 2026 Zhongzhi Yu <7296488+markzyu@users.noreply.github.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.

use crate::common;
use crate::common::{SysAugError, SyscallInfo, PERMS_IDBIT_UG};
use crate::handler::AsyncTraceeHandler;
use crate::mods;
use ptrace::GenericPurposeRegs;
use tracing::{event, Level};

impl<PtraceClient: executor::PtraceClient> AsyncTraceeHandler<'_, PtraceClient> {
    pub async fn augment_sys_perms(
        &self,
        orig_regs: GenericPurposeRegs,
        syscall: &SyscallInfo,
    ) -> Result<(), SysAugError> {
        if syscall.is_setter {
            if syscall.num == libc::SYS_setgroups {
                return self.do_skip_syscall(0).await;
            }

            let res_bits = syscall.res_bits;
            if res_bits == 0 {
                self.call_mods(mods::ModFeature::OnSetid, |m| {
                    m.on_setid(syscall.resf_bit, orig_regs.arg0, syscall)
                })
                .await?;
            } else {
                let ug_bit = res_bits & PERMS_IDBIT_UG;
                let possible_args = &[orig_regs.arg0, orig_regs.arg1, orig_regs.arg2];
                for (i, possible_arg) in possible_args.iter().enumerate() {
                    let match_bit = res_bits & (1 << i);
                    if match_bit == 0 {
                        continue;
                    }

                    self.call_mods(mods::ModFeature::OnSetid, |m| {
                        m.on_setid(match_bit | ug_bit, *possible_arg, syscall)
                    })
                    .await?;
                }
            }
        }

        let regs = self.do_resume_syscall().await?;

        if !syscall.is_setter {
            if syscall.num == libc::SYS_getgroups {
                return self.write_retval(regs, 0);
            }

            let res_bits = syscall.res_bits;
            if res_bits == 0 {
                let maybe_override = common::rwlock_read(&self.states.perms_ids)?;
                if let Some(val) = maybe_override[syscall.resf_bit as usize].as_ref() {
                    self.write_retval(regs, *val)?;
                }
            } else {
                return Err(SysAugError::UnimplementedAugment);
            }
        }
        Ok(())
    }

    fn write_retval(&self, mut regs: GenericPurposeRegs, val: usize) -> Result<(), SysAugError> {
        event!(Level::INFO, "Setting return value: {}", val);
        regs.set_syscall_retval(val);
        let pid = self.pid;
        self.ptrace_client
            .execute(move || ptrace::setregs(pid, regs))??;
        Ok(())
    }
}
