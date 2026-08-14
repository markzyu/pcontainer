// Copyright 2026 Zhongzhi Yu <7296488+markzyu@users.noreply.github.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

use crate::common::{PermsMode, SysAugError, SyscallInfo};
use crate::config::walk_resf_syscall;
use crate::handler_async::AsyncTraceeHandler;
use ptrace::GenericPurposeRegs;
use tracing::{Level, event};

impl<PtraceClient: executor::PtraceClient> AsyncTraceeHandler<'_, PtraceClient> {
    pub async fn augment_sys_perms(
        &self,
        orig_regs: GenericPurposeRegs,
        syscall: &SyscallInfo,
    ) -> Result<(), SysAugError> {
        let possible_args = &[orig_regs.arg0, orig_regs.arg1, orig_regs.arg2];
        if syscall.is_setter && self.consts.args.perms_mode != PermsMode::Passthrough {
            let is_handled = walk_resf_syscall(syscall, true, &self.perms_ids, |i, val| {
                let proposed_id = if let Some(i) = i {
                    possible_args[i]
                } else {
                    orig_regs.syscall_retval()
                };
                let final_id = self.handle_setid(syscall, proposed_id)?;
                *val = Some(final_id);
                Ok(())
            })?;

            if !is_handled {
                return self.do_skip_syscall(0).await;
            }
        }

        let regs = self.do_resume_syscall().await?;

        if !syscall.is_setter && self.consts.args.perms_mode != PermsMode::Passthrough {
            let is_known_getter = walk_resf_syscall(
                syscall,
                regs.syscall_retval() == 0,
                &self.perms_ids,
                |i, val| {
                    if let Some(i) = i {
                        let pid = self.pid;
                        let ptr_addr = possible_args[i];
                        if let Some(val) = val.as_ref() {
                            let val = *val;
                            event!(
                                Level::INFO,
                                "Writing id {} to tracee pointer {:x}",
                                val,
                                ptr_addr
                            );
                            self.ptrace_client
                                .execute(move || ptrace::write(pid, ptr_addr, val))??;
                        }
                    } else if let Some(val) = val.as_ref() {
                        event!(
                            Level::INFO,
                            "Writing id {} to return value of {}",
                            *val,
                            syscall.name()
                        );
                        self.write_retval(regs.clone(), *val)?;
                    }
                    Ok(())
                },
            )?;
            if !is_known_getter && (regs.syscall_retval() as isize) < 0 {
                // The default behavior is to let the unknown getter syscall succeed.
                return self.write_retval(regs, 0);
            }
        }
        Ok(())
    }

    fn handle_setid(
        &self,
        syscall: &SyscallInfo,
        proposed_id: usize,
    ) -> Result<usize, SysAugError> {
        if self.consts.args.perms_mode == PermsMode::RootOnly {
            if proposed_id >= usize::MAX / 2 {
                event!(
                    Level::INFO,
                    "Ignoring {} where id is negative",
                    syscall.name()
                );
                return Ok(0);
            }
        }
        event!(
            Level::INFO,
            "Setting id ({}) to {}",
            syscall.name(),
            proposed_id
        );
        Ok(proposed_id)
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
