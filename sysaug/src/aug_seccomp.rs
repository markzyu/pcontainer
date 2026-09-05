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

use crate::common::{PR_SET_SECCOMP, SECCOMP_SET_MODE_FILTER, SysAugError, SyscallInfo};
use crate::handler_async::AsyncTraceeHandler;
use pocker_ptrace::GenericPurposeRegs;
use tracing::{Level, event};

impl<PtraceClient: pocker_executor::PtraceClient> AsyncTraceeHandler<'_, PtraceClient> {
    pub async fn augment_sys_seccomp(
        &self,
        regs: GenericPurposeRegs,
        syscall: &SyscallInfo,
    ) -> Result<(), SysAugError> {
        if syscall.num == libc::SYS_prctl {
            if regs.arg0 != PR_SET_SECCOMP {
                self.do_resume_syscall().await?;
                return Ok(());
            }
        }

        let Some(seccomp_position) = syscall.seccomp_position else {
            event!(
                Level::WARN,
                "Seccomp operation code not defined for syscall {}",
                syscall.name
            );
            self.do_skip_syscall(-libc::ENOSYS as usize).await?;
            return Ok(());
        };
        if seccomp_position >= 3 {
            event!(
                Level::WARN,
                "Seccomp operation code not defined for syscall {}",
                syscall.name
            );
            self.do_skip_syscall(-libc::ENOSYS as usize).await?;
            return Ok(());
        }
        let possible_args = [regs.arg0, regs.arg1, regs.arg2];

        // Read the actual seccomp operation code and decide next steps
        let seccomp_operation = possible_args[seccomp_position];
        if seccomp_operation == SECCOMP_SET_MODE_FILTER {
            event!(
                Level::ERROR,
                "Recursive seccomp is not implemented yet, and was attempted by tracee"
            );
            self.do_skip_syscall(-libc::ENOSYS as usize).await?;
            return Ok(());
        }

        self.do_resume_syscall().await?;
        Ok(())
    }
}
