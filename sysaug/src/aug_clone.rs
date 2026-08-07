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

use crate::common::{SysAugError, SyscallInfo};
use crate::handler::AsyncTraceeHandler;
use ptrace::GenericPurposeRegs;

impl<PtraceClient: executor::PtraceClient> AsyncTraceeHandler<'_, PtraceClient> {
    pub async fn augment_sys_clone(
        &self,
        mut regs: GenericPurposeRegs,
        _syscall: &SyscallInfo,
    ) -> Result<(), SysAugError> {
        let pid2 = self.pid;

        regs.arg0 |= libc::CLONE_PTRACE as usize;
        regs.arg0 &= !(libc::CLONE_UNTRACED as usize);
        self.ptrace_client
            .execute(move || ptrace::setregs(pid2, regs))??;

        self.do_resume_syscall().await?;
        Ok(())
    }
}
