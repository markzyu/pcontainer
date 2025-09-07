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
