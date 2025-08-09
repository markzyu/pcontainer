use crate::common;
use crate::common::{rwlock_read, SysAugError, SyscallInfo};
use crate::handler::TraceeHandler;
use ptrace::GenericPurposeRegs;
use std::sync::Arc;
use tracing::{event, Level};

pub struct AugmentMmap<PtraceClient: executor::PtraceClient> {
    pub handler: Arc<TraceeHandler<PtraceClient>>,
}

impl<PtraceClient: executor::PtraceClient> common::AugmentSyscall for AugmentMmap<PtraceClient> {
    fn before_call(
        &self,
        mut regs: GenericPurposeRegs,
        syscall: &SyscallInfo,
    ) -> Result<(), SysAugError> {
        let mmap_addr = rwlock_read(&self.handler.states.mmap_addr)?;
        let read_args = [regs.arg0, regs.arg1, regs.arg2, regs.arg3];
        if syscall.is_unmap {
            event!(
                Level::INFO,
                "Checking munmap for {:?}",
                &read_args[syscall.map_addr_position]
            );
            if Some(read_args[syscall.map_addr_position]) == *mmap_addr {
                event!(Level::INFO, "Skipping munmap for {:?}", *mmap_addr);
                self.handler.skip_syscall(0 as usize)?;
                return Ok(());
            }
        }
        Ok(())
    }

    fn after_call(
        &self,
        _regs: GenericPurposeRegs,
        _syscall: &SyscallInfo,
    ) -> Result<(), SysAugError> {
        Ok(())
    }
}

impl<PtraceClient: executor::PtraceClient> AugmentMmap<PtraceClient> {
    pub fn new(handler: Arc<TraceeHandler<PtraceClient>>) -> Self {
        AugmentMmap { handler }
    }
}
