use lazy_static::lazy_static;
use nix::sys;
use std::convert::TryInto;
use thiserror::Error;

pub const NT_PRSTATUS: libc::c_int = 1;
pub const STACK_SAFE_ZONE_SIZE: usize = 16 * 1024;
pub const MAX_NUM_TRACEES: usize = 8192;
pub const MAX_STRUCT_SIZE: usize = 2048;

/// Should be exactly 128MB of RAM, divided into 8192 regions of shared 'stack'
///
/// This RAM is shared from tracer to all tracees, readonly for tracees.
///
/// Each region is indexed and there will be a global hashmap + vec in tracer's
/// private RAM, to allocate and track regions for tracees. Every alive tracee
/// keeps their index once allocated and releases it back into the vec + hashmap
/// when tracee exits.
pub const SHARED_MMAP_SIZE: usize = MAX_NUM_TRACEES * STACK_SAFE_ZONE_SIZE;

/// Max number of total structs in the entire shared mmap
pub const MAX_NUM_STRUCTS: usize = SHARED_MMAP_SIZE / MAX_STRUCT_SIZE;

/// Max number of total structs in the an individual region of shared mmap
pub const MAX_NUM_STRUCTS_PER_TRACEE: usize = STACK_SAFE_ZONE_SIZE / MAX_STRUCT_SIZE;

#[cfg(not(any(target_env = "gnu")))]
pub const PTRACE_GETEVENTMSG: i32 = libc::PTRACE_GETEVENTMSG as i32;

#[cfg(any(target_env = "gnu"))]
pub const PTRACE_GETEVENTMSG: u32 = sys::ptrace::Request::PTRACE_GETEVENTMSG as u32;

#[cfg(not(any(target_env = "gnu")))]
pub const PTRACE_GETREGSET: i32 = libc::PTRACE_GETREGSET as i32;

#[cfg(any(target_env = "gnu"))]
pub const PTRACE_GETREGSET: u32 = sys::ptrace::Request::PTRACE_GETREGSET as u32;

#[cfg(not(any(target_env = "gnu")))]
pub const PTRACE_SETREGSET: i32 = libc::PTRACE_SETREGSET as i32;

#[cfg(any(target_env = "gnu"))]
pub const PTRACE_SETREGSET: u32 = sys::ptrace::Request::PTRACE_SETREGSET as u32;

lazy_static! {
    pub static ref USIZE_SIZE: usize = std::mem::size_of::<usize>();
}

/// To help us index the structs within a tracee's own mmap region
pub type SharedStructs = [[usize; MAX_STRUCT_SIZE]; MAX_NUM_STRUCTS_PER_TRACEE];

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub type NixISize = i64;

#[cfg(any(target_arch = "x86", target_arch = "arm"))]
pub type NixISize = i32;

#[derive(Debug, Error)]
pub enum PtraceError {
    #[error("Failed to run the command specified in --cmd: {0}")]
    StartInitCmd(nix::Error),

    #[error("Failed to run the command specified in --cmd: {0}")]
    InitCmdFailed(std::io::Error),

    #[error("Failed to parse pid {0}: {1}")]
    ParsePid(u64, <u64 as TryInto<libc::pid_t>>::Error),

    #[error("Failed to parse usize {0:#x}: {1}")]
    ParseUsize(i64, <i64 as TryInto<usize>>::Error),

    #[error("PTRACE_GETEVENTMSG error: {0}")]
    GetEventMsg(nix::Error),

    #[error("Cannot get tracee's CPU registers: {0}")]
    GetRegs(nix::Error),

    #[error("Cannot set tracee's CPU registers: {0}")]
    SetRegs(nix::Error),

    #[error("Cannot read tracee memory: {0}")]
    Read(nix::Error),

    #[error("Cannot read tracee memory of size {0} (not aligned)")]
    ReadItemNotAligned(usize),

    #[error("Cannot read tracee memory: item too big: {0} > {1}")]
    ReadItemTooBig(usize, usize),

    #[error("Cannot read tracee memory: header too big: {1} > {0}")]
    ReadInvalidItemSize1(usize, usize),

    #[error("Accessing tracee memory: buffer overflow: {1:#x} + {0} > {2:#x}")]
    BufferOverflow(usize, usize, usize),

    #[error("Accessing tracee memory: object header is too big: {0} > {1}")]
    HeaderTooBig(usize, usize),

    #[error("Accessing tracee memory: failed to convert pointers")]
    Pointer,

    #[error("Cannot write tracee memory: {0}")]
    Write(nix::Error),

    #[error("Cannot write tracee memory of offset {0} (not aligned)")]
    WriteOffsetNotAligned(usize),

    #[error("Failed to wait/waitpid for tracee: {0}")]
    Waitpid(nix::Error),

    #[error("Integer overflow: {0} {1} {2}")]
    IntOverflow(usize, &'static str, usize),

    #[error("Cannot create linux memfd: {0}")]
    CreateMemoryFile(nix::Error),

    #[error("Internal error, async runtime detected invalid usage of external async library")]
    AsyncBanOfExternalCode,
}

pub trait CHeader {
    /// See read_bytes_to_structs
    fn item_size_deducer(&self) -> usize;

    /// See structs_to_tracee_buffer
    fn item_size_updater(&mut self, _size: usize);
}

pub trait CStruct {
    type H: CHeader;
}

/// For Android, See https://android.googlesource.com/platform/prebuilts/ndk/+/1b55d7b281f282232ee58da5d09d3da5969ff11d/9/platforms/android-19/arch-arm64/usr/include/sys/user.h
/// https://android.googlesource.com/kernel/common/+/60ffc30d5652810dd34ea2eec41504222f5d5791/arch/arm64/include/asm/ptrace.h (user_pt_regs)
#[cfg(target_arch = "aarch64")]
#[derive(Debug, Clone)]
#[repr(C)]
#[allow(dead_code)]
pub struct GenericPurposeRegs {
    pub arg0: usize,
    pub arg1: usize,
    pub arg2: usize,
    pub arg3: usize,
    pub arg4: usize,
    pub arg5: usize,
    pub arg6: usize,
    unknown_x7: usize,
    pub syscall_num: usize,
    unknown_x9: usize,
    unknown_x10: usize,
    unknown_x11: usize,
    unknown_x12: usize,
    unknown_x13: usize,
    unknown_x14: usize,
    unknown_x15: usize,
    unknown_x16: usize,
    unknown_x17: usize,
    unknown_x18: usize,
    unknown_x19: usize,
    unknown_x20: usize,
    unknown_x21: usize,
    unknown_x22: usize,
    unknown_x23: usize,
    unknown_x24: usize,
    unknown_x25: usize,
    unknown_x26: usize,
    unknown_x27: usize,
    unknown_x28: usize,
    unknown_x29: usize,
    unknown_x30: usize,
    pub sp: usize,
    pub pc: usize,
    pstate: usize,
}

#[cfg(target_arch = "arm")]
#[derive(Debug, Clone)]
#[repr(C)]
#[allow(dead_code)]
pub struct GenericPurposeRegs {
    pub arg0: usize,
    pub arg1: usize,
    pub arg2: usize,
    pub arg3: usize,
    pub arg4: usize,
    pub arg5: usize,
    pub arg6: usize,
    pub syscall_num: usize,
    unknown_x8: usize,
    unknown_x9: usize,
    unknown_x10: usize,
    unknown_x11: usize,
    unknown_x12: usize,
    pub sp: usize,
    unknown_x14: usize,
    pub pc: usize,
    unknown_x16: usize,
    pub orig_r0: usize,
}

// https://man7.org/linux/man-pages/man2/syscall.2.html
#[cfg(target_arch = "x86_64")]
#[derive(Debug, Clone)]
#[repr(C)]
#[allow(dead_code)]
pub struct GenericPurposeRegs {
    unknown_x1: usize,
    unknown_x2: usize,
    unknown_x3: usize,
    unknown_x4: usize,
    unknown_x5: usize,
    unknown_x6: usize,
    unknown_x7: usize,
    pub arg3: usize,
    pub arg5: usize,
    pub arg4: usize,
    // "rax"
    rax: usize,
    unknown_x12: usize,
    pub arg2: usize,
    pub arg1: usize,
    pub arg0: usize,
    // "orig_rax"
    pub syscall_num: usize,
    pub pc: usize,
    unknown_x18: usize,
    unknown_x19: usize,
    pub sp: usize,
    unknown_x21: usize,
    unknown_x22: usize,
    unknown_x23: usize,
    unknown_x24: usize,
    unknown_x25: usize,
    unknown_x26: usize,
    unknown_x27: usize,
}

#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
impl GenericPurposeRegs {
    pub fn syscall_retval(&self) -> usize {
        self.arg0
    }

    pub fn set_syscall_retval(&mut self, val: usize) {
        self.arg0 = val
    }
}

#[cfg(target_arch = "x86_64")]
impl GenericPurposeRegs {
    pub fn syscall_retval(&self) -> usize {
        self.rax
    }

    pub fn set_syscall_retval(&mut self, val: usize) {
        self.rax = val
    }
}

/// Use this as reference: https://android.googlesource.com/platform/system/core/+/59d16c9e9171f4367ad3a0516e7000c0d95e89cf/debuggerd/arm64/machine.cpp
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
pub fn getregs(pid: nix::unistd::Pid) -> Result<GenericPurposeRegs, PtraceError> {
    let mut data = std::mem::MaybeUninit::uninit();
    let res = unsafe {
        let mut iov = libc::iovec {
            iov_base: data.as_mut_ptr() as *mut _ as *mut libc::c_void,
            iov_len: std::mem::size_of::<GenericPurposeRegs>(),
        };
        libc::ptrace(
            PTRACE_GETREGSET,
            libc::pid_t::from(pid),
            NT_PRSTATUS as *mut libc::c_void,
            &mut iov as *mut _ as *mut libc::c_void,
        )
    };
    nix::errno::Errno::result(res).map_err(PtraceError::GetRegs)?;
    Ok(unsafe { data.assume_init() })
}

/// Use this as reference: https://android.googlesource.com/platform/prebuilts/ndk/+/refs/heads/lollipop-dev/9/platforms/android-5/arch-arm/usr/include/asm/ptrace.h
#[cfg(target_arch = "arm")]
pub fn getregs(pid: nix::unistd::Pid) -> Result<GenericPurposeRegs, PtraceError> {
    let mut data = std::mem::MaybeUninit::uninit();
    let res = unsafe {
        libc::ptrace(
            // PTRACE_GETREGS
            12,
            libc::pid_t::from(pid),
            std::ptr::null_mut::<i32>(),
            data.as_mut_ptr() as *mut _ as *mut libc::c_void,
        )
    };
    nix::errno::Errno::result(res).map_err(PtraceError::GetRegs)?;
    Ok(unsafe { data.assume_init() })
}

/// Use this as reference: https://android.googlesource.com/platform/system/core/+/59d16c9e9171f4367ad3a0516e7000c0d95e89cf/debuggerd/arm64/machine.cpp
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
pub fn setregs(pid: nix::unistd::Pid, mut data: GenericPurposeRegs) -> Result<(), PtraceError> {
    let res = unsafe {
        let mut iov = libc::iovec {
            iov_base: &mut data as *mut _ as *mut libc::c_void,
            iov_len: std::mem::size_of::<GenericPurposeRegs>(),
        };
        libc::ptrace(
            PTRACE_SETREGSET,
            libc::pid_t::from(pid),
            NT_PRSTATUS as *mut libc::c_void,
            &mut iov as *mut _ as *mut libc::c_void,
        )
    };
    nix::errno::Errno::result(res).map_err(PtraceError::SetRegs)?;
    Ok(())
}

/// Use this as reference: https://android.googlesource.com/platform/prebuilts/ndk/+/refs/heads/lollipop-dev/9/platforms/android-5/arch-arm/usr/include/asm/ptrace.h
#[cfg(target_arch = "arm")]
pub fn setregs(pid: nix::unistd::Pid, mut data: GenericPurposeRegs) -> Result<(), PtraceError> {
    let res = unsafe {
        libc::ptrace(
            13,
            libc::pid_t::from(pid),
            std::ptr::null_mut::<i32>(),
            &mut data as *mut _ as *mut libc::c_void,
        )
    };
    nix::errno::Errno::result(res).map_err(PtraceError::SetRegs)?;
    Ok(())
}

#[inline]
pub fn checked_add(a: usize, b: usize) -> Result<usize, PtraceError> {
    a.checked_add(b).ok_or(PtraceError::IntOverflow(a, "+", b))
}

#[inline]
pub fn checked_sub(a: usize, b: usize) -> Result<usize, PtraceError> {
    a.checked_sub(b).ok_or(PtraceError::IntOverflow(a, "-", b))
}

#[inline]
pub fn checked_mul(a: usize, b: usize) -> Result<usize, PtraceError> {
    a.checked_mul(b).ok_or(PtraceError::IntOverflow(a, "*", b))
}

#[inline]
pub fn checked_div(a: usize, b: usize) -> Result<usize, PtraceError> {
    a.checked_div(b).ok_or(PtraceError::IntOverflow(a, "*", b))
}

pub fn bytes_to_usizes(bytes: &[u8]) -> Result<Vec<usize>, PtraceError> {
    let mut result: Vec<usize> = Vec::new();
    let iter = bytes.chunks_exact(*USIZE_SIZE);
    for chunk in iter {
        result.push(usize::from_ne_bytes(chunk.try_into().unwrap()));
    }

    let remainder_pos = checked_mul(result.len(), *USIZE_SIZE)?;
    let mut remainder_vec: Vec<u8> = Vec::new();
    remainder_vec.resize(*USIZE_SIZE, 0);

    for (i, byte) in bytes.iter().skip(remainder_pos).enumerate() {
        remainder_vec[i] = *byte;
    }
    result.push(usize::from_ne_bytes(
        (&remainder_vec[..]).try_into().unwrap(),
    ));
    Ok(result)
}

pub fn aligned(val: usize) -> Result<usize, PtraceError> {
    let num_usizes = checked_div(checked_sub(checked_add(val, *USIZE_SIZE)?, 1)?, *USIZE_SIZE)?;
    checked_mul(num_usizes, *USIZE_SIZE)
}

#[cfg(target_arch = "aarch64")]
#[cfg(test)]
mod tests {
    use crate::common;

    #[test]
    fn test_convert_bytes_to_usizes_exact() {
        let bytes: &[u8] = b"abcdefghijklmnop";
        let _expect: Vec<usize> = vec![7523094288207667809, 8101815670912281193];
        assert!(matches!(common::bytes_to_usizes(bytes), Ok(_expect)));
    }

    #[test]
    fn test_convert_bytes_to_usizes_remainder() {
        let bytes: &[u8] = b"abcdefghijklmnop9";
        let _expect: Vec<usize> = vec![7523094288207667809, 8101815670912281193, 57];
        assert!(matches!(common::bytes_to_usizes(bytes), Ok(_expect)));
    }
}
