use lazy_static::lazy_static;
use nix::sys;
use nix::sys::wait;
use nix::unistd;
use std::convert::TryInto;
use std::os::unix::process::CommandExt;
use std::process;
use thiserror::Error;
use tracing::{event, Level};

const NT_PRSTATUS: libc::c_int = 1;
const STACK_SAFE_ZONE_SIZE: usize = 16 * 1024;
const MAX_STRUCT_SIZE: usize = 2048;

lazy_static! {
    static ref USIZE_SIZE: usize = std::mem::size_of::<usize>();
}

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

    #[error("Failed to wait/waitpid for tracee: {0}")]
    Waitpid(nix::Error),

    #[error("Integer overflow: {0} {1} {2}")]
    IntOverflow(usize, &'static str, usize),
}

pub trait CHeader {
    /// See read_bytes_to_structs
    fn item_size_deducer(&self) -> usize;

    /// See structs_to_tracee_buffer
    fn item_size_updater(&mut self, _size: usize) -> ();
}

pub trait CStruct {
    type H: CHeader;
}

pub fn is_trace_stop(status: &wait::WaitStatus) -> bool {
    matches!(
        status,
        wait::WaitStatus::PtraceEvent(_, _, _)
            | wait::WaitStatus::Stopped(_, nix::sys::signal::Signal::SIGTRAP)
    )
}

pub fn is_syscall_stop(status: &wait::WaitStatus) -> bool {
    matches!(
        status,
        wait::WaitStatus::PtraceEvent(_, _, _) | wait::WaitStatus::PtraceSyscall(_)
    )
}

pub fn is_still_alive(status: &wait::WaitStatus) -> bool {
    !matches!(status, wait::WaitStatus::Exited(_, _))
}

pub fn start(cmd: &mut process::Command, no_attach: bool) -> Result<unistd::Pid, PtraceError> {
    match unsafe { unistd::fork() } {
        Ok(unistd::ForkResult::Parent { child, .. }) => Ok(child),
        Ok(unistd::ForkResult::Child) => {
            if no_attach {
                // Use PTRACE_TRACEME, and wait for tracer's main thread
                nix::sys::ptrace::traceme().unwrap();
            } else {
                // Pause child execution and wait for tracer to PTRACE_ATTACH
                sys::signal::raise(sys::signal::Signal::SIGSTOP).unwrap();
            }
            let e = cmd.exec();
            Err(PtraceError::InitCmdFailed(e))
        }
        Err(e) => Err(PtraceError::StartInitCmd(e)),
    }
}

pub fn pid(child: &process::Child) -> Result<nix::unistd::Pid, PtraceError> {
    let raw_id: u64 = child.id().into();
    let pid: libc::pid_t = raw_id
        .try_into()
        .map_err(|e| PtraceError::ParsePid(raw_id, e))?;
    Ok(nix::unistd::Pid::from_raw(pid))
}

pub fn waitpid(pid: nix::unistd::Pid) -> Result<wait::WaitStatus, PtraceError> {
    Ok(wait::waitpid(pid, Some(wait::WaitPidFlag::WNOHANG)).map_err(PtraceError::Waitpid)?)
}

pub fn wait(child: &process::Child) -> Result<wait::WaitStatus, PtraceError> {
    waitpid(pid(&child)?)
}

pub fn waitpid_hang(pid: nix::unistd::Pid) -> Result<wait::WaitStatus, PtraceError> {
    Ok(wait::waitpid(pid, None).map_err(PtraceError::Waitpid)?)
}

pub fn wait_hang(child: &process::Child) -> Result<wait::WaitStatus, PtraceError> {
    waitpid_hang(pid(&child)?)
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
    unknown_x3: usize,
    unknown_x4: usize,
    unknown_x5: usize,
    unknown_x6: usize,
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
    unknown_x3: usize,
    unknown_x4: usize,
    unknown_x5: usize,
    unknown_x6: usize,
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
    arg3: usize,
    arg5: usize,
    arg4: usize,
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
            sys::ptrace::Request::PTRACE_GETREGSET as u32,
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
            12_u32,
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
            sys::ptrace::Request::PTRACE_SETREGSET as u32,
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
            13_u32,
            libc::pid_t::from(pid),
            std::ptr::null_mut::<i32>(),
            &mut data as *mut _ as *mut libc::c_void,
        )
    };
    nix::errno::Errno::result(res).map_err(PtraceError::SetRegs)?;
    Ok(())
}

#[inline]
fn checked_add(a: usize, b: usize) -> Result<usize, PtraceError> {
    a.checked_add(b).ok_or(PtraceError::IntOverflow(a, "+", b))
}

#[inline]
fn checked_sub(a: usize, b: usize) -> Result<usize, PtraceError> {
    a.checked_sub(b).ok_or(PtraceError::IntOverflow(a, "-", b))
}

#[inline]
fn checked_mul(a: usize, b: usize) -> Result<usize, PtraceError> {
    a.checked_mul(b).ok_or(PtraceError::IntOverflow(a, "*", b))
}

#[inline]
fn checked_div(a: usize, b: usize) -> Result<usize, PtraceError> {
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

pub fn bytes_to_stack(pid: nix::unistd::Pid, bytes: &[u8]) -> Result<usize, PtraceError> {
    let usizes = bytes_to_usizes(bytes)?;
    let size = checked_mul(usizes.len(), *USIZE_SIZE)?;
    let regs = getregs(pid)?;
    let start: usize = checked_sub(regs.sp, checked_add(STACK_SAFE_ZONE_SIZE, size)?)?;
    event!(
        Level::TRACE,
        "Writing {} bytes to tracee stack, {:#x}",
        bytes.len(),
        start
    );
    let mut addr = start;
    for value in usizes.iter() {
        write(pid, addr, *value)?;
        addr = checked_add(addr, *USIZE_SIZE)?;
    }
    Ok(start)
}

pub fn write(pid: nix::unistd::Pid, addr: usize, value: usize) -> Result<(), PtraceError> {
    unsafe {
        sys::ptrace::write(pid, addr as *mut libc::c_void, value as *mut libc::c_void)
            .map_err(PtraceError::Write)?;
    }
    Ok(())
}

pub fn checked_write(
    pid: nix::unistd::Pid,
    addr: usize,
    overflow_addr: usize,
    value: usize,
) -> Result<(), PtraceError> {
    event!(Level::TRACE, "PTRACE_WRITE addr: {:x}", addr);
    if addr >= overflow_addr {
        Err(PtraceError::BufferOverflow(0, addr, overflow_addr))
    } else {
        write(pid, addr, value)
    }
}

/// Read multiple C syscall structures from tracee memory.
/// Here is an explannation:
///
/// Syscalls layout [ ..int.. ..char.. ..char.. (up to 512 chars) ]
/// T struct layout [ ..int.. ..[char; 512].. (exactly 512 chars) ] + #[repr(C)]
///
/// The function returns values in the layout of Rust structs, not C structs.
///
/// Input arguments:
///     T: Rust version of the C structure
///     T::H: Rust version of the header part of the C structure, which should
///                  contain enough information for item_size_deducer to deduce
///                  item_size of this specific structure.
///     item_size: the size of one of the C structure, in syscall layout
///     item_size_deducer: This function will receive T::H,
///                        which only contains the header information. The remaining
///                        information is instantiated as if their byte representations
///                        were zeroed out. This function should return the item_size
///     total_size: The number of bytes representing the entire list of C structures,
///                 as seen in tracee memory.
///
/// Note: The Rust struct must align to the size of machine word:
///             sizeof(T) % sizeof(usize) == 0
///       Otherwise, this function will fail with ReadItemNotAligned
///
/// Note: If Rust struct didn't reserve enough space for item_size, this function will
///       fail with ReadItemTooBig.
///
/// Note: This function reserves a buffer of MAX_STRUCT_SIZE bytes to represent T. If T is bigger,
///       it will fail with ReadItemTooBig.
///
/// Note: If item_size_deducer returns a value smaller than sizeof(T::H), this function
///       will fail with ReadInvalidItemSize1.
///
/// Note: If item_size_deducer returns a value too big for total_size, this function
///       will fail with BufferOverflow.
///
/// Note: Any pointer conversion failure will be reported as Pointer
pub fn read_bytes_to_structs<T>(
    pid: nix::unistd::Pid,
    addr: usize,
    total_size: usize,
) -> Result<Vec<T>, PtraceError>
where
    T: Sized + Clone + CStruct,
{
    let mut result: Vec<T> = Vec::new();
    let mut curr_addr = addr;
    let final_addr = checked_add(addr, total_size)?;
    let t_size = std::mem::size_of::<T>();
    let header_size = std::mem::size_of::<T::H>();
    if t_size % *USIZE_SIZE != 0 {
        return Err(PtraceError::ReadItemNotAligned(t_size));
    }
    if t_size > MAX_STRUCT_SIZE {
        return Err(PtraceError::ReadItemTooBig(t_size, MAX_STRUCT_SIZE));
    }
    if t_size < header_size {
        return Err(PtraceError::HeaderTooBig(header_size, t_size));
    }

    while curr_addr < final_addr {
        let mut buffer = [0_u8; MAX_STRUCT_SIZE];
        let header: &T::H = unsafe {
            (buffer.as_ptr() as *const T::H)
                .as_ref()
                .ok_or(PtraceError::Pointer)?
        };
        let item: &T = unsafe {
            (buffer.as_ptr() as *const T)
                .as_ref()
                .ok_or(PtraceError::Pointer)?
        };

        // Read header
        if checked_add(curr_addr, header_size)? > final_addr {
            return Err(PtraceError::BufferOverflow(
                header_size,
                curr_addr,
                final_addr,
            ));
        }
        read_bytes(pid, curr_addr, header_size, &mut buffer[..])?;
        curr_addr = checked_add(curr_addr, header_size)?;

        // Deduce item_size, remainder_size
        let item_size = header.item_size_deducer();
        let remainder_size = item_size - header_size;
        if item_size < header_size {
            return Err(PtraceError::ReadInvalidItemSize1(item_size, header_size));
        }
        if item_size > t_size {
            return Err(PtraceError::ReadItemTooBig(item_size, t_size));
        }
        if checked_add(curr_addr, remainder_size)? > final_addr {
            return Err(PtraceError::BufferOverflow(
                remainder_size,
                curr_addr,
                final_addr,
            ));
        }

        // Read remainder of item
        read_bytes(pid, curr_addr, remainder_size, &mut buffer[header_size..])?;
        curr_addr = checked_add(curr_addr, remainder_size)?;

        // Save item to result
        result.push(item.clone());
    }
    Ok(result)
}

pub fn read_bytes(
    pid: nix::unistd::Pid,
    addr: usize,
    size: usize,
    result: &mut [u8],
) -> Result<(), PtraceError> {
    let mut curr_addr = addr;

    let mut n_bytes_read = 0;
    while n_bytes_read < size {
        event!(Level::TRACE, "PTRACE_READ addr: {:x}", curr_addr);
        let new_n_bytes_read = checked_add(n_bytes_read, *USIZE_SIZE)?;
        if new_n_bytes_read > size {
            let machine_word = read(pid, curr_addr)?;
            for (i, byte) in machine_word
                .to_ne_bytes()
                .iter()
                .take(size - n_bytes_read)
                .enumerate()
            {
                result[n_bytes_read + i] = *byte;
            }
        } else {
            unsafe {
                let ptr = &mut result[n_bytes_read] as *mut u8 as *mut usize;
                *ptr = read(pid, curr_addr)?;
            }
        }
        curr_addr = checked_add(curr_addr, *USIZE_SIZE)?;
        n_bytes_read = new_n_bytes_read;
    }
    Ok(())
}

pub fn read_bytes_until_zero(pid: nix::unistd::Pid, addr: usize) -> Result<Vec<u8>, PtraceError> {
    let mut result: Vec<u8> = Vec::new();
    let mut curr_addr = addr;
    loop {
        let machine_word = read(pid, curr_addr)?;
        for byte in machine_word.to_ne_bytes().iter() {
            if *byte == b'\0' {
                return Ok(result);
            }
            result.push(*byte);
        }
        curr_addr = checked_add(curr_addr, *USIZE_SIZE)?;
    }
}

/// Write multiple C syscall structures back to tracee memory.
/// Here is an explannation:
///
/// Syscalls layout [ ..int.. ..char.. ..char.. (up to 512 chars) ]
/// T struct layout [ ..int.. ..[char; 512].. (exactly 512 chars) ] + #[repr(C)]
///
/// The function consumes a list of T objects, and writes them out as structs in
/// syscall layouts, by shrinking down the size of T structs, whenever there are
/// too many repeated recurrances of zeroed bytes.
///
/// Input arguments:
///     T: Rust version of the C structure
///     T::H: Rust version of the header part of the C structure, which should
///                  contain a field representing the size of the C structure
///                  itself. Bytes in the header part of the structure will never
///                  be shrunk (see shrink_criteria).
///     shrink_criteria: how many words of consecutive zeroes must be seen before
///                      the remaining consecutive zeroes will be deleted. One word
///                      is the same size as one usize integer. Bytes in T::H will
///                      never be shrunk.
///     item_size_updater: This closure will receive T::H, which is the header part of
///                        the T object, and also receive the correct size after
///                        T is shrunk to syscall format. This closure must update
///                        the correct field in T::H to reflect the change in size.
///                        (Usually this is the `size` field in the structure itself)
///     buffer_size: The maximum number of bytes that can be safely written to
///                  tracee's buffer.
///
/// Returns: Number of bytes written
///
/// Note: The Rust struct must align to the size of machine word:
///             sizeof(T) % sizeof(usize) == 0
///       Otherwise, this function will fail with ReadItemNotAligned
///
/// Note: This function reserves a buffer of MAX_STRUCT_SIZE bytes to represent T. If T is bigger,
///       it will fail with ReadItemTooBig.
///
/// Note: Any pointer conversion failure will be reported as Pointer
pub fn structs_to_tracee_buffer<T>(
    pid: nix::unistd::Pid,
    addr: usize,
    buffer_size: usize,
    mut items: Vec<T>,
    shrink_criteria: usize,
) -> Result<usize, PtraceError>
where
    T: Sized + CStruct,
{
    event!(
        Level::TRACE,
        "Writing ~{} bytes to tracee buffer, {:#x}",
        buffer_size,
        addr
    );
    let mut curr_addr = addr;
    let max_addr = checked_add(addr, buffer_size)?;
    let t_size = std::mem::size_of::<T>();
    let header_size = std::mem::size_of::<T::H>();
    if t_size % *USIZE_SIZE != 0 {
        return Err(PtraceError::ReadItemNotAligned(t_size));
    }
    if t_size > MAX_STRUCT_SIZE {
        return Err(PtraceError::ReadItemTooBig(t_size, MAX_STRUCT_SIZE));
    }
    if t_size < header_size {
        return Err(PtraceError::HeaderTooBig(header_size, t_size));
    }
    let skip_header = checked_div(
        checked_sub(checked_add(header_size, *USIZE_SIZE)?, 1)?,
        *USIZE_SIZE,
    )?;
    let skip_header_bytes = checked_mul(skip_header, *USIZE_SIZE)?;

    for item in items.iter_mut() {
        let mut curr_remainder_addr = checked_add(curr_addr, skip_header_bytes)?;
        let buffer: &mut [usize] = unsafe {
            let ptr = item as *mut T as *mut usize;
            let len = t_size / *USIZE_SIZE;
            std::slice::from_raw_parts_mut(ptr, len)
        };
        let header: &mut T::H = unsafe {
            (buffer.as_mut_ptr() as *mut T::H)
                .as_mut()
                .ok_or(PtraceError::Pointer)?
        };
        if curr_remainder_addr > max_addr {
            return Err(PtraceError::BufferOverflow(
                skip_header_bytes,
                curr_addr,
                max_addr,
            ));
        }

        // Remove excess zeroes and write T without writing T::H
        let mut count_zeroes: usize = 0;
        let mut skipped_zeroes: usize = 0;
        for machine_word in buffer.iter().skip(skip_header) {
            if *machine_word == 0 {
                count_zeroes = checked_add(count_zeroes, 1)?;
                if count_zeroes > shrink_criteria {
                    skipped_zeroes = checked_add(skipped_zeroes, 1)?;
                    continue;
                }
                checked_write(pid, curr_remainder_addr, max_addr, *machine_word)?;
            } else {
                count_zeroes = 0;
                checked_write(pid, curr_remainder_addr, max_addr, *machine_word)?;
            }
            curr_remainder_addr = checked_add(curr_remainder_addr, *USIZE_SIZE)?;
        }

        // Update T::H and write T::H
        if skipped_zeroes > 0 {
            header.item_size_updater(checked_sub(t_size, skipped_zeroes * *USIZE_SIZE)?);
        }
        for machine_word in buffer.iter().take(skip_header) {
            write(pid, curr_addr, *machine_word)?;
            curr_addr = checked_add(curr_addr, *USIZE_SIZE)?;
        }
        curr_addr = curr_remainder_addr;
    }
    Ok(curr_addr - addr)
}

/// Our version of sys::ptrace::read, which returns an integer of the correct size
pub fn read(pid: nix::unistd::Pid, addr: usize) -> Result<usize, PtraceError> {
    event!(Level::TRACE, "PTRACE_READ addr: {:x}", addr);
    let raw_data = sys::ptrace::read(pid, addr as *mut libc::c_void).map_err(PtraceError::Read)?;
    Ok(raw_data as usize)
}

pub fn getevent(pid: nix::unistd::Pid) -> Result<libc::c_ulong, PtraceError> {
    let mut data = std::mem::MaybeUninit::uninit();
    let res = unsafe {
        libc::ptrace(
            sys::ptrace::Request::PTRACE_GETEVENTMSG as u32,
            libc::pid_t::from(pid),
            0 as *mut libc::c_void,
            data.as_mut_ptr() as *mut libc::c_void,
        )
    };
    nix::errno::Errno::result(res).map_err(PtraceError::GetEventMsg)?;
    Ok(unsafe { data.assume_init() })
}

pub fn set_syscall_num(pid: nix::unistd::Pid, val: usize) -> Result<(), PtraceError> {
    let mut regs = getregs(pid)?;
    event!(
        Level::INFO,
        "Replacing syscall {} with {}",
        regs.syscall_num,
        val,
    );

    regs.syscall_num = val;
    setregs(pid, regs)?;

    let regs2 = getregs(pid)?;
    event!(
        Level::TRACE,
        "Confirm regs: syscall {} with {:x} {:x} {:x}",
        regs2.syscall_num,
        regs2.arg0,
        regs2.arg1,
        regs2.arg2,
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use nix::sys::ptrace;
    use nix::sys::wait;
    use ntest::timeout;
    use std::thread;
    use std::time::Duration;

    fn _start_cmd() -> std::process::Child {
        let mut cmd = std::process::Command::new("ls");
        crate::start(&mut cmd).unwrap()
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn test_convert_bytes_to_usizes_exact() {
        let bytes: &[u8] = b"abcdefghijklmnop";
        let _expect: Vec<usize> = vec![7523094288207667809, 8101815670912281193];
        assert!(matches!(crate::bytes_to_usizes(bytes), Ok(_expect)));
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn test_convert_bytes_to_usizes_remainder() {
        let bytes: &[u8] = b"abcdefghijklmnop9";
        let _expect: Vec<usize> = vec![7523094288207667809, 8101815670912281193, 57];
        assert!(matches!(crate::bytes_to_usizes(bytes), Ok(_expect)));
    }

    #[test]
    #[timeout(100)]
    fn test_start_cmd_does_wait_and_child_is_stopped() {
        let child = _start_cmd();
        let status = crate::wait(&child).unwrap();
        assert!(matches!(status, wait::WaitStatus::StillAlive));
        assert!(!crate::is_trace_stop(&status));
        assert!(crate::is_still_alive(&status));
    }

    #[test]
    #[timeout(100)]
    fn test_is_trace_stop_and_is_still_alive() {
        let child = _start_cmd();
        let pid = crate::pid(&child).unwrap();
        ptrace::setoptions(pid.clone(), ptrace::Options::PTRACE_O_TRACEEXIT).unwrap();
        ptrace::cont(pid.clone(), None).unwrap();

        thread::sleep(Duration::from_millis(20)); // Note: without sleep, wait will return StillAlive instead.
        let status = crate::wait(&child).unwrap();
        assert!(matches!(status, wait::WaitStatus::PtraceEvent(_, _, _)));
        assert!(crate::is_trace_stop(&status));
        assert!(crate::is_still_alive(&status));
    }

    #[test]
    #[timeout(100)]
    fn test_child_finished_and_is_not_still_alive() {
        let child = _start_cmd();
        let pid = crate::pid(&child).unwrap();
        let mut status = crate::wait(&child).unwrap();
        assert!(matches!(status, wait::WaitStatus::StillAlive));
        assert!(!crate::is_trace_stop(&status));
        assert!(crate::is_still_alive(&status));

        ptrace::detach(pid.clone(), None).unwrap();
        status = crate::wait_hang(&child).unwrap();
        assert!(!crate::is_trace_stop(&status));
        assert!(!crate::is_still_alive(&status));
    }
}
