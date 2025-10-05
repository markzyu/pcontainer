/// Slower, but more supported method to access tracee memory (ptrace)
use crate::common::{
    aligned, bytes_to_usizes, checked_add, checked_div, checked_mul, checked_sub, getregs, CHeader,
    CStruct, NixISize, PtraceError, MAX_STRUCT_SIZE, STACK_SAFE_ZONE_SIZE, USIZE_SIZE, MemHelpers, write
};
use nix::sys;
use tracing::{event, Level};

/// This always writes to the same location of tracee stack.
/// So if you want to write multiple byte arrays, each one must have a different offset
///
/// # Parameters
///
/// pid: The actual process id of your tracee
/// offset: Offset in the safe memory region where we'd start writing `bytes`
/// bytes: The content to write
///
/// # Returns
///
/// start: The actual tracee side pointer
/// new_offset: The unit is in bytes
///
/// # Safety
/// This function is unsafe because you need to choose `offset` carefully. If you call
/// this function multiple times during the same system call, you might overwrite your
/// own progress if `offset` is incorrect.
unsafe fn write_bytes_to_tracee(
    pid: nix::unistd::Pid,
    offset: usize,
    bytes: &[u8],
) -> Result<(usize, usize), PtraceError> {
    if offset % *USIZE_SIZE != 0 {
        return Err(PtraceError::WriteOffsetNotAligned(offset));
    }
    let usizes = bytes_to_usizes(bytes)?;
    let size = checked_mul(usizes.len(), *USIZE_SIZE)?;
    let regs = getregs(pid)?;
    let total_offset = checked_add(offset, checked_add(STACK_SAFE_ZONE_SIZE, size)?)?;
    let start: usize = checked_sub(regs.sp, total_offset)?;
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

    let new_offset = checked_add(offset, size)?;
    Ok((start, new_offset))
}

fn read_bytes(
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

fn read_bytes_until_num_zeroes(
    pid: nix::unistd::Pid,
    addr: usize,
    n0: usize,
) -> Result<Vec<u8>, PtraceError> {
    let mut result: Vec<u8> = Vec::new();
    let mut curr_addr = addr;
    let mut total_zeroes = 0;
    loop {
        let machine_word = read(pid, curr_addr)?;
        for byte in machine_word.to_ne_bytes().iter() {
            if *byte == b'\0' {
                total_zeroes += 1;
                if total_zeroes >= n0 {
                    return Ok(result);
                }
            } else {
                total_zeroes = 0;
            }
            result.push(*byte);
        }
        curr_addr = checked_add(curr_addr, *USIZE_SIZE)?;
    }
}

fn read_bytes_until_zero(pid: nix::unistd::Pid, addr: usize) -> Result<Vec<u8>, PtraceError> {
    read_bytes_until_num_zeroes(pid, addr, 1)
}

/// Our version of sys::ptrace::read, which returns an integer of the correct size
fn read(pid: nix::unistd::Pid, addr: usize) -> Result<usize, PtraceError> {
    event!(Level::TRACE, "PTRACE_READ addr: {:x}", addr);
    let raw_data = sys::ptrace::read(pid, addr as *mut libc::c_void).map_err(PtraceError::Read)?;
    Ok(raw_data as usize)
}

fn close_tracee(_: &nix::unistd::Pid) -> Result<(), PtraceError> {
    Ok(())
}

pub const slow_mem_helper: MemHelpers = MemHelpers {
    close_tracee,
    read,
    read_bytes,
    read_bytes_until_num_zeroes,
    read_bytes_until_zero,
    write_bytes_to_tracee,
};
