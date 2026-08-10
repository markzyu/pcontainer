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

// Faster, but less supported method to access tracee memory (mmap)
use crate::common::{
    checked_add, MemHelpers, PtraceError, AVAILABLE_REGION_IDS, MAX_NUM_TRACEES, REGION_IDS_BY_PID,
    SHARED_REGIONS, STACK_SAFE_ZONE_SIZE,
};
use nix::fcntl::OFlag;
use nix::sys::stat::Mode;
use std::cell::RefCell;
use std::num::NonZeroUsize;
use std::os::fd::{AsFd, OwnedFd};
use tracing::{event, Level};

const READ_BUFFER_SIZE: usize = 1024;

thread_local! {
    /// A lookup table of trace memory region files (as actual file names) to tracer mmap address
    static TRACEE_READ_FD: RefCell<Option<OwnedFd>> = RefCell::new(None);

    /// The tracee side pointer of its own writeable `shared_region`
    static TRACEE_WRITE_REGION_ADDR: RefCell<Option<NonZeroUsize>> = RefCell::new(None);

    /// The index into `SHARED_REGIONS`, which reveals a writeable mmap
    static TRACEE_WRITE_REGION_ID: RefCell<Option<usize>> = RefCell::new(None);
}

pub fn set_tracee_write_region_addr(addr: usize) -> Result<(), PtraceError> {
    TRACEE_WRITE_REGION_ADDR.with_borrow_mut(|maybe_addr| {
        maybe_addr.replace(
            NonZeroUsize::new(addr)
                .ok_or(PtraceError::IntIsZero("set_tracee_write_region_addr/addr"))?,
        );
        Ok(())
    })
}

/// Get or create a region id from the tracee thread
pub fn get_own_region_id(pid: &nix::unistd::Pid) -> Result<usize, PtraceError> {
    TRACEE_WRITE_REGION_ID.with_borrow_mut(|cache| {
        if let Some(value) = *cache {
            return Ok(value);
        }
        let mut region_ids = AVAILABLE_REGION_IDS
            .write()
            .map_err(|_| PtraceError::LockGlobalMmap)?;
        let mut by_pid = REGION_IDS_BY_PID
            .write()
            .map_err(|_| PtraceError::LockGlobalMmap)?;
        let result = region_ids.pop().ok_or(PtraceError::MaxTracee)?;
        *cache = Some(result.clone());
        by_pid.insert(pid.clone(), result.clone());
        Ok(result)
    })
}

/// Get a region id from any thread, for the tracee `pid`
#[allow(dead_code)]
fn get_region_id(pid: &nix::unistd::Pid) -> Result<Option<usize>, PtraceError> {
    let region_ids = REGION_IDS_BY_PID
        .read()
        .map_err(|_| PtraceError::LockGlobalMmap)?;
    Ok(region_ids.get(pid).cloned())
}

/// Close the mmaps used by tracee
fn close_tracee(pid: &nix::unistd::Pid) -> Result<(), PtraceError> {
    // Release Writeable mmap
    let mut region_ids = AVAILABLE_REGION_IDS
        .write()
        .map_err(|_| PtraceError::LockGlobalMmap)?;
    let mut by_pid = REGION_IDS_BY_PID
        .write()
        .map_err(|_| PtraceError::LockGlobalMmap)?;
    let region_id = by_pid.remove(pid).ok_or(PtraceError::LockGlobalMmap)?;
    let mut maybe_region_box = SHARED_REGIONS[region_id]
        .write()
        .map_err(|_| PtraceError::LockGlobalMmap)?;
    let region_box = maybe_region_box
        .as_mut()
        .ok_or(PtraceError::LockGlobalMmap)?;
    region_box.fill(0);
    region_ids.push(region_id);

    event!(Level::INFO, "Closed tracee mmap resource");
    Ok(())
}

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
    let tracee_base: usize = TRACEE_WRITE_REGION_ADDR
        .with_borrow(|val| val.ok_or(PtraceError::MmapUninitialized))?
        .into();
    let tracee_start: usize = checked_add(tracee_base, offset)?;
    let new_offset = checked_add(offset, bytes.len())?;

    if offset >= STACK_SAFE_ZONE_SIZE {
        return Err(PtraceError::IntTooBigEqual(offset, STACK_SAFE_ZONE_SIZE));
    }
    if new_offset > STACK_SAFE_ZONE_SIZE {
        return Err(PtraceError::BufferOverflow(
            offset,
            bytes.len(),
            STACK_SAFE_ZONE_SIZE,
        ));
    }

    let region_id = get_own_region_id(&pid)?;
    if region_id > MAX_NUM_TRACEES {
        return Err(PtraceError::BufferOverflow(0, region_id, MAX_NUM_TRACEES));
    }

    let mut maybe_region_box = SHARED_REGIONS[region_id]
        .write()
        .map_err(|_| PtraceError::LockGlobalMmap)?;
    let region_box = maybe_region_box
        .as_mut()
        .ok_or(PtraceError::LockGlobalMmap)?;
    event!(
        Level::DEBUG,
        "Writing {} bytes to tracee mmap, {:#x}",
        bytes.len(),
        offset
    );
    region_box[offset..new_offset].copy_from_slice(bytes);
    Ok((tracee_start, new_offset))
}

#[cfg(target_pointer_width = "64")]
type LseekSize = i64;
#[cfg(target_pointer_width = "32")]
type LseekSize = i32;

fn read_bytes(
    pid: nix::unistd::Pid,
    addr: usize,
    size: usize,
    result: &mut [u8],
) -> Result<(), PtraceError> {
    event!(Level::DEBUG, "DIRECT_READ addr: {:x} size {}", addr, size);
    let pid_string = pid.to_string();
    TRACEE_READ_FD.with_borrow_mut(|maybe_fd| {
        if let Some(orig_fd) = maybe_fd.as_mut() {
            let fd = orig_fd.as_fd();
            nix::unistd::lseek(
                fd,
                // The address itself doesn't actually have a sign.
                addr as LseekSize,
                nix::unistd::Whence::SeekSet,
            )
            .map_err(PtraceError::Read)?;
            nix::unistd::read(fd, &mut result[..size]).map_err(PtraceError::Read)?;
            return Ok(());
        }

        let map_path: std::path::PathBuf = ["/proc", &pid_string, "mem"].iter().collect();
        let mmap_fd = nix::fcntl::open(&map_path, OFlag::O_RDONLY, Mode::S_IRUSR)
            .map_err(PtraceError::Read)?;
        let fd = mmap_fd.as_fd();
        nix::unistd::lseek(
            fd,
            // The address itself doesn't actually have a sign.
            addr as LseekSize,
            nix::unistd::Whence::SeekSet,
        )
        .map_err(PtraceError::Read)?;
        nix::unistd::read(fd, &mut result[..size]).map_err(PtraceError::Read)?;
        maybe_fd.replace(mmap_fd);
        Ok(())
    })
}

fn read_bytes_until_num_zeroes(
    pid: nix::unistd::Pid,
    addr: usize,
    n0: usize,
) -> Result<Vec<u8>, PtraceError> {
    let mut buffer: [u8; READ_BUFFER_SIZE] = [0; READ_BUFFER_SIZE];
    let mut result: Vec<u8> = Vec::new();
    let mut curr_addr = addr;
    let mut total_zeroes = 0;
    loop {
        read_bytes(pid, curr_addr, READ_BUFFER_SIZE, &mut buffer)?;
        for byte in buffer {
            if byte == b'\0' {
                total_zeroes += 1;
                if total_zeroes >= n0 {
                    return Ok(result);
                }
            } else {
                total_zeroes = 0;
            }
            result.push(byte);
        }
        curr_addr = checked_add(curr_addr, READ_BUFFER_SIZE)?;
    }
}

fn read_bytes_until_zero(pid: nix::unistd::Pid, addr: usize) -> Result<Vec<u8>, PtraceError> {
    read_bytes_until_num_zeroes(pid, addr, 1)
}

fn read(pid: nix::unistd::Pid, addr: usize) -> Result<usize, PtraceError> {
    event!(Level::TRACE, "PTRACE_READ addr: {:x}", addr);
    let raw_data =
        nix::sys::ptrace::read(pid, addr as *mut libc::c_void).map_err(PtraceError::Read)?;
    Ok(raw_data as usize)
}

pub const DIRECT_MEM_HELPERS: MemHelpers = MemHelpers {
    close_tracee,
    read,
    read_bytes,
    read_bytes_until_num_zeroes,
    read_bytes_until_zero,
    write_bytes_to_tracee,
};
