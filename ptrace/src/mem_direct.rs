/// Faster, but less supported method to access tracee memory (mmap)
use core::ffi::c_void;
use crate::common::{
    aligned, checked_add, checked_div, checked_mul, checked_sub, CHeader,
    CStruct, PtraceError, MAX_STRUCT_SIZE, STACK_SAFE_ZONE_SIZE, USIZE_SIZE, MAX_READ_MAPS_PER_TRACEE,
    availabe_region_ids, region_ids_by_pid, shared_regions, MAX_NUM_TRACEES, MemHelpers
};
use nix::fcntl::OFlag;
use nix::sys::mman;
use nix::sys::stat::Mode;
use std::cell::RefCell;
use std::num::NonZeroUsize;
use std::ptr::NonNull;
use tracing::{event, Level};

#[derive(Clone)]
struct MmapInfo {
    tracer_addr: NonNull<c_void>,
    base_addr: NonZeroUsize,
    length: NonZeroUsize,
}

thread_local! {
    /// A lookup table of trace memory region files (as actual file names) to tracer mmap address
    static TRACEE_READ_MMAPS: RefCell<lru::LruCache<std::path::PathBuf, MmapInfo>> = RefCell::new(lru::LruCache::new(NonZeroUsize::new(MAX_READ_MAPS_PER_TRACEE).unwrap()));

    /// The tracee side pointer of its own writeable `shared_region`
    static TRACEE_WRITE_REGION_ADDR: RefCell<Option<NonZeroUsize>> = RefCell::new(None);

    /// The index into `shared_regions`, which reveals a writeable mmap
    static TRACEE_WRITE_REGION_ID: RefCell<Option<usize>> = RefCell::new(None);
}

/// Get or create a region id from the tracee thread
fn get_own_region_id(pid: &nix::unistd::Pid) -> Result<usize, PtraceError> {
    TRACEE_WRITE_REGION_ID.with_borrow_mut(|cache| {
        if let Some(value) = *cache {
            return Ok(value);
        }
        let mut region_ids = availabe_region_ids.write().map_err(|_| PtraceError::LockGlobalMmap)?;
        let mut by_pid = region_ids_by_pid.write().map_err(|_| PtraceError::LockGlobalMmap)?;
        let result = region_ids.pop().ok_or(PtraceError::MaxTracee)?;
        *cache = Some(result.clone());
        by_pid.insert(pid.clone(), result.clone());
        Ok(result)
    })
}

/// Get a region id from any thread, for the tracee `pid`
fn get_region_id(pid: &nix::unistd::Pid) -> Result<Option<usize>, PtraceError> {
    let region_ids = region_ids_by_pid.read().map_err(|_| PtraceError::LockGlobalMmap)?;
    Ok(region_ids.get(pid).cloned())
}

/// Close the mmaps used by tracee
fn close_tracee(pid: &nix::unistd::Pid) -> Result<(), PtraceError> {
    {
        // Writeable mmap
        let mut region_ids = availabe_region_ids.write().map_err(|_| PtraceError::LockGlobalMmap)?;
        let mut by_pid = region_ids_by_pid.write().map_err(|_| PtraceError::LockGlobalMmap)?;
        let region_id = by_pid.remove(pid).ok_or(PtraceError::LockGlobalMmap)?;
        let mut maybe_region_box = shared_regions[region_id].write().map_err(|_| PtraceError::LockGlobalMmap)?;
        let region_box = maybe_region_box.as_mut().ok_or(PtraceError::LockGlobalMmap)?;
        region_box.fill(0);
        region_ids.push(region_id);
    }

    TRACEE_READ_MMAPS.with_borrow(|mmaps| {
        // Readable mmaps
        for (_, mmap_info) in mmaps.iter() {
            unsafe {
                mman::munmap(mmap_info.tracer_addr, mmap_info.length.into()).map_err(PtraceError::Unmap)?;
            }
        }
        Ok(())
    })
}

fn non_zero_usize(val: usize, err: &'static str) -> Result<NonZeroUsize, PtraceError> {
    NonZeroUsize::new(val).ok_or(PtraceError::IntIsZero(err))
}

fn open_tracee_read_map(pid: &nix::unistd::Pid, addr: usize, size: usize) -> Result<Option<MmapInfo>, PtraceError> {
    let pid_string = pid.to_string();
    let maps_path: std::path::PathBuf = ["/proc", &pid_string, "maps"].iter().collect();
    let maps_str = std::fs::read_to_string(maps_path).map_err(PtraceError::ReadStdIoError)?;
    for line in maps_str.lines() {
        if let Some(addr_pair) = line.split(' ').next() {
            let pair: Vec<_> = addr_pair.split('-').collect();
            if pair.len() != 2 {
                continue
            }
            let start: usize = pair[0].parse().map_err(|_| PtraceError::ParseUsizeFromString(pair[0].to_string()))?;
            let end: usize = pair[1].parse().map_err(|_| PtraceError::ParseUsizeFromString(pair[1].to_string()))?;
            let length = non_zero_usize(end - start, "open_tracee_read_map/length")?;
            if start < addr || checked_add(addr, size)? > end {
                continue
            }
            return TRACEE_READ_MMAPS.with_borrow_mut(|infos| {
                let map_path: std::path::PathBuf = ["/proc", &pid_string, "map_files", addr_pair].iter().collect();
                if let Some(info) = infos.get(&map_path) {
                    return Ok(Some(info.clone()));
                }
                let mmap_fd = nix::fcntl::open(&map_path, OFlag::O_RDONLY, Mode::S_IRUSR).map_err(PtraceError::Read)?;
                let mmap_addr = unsafe {
                    mman::mmap(
                        None,
                        length,
                        mman::ProtFlags::PROT_READ,
                        mman::MapFlags::MAP_SHARED,
                        &mmap_fd,
                        0,
                    )
                    .map_err(PtraceError::Read)?
                };

                let new_info = MmapInfo {
                    base_addr: non_zero_usize(start, "open_tracee_read_map/start")?,
                    tracer_addr: mmap_addr.clone(),
                    length: length
                };
                if let Some(old_info) = infos.put(map_path, new_info.clone()) {
                    unsafe {
                        mman::munmap(old_info.tracer_addr, old_info.length.into()).map_err(PtraceError::Unmap)?;
                    }
                }
                Ok(Some(new_info))
            });
        }
    }

    Ok(None)
}

fn get_first_writeable_addr() -> Result<usize, PtraceError> {
    let result: usize = TRACEE_WRITE_REGION_ADDR.with_borrow(|val| val.ok_or(PtraceError::MmapUninitialized))?.into();
    Ok(result)
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
    let tracee_start: usize = get_first_writeable_addr()?;
    let tracee_end = checked_add(tracee_start, STACK_SAFE_ZONE_SIZE)?;
    let new_offset = checked_add(offset, bytes.len())?;

    if offset < tracee_start {
        return Err(PtraceError::BufferUnderflow(offset, tracee_start));
    }
    if offset >= tracee_end {
        return Err(PtraceError::IntTooBigEqual(offset, tracee_end));
    }
    if new_offset > tracee_end {
        return Err(PtraceError::BufferOverflow(offset, bytes.len(), tracee_end));
    }

    let region_id = get_own_region_id(&pid)?;
    if region_id > MAX_NUM_TRACEES {
        return Err(PtraceError::BufferOverflow(0, region_id, MAX_NUM_TRACEES));
    }
    
    let relative_start = checked_sub(offset, tracee_start)?;
    let relative_end = checked_add(relative_start, bytes.len())?;
    let mut maybe_region_box = shared_regions[region_id].write().map_err(|_| PtraceError::LockGlobalMmap)?;
    let region_box = maybe_region_box.as_mut().ok_or(PtraceError::LockGlobalMmap)?;
    event!(
        Level::TRACE,
        "Writing {} bytes to tracee mmap, {:#x}",
        bytes.len(),
        offset
    );
    region_box[relative_start..relative_end].copy_from_slice(bytes);
    Ok((offset, new_offset))
}

fn read_bytes(
    pid: nix::unistd::Pid,
    addr: usize,
    size: usize,
    result: &mut [u8],
) -> Result<(), PtraceError> {
    event!(Level::TRACE, "DIRECT_READ addr: {:x} size {}", addr, size);
    let info = open_tracee_read_map(&pid, addr, size)?.ok_or(PtraceError::ReadMmapNotFound)?;
    unsafe {
        let offset = checked_sub(addr, info.base_addr.into())?;
        let ptr = (info.tracer_addr.as_ptr() as *const u8).add(offset);
        result.copy_from_slice(std::slice::from_raw_parts(ptr, size));
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

fn read(pid: nix::unistd::Pid, addr: usize) -> Result<usize, PtraceError> {
    event!(Level::TRACE, "DIRECT_READ addr: {:x}", addr);
    let info = open_tracee_read_map(&pid, addr, *USIZE_SIZE)?.ok_or(PtraceError::ReadMmapNotFound)?;
    unsafe {
        let offset = checked_sub(addr, info.base_addr.into())?;
        let ptr = (info.tracer_addr.as_ptr() as *const u8).add(offset) as *const usize;
        Ok(*ptr)
    }
}

pub const direct_mem_helper: MemHelpers = MemHelpers {
    get_first_writeable_addr,
    close_tracee,
    read,
    read_bytes,
    read_bytes_until_num_zeroes,
    read_bytes_until_zero,
    write_bytes_to_tracee,
};
