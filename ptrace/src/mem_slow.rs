use crate::common::{
    aligned, bytes_to_usizes, checked_add, checked_div, checked_mul, checked_sub, getregs, CHeader,
    CStruct, PtraceError, MAX_STRUCT_SIZE, STACK_SAFE_ZONE_SIZE, USIZE_SIZE,
};
use nix::sys;
use tracing::{event, Level};

/// This always writes to the same location of stack.
/// So if you want to write multiple byte arrays, each one must have a different offset
///
/// # Safety
/// This function is unsafe because you need to choose `offset` carefully. If you call
/// this function multiple times during the same system call, you might overwrite your
/// own progress if `offset` is incorrect.
pub unsafe fn write_bytes_to_tracee(
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

/// Read multiple Rust "repr(C)" structures from tracee memory.
/// Here is an explannation:
///
/// C struct layout    [ ..int.. ..char*.. (up to 512 chars)         ]
/// Rust struct layout [ ..int.. ..[char; 512].. (exactly 512 chars) ]
///
/// Notes about terminology:
///     "C struct" just means the original in-memory data.
///     "Rust struct" just means the result of the read. It must still declare #[repr(C)]
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

pub fn read_bytes_until_num_zeroes(
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

pub fn read_bytes_until_zero(pid: nix::unistd::Pid, addr: usize) -> Result<Vec<u8>, PtraceError> {
    read_bytes_until_num_zeroes(pid, addr, 1)
}

/// Write multiple "repr(C)" structs back to tracee memory.
/// Here is an explannation:
///
/// C struct layout    [ ..int.. ..char*.. (up to 512 chars)         ]
/// Rust struct layout [ ..int.. ..[char; 512].. (exactly 512 chars) ]
///
/// Notes about terminology:
///     "C struct" just means the native in-memory data.
///     "Rust struct" just means the source data in Rust. It must still declare #[repr(C)]
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
pub fn write_structs_to_tracee<T>(
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
    let skip_header = checked_div(aligned(header_size)?, *USIZE_SIZE)?;
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
            } else {
                count_zeroes = 0;
            }
            checked_write(pid, curr_remainder_addr, max_addr, *machine_word)?;
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
