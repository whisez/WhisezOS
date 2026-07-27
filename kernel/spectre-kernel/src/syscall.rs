//! System-call policy: what each call does, and what it refuses.
//!
//! The entry path in `arch/syscall.rs` is the mechanism; this is the part that
//! decides. Keeping them apart matters because the mechanism is untestable
//! assembly and the policy is ordinary code — every check below is reachable
//! from a host test through `usercopy`, and the handlers themselves are short
//! enough to read as a list of rules.
//!
//! # Every pointer is hostile until checked
//!
//! `a0` and `a1` in `SYS_LOG` are whatever the process put in `rdi` and `rsi`.
//! The kernel is running with full privilege on a kernel stack, so the only
//! thing standing between a user-supplied `u64` and a read of kernel memory is
//! `validate_user_range`. It runs before the pointer is turned into a reference,
//! not after — and it validates against the ranges of the process that is
//! *currently scheduled*, which is why it asks the scheduler rather than
//! holding a pointer to a process of its own.

use crate::abi::{
    SyscallError, MAX_LOG_BYTES, PING_COOKIE, SYS_CALL, SYS_DEVICE_INFO, SYS_EXIT, SYS_LOG,
    SYS_MAP_DEVICE, SYS_PING, SYS_RECEIVE, SYS_REPLY,
};
use crate::arch;
use crate::arch::trap::TrapFrame;
use crate::channel::{self, Outcome};
use crate::device;
use crate::kprintln;
use crate::task;
use crate::usercopy::validate_user_range;

/// Dispatches one call. Returns the value user space will see in `rax`.
///
/// `frame` is the caller's complete state. The IPC calls need it because they
/// can block: the frame is what the process resumes from when its exchange
/// completes, with the result written into its `rax`.
#[allow(clippy::too_many_arguments)]
pub fn handle(
    number: u64,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    frame: &TrapFrame,
) -> Result<u64, SyscallError> {
    match number {
        SYS_LOG => sys_log(a0, a1),
        SYS_EXIT => sys_exit(a0),
        SYS_PING => Ok(a0 ^ PING_COOKIE),
        SYS_CALL => blocking(
            channel::call(
                task::current_pid(),
                task::current_root(),
                a0,
                a1,
                a2,
                a3,
                a4,
            ),
            frame,
        ),
        SYS_RECEIVE => blocking(
            channel::receive(task::current_pid(), task::current_root(), a0, a1, a2),
            frame,
        ),
        SYS_REPLY => blocking(channel::reply(task::current_pid(), a0, a1, a2), frame),
        SYS_DEVICE_INFO => sys_device_info(a0, a1, a2, a3),
        SYS_MAP_DEVICE => sys_map_device(a0, a1),
        // An unknown number is refused rather than ignored. Returning success
        // for a call the kernel did not make would let a process built against
        // a newer ABI believe something happened.
        _ => Err(SyscallError::BadNumber),
    }
}

/// Turns a channel outcome into either a return value or a context switch.
///
/// The switch never comes back here: `block_current` saves `frame` and resumes
/// somebody else, and the value this call eventually returns is written into
/// that saved frame by whichever process completes the exchange.
fn blocking(
    outcome: Result<Outcome, SyscallError>,
    frame: &TrapFrame,
) -> Result<u64, SyscallError> {
    match outcome? {
        Outcome::Return(value) => Ok(value),
        // SAFETY: reached from a system call with interrupts disabled, on the
        // syscall stack, and nothing on that stack is needed afterwards.
        Outcome::Block => unsafe { task::block_current(frame) },
    }
}

/// `SYS_LOG(ptr, len) -> bytes written`.
fn sys_log(ptr: u64, len: u64) -> Result<u64, SyscallError> {
    task::with_current_regions(|regions| {
        validate_user_range(regions, ptr, len, MAX_LOG_BYTES as u64)
    })?;

    // A fixed stack buffer, sized by the constant the validation just enforced,
    // so the copy cannot be made to consume more kernel stack than this.
    let mut buffer = [0u8; MAX_LOG_BYTES];
    let len = len as usize;
    // SAFETY: `validate_user_range` established that `ptr..ptr + len` lies
    // entirely inside a region the running process was given, and those regions
    // are mapped in the address space currently in CR3 — the syscall path does
    // not switch away from it, and a timer tick cannot interpose because
    // `SFMASK` cleared IF on entry.
    unsafe {
        core::ptr::copy_nonoverlapping(ptr as *const u8, buffer.as_mut_ptr(), len);
    }

    // Printed a byte at a time rather than as a `str`: this is user-controlled
    // input and need not be valid UTF-8, and a lossy conversion would need an
    // allocator the kernel does not have.
    for &byte in &buffer[..len] {
        let printable = if (0x20..0x7F).contains(&byte) || byte == b'\n' || byte == b'\r' {
            byte
        } else {
            b'.'
        };
        if printable == b'\n' {
            kprintln!();
        } else {
            crate::kprint!("{}", printable as char);
        }
    }
    Ok(len as u64)
}

/// `SYS_DEVICE_INFO(grant, index, out_ptr, out_cap) -> bytes written`.
fn sys_device_info(grant: u64, index: u64, ptr: u64, capacity: u64) -> Result<u64, SyscallError> {
    // The grant is checked before the pointer, so a process without one learns
    // nothing about whether its buffer would have been acceptable.
    let info = device::describe(grant, index)?;

    let bytes = core::mem::size_of::<device::DeviceInfo>() as u64;
    if capacity < bytes {
        return Err(SyscallError::TooLong);
    }
    task::with_current_regions(|regions| validate_user_range(regions, ptr, bytes, bytes))?;

    // SAFETY: the range was just validated against the running process's own
    // regions, and its address space is the one in CR3.
    unsafe {
        core::ptr::copy_nonoverlapping(
            (&raw const info).cast::<u8>(),
            ptr as *mut u8,
            bytes as usize,
        );
    }
    Ok(bytes)
}

/// `SYS_MAP_DEVICE(grant, index) -> virtual address`.
fn sys_map_device(grant: u64, index: u64) -> Result<u64, SyscallError> {
    let (phys, length) = device::extent(grant, index)?;
    let slot = task::devices_mapped();

    // SAFETY: the extent came from the kernel's own device table, reached only
    // through a grant this process holds, and `current_root` is the address
    // space it is running in.
    let (base, mapped) =
        unsafe { arch::user::map_device(task::current_root(), phys, length, slot) }
            .map_err(|_| SyscallError::BadArgument)?;

    // The mapping has to become one of the process's permitted ranges before it
    // returns: a driver reading its own framebuffer through any other system
    // call would otherwise be refused by the pointer validator.
    let window_base = base & !(4096 - 1);
    if task::record_device_mapping(window_base, mapped).is_none() {
        return Err(SyscallError::TooLong);
    }
    kprintln!(
        "[kernel] device {index} mapped for pid {} at {base:#x}",
        task::current_pid()
    );
    Ok(base)
}

/// `SYS_EXIT(code)`.
///
/// Marks the process finished and then waits to be scheduled away. It does not
/// switch by itself: the only code that decides what runs next is the timer
/// path, and having one such place is worth more than the few milliseconds this
/// costs. Enabling interrupts before halting is what lets that tick arrive —
/// without it the system would stop here with runnable processes left.
fn sys_exit(code: u64) -> ! {
    let pid = task::exit_current(code);
    // Before anything else waits on a process that is no longer there. A client
    // blocked on this server has to be told, or it waits for a reply that
    // cannot arrive.
    channel::on_process_gone(pid);
    if code == 0 {
        kprintln!("[kernel] pid {pid} exited with code 0");
    } else {
        kprintln!("[kernel] pid {pid} FAILED with code {code}");
    }

    arch::enable_interrupts();
    loop {
        arch::halt_once();
    }
}
