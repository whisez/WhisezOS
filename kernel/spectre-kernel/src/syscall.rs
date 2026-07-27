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
//! not after.

use crate::abi::{SyscallError, MAX_LOG_BYTES, PING_COOKIE, SYS_EXIT, SYS_LOG, SYS_PING};
use crate::arch;
use crate::kprintln;
use crate::usercopy::validate_user_range;

/// Dispatches one call. Returns the value user space will see in `rax`.
pub fn handle(number: u64, a0: u64, a1: u64, _a2: u64, _a3: u64) -> Result<u64, SyscallError> {
    match number {
        SYS_LOG => sys_log(a0, a1),
        SYS_EXIT => sys_exit(a0),
        SYS_PING => Ok(a0 ^ PING_COOKIE),
        // An unknown number is refused rather than ignored. Returning success
        // for a call the kernel did not make would let a process built against
        // a newer ABI believe something happened.
        _ => Err(SyscallError::BadNumber),
    }
}

/// `SYS_LOG(ptr, len) -> bytes written`.
fn sys_log(ptr: u64, len: u64) -> Result<u64, SyscallError> {
    arch::user::with_current_regions(|regions| {
        validate_user_range(regions, ptr, len, MAX_LOG_BYTES as u64)
    })?;

    // A fixed stack buffer, sized by the constant the validation just enforced,
    // so the copy cannot be made to consume more kernel stack than this.
    let mut buffer = [0u8; MAX_LOG_BYTES];
    let len = len as usize;
    // SAFETY: `validate_user_range` established that `ptr..ptr + len` lies
    // entirely inside a region this process was given, and those regions are
    // mapped in the address space currently in CR3 — the syscall path does not
    // switch away from it.
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

/// `SYS_EXIT(code)`.
///
/// Does not return, and does not yet tear anything down. There is no scheduler
/// to pick something else and no process table to remove an entry from, so the
/// honest behaviour is to report and stop rather than to return to a caller
/// that no longer exists.
fn sys_exit(code: u64) -> ! {
    kprintln!("[kernel] init exited with code {code}");
    if code == 0 {
        kprintln!("[kernel] stage 2 complete");
    } else {
        kprintln!("[kernel] STAGE 2 FAILED: init reported {code}");
    }
    kprintln!("[kernel] no scheduler yet, halting");
    arch::halt_forever()
}
