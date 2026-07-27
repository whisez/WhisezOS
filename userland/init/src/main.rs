//! init — the first user-space process.
//!
//! It is deliberately small, and it is not a service manager yet. Its job right
//! now is to be the proof that ring 3 exists: that the kernel can build a user
//! address space, enter it, service a system call, and come back. Everything it
//! prints is evidence of a step that has no other observable effect.
//!
//! The last three checks matter most. Printing from ring 3 shows the path
//! works; being *refused* shows the boundary is real. A kernel that happily
//! read a kernel pointer on behalf of a user process would pass every other
//! check in this file.

#![no_std]
#![no_main]

/// The syscall numbers and calling convention, compiled from the same file the
/// kernel compiles.
#[path = "../../../kernel/spectre-kernel/src/abi.rs"]
mod abi;

use abi::{decode, SyscallError, MAX_LOG_BYTES, PING_COOKIE, SYS_EXIT, SYS_LOG, SYS_PING};

/// An address inside the kernel's identity map. User space must never be able
/// to make the kernel read it on its behalf.
const KERNEL_ADDRESS: u64 = 0x0200_0000;

/// A syscall number nothing implements.
const UNASSIGNED_SYSCALL: u64 = 9999;

fn log(message: &str) {
    // SAFETY: the pointer and length describe a live `&str` in this process's
    // own image, which is exactly what the kernel will validate.
    unsafe {
        abi::syscall2(SYS_LOG, message.as_ptr() as u64, message.len() as u64);
    }
}

/// Logs `message`, then `value` in hex. Formatting by hand because there is no
/// allocator and no `core::fmt` machinery worth pulling into a process this
/// small.
fn log_hex(message: &str, value: u64) {
    log(message);
    let mut buffer = [0u8; 19];
    buffer[0] = b'0';
    buffer[1] = b'x';
    for nibble in 0..16 {
        let shift = 60 - nibble * 4;
        let digit = ((value >> shift) & 0xF) as u8;
        buffer[2 + nibble] = if digit < 10 {
            b'0' + digit
        } else {
            b'a' + digit - 10
        };
    }
    buffer[18] = b'\n';
    // SAFETY: `buffer` is a live local, and the length is its exact size.
    unsafe {
        abi::syscall2(SYS_LOG, buffer.as_ptr() as u64, buffer.len() as u64);
    }
}

fn call(number: u64, a0: u64, a1: u64) -> Result<u64, SyscallError> {
    // SAFETY: every call site below passes arguments the corresponding syscall
    // accepts, or deliberately does not — the refusals are the point.
    decode(unsafe { abi::syscall2(number, a0, a1) })
}

fn expect_refused(what: &str, expected: SyscallError, result: Result<u64, SyscallError>) {
    match result {
        Err(error) if error == expected => {
            log("[init] refused as expected: ");
            log(what);
            log("\n");
        }
        other => {
            log("[init] SECURITY CHECK FAILED: ");
            log(what);
            log("\n");
            let _ = other;
            exit(2);
        }
    }
}

fn exit(code: u64) -> ! {
    // SAFETY: `SYS_EXIT` does not return.
    unsafe {
        abi::syscall1(SYS_EXIT, code);
    }
    // The kernel does not come back from `SYS_EXIT`, but the compiler cannot
    // know that, and falling off the end of a `-> !` function would execute
    // whatever follows.
    loop {
        core::hint::spin_loop();
    }
}

#[no_mangle]
pub extern "sysv64" fn _start() -> ! {
    log("[init] hello from ring 3\n");

    // The round trip. Printing could be faked by a kernel that never left ring
    // 0; a value the kernel transformed and returned could not.
    let sent = 0x0123_4567_89AB_CDEF;
    match call(SYS_PING, sent, 0) {
        Ok(reply) if reply == sent ^ PING_COOKIE => {
            log_hex("[init] ping round trip ok, reply ", reply);
        }
        Ok(reply) => {
            log_hex("[init] PING MISMATCH, got ", reply);
            exit(1);
        }
        Err(error) => {
            log("[init] ping failed: ");
            log(error.name());
            log("\n");
            exit(1);
        }
    }

    // --- the boundary ----------------------------------------------------
    // Each of these would be a privilege escalation if it succeeded.

    expect_refused(
        "reading kernel memory through SYS_LOG",
        SyscallError::BadPointer,
        call(SYS_LOG, KERNEL_ADDRESS, 16),
    );

    expect_refused(
        "a length past the end of the buffer limit",
        SyscallError::TooLong,
        call(SYS_LOG, 0x1000_0000_0000, MAX_LOG_BYTES as u64 + 1),
    );

    expect_refused(
        "an unassigned syscall number",
        SyscallError::BadNumber,
        call(UNASSIGNED_SYSCALL, 0, 0),
    );

    log("[init] all checks passed\n");
    exit(0);
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    log("[init] panic\n");
    exit(3)
}
