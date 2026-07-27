//! The system-call ABI, shared by the kernel and by user space.
//!
//! Like `boot_info.rs`, this file is the single definition both sides compile,
//! rather than a header the kernel writes and user space copies. A syscall
//! number that means one thing in the kernel's table and another in a process's
//! stub is a bug with no symptom until the wrong handler runs.
//!
//! # The register convention, and why it is not negotiable
//!
//! `SYSCALL` is not a call instruction. It destroys `rcx` and `r11` before the
//! kernel sees them — the CPU puts the return address in `rcx` and `RFLAGS` in
//! `r11` — so the fourth argument goes in `r10` rather than the `rcx` the System
//! V C convention would use. Every user-space stub has to know that, which is
//! the main reason the stub lives here next to the numbers.
//!
//!   number  rax
//!   args    rdi, rsi, rdx, r10, r8
//!   result  rax
//!
//! # Error encoding
//!
//! One register carries both outcomes, so the two have to be distinguishable
//! without ambiguity. Errors occupy the top of the range: `u64::MAX` downwards,
//! a few thousand values. A successful result would have to be within 4096 of
//! `u64::MAX` to collide, and no call here returns a length, a count, or a
//! handle anywhere near there.

#![allow(dead_code)]

/// Write bytes to the kernel console. `(ptr, len) -> bytes written`.
///
/// The only output a process has until a console service exists. It is a
/// deliberate temporary: the moment there is a user-space console process, this
/// becomes an IPC message and the syscall goes away.
pub const SYS_LOG: u64 = 0;

/// Stop this process. `(code) -> never returns`.
pub const SYS_EXIT: u64 = 1;

/// Round-trip a value through the kernel. `(value) -> value ^ PING_COOKIE`.
///
/// A stand-in for a real IPC round trip, and the smallest thing that proves the
/// path works end to end: user space computed an argument, the kernel received
/// it unmodified, transformed it, and user space observed the transformation.
/// A `SYS_LOG` that prints could be faked by a kernel that never left ring 0;
/// this cannot.
pub const SYS_PING: u64 = 2;

/// Mixed into `SYS_PING` replies. Arbitrary, but fixed, so the check is exact.
pub const PING_COOKIE: u64 = 0x5768_6973_657A_0002;

/// Send a message and block until the reply.
/// `(endpoint, send_ptr, send_len, reply_ptr, reply_cap) -> reply_len`.
///
/// Synchronous by design. An asynchronous send needs a queue, a queue needs a
/// policy for what happens when it is full, and every such policy is either
/// "block anyway" or "lose messages". A rendezvous has neither problem and is
/// what the architecture specifies.
pub const SYS_CALL: u64 = 3;

/// Block until a message arrives on an endpoint this process owns.
/// `(endpoint, buf_ptr, buf_cap) -> len`.
pub const SYS_RECEIVE: u64 = 4;

/// Reply to the message last received, unblocking its sender.
/// `(ptr, len) -> bytes sent`.
pub const SYS_REPLY: u64 = 5;

/// Describe a device this process was granted.
/// `(grant, index, out_ptr, out_cap) -> bytes written`.
pub const SYS_DEVICE_INFO: u64 = 6;

/// Map a granted device into this process's address space.
/// `(grant, index) -> virtual address`.
///
/// The process names an index, never an address. It cannot express a request
/// for anything the kernel did not list for it, which is a stronger property
/// than requests for other things being refused.
pub const SYS_MAP_DEVICE: u64 = 7;

/// Allocate a buffer a device can read and write.
/// `(bytes, out_ptr, out_cap) -> bytes written`.
///
/// Returns a `DmaRegion` rather than a single value because the caller needs
/// two addresses that are not derivable from one another: the one it uses and
/// the one it programs into the device. See `dma.rs` for why the second exists
/// at all, given that `SYS_MAP_DEVICE` exists precisely so physical addresses
/// need not be spoken aloud.
pub const SYS_ALLOC_DMA: u64 = 8;

/// Wait for a granted device's interrupt. `(grant, index) -> count`.
///
/// Returns how many interrupts arrived since the last call, which is at least
/// one — the call blocks until there is something to report. A count rather
/// than one wake per interrupt because interrupts carry no data: the driver
/// reads the device afterwards and finds whatever accumulated, and a queue of
/// identical empty events would only add a depth to overflow. See `irq.rs`.
pub const SYS_IRQ_WAIT: u64 = 9;

/// Longest message body, in either direction.
///
/// The kernel holds one buffer of this size per endpoint, so it bounds kernel
/// memory rather than being a limit the sender chooses.
pub const MAX_MESSAGE_BYTES: usize = 256;

/// Longest single `SYS_LOG`.
///
/// The kernel copies into a fixed stack buffer, so the bound is what stops a
/// user-supplied length from deciding how much kernel stack to consume.
pub const MAX_LOG_BYTES: usize = 256;

/// Highest error code. Everything from `u64::MAX - ERROR_SPACE` up is an error.
const ERROR_SPACE: u64 = 4095;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum SyscallError {
    /// No such call.
    BadNumber = 1,
    /// A pointer argument is not in this process's address space, or the range
    /// wraps.
    BadPointer = 2,
    /// Length argument exceeds the fixed limit for the call.
    TooLong = 3,
    /// The process holds no capability for this.
    NotPermitted = 4,
    /// Argument outside the range the call accepts.
    BadArgument = 5,
    /// No endpoint with that handle, or not one this process may use.
    ///
    /// Deliberately the same answer for both. Distinguishing "no such endpoint"
    /// from "not yours" tells a process whether a handle it guessed exists,
    /// which is exactly the information a handle is supposed to withhold.
    BadEndpoint = 6,
    /// The endpoint is already in the middle of an exchange.
    Busy = 7,
    /// Replying with no message outstanding.
    NoReplyPending = 8,
}

impl SyscallError {
    #[must_use]
    pub const fn code(self) -> u16 {
        self as u16
    }

    #[must_use]
    pub const fn from_code(code: u16) -> Option<Self> {
        match code {
            1 => Some(Self::BadNumber),
            2 => Some(Self::BadPointer),
            3 => Some(Self::TooLong),
            4 => Some(Self::NotPermitted),
            5 => Some(Self::BadArgument),
            6 => Some(Self::BadEndpoint),
            7 => Some(Self::Busy),
            8 => Some(Self::NoReplyPending),
            _ => None,
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::BadNumber => "bad-number",
            Self::BadPointer => "bad-pointer",
            Self::TooLong => "too-long",
            Self::NotPermitted => "not-permitted",
            Self::BadArgument => "bad-argument",
            Self::BadEndpoint => "bad-endpoint",
            Self::Busy => "busy",
            Self::NoReplyPending => "no-reply-pending",
        }
    }
}

/// Packs a result into the single register the ABI returns.
#[must_use]
pub const fn encode(result: Result<u64, SyscallError>) -> u64 {
    match result {
        Ok(value) => value,
        Err(error) => u64::MAX - (error.code() as u64) + 1,
    }
}

/// Unpacks what `encode` produced.
pub const fn decode(raw: u64) -> Result<u64, SyscallError> {
    if raw > u64::MAX - ERROR_SPACE {
        let code = (u64::MAX - raw + 1) as u16;
        match SyscallError::from_code(code) {
            Some(error) => Err(error),
            // A value in the error range that names no error. Treating it as
            // success would hand user space a nonsense pointer or length.
            None => Err(SyscallError::BadNumber),
        }
    } else {
        Ok(raw)
    }
}

/// The user-space side of the calling convention.
///
/// # Safety
/// The kernel is about to act on these registers. `number` must name a real
/// call and the arguments must satisfy whatever that call requires; the kernel
/// validates what it can, but a pointer argument that is valid and wrong is
/// still wrong.
#[cfg(target_arch = "x86_64")]
pub unsafe fn syscall5(number: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> u64 {
    let result: u64;
    // SAFETY: the caller guarantees the arguments. `rcx` and `r11` are declared
    // clobbered because the instruction overwrites them unconditionally, and
    // memory is not declared `nomem` because `SYS_LOG` reads through a pointer.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") number => result,
            in("rdi") a0,
            in("rsi") a1,
            in("rdx") a2,
            in("r10") a3,
            in("r8") a4,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    result
}

/// # Safety
/// As `syscall5`: the kernel acts on these registers, and a pointer argument
/// that is valid and wrong is still wrong.
#[cfg(target_arch = "x86_64")]
pub unsafe fn syscall1(number: u64, a0: u64) -> u64 {
    // SAFETY: forwarded to `syscall5` with the unused arguments zeroed.
    unsafe { syscall5(number, a0, 0, 0, 0, 0) }
}

/// # Safety
/// As `syscall5`.
#[cfg(target_arch = "x86_64")]
pub unsafe fn syscall2(number: u64, a0: u64, a1: u64) -> u64 {
    // SAFETY: as above.
    unsafe { syscall5(number, a0, a1, 0, 0, 0) }
}

/// # Safety
/// As `syscall5`.
#[cfg(target_arch = "x86_64")]
pub unsafe fn syscall3(number: u64, a0: u64, a1: u64, a2: u64) -> u64 {
    // SAFETY: as above.
    unsafe { syscall5(number, a0, a1, a2, 0, 0) }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_ERRORS: [SyscallError; 8] = [
        SyscallError::BadNumber,
        SyscallError::BadPointer,
        SyscallError::TooLong,
        SyscallError::NotPermitted,
        SyscallError::BadArgument,
        SyscallError::BadEndpoint,
        SyscallError::Busy,
        SyscallError::NoReplyPending,
    ];

    #[test]
    fn every_error_round_trips_through_the_register() {
        for error in ALL_ERRORS {
            assert_eq!(decode(encode(Err(error))), Err(error), "{error:?}");
        }
    }

    #[test]
    fn every_error_code_maps_back_to_its_variant() {
        for error in ALL_ERRORS {
            assert_eq!(SyscallError::from_code(error.code()), Some(error));
            assert!(!error.name().is_empty());
        }
        assert_eq!(SyscallError::from_code(0), None);
        assert_eq!(SyscallError::from_code(9999), None);
    }

    #[test]
    fn ordinary_success_values_round_trip() {
        for value in [0u64, 1, 42, 4096, 1 << 32, u64::MAX / 2] {
            assert_eq!(decode(encode(Ok(value))), Ok(value));
        }
    }

    #[test]
    fn success_and_error_encodings_never_collide() {
        // The whole point of the split. If any error encoding were also a
        // plausible success value, a caller could not tell them apart.
        for error in ALL_ERRORS {
            let raw = encode(Err(error));
            assert!(raw > u64::MAX - ERROR_SPACE, "{error:?} landed in Ok space");
            assert!(decode(raw).is_err());
        }
    }

    #[test]
    fn a_value_just_below_the_error_range_is_still_success() {
        // Off-by-one at the boundary would turn a large legitimate return into
        // a spurious error.
        let boundary = u64::MAX - ERROR_SPACE;
        assert_eq!(decode(boundary), Ok(boundary));
        assert!(decode(boundary + 1).is_err());
    }

    #[test]
    fn an_unassigned_code_in_the_error_range_is_not_read_as_success() {
        // A kernel returning a code this build does not know must not have it
        // interpreted as an enormous successful length.
        let raw = u64::MAX - 100 + 1;
        assert_eq!(decode(raw), Err(SyscallError::BadNumber));
    }

    #[test]
    fn the_syscall_numbers_are_distinct_and_stable() {
        let numbers = [
            SYS_LOG,
            SYS_EXIT,
            SYS_PING,
            SYS_CALL,
            SYS_RECEIVE,
            SYS_REPLY,
        ];
        for (i, a) in numbers.iter().enumerate() {
            for b in &numbers[i + 1..] {
                assert_ne!(a, b);
            }
        }
        // Pinned: user space is built separately, so renumbering silently
        // repoints every existing binary at a different handler.
        assert_eq!((SYS_LOG, SYS_EXIT, SYS_PING), (0, 1, 2));
        assert_eq!((SYS_CALL, SYS_RECEIVE, SYS_REPLY), (3, 4, 5));
        assert_eq!((SYS_DEVICE_INFO, SYS_MAP_DEVICE), (6, 7));
        assert_eq!((SYS_ALLOC_DMA, SYS_IRQ_WAIT), (8, 9));
    }

    #[test]
    fn the_ping_transform_is_reversible_and_not_the_identity() {
        // If the cookie were zero, a kernel that returned its argument
        // unchanged would pass the round-trip check without doing anything.
        assert_ne!(PING_COOKIE, 0);
        for value in [0u64, 1, 0xDEAD_BEEF, u64::MAX] {
            let reply = value ^ PING_COOKIE;
            assert_ne!(reply, value);
            assert_eq!(reply ^ PING_COOKIE, value);
        }
    }
}
