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

/// Permit this process to use a granted device's ports.
/// `(grant, index) -> ports permitted`.
///
/// The last thing a driver needs that the kernel was doing for it. A device
/// with no MMIO window — the RTC, the i8042, the legacy serial port — is
/// reached through `in` and `out` or not at all, and until this existed that
/// meant a fragment of every such driver lived in ring 0. See `portauth.rs`,
/// including for what the kernel will not hand over at any price.
pub const SYS_GRANT_PORTS: u64 = 10;

/// Wait for any interrupt this process is entitled to. `(grant) -> packed`.
///
/// The result is `(line << 32) | count`. A driver with several devices cannot
/// use `SYS_IRQ_WAIT`: it names one line, so blocking on the keyboard means
/// missing the mouse, and polling instead loses bytes — the i8042 holds one at
/// a time and a dropped byte desynchronises a movement packet.
///
/// The line number is not a device index. It is the kernel's own numbering,
/// and a process learns which line belongs to which of its devices by waiting
/// on them individually once, or by not caring — a driver that services
/// whatever answered needs no map at all.
pub const SYS_IRQ_WAIT_ANY: u64 = 11;

/// Take a granted device's interrupt line without waiting on it.
/// `(grant, index) -> line`.
///
/// `SYS_IRQ_WAIT` used to be the only way to claim a line, on the argument that
/// a process able to wait for a device's interrupt is exactly a process that
/// owns it, so a separate claim would be a second name for the same authority.
/// That was true of a driver with one device and false of one with several: the
/// lines all have to be live before anything blocks, and claiming by waiting
/// means blocking on the first device until it interrupts. A keyboard does not
/// interrupt until somebody presses a key, so the session stopped there —
/// having claimed the clock, holding the mouse unclaimed, and waiting forever.
pub const SYS_IRQ_CLAIM: u64 = 12;

/// Turn the machine off. `(grant) -> never returns, if it works`.
///
/// The one device the kernel keeps. The register that powers a machine down is
/// above the window the I/O permission bitmap covers, so `portauth` cannot
/// grant it to anybody — which was a deliberate boundary rather than an
/// oversight, and shutting the machine down is the kind of authority it was
/// drawn to keep.
///
/// Returns only on failure, which is the honest shape: a shutdown that worked
/// has no observer.
pub const SYS_SHUTDOWN: u64 = 13;

/// What a device is, so a driver can tell what it was handed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DeviceKind {
    /// Nothing here.
    None = 0,
    /// A linear framebuffer, already configured by the firmware.
    Framebuffer = 1,
    /// A periodic interrupt source with no registers worth mapping.
    Ticker = 2,
    /// A virtio block device: a disk, reached through a mapped window.
    Block = 3,
    /// A virtio sound device: playback and capture, same transport as the disk.
    Sound = 4,
    /// The keyboard half of the i8042.
    Keyboard = 5,
    /// The mouse half of the same chip, on its own interrupt.
    Mouse = 6,
    /// A virtio Ethernet adapter driven from ring 3.
    Network = 7,
}

/// `SYS_TASK_LIST(buffer, capacity) -> bytes written`.
///
/// The only call that describes something other than the caller. It is
/// deliberately read-only and deliberately says nothing a process could use to
/// reach another one: no address space, no register state, no capability list —
/// a task manager needs to show what is running, not to touch it.
pub const SYS_TASK_LIST: u64 = 14;

/// Entries `SYS_TASK_LIST` can return. Matches the kernel's process table; a
/// const assertion beside that table keeps the two from drifting apart.
pub const MAX_TASK_ENTRIES: usize = 4;

/// State codes, in the order the kernel's `State` declares them.
pub mod task_state {
    pub const EMPTY: u64 = 0;
    pub const READY: u64 = 1;
    pub const RUNNING: u64 = 2;
    pub const BLOCKED: u64 = 3;
    pub const EXITED: u64 = 4;
}

/// What to call a state code. Here rather than in the task manager so that a
/// state added to the kernel cannot be displayed under an older name.
#[must_use]
pub const fn task_state_name(code: u64) -> &'static [u8] {
    match code {
        task_state::EMPTY => b"EMPTY",
        task_state::READY => b"READY",
        task_state::RUNNING => b"RUNNING",
        task_state::BLOCKED => b"BLOCKED",
        task_state::EXITED => b"EXITED",
        _ => b"UNKNOWN",
    }
}

/// One live process, as a task manager sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct TaskEntry {
    pub pid: u64,
    pub state: u64,
    pub dma_regions: u64,
    pub devices_mapped: u64,
}

impl TaskEntry {
    pub const EMPTY: Self = Self {
        pid: 0,
        state: task_state::EMPTY,
        dma_regions: 0,
        devices_mapped: 0,
    };
}

/// What `SYS_TASK_LIST` writes.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct TaskList {
    /// How many entries are filled. Empty slots are not returned: a table with
    /// four rows of which two say EMPTY reads as two dead processes.
    pub count: u64,
    /// Timer ticks the kernel has seen, and context switches it has made. Two
    /// numbers that prove the scheduler is still working, which is most of what
    /// a task manager is for.
    pub ticks: u64,
    pub switches: u64,
    pub entries: [TaskEntry; MAX_TASK_ENTRIES],
}

impl TaskList {
    pub const EMPTY: Self = Self {
        count: 0,
        ticks: 0,
        switches: 0,
        entries: [TaskEntry::EMPTY; MAX_TASK_ENTRIES],
    };
}

/// What `SYS_DEVICE_INFO` writes.
///
/// This lives in `abi.rs` rather than beside the device table for the same
/// reason the syscall numbers do: it is compiled by the kernel and by every
/// process, and one definition is the only arrangement in which they cannot
/// disagree.
///
/// It did not start here. It was a struct in `device.rs` with a hand-written
/// copy in init and a comment claiming an assertion kept the two the same size
/// — which it did not, because each side asserted against its own idea of the
/// size. Growing the kernel's copy produced a driver whose buffer was suddenly
/// too small, reported as `TooLong` from a call that had worked for weeks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct DeviceInfo {
    pub kind: u32,
    pub _pad: u32,
    /// Bytes the mapping covers.
    pub length: u64,
    /// Geometry, meaningful for a framebuffer and zero otherwise. Not a
    /// physical address: a driver has no use for one, and telling it would be
    /// telling it where everything else is not.
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub bytes_per_pixel: u32,
    /// Offsets of the four virtio structures within the mapped window, and the
    /// notification stride. Meaningful for a `Block` device and zero otherwise.
    ///
    /// The kernel reads these out of PCI configuration space, which a driver
    /// cannot reach, and passes them on without knowing what any of them are
    /// for.
    pub common_offset: u32,
    pub notify_offset: u32,
    pub notify_multiplier: u32,
    pub isr_offset: u32,
    pub config_offset: u32,
    pub _pad2: u32,
}

impl DeviceInfo {
    pub const EMPTY: Self = Self {
        kind: DeviceKind::None as u32,
        _pad: 0,
        length: 0,
        width: 0,
        height: 0,
        stride: 0,
        bytes_per_pixel: 0,
        common_offset: 0,
        notify_offset: 0,
        notify_multiplier: 0,
        isr_offset: 0,
        config_offset: 0,
        _pad2: 0,
    };
}

const _: () = assert!(core::mem::size_of::<DeviceInfo>() == 56);

/// What `SYS_ALLOC_DMA` writes. Here for the same reason as `DeviceInfo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct DmaRegion {
    /// Where the process reads and writes it.
    pub virt: u64,
    /// What the process programs into the device.
    pub bus: u64,
    /// Bytes mapped, rounded up from what was asked for.
    pub length: u64,
}

impl DmaRegion {
    pub const EMPTY: Self = Self {
        virt: 0,
        bus: 0,
        length: 0,
    };
}

const _: () = assert!(core::mem::size_of::<DmaRegion>() == 24);

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
        assert_eq!((SYS_ALLOC_DMA, SYS_IRQ_WAIT, SYS_GRANT_PORTS), (8, 9, 10));
        assert_eq!(
            (SYS_IRQ_WAIT_ANY, SYS_IRQ_CLAIM, SYS_SHUTDOWN),
            (11, 12, 13)
        );
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
