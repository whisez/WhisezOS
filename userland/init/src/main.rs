//! init — the first user-space process.
//!
//! Deliberately small, and not a service manager yet. Its job is to be the
//! proof that ring 3 exists and that the scheduler is real: that the kernel can
//! build a user address space, enter it, service a system call, take the
//! processor away mid-loop, and give it back with every register intact.
//!
//! Two instances of this same image run at once, in separate address spaces,
//! distinguished only by the value the kernel puts in `rdi`. Neither can
//! observe the other; the interleaving in the boot log is the only evidence
//! either was ever descheduled.
//!
//! The refusal checks matter most. Printing from ring 3 shows the path works;
//! being *refused* shows the boundary is real. A kernel that happily read a
//! kernel pointer on behalf of a user process would pass every other check
//! here.

#![no_std]
#![no_main]

/// The syscall numbers and calling convention, compiled from the same file the
/// kernel compiles.
#[path = "../../../kernel/spectre-kernel/src/abi.rs"]
mod abi;

/// The glyph table, compiled from the same file the kernel and the UEFI preview
/// compile. A second copy would be a second thing to keep in step for no gain.
#[path = "../../../kernel/spectre-kernel/src/font.rs"]
mod font;

/// Scancodes to characters, and the shell's text buffer. Both are pure logic
/// and both are compiled by the host test harness as well as here — a shell is
/// the part most likely to be wrong in ways a person notices, and squinting at
/// a screenshot is a poor way to find out.
mod console;
mod keymap;

use abi::{
    decode, DeviceInfo, DeviceKind, DmaRegion, SyscallError, MAX_LOG_BYTES, PING_COOKIE,
    SYS_ALLOC_DMA, SYS_CALL, SYS_DEVICE_INFO, SYS_EXIT, SYS_GRANT_PORTS, SYS_IRQ_CLAIM,
    SYS_IRQ_WAIT, SYS_IRQ_WAIT_ANY, SYS_LOG, SYS_MAP_DEVICE, SYS_PING, SYS_RECEIVE, SYS_REPLY,
};

/// An address inside the kernel's identity map. User space must never be able
/// to make the kernel read it on its behalf.
const KERNEL_ADDRESS: u64 = 0x0200_0000;

/// A syscall number nothing implements.
const UNASSIGNED_SYSCALL: u64 = 9999;

/// Rounds of the work loop.
///
/// Enough that a 10 ms timer slice cannot cover them all, so at least one
/// preemption has to happen somewhere in the middle. Few enough that the boot
/// test does not spend a noticeable time on it.
const ROUNDS: u64 = 6;

/// Iterations of the busy loop per round, chosen to take a few milliseconds.
const SPIN: u64 = 3_000_000;

fn log(message: &str) {
    // SAFETY: the pointer and length describe a live `&str` in this process's
    // own image, which is exactly what the kernel will validate.
    unsafe {
        abi::syscall2(SYS_LOG, message.as_ptr() as u64, message.len() as u64);
    }
}

fn log_bytes(bytes: &[u8]) {
    // SAFETY: `bytes` is a live local slice and the length is its exact size.
    unsafe {
        abi::syscall2(SYS_LOG, bytes.as_ptr() as u64, bytes.len() as u64);
    }
}

/// Writes `value` as hex into `out`, returning the written slice.
///
/// By hand because there is no allocator and no reason to pull `core::fmt` into
/// a process this small.
fn hex(value: u64, out: &mut [u8; 18]) -> &[u8] {
    out[0] = b'0';
    out[1] = b'x';
    for nibble in 0..16 {
        let digit = ((value >> (60 - nibble * 4)) & 0xF) as u8;
        out[2 + nibble] = if digit < 10 {
            b'0' + digit
        } else {
            b'a' + digit - 10
        };
    }
    &out[..]
}

/// `[init N] ` prefix, so two processes are distinguishable in one log.
fn tag(pid: u64, out: &mut [u8; 10]) -> &[u8] {
    let text = b"[init ?] ";
    out[..text.len()].copy_from_slice(text);
    out[6] = b'0' + (pid % 10) as u8;
    &out[..text.len()]
}

/// Emits one tagged line in a single system call.
///
/// Building the line first is not tidiness. A process can be preempted between
/// two calls, so writing a prefix and then a message as separate calls lets
/// another process interleave inside the line — which it did, and the result
/// was output that read as though the kernel had scrambled it. One call per
/// line is the only way to make a line atomic without a lock user space does
/// not have.
fn say(pid: u64, parts: &[&[u8]]) {
    let mut line = [0u8; 192];
    let mut len = 0usize;

    let mut prefix = [0u8; 10];
    for chunk in core::iter::once(tag(pid, &mut prefix) as &[u8]).chain(parts.iter().copied()) {
        let take = chunk.len().min(line.len() - len - 1);
        line[len..len + take].copy_from_slice(&chunk[..take]);
        len += take;
    }
    line[len] = b'\n';
    len += 1;
    log_bytes(&line[..len]);
}

/// Clients the server answers before it stops. Two of the three processes are
/// clients; the third owns the endpoint.
const CLIENTS: usize = 2;

fn call5(number: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> Result<u64, SyscallError> {
    // SAFETY: every call site passes arguments the corresponding syscall
    // accepts, or deliberately does not — the refusals are the point.
    decode(unsafe { abi::syscall5(number, a0, a1, a2, a3, a4) })
}

fn call(number: u64, a0: u64, a1: u64) -> Result<u64, SyscallError> {
    // SAFETY: every call site below passes arguments the corresponding syscall
    // accepts, or deliberately does not — the refusals are the point.
    decode(unsafe { abi::syscall2(number, a0, a1) })
}

fn expect_refused(pid: u64, what: &str, expected: SyscallError, result: Result<u64, SyscallError>) {
    match result {
        Err(error) if error == expected => {
            say(pid, &[b"refused as expected: ", what.as_bytes()]);
        }
        _ => {
            say(pid, &[b"SECURITY CHECK FAILED: ", what.as_bytes()]);
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

/// Burns time without calling the kernel.
///
/// The point is to be interruptible and nothing else. `black_box` keeps the
/// optimiser from noticing the loop has no effect and deleting it, which would
/// remove the only window in which a timer tick can land.
fn spin(iterations: u64) {
    let mut sink = 0u64;
    for i in 0..iterations {
        sink = core::hint::black_box(sink.wrapping_add(i));
    }
    core::hint::black_box(sink);
}

/// The argument the kernel starts the session with.
///
/// Not 1, 2, or 3: those are the demonstration's processes, and a session that
/// shared a number with one of them would run its test battery — which ends in
/// `SYS_EXIT`, and a session that exits is the thing this exists to stop.
const SESSION_ROLE: u64 = 9;

#[no_mangle]
pub extern "sysv64" fn _start(pid: u64, endpoint: u64, grant: u64) -> ! {
    // The session is a different program that happens to share an image. It
    // runs after the demonstration has finished and been accounted for, and it
    // does not return.
    if pid == SESSION_ROLE {
        session(grant);
    }

    say(pid, &[b"hello from ring 3"]);

    // The round trip. Printing could be faked by a kernel that never left ring
    // 0; a value the kernel transformed and returned could not.
    let sent = 0x0123_4567_89AB_CDEF ^ pid;
    match call(SYS_PING, sent, 0) {
        Ok(reply) if reply == sent ^ PING_COOKIE => {
            let mut buffer = [0u8; 18];
            say(
                pid,
                &[b"ping round trip ok, reply ", hex(reply, &mut buffer)],
            );
        }
        _ => {
            say(pid, &[b"PING FAILED"]);
            exit(1);
        }
    }

    // --- the boundary ----------------------------------------------------
    // Each of these would be a privilege escalation if it succeeded.

    expect_refused(
        pid,
        "reading kernel memory through SYS_LOG",
        SyscallError::BadPointer,
        call(SYS_LOG, KERNEL_ADDRESS, 16),
    );
    expect_refused(
        pid,
        "a length past the end of the buffer limit",
        SyscallError::TooLong,
        call(SYS_LOG, 0x1000_0000_0000, MAX_LOG_BYTES as u64 + 1),
    );
    expect_refused(
        pid,
        "an unassigned syscall number",
        SyscallError::BadNumber,
        call(UNASSIGNED_SYSCALL, 0, 0),
    );

    // --- the scheduler ----------------------------------------------------
    // A loop that never enters the kernel. Anything that happens between two
    // rounds happened because the processor was taken away, not because this
    // process asked for anything.
    for round in 0..ROUNDS {
        spin(SPIN);
        let digit = [b'0' + (round % 10) as u8];
        say(pid, &[b"round ", &digit]);
    }

    // --- memory a device could read ---------------------------------------
    // Unlike a device mapping, this needs no grant: a process asking for its
    // own buffer is asking for nothing that belongs to anyone else.
    take_dma_buffer(pid);

    // --- driving a device -------------------------------------------------
    // Only the process the kernel gave a grant to gets past the first call.
    // Everything else here holds zero, and zero never matches.
    drive_display(pid, grant);

    // --- waiting on hardware ----------------------------------------------
    // The other half of driving a device: the device answering.
    await_interrupts(pid, grant);

    // --- a real PCI device ------------------------------------------------
    probe_disk(pid, grant);

    // --- the same transport, a completely different device ----------------
    probe_sound(pid, grant);

    // --- talking to another process ---------------------------------------
    if endpoint != 0 {
        if pid == SERVER_ROLE {
            serve(pid, endpoint);
        } else {
            request(pid, endpoint);
        }
    }

    say(pid, &[b"all checks passed"]);
    exit(0);
}

/// The process that owns the endpoint. Given the endpoint by the kernel at
/// spawn; every other process is a client.
const SERVER_ROLE: u64 = 1;

/// The device index of the ticker, which is the second entry the kernel lists.
const TICKER_DEVICE: u64 = 1;

/// The device index of the virtio disk, the first the PCI scan appends.
const BLOCK_DEVICE: u64 = 4;

/// Offsets in the virtio common configuration structure (virtio 1.0 §4.1.4.3).
mod common {
    pub const DEVICE_FEATURE_SELECT: u32 = 0x00;
    pub const DEVICE_FEATURE: u32 = 0x04;
    pub const DRIVER_FEATURE_SELECT: u32 = 0x08;
    pub const DRIVER_FEATURE: u32 = 0x0C;
    pub const NUM_QUEUES: u32 = 0x12;
    pub const DEVICE_STATUS: u32 = 0x14;
    pub const QUEUE_SELECT: u32 = 0x16;
    pub const QUEUE_SIZE: u32 = 0x18;
    pub const QUEUE_MSIX_VECTOR: u32 = 0x1A;
    pub const QUEUE_ENABLE: u32 = 0x1C;
    pub const QUEUE_NOTIFY_OFF: u32 = 0x1E;
    pub const QUEUE_DESC: u32 = 0x20;
    pub const QUEUE_DRIVER: u32 = 0x28;
    pub const QUEUE_DEVICE: u32 = 0x30;
}

/// No MSI-X vector. The device must be told this explicitly: the field powers
/// up as `NO_VECTOR` on QEMU but is not architecturally guaranteed to, and a
/// queue pointing at an MSI-X vector this driver never configured is a queue
/// whose completions go nowhere.
const NO_MSIX_VECTOR: u16 = 0xFFFF;

/// Descriptor flags (virtio 1.0 §2.6.5).
mod desc_flag {
    /// This descriptor chains to another.
    pub const NEXT: u16 = 1;
    /// The *device* writes into this buffer. Its absence means the device
    /// reads. Getting this backwards is the difference between a disk read and
    /// a disk write, with no complaint from anything.
    pub const WRITE: u16 = 2;
}

/// virtio-blk request types (virtio 1.0 §5.2.6).
mod blk {
    pub const IN: u32 = 0;
    pub const OUT: u32 = 1;
    /// The device writes this into the status byte on success.
    pub const STATUS_OK: u8 = 0;
}

/// `VIRTIO_F_VERSION_1` is feature bit 32 — bit 0 of the second feature word.
///
/// A virtio 1.0 device refuses to leave `FEATURES_OK` set unless the driver
/// accepts it, which is the specification's way of making sure a driver written
/// for the legacy layout cannot accidentally drive a modern device.
const FEATURE_VERSION_1_WORD: u32 = 1;
const FEATURE_VERSION_1_BIT: u32 = 1;

/// Device status bits (virtio 1.0 §2.1). Written in order; each one tells the
/// device how far the driver has got, and the device may refuse to proceed if
/// they arrive out of sequence.
mod status {
    /// The driver has noticed the device.
    pub const ACKNOWLEDGE: u8 = 1;
    /// The driver knows how to drive it.
    pub const DRIVER: u8 = 2;
    /// The driver is ready. Queues may be used from here on.
    pub const DRIVER_OK: u8 = 4;
    /// The driver has finished negotiating features. The device clears this bit
    /// if it cannot work with what was accepted, which is the one handshake
    /// step that can fail without anything else going wrong.
    pub const FEATURES_OK: u8 = 8;
    /// Set by the *device* when it has given up on the driver.
    pub const FAILED: u8 = 128;
}

/// Bytes per sector, which virtio-blk fixes regardless of the disk's own
/// geometry.
const SECTOR_BYTES: u64 = 512;

/// The size of the disk the build attaches, in bytes.
///
/// Checked rather than merely printed. A capacity read through a mapping that
/// is subtly wrong — off by a page, pointing at the ISR structure — produces a
/// plausible number, and only comparing it against a value chosen elsewhere
/// turns "we read something" into "we read the right thing".
const EXPECTED_DISK_BYTES: u64 = 16 * 1024 * 1024;

/// A split virtqueue, laid out in one DMA buffer.
///
/// # Why the three rings are placed by hand
///
/// A virtqueue is three structures the device reads at three physical
/// addresses it is told separately. They have different alignments — 16 for the
/// descriptor table, 2 for the available ring, 4 for the used ring — and in
/// virtio 1.0 they need not be adjacent at all. Packing them into one
/// contiguous allocation at page-aligned offsets satisfies every alignment at
/// once and costs one DMA buffer instead of three.
///
/// # Sizes
///
/// A queue of 256 descriptors, which is what QEMU offers, needs 4 KiB of
/// descriptor table, 518 bytes of available ring, and 2054 of used ring. Laid
/// out a page apart that is 12 KiB, which is why the buffer below is 16.
struct Queue {
    /// Virtual addresses, for this process.
    desc: u64,
    avail: u64,
    used: u64,
    /// Bus addresses, for the device.
    desc_bus: u64,
    avail_bus: u64,
    used_bus: u64,
    size: u16,
    /// Where in the notification region this queue's doorbell is.
    notify: u64,
    /// The next slot this driver will write in the available ring.
    next_avail: u16,
    /// The last used-ring index this driver has seen.
    last_used: u16,
}

/// Bytes of DMA for the queue. See `Queue` for where the number comes from.
const QUEUE_BYTES: u64 = 16 * 1024;
/// Offsets of the three rings within that buffer.
const DESC_OFFSET: u64 = 0;
const AVAIL_OFFSET: u64 = 4096;
const USED_OFFSET: u64 = 8192;

/// Descriptors this driver uses per request: header, data, status.
const DESCRIPTORS_PER_REQUEST: u16 = 3;

/// Bytes of DMA for one request: a 16-byte header, a sector, a status byte.
const REQUEST_BYTES: u64 = 4096;
/// Offsets within that buffer.
const HEADER_OFFSET: u64 = 0;
const DATA_OFFSET: u64 = 512;
const STATUS_OFFSET: u64 = 2048;

/// How long to spin waiting for the device before giving up.
///
/// A bound rather than a forever loop: a device that never completes a request
/// is a bug worth reporting, and a driver that hangs waiting for one takes the
/// evidence with it. QEMU answers a 512-byte read in microseconds, so anything
/// near this many iterations means something is wrong rather than slow.
const COMPLETION_SPINS: u64 = 200_000_000;

/// # Safety
/// `address` must be inside a device window this process was given.
unsafe fn mmio_read8(address: u64) -> u8 {
    // SAFETY: the caller guarantees the mapping. Volatile because these are
    // device registers with side effects, not memory.
    unsafe { (address as *const u8).read_volatile() }
}

/// # Safety
/// As `mmio_read8`.
unsafe fn mmio_read16(address: u64) -> u16 {
    // SAFETY: as above.
    unsafe { (address as *const u16).read_volatile() }
}

/// # Safety
/// As `mmio_read8`.
unsafe fn mmio_read32(address: u64) -> u32 {
    // SAFETY: as above.
    unsafe { (address as *const u32).read_volatile() }
}

/// # Safety
/// As `mmio_read8`, and a write to a device register does something.
unsafe fn mmio_write8(address: u64, value: u8) {
    // SAFETY: as above.
    unsafe { (address as *mut u8).write_volatile(value) }
}

/// # Safety
/// As `mmio_write8`.
unsafe fn mmio_write16(address: u64, value: u16) {
    // SAFETY: as above.
    unsafe { (address as *mut u16).write_volatile(value) }
}

/// # Safety
/// As `mmio_write8`.
unsafe fn mmio_write32(address: u64, value: u32) {
    // SAFETY: as above.
    unsafe { (address as *mut u32).write_volatile(value) }
}

/// Writes a 64-bit configuration field as two 32-bit halves.
///
/// The specification permits either, and a single 64-bit write is what a driver
/// would reach for. Two halves is the portable choice: a device is only
/// required to implement 32-bit accesses to these fields, and the low-then-high
/// order is the one the specification names.
///
/// # Safety
/// As `mmio_write8`.
unsafe fn mmio_write64_split(address: u64, value: u64) {
    // SAFETY: as above.
    unsafe {
        mmio_write32(address, value as u32);
        mmio_write32(address + 4, (value >> 32) as u32);
    }
}

/// Brings a real PCI device up to the point where a queue could be created.
///
/// This is the first three steps of the virtio initialisation sequence, done
/// from ring 3 on hardware the kernel found and mapped but does not understand.
/// The kernel knows this device is virtio type 2 and where its four structures
/// are; it does not know what a status register is, and nothing here goes
/// through it.
///
/// The capacity read at the end is the part that cannot be faked. It comes from
/// the device-specific configuration structure, at an offset the kernel took
/// out of PCI capability space, and it has to equal the size of the file the
/// build attached — which is decided in `xtask` and known to neither side.
fn probe_disk(pid: u64, grant: u64) {
    let mut info = DeviceInfo::EMPTY;
    let size = core::mem::size_of::<DeviceInfo>() as u64;

    match call5(
        SYS_DEVICE_INFO,
        grant,
        BLOCK_DEVICE,
        (&raw mut info) as u64,
        size,
        0,
    ) {
        Ok(_) => {}
        Err(SyscallError::NotPermitted) => {
            say(pid, &[b"no disk grant, as expected"]);
            return;
        }
        Err(error) => {
            say(pid, &[b"disk info failed: ", error.name().as_bytes()]);
            exit(20);
        }
    }

    if info.kind != DeviceKind::Block as u32 {
        say(pid, &[b"the disk device is not a block device"]);
        exit(21);
    }

    let window = match call(SYS_MAP_DEVICE, grant, BLOCK_DEVICE) {
        Ok(base) => base,
        Err(error) => {
            say(pid, &[b"disk map failed: ", error.name().as_bytes()]);
            exit(22);
        }
    };

    let common = window + u64::from(info.common_offset);
    let config = window + u64::from(info.config_offset);

    // SAFETY: `window` is a device mapping the kernel just gave this process,
    // and every offset below came from the same call that described it.
    unsafe {
        // Reset. Writing zero to the status register is how a driver tells a
        // virtio device to forget whatever the firmware did with it, and the
        // device answering with zero is the first evidence the mapping reaches
        // the device at all rather than reading back stale bytes.
        mmio_write8(common + u64::from(common::DEVICE_STATUS), 0);
        if mmio_read8(common + u64::from(common::DEVICE_STATUS)) != 0 {
            say(pid, &[b"disk did not accept a reset"]);
            exit(23);
        }

        // Two steps of the handshake, each read back. A mapping that was
        // write-only, or pointed at the wrong structure, would fail here.
        mmio_write8(
            common + u64::from(common::DEVICE_STATUS),
            status::ACKNOWLEDGE,
        );
        mmio_write8(
            common + u64::from(common::DEVICE_STATUS),
            status::ACKNOWLEDGE | status::DRIVER,
        );
        let state = mmio_read8(common + u64::from(common::DEVICE_STATUS));
        if state != status::ACKNOWLEDGE | status::DRIVER {
            say(pid, &[b"disk refused the handshake"]);
            exit(24);
        }
        if state & status::FAILED != 0 {
            say(pid, &[b"disk gave up on this driver"]);
            exit(25);
        }

        // A read that depends on a write: selecting feature word 0 and reading
        // what comes back. If the window were mapped read-only, or the writes
        // were going somewhere else, this would not track the selector.
        mmio_write32(common + u64::from(common::DEVICE_FEATURE_SELECT), 0);
        let low = mmio_read32(common + u64::from(common::DEVICE_FEATURE));
        mmio_write32(common + u64::from(common::DEVICE_FEATURE_SELECT), 1);
        let high = mmio_read32(common + u64::from(common::DEVICE_FEATURE));
        if low == high {
            // Not impossible in principle, but for QEMU's virtio-blk the two
            // words differ, and equal ones mean the selector was ignored.
            say(pid, &[b"disk feature selector had no effect"]);
            exit(26);
        }

        let queues = mmio_read16(common + u64::from(common::NUM_QUEUES));
        if queues == 0 {
            say(pid, &[b"disk reports no queues"]);
            exit(27);
        }

        // The capacity, in 512-byte sectors, from the device-specific
        // structure. Read as two halves because the field is not guaranteed
        // aligned for a 64-bit access on every device.
        let sectors = u64::from(mmio_read32(config)) | u64::from(mmio_read32(config + 4)) << 32;
        let bytes = sectors * SECTOR_BYTES;
        if bytes != EXPECTED_DISK_BYTES {
            say(pid, &[b"disk capacity is not the size the build attached"]);
            exit(28);
        }

        let mut buffer = [0u8; 18];
        say(
            pid,
            &[
                b"disk ready from ring 3: ",
                hex(sectors, &mut buffer),
                b" sectors",
            ],
        );
    }

    // --- feature negotiation ----------------------------------------------
    // A virtio 1.0 device refuses to proceed unless the driver accepts
    // VERSION_1, which is how the specification stops a driver written for the
    // legacy layout from accidentally driving a modern device.
    // SAFETY: as above.
    unsafe {
        mmio_write32(common + u64::from(common::DRIVER_FEATURE_SELECT), 0);
        mmio_write32(common + u64::from(common::DRIVER_FEATURE), 0);
        mmio_write32(
            common + u64::from(common::DRIVER_FEATURE_SELECT),
            FEATURE_VERSION_1_WORD,
        );
        mmio_write32(
            common + u64::from(common::DRIVER_FEATURE),
            FEATURE_VERSION_1_BIT,
        );

        mmio_write8(
            common + u64::from(common::DEVICE_STATUS),
            status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK,
        );
        // The device clears this bit if it cannot work with what was accepted.
        // Reading it back is the only way to find out, and a driver that skips
        // the check goes on to set up a queue the device will ignore.
        if mmio_read8(common + u64::from(common::DEVICE_STATUS)) & status::FEATURES_OK == 0 {
            say(pid, &[b"disk rejected the negotiated features"]);
            exit(29);
        }
    }

    let Some(mut queue) = setup_queue(
        pid,
        common,
        window + u64::from(info.notify_offset),
        &info,
        0,
        30,
    ) else {
        return;
    };

    // SAFETY: as above. The queue exists, so the device may be told the driver
    // is ready — which is what permits it to look at the rings at all.
    unsafe {
        mmio_write8(
            common + u64::from(common::DEVICE_STATUS),
            status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK | status::DRIVER_OK,
        );
    }

    exercise_disk(pid, &mut queue);
}

/// The device index of the sound card, the second the PCI scan appends.
const SOUND_DEVICE: u64 = 5;

/// The kernel's line numbers. Not device indices — a device index is what a
/// process names when asking for hardware, and a line is what the kernel calls
/// the wire. `SYS_IRQ_WAIT_ANY` reports the second, so a driver that services
/// several devices needs both.
const TICKER_LINE: u64 = 0;
const KEYBOARD_LINE: u64 = 1;
const MOUSE_LINE: u64 = 2;

/// The device indices of the two halves of the input controller.
///
/// The kernel lists what the firmware and the hardware give it, in that order:
/// framebuffer, ticker, keyboard, mouse, then whatever the PCI scan appends.
/// Inserting the input controller ahead of the scan moved the disk and the
/// sound card two places, and these constants were not updated with them — the
/// disk driver asked for device 2, got the keyboard, and the process that was
/// also the IPC server exited, which took the rest of the boot with it.
const KEYBOARD_DEVICE: u64 = 2;
const MOUSE_DEVICE: u64 = 3;

/// The i8042's registers, granted as two separate ports.
const I8042_DATA: u16 = 0x60;
const I8042_COMMAND: u16 = 0x64;

/// Status register bits (read from `I8042_COMMAND`).
mod i8042_status {
    /// A byte is waiting in the data register.
    pub const OUTPUT_FULL: u8 = 1 << 0;
    /// The controller has not consumed the last byte written to it.
    pub const INPUT_FULL: u8 = 1 << 1;
    /// The waiting byte came from the auxiliary port — the mouse — rather than
    /// the keyboard. Belt and braces: the interrupt already says which, and
    /// this says it again from the other side.
    pub const FROM_MOUSE: u8 = 1 << 5;
}

/// Controller commands (written to `I8042_COMMAND`).
mod i8042_command {
    pub const READ_CONFIG: u8 = 0x20;
    pub const WRITE_CONFIG: u8 = 0x60;
    /// Enable the auxiliary port, which is where the mouse is.
    pub const ENABLE_AUX: u8 = 0xA8;
    /// The next byte written to the data port goes to the mouse, not the
    /// keyboard.
    pub const TO_MOUSE: u8 = 0xD4;
}

/// Configuration byte bits.
mod i8042_config {
    pub const KEYBOARD_INTERRUPT: u8 = 1 << 0;
    pub const MOUSE_INTERRUPT: u8 = 1 << 1;
    /// Translate set 2 scancodes to set 1. Left as the firmware set it —
    /// changing it would mean decoding whichever set results, and this driver
    /// only needs to know that a key moved.
    pub const TRANSLATE: u8 = 1 << 6;
}

/// Mouse commands, sent through `TO_MOUSE`.
mod mouse_command {
    /// Start sending movement packets.
    pub const ENABLE_REPORTING: u8 = 0xF4;
    /// Restore defaults. The device answers `ACK` to both.
    pub const SET_DEFAULTS: u8 = 0xF6;
    pub const ACK: u8 = 0xFA;
}

/// How long to spin waiting for the controller.
///
/// The i8042 is slow by modern standards and a status bit that never changes
/// means the chip is not there — a bound turns that into a report rather than a
/// hang, in a process that must not exit.
const I8042_SPINS: u32 = 100_000;

/// # Safety
/// The process must hold a port grant covering `port`.
unsafe fn port_out(port: u16, value: u8) {
    // SAFETY: the caller guarantees the grant. Without it the CPU raises `#GP`
    // on the instruction itself, which is the mechanism working.
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") value,
                         options(nostack, preserves_flags));
    }
}

/// # Safety
/// As `port_out`.
unsafe fn port_in(port: u16) -> u8 {
    let value: u8;
    // SAFETY: as `port_out`.
    unsafe {
        core::arch::asm!("in al, dx", in("dx") port, out("al") value,
                         options(nostack, preserves_flags));
    }
    value
}

/// Waits until the controller has room for a byte.
///
/// # Safety
/// As `port_out`.
unsafe fn i8042_wait_writable() -> bool {
    for _ in 0..I8042_SPINS {
        // SAFETY: as `port_out`.
        if unsafe { port_in(I8042_COMMAND) } & i8042_status::INPUT_FULL == 0 {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// Waits until the controller has a byte, and takes it.
///
/// # Safety
/// As `port_out`.
unsafe fn i8042_read() -> Option<u8> {
    for _ in 0..I8042_SPINS {
        // SAFETY: as `port_out`.
        unsafe {
            if port_in(I8042_COMMAND) & i8042_status::OUTPUT_FULL != 0 {
                return Some(port_in(I8042_DATA));
            }
        }
        core::hint::spin_loop();
    }
    None
}

/// Sends one command to the controller.
///
/// # Safety
/// As `port_out`.
unsafe fn i8042_command(command: u8) -> bool {
    // SAFETY: as `port_out`.
    unsafe {
        if !i8042_wait_writable() {
            return false;
        }
        port_out(I8042_COMMAND, command);
    }
    true
}

/// Sends one byte to the mouse and waits for its acknowledgement.
///
/// # Safety
/// As `port_out`.
unsafe fn mouse_send(byte: u8) -> bool {
    // SAFETY: as `port_out`.
    unsafe {
        if !i8042_command(i8042_command::TO_MOUSE) || !i8042_wait_writable() {
            return false;
        }
        port_out(I8042_DATA, byte);
        i8042_read() == Some(mouse_command::ACK)
    }
}

/// Brings the controller up so both devices report.
///
/// # Why the configuration byte is read before it is written
///
/// It holds the translation bit, which decides which scancode set arrives, and
/// whatever the firmware chose is what the keyboard is currently speaking.
/// Writing a whole byte would change that as a side effect of enabling two
/// interrupts, and the driver would then decode the wrong set — which looks
/// like a keyboard that produces plausible but wrong keys.
///
/// # Safety
/// The process must hold grants for both controller ports.
unsafe fn i8042_init(pid: u64) -> bool {
    // SAFETY: the caller guarantees the grants.
    unsafe {
        // Drain anything the firmware left. A byte still waiting means the
        // controller raises no further interrupt, and the first real keystroke
        // would never arrive.
        while port_in(I8042_COMMAND) & i8042_status::OUTPUT_FULL != 0 {
            let _ = port_in(I8042_DATA);
        }

        if !i8042_command(i8042_command::ENABLE_AUX) {
            say(pid, &[b"i8042 did not accept the aux enable"]);
            return false;
        }

        if !i8042_command(i8042_command::READ_CONFIG) {
            say(pid, &[b"i8042 did not accept the config read"]);
            return false;
        }
        let Some(config) = i8042_read() else {
            say(pid, &[b"i8042 never returned its config byte"]);
            return false;
        };

        let wanted = config | i8042_config::KEYBOARD_INTERRUPT | i8042_config::MOUSE_INTERRUPT;
        if !i8042_command(i8042_command::WRITE_CONFIG) || !i8042_wait_writable() {
            say(pid, &[b"i8042 did not accept the config write"]);
            return false;
        }
        port_out(I8042_DATA, wanted);

        // The mouse defaults to not reporting. Both commands are acknowledged,
        // and a missing acknowledgement means there is no mouse behind the
        // auxiliary port — worth saying rather than discovering as a cursor
        // that never moves.
        if !mouse_send(mouse_command::SET_DEFAULTS) {
            say(pid, &[b"no mouse answered on the aux port"]);
            return false;
        }
        if !mouse_send(mouse_command::ENABLE_REPORTING) {
            say(pid, &[b"mouse refused to start reporting"]);
            return false;
        }

        let translated = config & i8042_config::TRANSLATE != 0;
        say(
            pid,
            &[
                b"input controller up, scancode translation ",
                if translated { b"on" } else { b"off" },
            ],
        );
    }
    true
}

/// The pointer's bounding box, in pixels. The cross is drawn inside it.
const POINTER_SIZE: usize = 13;

/// Where the pointer is, what it is doing, and what is underneath it.
struct Pointer {
    x: i64,
    y: i64,
    /// Bytes of the current three-byte movement packet.
    packet: [u8; 3],
    have: usize,
    left: bool,
    /// The desktop the cursor is currently covering, and where it was taken
    /// from.
    ///
    /// Saved before the cursor is drawn and put back before it moves. Without
    /// it the cursor leaves a trail of every position it has ever been in,
    /// which is what the first version did — a screen capture after a diagonal
    /// move showed eight crosses.
    ///
    /// The alternative is redrawing the desktop each frame, which tears and
    /// costs four megabytes to move a cursor. This costs 169 words.
    saved: [u32; POINTER_SIZE * POINTER_SIZE],
    saved_at: Option<(u64, u64)>,
}

/// A screen the session draws into, and the pixel arithmetic to do it.
///
/// Not a compositor. There are no windows a process can create, nothing is
/// clipped against anything, and the whole screen is redrawn each frame. What
/// it is: proof that a process outside the kernel owns the display and can put
/// a coherent picture on it, which is the thing that was missing when the
/// machine finished booting and left a wall of log text on screen.
struct Screen {
    base: u64,
    width: u64,
    height: u64,
    stride: u64,
}

mod colour {
    /// `0x00RRGGBB`, matching the framebuffer's format.
    pub const DESKTOP_TOP: u32 = 0x0006_0C1A;
    pub const DESKTOP_BOTTOM: u32 = 0x0001_0308;
    pub const PANEL: u32 = 0x000C_1830;
    pub const ACCENT: u32 = 0x0019_E6FF;
    pub const TEXT: u32 = 0x00D8_E8F8;
    pub const DIM: u32 = 0x0064_8098;
    pub const WINDOW: u32 = 0x0012_1E36;
    pub const WINDOW_BAR: u32 = 0x001B_2C4C;
    pub const SHADOW: u32 = 0x0000_0206;
}

/// Height of the bar across the top.
const PANEL_HEIGHT: u64 = 32;
/// How much the glyphs are scaled. A 6x7 glyph is unreadable unscaled at this
/// resolution.
const TEXT_SCALE: u64 = 2;

/// Where the shell window sits, and how much of it is text.
const SHELL_X: u64 = 80;
const SHELL_Y: u64 = 430;
const SHELL_W: u64 = 1120;
const SHELL_H: u64 = 330;
/// Inside the frame, below the title bar.
const SHELL_TEXT_X: u64 = SHELL_X + 12;
const SHELL_TEXT_Y: u64 = SHELL_Y + 34;
/// One glyph cell, scaled. The gap makes lines legible at this size; without it
/// descenders touch the row below.
const CELL_W: u64 = font::GLYPH_WIDTH as u64 * TEXT_SCALE;
const CELL_H: u64 = font::GLYPH_HEIGHT as u64 * TEXT_SCALE + 3;

impl Screen {
    /// # Safety
    /// `base` must be a framebuffer window this process was granted, matching
    /// the geometry given.
    unsafe fn put(&self, x: u64, y: u64, colour: u32) {
        if x >= self.width || y >= self.height {
            return;
        }
        // SAFETY: bounds checked against the geometry the kernel reported.
        unsafe { ((self.base + (y * self.stride + x) * 4) as *mut u32).write_volatile(colour) }
    }

    /// Reads a pixel back, for saving what a cursor is about to cover.
    ///
    /// # Safety
    /// As `put`.
    unsafe fn get(&self, x: u64, y: u64) -> u32 {
        if x >= self.width || y >= self.height {
            return 0;
        }
        // SAFETY: bounds checked against the geometry the kernel reported.
        unsafe { ((self.base + (y * self.stride + x) * 4) as *const u32).read_volatile() }
    }

    /// # Safety
    /// As `put`.
    unsafe fn fill(&self, x: u64, y: u64, w: u64, h: u64, colour: u32) {
        for row in y..(y + h).min(self.height) {
            for column in x..(x + w).min(self.width) {
                // SAFETY: as `put`.
                unsafe { self.put(column, row, colour) };
            }
        }
    }

    /// A vertical gradient, which is the cheapest thing that does not look like
    /// a framebuffer somebody forgot to clear.
    ///
    /// # Safety
    /// As `put`.
    unsafe fn gradient(&self, y: u64, h: u64, top: u32, bottom: u32) {
        for row in 0..h {
            // Signed, because the bottom colour is darker than the top and the
            // difference is negative. Computed in `u32` it wrapped to a huge
            // positive number and every channel saturated, which put a flat
            // grey on screen where the desktop should have been — the kind of
            // wrong that looks like a missing feature rather than a bug.
            let mix = |shift: u32| -> u32 {
                let a = ((top >> shift) & 0xFF) as i32;
                let b = ((bottom >> shift) & 0xFF) as i32;
                (a + (b - a) * row as i32 / h.max(1) as i32).clamp(0, 255) as u32
            };
            let colour = (mix(16) << 16) | (mix(8) << 8) | mix(0);
            // SAFETY: as `put`.
            unsafe { self.fill(0, y + row, self.width, 1, colour) };
        }
    }

    /// # Safety
    /// As `put`.
    unsafe fn text(&self, x: u64, y: u64, bytes: &[u8], colour: u32) {
        for (index, byte) in bytes.iter().enumerate() {
            let rows = font::glyph(font::normalise(*byte));
            for (row, bits) in rows.iter().enumerate() {
                for column in 0..5u64 {
                    if bits & (1 << (4 - column)) == 0 {
                        continue;
                    }
                    for sy in 0..TEXT_SCALE {
                        for sx in 0..TEXT_SCALE {
                            // SAFETY: as `put`.
                            unsafe {
                                self.put(
                                    x + index as u64 * font::GLYPH_WIDTH as u64 * TEXT_SCALE
                                        + column * TEXT_SCALE
                                        + sx,
                                    y + row as u64 * TEXT_SCALE + sy,
                                    colour,
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    /// A window: a shadow, a body, a title bar, and a title.
    ///
    /// # Safety
    /// As `put`.
    unsafe fn window(&self, x: u64, y: u64, w: u64, h: u64, title: &[u8], focused: bool) {
        // SAFETY: as `put`.
        unsafe {
            self.fill(x + 4, y + 4, w, h, colour::SHADOW);
            self.fill(x, y, w, h, colour::WINDOW);
            self.fill(x, y, w, 24, colour::WINDOW_BAR);
            // The focused window is the one with the accent stripe. One bit of
            // state, drawn rather than described.
            if focused {
                self.fill(x, y, 3, h, colour::ACCENT);
            }
            self.text(x + 10, y + 6, title, colour::TEXT);
        }
    }
}

/// The resident process: what the machine is once the demonstration is over.
///
/// # Why this exists
///
/// Without it the system halts. Every process ran its checks, exited, and was
/// reaped, the kernel reported that nothing was left to schedule, and the screen
/// froze on that line. Nothing was wrong — there was simply nothing after — but
/// a machine that finishes and stops is indistinguishable, from the outside,
/// from one that hung.
///
/// So this does not exit. It owns the display band and the ticker, and it
/// redraws on every interrupt, which makes the screen visibly alive: an
/// advancing bar is proof that interrupts are still arriving, that the
/// scheduler is still running, and that a ring 3 process is still being given
/// the processor.
///
/// It is not a service manager yet. It starts nothing and answers nothing —
/// that is the next piece, and it needs a way to spawn a process on request
/// rather than on a budget.
fn session(grant: u64) -> ! {
    let pid = SESSION_ROLE;
    say(pid, &[b"session started, the machine is up"]);

    let mut info = DeviceInfo::EMPTY;
    let size = core::mem::size_of::<DeviceInfo>() as u64;
    if call5(SYS_DEVICE_INFO, grant, 0, (&raw mut info) as u64, size, 0).is_err()
        || info.kind != DeviceKind::Framebuffer as u32
    {
        // No screen. The serial console still works, so this is a degradation
        // rather than a reason to stop — and stopping is the one thing this
        // process must not do.
        say(pid, &[b"session has no framebuffer, running blind"]);
        idle_forever(pid);
    }

    let base = match call(SYS_MAP_DEVICE, grant, 0) {
        Ok(base) => base,
        Err(error) => {
            say(
                pid,
                &[b"session display map failed: ", error.name().as_bytes()],
            );
            idle_forever(pid);
        }
    };

    // Ports before lines, for every device. A driver that waits before it can
    // service the hardware gets one interrupt and then waits forever.
    for device in [TICKER_DEVICE, KEYBOARD_DEVICE, MOUSE_DEVICE] {
        if let Err(error) = call(SYS_GRANT_PORTS, grant, device) {
            say(
                pid,
                &[b"session port grant failed: ", error.name().as_bytes()],
            );
            idle_forever(pid);
        }
    }

    // SAFETY: the grants above cover both controller registers.
    if !unsafe { i8042_init(pid) } {
        say(pid, &[b"session has no input, running without it"]);
    }

    // Claim, do not wait. Every line has to be live before anything blocks:
    // claiming by waiting means stopping on the first device until it
    // interrupts, and a keyboard does not interrupt until somebody presses a
    // key — which is exactly where this stopped before `SYS_IRQ_CLAIM` existed.
    for device in [TICKER_DEVICE, KEYBOARD_DEVICE, MOUSE_DEVICE] {
        if let Err(error) = call(SYS_IRQ_CLAIM, grant, device) {
            say(
                pid,
                &[b"session could not claim a line: ", error.name().as_bytes()],
            );
            idle_forever(pid);
        }
    }

    say(pid, &[b"session owns the display, the clock, and input"]);

    let screen = Screen {
        base,
        width: u64::from(info.width),
        height: u64::from(info.height),
        stride: u64::from(info.stride),
    };

    let mut tick = 0u64;
    let mut keys = 0u64;
    let mut reported = false;
    let mut painted = false;
    let mut extended = false;
    let mut modifiers = keymap::Modifiers::default();
    let mut shell = console::Console::new();
    shell.print(b"WhisezOS session. Type help.");

    // The disk, so `read` reads rather than reporting that it cannot. Failure
    // here is not fatal: a session without a disk is a session with one fewer
    // command, and exiting is the one thing it must not do.
    let mut disk = attach_disk(&mut shell, grant);
    let mut pointer = Pointer {
        x: (screen.width / 2) as i64,
        y: (screen.height / 2) as i64,
        packet: [0; 3],
        have: 0,
        left: false,
        saved: [0; POINTER_SIZE * POINTER_SIZE],
        saved_at: None,
    };

    loop {
        // One wait for three devices. Blocking on the clock alone would drop
        // every keystroke; polling the controller from the clock would drop
        // mouse bytes, because it holds one at a time and a lost byte
        // desynchronises a three-byte packet into a cursor that jumps.
        let packed = match call(SYS_IRQ_WAIT_ANY, grant, 0) {
            Ok(packed) => packed,
            Err(error) => {
                say(pid, &[b"session wait failed: ", error.name().as_bytes()]);
                idle_forever(pid);
            }
        };
        let line = packed >> 32;
        let count = packed & 0xFFFF_FFFF;

        match line {
            TICKER_LINE => {
                tick = tick.wrapping_add(count);
                // SAFETY: the port grant covers the CMOS registers, and the
                // read is what permits the device's next interrupt.
                unsafe {
                    cmos_read(CMOS_REG_C);
                }
            }
            KEYBOARD_LINE | MOUSE_LINE => {
                // Drain rather than read once. Several bytes can arrive between
                // two wakes, and the controller reports only that it has one —
                // stopping after a single read leaves the rest to be read by
                // the next interrupt, one behind forever.
                // SAFETY: the grants above cover both registers.
                unsafe {
                    while port_in(I8042_COMMAND) & i8042_status::OUTPUT_FULL != 0 {
                        let from_mouse = port_in(I8042_COMMAND) & i8042_status::FROM_MOUSE != 0;
                        let byte = port_in(I8042_DATA);
                        if from_mouse {
                            pointer.feed(byte, &screen);
                        } else if extended {
                            // The byte after the prefix is a different key from
                            // the same code without it, and none of them
                            // produce characters. Skipping it is what stops an
                            // arrow key from typing a letter.
                            extended = false;
                        } else if byte == keymap::EXTENDED {
                            extended = true;
                        } else {
                            match keymap::decode(byte, &mut modifiers) {
                                keymap::Key::Char(character) => {
                                    keys = keys.wrapping_add(1);
                                    shell.type_char(character);
                                }
                                keymap::Key::Backspace => shell.backspace(),
                                keymap::Key::Enter => {
                                    keys = keys.wrapping_add(1);
                                    match shell.enter() {
                                        console::Action::Redraw => painted = false,
                                        console::Action::ReadSector(sector) => {
                                            read_sector(&mut shell, disk.as_mut(), sector);
                                        }
                                        console::Action::Uptime => {
                                            report_uptime(&mut shell, tick);
                                        }
                                        console::Action::None => {}
                                    }
                                }
                                keymap::Key::None => {}
                            }
                        }
                    }
                }
            }
            _ => {}
        }

        // SAFETY: `screen` describes the framebuffer window this process was
        // granted, and every draw below is clipped to its geometry.
        unsafe {
            if !painted {
                painted = true;
                draw_desktop(&screen);
            }
            draw_status(&screen, tick, keys, &pointer);
            draw_shell(&screen, &shell);
            draw_sweep(&screen, tick);
            draw_pointer(&screen, &mut pointer);
        }

        if !reported && tick >= 3 {
            reported = true;
            say(pid, &[b"session is drawing the desktop"]);
        }
    }
}

impl Pointer {
    /// Copies the desktop under where the cursor is about to go.
    ///
    /// # Safety
    /// As `Screen::put`.
    unsafe fn save(&mut self, screen: &Screen, x: u64, y: u64) {
        let left = x.saturating_sub(6);
        let top = y.saturating_sub(6);
        for row in 0..POINTER_SIZE as u64 {
            for column in 0..POINTER_SIZE as u64 {
                // SAFETY: `get` clips to the screen and answers zero outside.
                self.saved[(row * POINTER_SIZE as u64 + column) as usize] =
                    unsafe { screen.get(left + column, top + row) };
            }
        }
        self.saved_at = Some((left, top));
    }

    /// Puts back what `save` took.
    ///
    /// # Safety
    /// As `Screen::put`.
    unsafe fn restore(&self, screen: &Screen) {
        let Some((left, top)) = self.saved_at else {
            return;
        };
        for row in 0..POINTER_SIZE as u64 {
            for column in 0..POINTER_SIZE as u64 {
                // SAFETY: `put` clips to the screen.
                unsafe {
                    screen.put(
                        left + column,
                        top + row,
                        self.saved[(row * POINTER_SIZE as u64 + column) as usize],
                    );
                }
            }
        }
    }

    /// Takes one byte of a movement packet, applying it once all three arrive.
    ///
    /// # The first byte is the only one that can be checked
    ///
    /// Bit 3 of it is always set. Nothing marks the second or third, so a
    /// stream that has lost a byte cannot be resynchronised by looking at them
    /// — the only recovery is to notice the first byte is wrong and start
    /// again, which is what the check below does. Without it a single dropped
    /// byte turns every later packet into nonsense permanently.
    fn feed(&mut self, byte: u8, screen: &Screen) {
        const ALWAYS_ONE: u8 = 1 << 3;
        const LEFT_BUTTON: u8 = 1 << 0;
        const X_SIGN: u8 = 1 << 4;
        const Y_SIGN: u8 = 1 << 5;
        // Movement larger than this means the packet is not a packet.
        const OVERFLOW: u8 = (1 << 6) | (1 << 7);

        if self.have == 0 && (byte & ALWAYS_ONE == 0 || byte & OVERFLOW != 0) {
            return;
        }
        self.packet[self.have] = byte;
        self.have += 1;
        if self.have < 3 {
            return;
        }
        self.have = 0;

        let flags = self.packet[0];
        // The deltas are nine-bit two's complement: eight bits in the byte and
        // the sign in the flags. Sign-extending by hand because the sign bit is
        // not where the value is.
        let mut dx = i64::from(self.packet[1]);
        let mut dy = i64::from(self.packet[2]);
        if flags & X_SIGN != 0 {
            dx -= 256;
        }
        if flags & Y_SIGN != 0 {
            dy -= 256;
        }

        self.left = flags & LEFT_BUTTON != 0;
        // The mouse's y grows upward and the screen's grows downward.
        self.x = (self.x + dx).clamp(0, screen.width as i64 - 1);
        self.y = (self.y - dy).clamp(0, screen.height as i64 - 1);
    }
}
/// Everything on the desktop that does not change.
///
/// # Safety
/// `screen` must describe a framebuffer window this process holds.
unsafe fn draw_desktop(screen: &Screen) {
    // SAFETY: the caller guarantees the window; every call clips to geometry.
    unsafe {
        screen.gradient(
            0,
            screen.height,
            colour::DESKTOP_TOP,
            colour::DESKTOP_BOTTOM,
        );

        // The panel across the top, and what it says.
        screen.fill(0, 0, screen.width, PANEL_HEIGHT, colour::PANEL);
        screen.fill(0, PANEL_HEIGHT, screen.width, 2, colour::ACCENT);
        // Placed by arithmetic rather than by eye. A glyph is `GLYPH_WIDTH`
        // wide before scaling, so eight characters of title occupy exactly
        // this much — guessing put the second word twelve pixels inside the
        // first and produced "WHISEZOSSESSION" on screen.
        const TITLE: &[u8] = b"WHISEZOS";
        let title_end = 12 + TITLE.len() as u64 * font::GLYPH_WIDTH as u64 * TEXT_SCALE;
        screen.text(12, 9, TITLE, colour::ACCENT);
        screen.text(title_end + 16, 9, b"SESSION", colour::DIM);

        // Two windows. They do not do anything — there is no process behind
        // either — and they are drawn from the same geometry a real one would
        // have, so that when there is, this is the code that already worked.
        screen.window(80, 90, 520, 300, b"DEVICES", true);
        screen.text(96, 130, b"DISK    VIRTIO-BLK  16 MIB", colour::DIM);
        screen.text(96, 154, b"AUDIO   VIRTIO-SND  1 OUT 1 IN", colour::DIM);
        screen.text(96, 178, b"CLOCK   RTC         64 HZ", colour::DIM);
        screen.text(96, 202, b"DISPLAY FRAMEBUFFER 1280X800", colour::DIM);
        screen.text(96, 250, b"ALL DRIVEN FROM RING 3", colour::ACCENT);

        screen.window(
            SHELL_X,
            SHELL_Y,
            SHELL_W,
            SHELL_H,
            b"SHELL - TYPE HELP",
            false,
        );
    }
}

/// The panel's live half: uptime, keystroke count, and pointer position.
///
/// The ticker is the only source of time this process has — 64 interrupts to
/// the second, counted. The other two numbers are there because they are the
/// cheapest proof that input works: a count that rises when a key is pressed
/// and coordinates that follow the mouse cannot be produced by a still image.
///
/// # Safety
/// As `draw_desktop`.
unsafe fn draw_status(screen: &Screen, tick: u64, keys: u64, pointer: &Pointer) {
    let seconds = tick / 64;
    let mut stamp = *b"UP 00:00:00";
    let hours = (seconds / 3600) % 100;
    let minutes = (seconds / 60) % 60;
    let secs = seconds % 60;
    stamp[3] = b'0' + (hours / 10) as u8;
    stamp[4] = b'0' + (hours % 10) as u8;
    stamp[6] = b'0' + (minutes / 10) as u8;
    stamp[7] = b'0' + (minutes % 10) as u8;
    stamp[9] = b'0' + (secs / 10) as u8;
    stamp[10] = b'0' + (secs % 10) as u8;

    let mut readout = *b"KEYS 000  X 0000 Y 0000  ";
    let k = keys % 1000;
    readout[5] = b'0' + (k / 100) as u8;
    readout[6] = b'0' + (k / 10 % 10) as u8;
    readout[7] = b'0' + (k % 10) as u8;
    let px = pointer.x.clamp(0, 9999) as u64;
    let py = pointer.y.clamp(0, 9999) as u64;
    for (offset, value) in [(12u64, px), (19, py)] {
        for digit in 0..4u64 {
            let place = 10u64.pow(3 - digit as u32);
            readout[(offset + digit) as usize] = b'0' + (value / place % 10) as u8;
        }
    }
    if pointer.left {
        readout[24] = b'*';
    }

    let x = screen.width.saturating_sub(160);
    // SAFETY: the caller guarantees the window.
    unsafe {
        // The panel behind each first: glyphs are drawn as set pixels only, so
        // without this the previous digit stays underneath the new one.
        screen.fill(x, 4, 150, 24, colour::PANEL);
        screen.text(x, 9, &stamp, colour::TEXT);
        screen.fill(260, 4, 400, 24, colour::PANEL);
        screen.text(260, 9, &readout, colour::DIM);
    }
}

/// Everything needed to read a sector, once the disk has been brought up.
struct Disk {
    queue: Queue,
    region: DmaRegion,
    sectors: u64,
}

/// Brings the disk up for the session, or explains why not.
///
/// The same sequence the demonstration runs, in a process that keeps going
/// afterwards. Every failure prints and returns `None` rather than exiting: the
/// session is what stops the machine looking dead, and a missing disk is one
/// command short of a full shell, not a reason to stop.
fn attach_disk(shell: &mut console::Console, grant: u64) -> Option<Disk> {
    let pid = SESSION_ROLE;
    let mut info = DeviceInfo::EMPTY;
    let size = core::mem::size_of::<DeviceInfo>() as u64;
    if call5(
        SYS_DEVICE_INFO,
        grant,
        BLOCK_DEVICE,
        (&raw mut info) as u64,
        size,
        0,
    )
    .is_err()
        || info.kind != DeviceKind::Block as u32
    {
        shell.print(b"no disk on this machine; read is unavailable");
        return None;
    }

    let window = call(SYS_MAP_DEVICE, grant, BLOCK_DEVICE).ok()?;
    let common = window + u64::from(info.common_offset);
    let config = window + u64::from(info.config_offset);

    if !virtio_handshake(pid, common, 60) {
        return None;
    }

    // SAFETY: `config` is inside the device window this process was granted.
    let sectors =
        unsafe { u64::from(mmio_read32(config)) | u64::from(mmio_read32(config + 4)) << 32 };

    let queue = setup_queue(
        pid,
        common,
        window + u64::from(info.notify_offset),
        &info,
        0,
        62,
    )?;

    // SAFETY: the queue exists, so the device may be told the driver is ready —
    // which is what permits it to look at the rings.
    unsafe {
        mmio_write8(
            common + u64::from(common::DEVICE_STATUS),
            status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK | status::DRIVER_OK,
        );
    }

    let mut region = DmaRegion::EMPTY;
    let bytes = core::mem::size_of::<DmaRegion>() as u64;
    if call5(
        SYS_ALLOC_DMA,
        REQUEST_BYTES,
        (&raw mut region) as u64,
        bytes,
        0,
        0,
    )
    .is_err()
    {
        shell.print(b"no memory for disk requests; read is unavailable");
        return None;
    }

    let mut line = [b' '; console::COLUMNS];
    let prefix = b"disk ready, ";
    line[..prefix.len()].copy_from_slice(prefix);
    let mut digits = [0u8; 20];
    let rendered = console::decimal(sectors, &mut digits);
    let mut at = prefix.len();
    line[at..at + rendered.len()].copy_from_slice(rendered);
    at += rendered.len();
    let tail = b" sectors";
    line[at..at + tail.len()].copy_from_slice(tail);
    at += tail.len();
    shell.print(&line[..at]);

    Some(Disk {
        queue,
        region,
        sectors,
    })
}

/// Reads one sector and prints the first bytes of it.
fn read_sector(shell: &mut console::Console, disk: Option<&mut Disk>, sector: u64) {
    let Some(disk) = disk else {
        shell.print(b"read: no disk attached");
        return;
    };
    if sector >= disk.sectors {
        shell.print(b"read: past the end of the disk");
        return;
    }

    if !submit(SESSION_ROLE, &mut disk.queue, &disk.region, blk::IN, sector) {
        shell.print(b"read: the device did not answer");
        return;
    }

    // Two rows of sixteen bytes. Enough to recognise what is there without
    // filling the history with one sector.
    let data = disk.region.virt + DATA_OFFSET;
    for row in 0..2u64 {
        let mut line = [b' '; console::COLUMNS];
        let mut at = 0usize;
        let mut digits = [0u8; 20];
        let offset = console::decimal(row * 16, &mut digits);
        line[at..at + offset.len()].copy_from_slice(offset);
        at += offset.len();
        line[at] = b':';
        at += 2;

        for column in 0..16u64 {
            // SAFETY: the device just wrote this range, which is inside the
            // request buffer this process owns.
            let byte = unsafe { ((data + row * 16 + column) as *const u8).read_volatile() };
            line[at] = hex_digit(byte >> 4);
            line[at + 1] = hex_digit(byte & 0xF);
            at += 3;
        }
        shell.print(&line[..at]);
    }
}

fn hex_digit(value: u8) -> u8 {
    if value < 10 {
        b'0' + value
    } else {
        b'a' + value - 10
    }
}

/// Answers `uptime` from the tick count, which is the only clock this process
/// has: 64 interrupts to the second, counted since the session started.
fn report_uptime(shell: &mut console::Console, tick: u64) {
    let seconds = tick / 64;
    let mut line = [b' '; console::COLUMNS];
    let mut digits = [0u8; 20];
    let rendered = console::decimal(seconds, &mut digits);

    let prefix = b"up ";
    line[..prefix.len()].copy_from_slice(prefix);
    let mut at = prefix.len();
    line[at..at + rendered.len()].copy_from_slice(rendered);
    at += rendered.len();
    let suffix = b" seconds, ";
    line[at..at + suffix.len()].copy_from_slice(suffix);
    at += suffix.len();

    let mut ticks = [0u8; 20];
    let rendered = console::decimal(tick, &mut ticks);
    line[at..at + rendered.len()].copy_from_slice(rendered);
    at += rendered.len();
    let tail = b" ticks";
    line[at..at + tail.len()].copy_from_slice(tail);
    at += tail.len();

    shell.print(&line[..at]);
}

/// Draws the shell's history and the line being typed.
///
/// The whole text area is repainted each frame rather than tracked for damage.
/// It is 78 by 17 cells, under a tenth of the screen, and the alternative is
/// bookkeeping that has to be right before anything appears — the same trade
/// the desktop makes in the other direction, where the static parts are large
/// and painted once.
///
/// # Safety
/// As `draw_desktop`.
unsafe fn draw_shell(screen: &Screen, shell: &console::Console) {
    // SAFETY: the caller guarantees the window; every draw clips.
    unsafe {
        // The history *and* the prompt row below it. Clearing only the history
        // left the prompt row untouched, so each frame drew a cursor block
        // beside the last one and the command line filled with them — the kind
        // of bug that is obvious on a screen and invisible to every test that
        // reads text rather than pixels.
        screen.fill(
            SHELL_TEXT_X - 4,
            SHELL_TEXT_Y - 4,
            SHELL_W - 16,
            (console::ROWS as u64 + 1) * CELL_H + 8,
            colour::WINDOW,
        );

        shell.each_line(|index, line| {
            screen.text(
                SHELL_TEXT_X,
                SHELL_TEXT_Y + index as u64 * CELL_H,
                line,
                colour::DIM,
            );
        });

        // The prompt on the row below the history, with a block for a cursor.
        // Drawn after it so a full buffer cannot push the prompt off the
        // window — the one line that must always be visible is the one being
        // typed into.
        let row = SHELL_TEXT_Y + (console::ROWS as u64) * CELL_H;
        screen.text(SHELL_TEXT_X, row, b">", colour::ACCENT);
        let typed = shell.input();
        screen.text(SHELL_TEXT_X + CELL_W * 2, row, typed, colour::TEXT);
        screen.fill(
            SHELL_TEXT_X + CELL_W * (2 + typed.len() as u64),
            row,
            CELL_W - 2,
            CELL_H - 3,
            colour::ACCENT,
        );
    }
}

/// Puts back what the cursor was covering, then draws it in its new place.
///
/// Drawn as a small cross rather than an arrow: an arrow needs a mask to avoid
/// a rectangle of background around it, and a cross is legible against both the
/// desktop and a window, which is the whole requirement.
///
/// # Safety
/// As `draw_desktop`.
unsafe fn draw_pointer(screen: &Screen, pointer: &mut Pointer) {
    // SAFETY: the caller guarantees the window; every access clips.
    unsafe {
        pointer.restore(screen);

        let x = pointer.x.clamp(0, screen.width as i64 - 1) as u64;
        let y = pointer.y.clamp(0, screen.height as i64 - 1) as u64;
        pointer.save(screen, x, y);

        let colour = if pointer.left {
            colour::ACCENT
        } else {
            colour::TEXT
        };
        screen.fill(x.saturating_sub(6), y, 13, 2, colour);
        screen.fill(x, y.saturating_sub(6), 2, 13, colour);
    }
}

/// A marker sweeping along the accent line under the panel.
///
/// The one thing that moves on every single frame rather than once a second,
/// so a stalled machine is obvious at a glance instead of after waiting to see
/// whether the clock advances.
///
/// # Safety
/// As `draw_desktop`.
unsafe fn draw_sweep(screen: &Screen, tick: u64) {
    let width = screen.width.max(1);
    let position = (tick * 6) % width;
    // SAFETY: the caller guarantees the window.
    unsafe {
        screen.fill(0, PANEL_HEIGHT, screen.width, 2, colour::ACCENT);
        screen.fill(position, PANEL_HEIGHT, 90, 2, colour::TEXT);
    }
}
/// Stays alive without a screen or a clock.
///
/// The session must not exit, so every failure above lands here rather than in
/// `exit`. `SYS_PING` is used as the sleep: it enters the kernel, which gives
/// the scheduler a chance to run something else, and it is the one call that
/// cannot fail.
fn idle_forever(pid: u64) -> ! {
    say(pid, &[b"session idling"]);
    loop {
        let _ = call(SYS_PING, 0, 0);
        spin(SPIN);
    }
}

/// virtio-sound's queues (virtio 1.2 §5.14.2).
///
/// Three of the four are named and unused. They are the shape of what comes
/// next — playback pushes buffers to `TX`, capture takes them from `RX` — and
/// naming them here is cheaper than rediscovering the numbering later. The
/// `allow` is the honest marker that they are not driven yet.
#[allow(dead_code)]
mod snd_queue {
    /// Requests and their replies. The only one this driver uses so far.
    pub const CONTROL: u16 = 0;
    pub const EVENT: u16 = 1;
    /// Playback: the driver writes samples here.
    pub const TX: u16 = 2;
    /// Capture: the device writes samples here. This is the microphone.
    pub const RX: u16 = 3;
}

/// virtio-sound control request codes (virtio 1.2 §5.14.6).
mod snd_code {
    /// Enumerate PCM streams. The reply says how many there are, which way each
    /// one points, and what formats and rates it accepts.
    pub const PCM_INFO: u32 = 0x0100;
    /// The device's answer when it accepted the request.
    pub const STATUS_OK: u32 = 0x8000;
}

/// Stream directions (virtio 1.2 §5.14.6.6).
mod snd_direction {
    /// Playback — a speaker or a line out.
    pub const OUTPUT: u8 = 0;
    /// Capture — a microphone or a line in.
    pub const INPUT: u8 = 1;
}

/// Offsets in `virtio_snd_config`, the sound card's device-specific structure.
mod snd_config {
    pub const JACKS: u64 = 0;
    pub const STREAMS: u64 = 4;
    pub const CHMAPS: u64 = 8;
}

/// Bytes in one `virtio_snd_pcm_info` (virtio 1.2 §5.14.6.6.3).
const PCM_INFO_BYTES: u32 = 32;
/// Offset of the `direction` byte within one.
const PCM_INFO_DIRECTION: u64 = 24;
/// Streams this driver will enumerate. More than any device here reports, so
/// the count comes from the device rather than from this number.
const MAX_STREAMS: u32 = 8;

/// Brings the sound card up and asks it what it can do.
///
/// # Why this is short
///
/// Everything expensive was already built for the disk. PCI enumeration found
/// the card, the kernel parsed the same four virtio capabilities, the same
/// status handshake applies, and `setup_queue` builds the same split virtqueue.
/// The device class is completely different and the transport is identical —
/// which is the claim the microkernel arrangement rests on, tested here rather
/// than asserted.
///
/// What this establishes is what hardware is present: how many jacks, how many
/// PCM streams, and which of those are outputs and which are inputs. The input
/// count is the microphone.
fn probe_sound(pid: u64, grant: u64) {
    let mut info = DeviceInfo::EMPTY;
    let size = core::mem::size_of::<DeviceInfo>() as u64;

    match call5(
        SYS_DEVICE_INFO,
        grant,
        SOUND_DEVICE,
        (&raw mut info) as u64,
        size,
        0,
    ) {
        Ok(_) => {}
        Err(SyscallError::NotPermitted) => {
            say(pid, &[b"no sound grant, as expected"]);
            return;
        }
        Err(error) => {
            say(pid, &[b"sound info failed: ", error.name().as_bytes()]);
            exit(40);
        }
    }

    if info.kind != DeviceKind::Sound as u32 {
        say(pid, &[b"the sound device is not a sound card"]);
        exit(41);
    }

    let window = match call(SYS_MAP_DEVICE, grant, SOUND_DEVICE) {
        Ok(base) => base,
        Err(error) => {
            say(pid, &[b"sound map failed: ", error.name().as_bytes()]);
            exit(42);
        }
    };

    let common = window + u64::from(info.common_offset);
    let config = window + u64::from(info.config_offset);

    if !virtio_handshake(pid, common, 43) {
        return;
    }

    // SAFETY: `config` is inside the device window this process was given.
    let (jacks, streams, chmaps) = unsafe {
        (
            mmio_read32(config + snd_config::JACKS),
            mmio_read32(config + snd_config::STREAMS),
            mmio_read32(config + snd_config::CHMAPS),
        )
    };

    if streams == 0 {
        say(pid, &[b"sound card reports no pcm streams"]);
        exit(44);
    }

    let mut buffer = [0u8; 18];
    say(
        pid,
        &[
            b"sound card: ",
            hex(u64::from(jacks), &mut buffer),
            b" jacks",
        ],
    );
    let mut buffer = [0u8; 18];
    say(
        pid,
        &[
            b"sound card: ",
            hex(u64::from(streams), &mut buffer),
            b" pcm streams, ",
            hex(u64::from(chmaps), &mut [0u8; 18]),
            b" channel maps",
        ],
    );

    let Some(mut queue) = setup_queue(
        pid,
        common,
        window + u64::from(info.notify_offset),
        &info,
        snd_queue::CONTROL,
        45,
    ) else {
        return;
    };

    // SAFETY: the control queue exists, so the device may be told the driver is
    // ready — which is what permits it to look at the rings.
    unsafe {
        mmio_write8(
            common + u64::from(common::DEVICE_STATUS),
            status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK | status::DRIVER_OK,
        );
    }

    enumerate_streams(pid, &mut queue, streams.min(MAX_STREAMS));
}

/// Asks the card about each PCM stream and reports which way they point.
///
/// The counts are the answer to "is there sound, and is there a microphone":
/// an output stream is a speaker, an input stream is a capture device. They are
/// read from the card rather than assumed, which matters because the same
/// driver has to work against a card configured with only one of them.
fn enumerate_streams(pid: u64, queue: &mut Queue, streams: u32) {
    let mut region = DmaRegion::EMPTY;
    let size = core::mem::size_of::<DmaRegion>() as u64;
    if let Err(error) = call5(
        SYS_ALLOC_DMA,
        REQUEST_BYTES,
        (&raw mut region) as u64,
        size,
        0,
        0,
    ) {
        say(
            pid,
            &[b"sound request memory refused: ", error.name().as_bytes()],
        );
        exit(46);
    }

    // `virtio_snd_query_info`: the code, the first stream wanted, how many, and
    // how large each returned record is. The size is sent by the driver so a
    // device with a longer record than this build knows about truncates rather
    // than overruns.
    let request = region.virt + HEADER_OFFSET;
    // SAFETY: the DMA buffer is this process's own, mapped writable.
    unsafe {
        (request as *mut u32).write_volatile(snd_code::PCM_INFO);
        ((request + 4) as *mut u32).write_volatile(0);
        ((request + 8) as *mut u32).write_volatile(streams);
        ((request + 12) as *mut u32).write_volatile(PCM_INFO_BYTES);
    }

    // The reply is a status word followed by one record per stream.
    let reply_bytes = 4 + streams * PCM_INFO_BYTES;
    if u64::from(reply_bytes) > REQUEST_BYTES - DATA_OFFSET {
        say(pid, &[b"sound reply would not fit the request buffer"]);
        exit(47);
    }

    if !control_request(pid, queue, &region, 16, reply_bytes) {
        say(pid, &[b"SOUND CONTROL REQUEST FAILED"]);
        exit(48);
    }

    let reply = region.virt + DATA_OFFSET;
    // SAFETY: the device just wrote this range, which is inside the buffer.
    let status = unsafe { (reply as *const u32).read_volatile() };
    if status != snd_code::STATUS_OK {
        let mut buffer = [0u8; 18];
        say(
            pid,
            &[
                b"sound card refused the query: ",
                hex(u64::from(status), &mut buffer),
            ],
        );
        exit(49);
    }

    let mut outputs = 0u64;
    let mut inputs = 0u64;
    for index in 0..u64::from(streams) {
        let record = reply + 4 + index * u64::from(PCM_INFO_BYTES);
        // SAFETY: `record` is inside the reply the device just wrote, whose
        // length was checked against the buffer above.
        let direction = unsafe { ((record + PCM_INFO_DIRECTION) as *const u8).read_volatile() };
        match direction {
            snd_direction::OUTPUT => outputs += 1,
            snd_direction::INPUT => inputs += 1,
            _ => {}
        }
    }

    let mut out_buffer = [0u8; 18];
    let mut in_buffer = [0u8; 18];
    say(
        pid,
        &[
            b"audio ready: ",
            hex(outputs, &mut out_buffer),
            b" playback, ",
            hex(inputs, &mut in_buffer),
            b" capture (microphone)",
        ],
    );

    if outputs == 0 {
        say(pid, &[b"NO PLAYBACK STREAM"]);
        exit(50);
    }
    if inputs == 0 {
        say(pid, &[b"NO CAPTURE STREAM"]);
        exit(51);
    }
}

/// Sends a control request and waits for the reply.
///
/// Two descriptors rather than the block driver's three: a device-readable
/// request and a device-writable reply. virtio-blk needs a third because its
/// status byte is separate from its data; a sound control reply carries its own
/// status as its first word.
fn control_request(
    pid: u64,
    queue: &mut Queue,
    region: &DmaRegion,
    request_bytes: u32,
    reply_bytes: u32,
) -> bool {
    use core::sync::atomic::{fence, Ordering};

    // SAFETY: every address is inside this process's own DMA buffer or the
    // device window it was granted.
    unsafe {
        // Poison the reply, so a device that writes nothing is distinguishable
        // from one that answers OK.
        ((region.virt + DATA_OFFSET) as *mut u32).write_volatile(0);

        write_descriptor(
            queue.desc,
            0,
            region.bus + HEADER_OFFSET,
            request_bytes,
            desc_flag::NEXT,
            1,
        );
        write_descriptor(
            queue.desc,
            1,
            region.bus + DATA_OFFSET,
            reply_bytes,
            desc_flag::WRITE,
            0,
        );

        let slot = queue.next_avail % queue.size;
        ((queue.avail + 4 + u64::from(slot) * 2) as *mut u16).write_volatile(0);
        fence(Ordering::Release);
        ((queue.avail + 2) as *mut u16).write_volatile(queue.next_avail.wrapping_add(1));
        fence(Ordering::Release);

        mmio_write16(queue.notify, snd_queue::CONTROL);

        let mut spins = 0u64;
        loop {
            fence(Ordering::Acquire);
            if ((queue.used + 2) as *const u16).read_volatile() != queue.last_used {
                break;
            }
            spins += 1;
            if spins > COMPLETION_SPINS {
                say(pid, &[b"sound card never answered"]);
                return false;
            }
            core::hint::spin_loop();
        }

        queue.next_avail = queue.next_avail.wrapping_add(1);
        queue.last_used = ((queue.used + 2) as *const u16).read_volatile();
    }
    true
}

/// Resets a virtio device and walks it through the status handshake.
///
/// Shared by both drivers because it is entirely generic: nothing here knows
/// whether it is talking to a disk or a sound card. `failure_base` is where this
/// device's exit codes start, so a failure names which device it was.
fn virtio_handshake(pid: u64, common: u64, failure_base: u64) -> bool {
    // SAFETY: `common` is inside a device window this process was given.
    unsafe {
        mmio_write8(common + u64::from(common::DEVICE_STATUS), 0);
        if mmio_read8(common + u64::from(common::DEVICE_STATUS)) != 0 {
            say(pid, &[b"device did not accept a reset"]);
            exit(failure_base);
        }

        mmio_write8(
            common + u64::from(common::DEVICE_STATUS),
            status::ACKNOWLEDGE,
        );
        mmio_write8(
            common + u64::from(common::DEVICE_STATUS),
            status::ACKNOWLEDGE | status::DRIVER,
        );

        mmio_write32(common + u64::from(common::DRIVER_FEATURE_SELECT), 0);
        mmio_write32(common + u64::from(common::DRIVER_FEATURE), 0);
        mmio_write32(
            common + u64::from(common::DRIVER_FEATURE_SELECT),
            FEATURE_VERSION_1_WORD,
        );
        mmio_write32(
            common + u64::from(common::DRIVER_FEATURE),
            FEATURE_VERSION_1_BIT,
        );

        mmio_write8(
            common + u64::from(common::DEVICE_STATUS),
            status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK,
        );
        if mmio_read8(common + u64::from(common::DEVICE_STATUS)) & status::FEATURES_OK == 0 {
            say(pid, &[b"device rejected the negotiated features"]);
            exit(failure_base + 1);
        }
    }
    true
}

/// Builds one queue and hands its three ring addresses to the device.
///
/// Returns `None` after reporting, for the failures that are worth continuing
/// past — there is nothing else in this process that depends on the disk.
fn setup_queue(
    pid: u64,
    common: u64,
    notify_base: u64,
    info: &DeviceInfo,
    queue_index: u16,
    failure_base: u64,
) -> Option<Queue> {
    let mut region = DmaRegion::EMPTY;
    let size = core::mem::size_of::<DmaRegion>() as u64;
    if let Err(error) = call5(
        SYS_ALLOC_DMA,
        QUEUE_BYTES,
        (&raw mut region) as u64,
        size,
        0,
        0,
    ) {
        say(pid, &[b"queue memory refused: ", error.name().as_bytes()]);
        exit(failure_base);
    }

    // SAFETY: `common` is inside the device window this process was given.
    let (queue_size, notify_off) = unsafe {
        mmio_write16(common + u64::from(common::QUEUE_SELECT), queue_index);
        (
            mmio_read16(common + u64::from(common::QUEUE_SIZE)),
            mmio_read16(common + u64::from(common::QUEUE_NOTIFY_OFF)),
        )
    };

    if queue_size == 0 {
        say(pid, &[b"queue does not exist on this device"]);
        exit(failure_base + 1);
    }
    // Three descriptors per request is the smallest chain virtio-blk allows, so
    // a queue shorter than that cannot carry even one.
    if queue_size < DESCRIPTORS_PER_REQUEST {
        say(pid, &[b"queue is too short to hold one request"]);
        exit(failure_base + 2);
    }
    // The rings are sized by the queue, and the buffer is fixed. A device
    // offering a larger queue than the buffer can describe must be told a
    // smaller size rather than have its offer quietly overrun the allocation.
    let usable = if u64::from(queue_size) * 16 > AVAIL_OFFSET {
        (AVAIL_OFFSET / 16) as u16
    } else {
        queue_size
    };

    let queue = Queue {
        desc: region.virt + DESC_OFFSET,
        avail: region.virt + AVAIL_OFFSET,
        used: region.virt + USED_OFFSET,
        desc_bus: region.bus + DESC_OFFSET,
        avail_bus: region.bus + AVAIL_OFFSET,
        used_bus: region.bus + USED_OFFSET,
        size: usable,
        notify: notify_base + u64::from(notify_off) * u64::from(info.notify_multiplier),
        next_avail: 0,
        last_used: 0,
    };

    // SAFETY: every address below is either inside the device window or the DMA
    // buffer the kernel just gave this process.
    unsafe {
        mmio_write16(common + u64::from(common::QUEUE_SIZE), queue.size);
        mmio_write16(
            common + u64::from(common::QUEUE_MSIX_VECTOR),
            NO_MSIX_VECTOR,
        );
        mmio_write64_split(common + u64::from(common::QUEUE_DESC), queue.desc_bus);
        mmio_write64_split(common + u64::from(common::QUEUE_DRIVER), queue.avail_bus);
        mmio_write64_split(common + u64::from(common::QUEUE_DEVICE), queue.used_bus);
        mmio_write16(common + u64::from(common::QUEUE_ENABLE), 1);
    }

    let mut buffer = [0u8; 18];
    say(
        pid,
        &[
            b"queue armed, ",
            hex(u64::from(queue.size), &mut buffer),
            b" descriptors",
        ],
    );
    Some(queue)
}

/// Writes a pattern to a sector, reads it back, and checks it survived.
///
/// # Why write then read rather than just read
///
/// The disk the build attaches is a fresh sparse file, so every sector reads as
/// zeros. A read alone would prove the request completed and the buffer was
/// filled with — zeros, which is also what the buffer already held. Writing a
/// pattern first makes the comparison mean something: the bytes came back
/// because they went out, through the device, and not because nothing happened.
fn exercise_disk(pid: u64, queue: &mut Queue) {
    let mut region = DmaRegion::EMPTY;
    let size = core::mem::size_of::<DmaRegion>() as u64;
    if let Err(error) = call5(
        SYS_ALLOC_DMA,
        REQUEST_BYTES,
        (&raw mut region) as u64,
        size,
        0,
        0,
    ) {
        say(pid, &[b"request memory refused: ", error.name().as_bytes()]);
        exit(33);
    }

    let data = region.virt + DATA_OFFSET;

    // A pattern that is not zeros and not constant, so a partial transfer or an
    // off-by-one in the descriptor lengths shows up as a mismatch rather than
    // as a coincidence.
    // SAFETY: the DMA buffer is this process's, mapped writable.
    unsafe {
        for index in 0..SECTOR_BYTES {
            let byte = (index as u8) ^ 0x5A;
            ((data + index) as *mut u8).write_volatile(byte);
        }
    }

    if !submit(pid, queue, &region, blk::OUT, 0) {
        say(pid, &[b"DISK WRITE FAILED"]);
        exit(34);
    }

    // Scribble over the buffer before reading, so bytes that come back are
    // bytes the device put there rather than the ones still sitting in memory
    // from the write.
    // SAFETY: as above.
    unsafe {
        for index in 0..SECTOR_BYTES {
            ((data + index) as *mut u8).write_volatile(0xEE);
        }
    }

    if !submit(pid, queue, &region, blk::IN, 0) {
        say(pid, &[b"DISK READ FAILED"]);
        exit(35);
    }

    // SAFETY: as above.
    let mismatch = unsafe {
        (0..SECTOR_BYTES)
            .find(|index| ((data + index) as *const u8).read_volatile() != (*index as u8) ^ 0x5A)
    };
    if let Some(index) = mismatch {
        let mut buffer = [0u8; 18];
        say(
            pid,
            &[b"disk returned wrong bytes at ", hex(index, &mut buffer)],
        );
        exit(36);
    }

    say(pid, &[b"disk wrote and read back 512 bytes, verified"]);
}

/// Submits one block request and waits for the device to finish it.
///
/// Named `submit` rather than `request` because this file already has a
/// `request` — the IPC client role. Two things called the same thing in one
/// process is how the wrong one gets called.
///
/// Returns whether the device reported success.
///
/// # The three descriptors
///
/// virtio-blk wants a chain: a header the device reads, a data buffer, and a
/// status byte the device writes. Whether the data buffer is device-readable or
/// device-writable is the entire difference between a write and a read, and
/// getting it backwards produces no complaint from anything — the device simply
/// does the other operation.
fn submit(pid: u64, queue: &mut Queue, region: &DmaRegion, kind: u32, sector: u64) -> bool {
    use core::sync::atomic::{fence, Ordering};

    let header = region.virt + HEADER_OFFSET;
    let status_byte = region.virt + STATUS_OFFSET;

    // SAFETY: every address is inside this process's own DMA buffer or the
    // device window it was granted.
    unsafe {
        // The request header: type, a reserved word, and the sector.
        (header as *mut u32).write_volatile(kind);
        ((header + 4) as *mut u32).write_volatile(0);
        ((header + 8) as *mut u64).write_volatile(sector);
        // Not a status the device uses, so a byte left unchanged is
        // distinguishable from a success it never wrote.
        (status_byte as *mut u8).write_volatile(0xFF);

        // Descriptor 0: the header. The device reads it.
        write_descriptor(
            queue.desc,
            0,
            region.bus + HEADER_OFFSET,
            16,
            desc_flag::NEXT,
            1,
        );
        // Descriptor 1: the data. Device-writable for a read, device-readable
        // for a write — this is the line that decides which operation happens.
        let data_flags = if kind == blk::IN {
            desc_flag::NEXT | desc_flag::WRITE
        } else {
            desc_flag::NEXT
        };
        write_descriptor(
            queue.desc,
            1,
            region.bus + DATA_OFFSET,
            SECTOR_BYTES as u32,
            data_flags,
            2,
        );
        // Descriptor 2: the status byte, which the device always writes.
        write_descriptor(
            queue.desc,
            2,
            region.bus + STATUS_OFFSET,
            1,
            desc_flag::WRITE,
            0,
        );

        // Publish the chain. The ring slot has to be visible before the index
        // that points at it, or the device can read an index that names a slot
        // still holding the previous request's head.
        let slot = queue.next_avail % queue.size;
        ((queue.avail + 4 + u64::from(slot) * 2) as *mut u16).write_volatile(0);
        fence(Ordering::Release);
        ((queue.avail + 2) as *mut u16).write_volatile(queue.next_avail.wrapping_add(1));
        fence(Ordering::Release);

        // The doorbell. Writing the queue index here is what tells the device
        // to look.
        mmio_write16(queue.notify, 0);

        // Wait for the used ring to advance. Polling rather than blocking on
        // the interrupt: the disk's line is not routed yet, and a driver that
        // waits on an interrupt nothing delivers waits forever. The bound is
        // what turns a device that never answers into a report.
        let mut spins = 0u64;
        loop {
            fence(Ordering::Acquire);
            let used_index = ((queue.used + 2) as *const u16).read_volatile();
            if used_index != queue.last_used {
                break;
            }
            spins += 1;
            if spins > COMPLETION_SPINS {
                say(pid, &[b"disk never completed the request"]);
                return false;
            }
            core::hint::spin_loop();
        }

        // Both indices advance only after the device has answered. Advancing
        // the available index earlier would be correct — the device has already
        // consumed it — but keeping the pair updated in one place is what makes
        // the next request's slot arithmetic obviously right.
        queue.next_avail = queue.next_avail.wrapping_add(1);
        queue.last_used = ((queue.used + 2) as *const u16).read_volatile();

        let reported = (status_byte as *const u8).read_volatile();
        reported == blk::STATUS_OK
    }
}

/// Fills in one descriptor.
///
/// # Safety
/// `table` must be the descriptor table of a live queue, and `index` inside it.
unsafe fn write_descriptor(
    table: u64,
    index: u16,
    address: u64,
    length: u32,
    flags: u16,
    next: u16,
) {
    let entry = table + u64::from(index) * 16;
    // SAFETY: the caller guarantees the table and index. The layout is virtio
    // 1.0 §2.6.5: address, length, flags, next.
    unsafe {
        (entry as *mut u64).write_volatile(address);
        ((entry + 8) as *mut u32).write_volatile(length);
        ((entry + 12) as *mut u16).write_volatile(flags);
        ((entry + 14) as *mut u16).write_volatile(next);
    }
}

/// Interrupts to wait for before moving on.
///
/// Three, not one. One proves an interrupt arrived; three prove the path works
/// repeatedly — that the device was acknowledged, that the line was not left
/// masked, and that the process can go back to sleep and be woken again. A
/// delivery path that fires once and stops is a common enough bug to be worth
/// spending two more wakes on.
const INTERRUPTS_TO_AWAIT: u64 = 3;

/// The CMOS index and data ports, which is the whole of the RTC's interface.
const CMOS_INDEX: u16 = 0x70;
const CMOS_DATA: u16 = 0x71;
/// Register C. Reading it is what permits the device's next interrupt.
const CMOS_REG_C: u8 = 0x0C;
/// Bit 7 of the index port suppresses NMI for the duration of the access.
const CMOS_NMI_DISABLE: u8 = 0x80;

/// Reads one CMOS register, from ring 3.
///
/// This is the point of the whole exercise. Two instructions the CPU would
/// refuse — `#GP` on `out`, before the port is even decoded — unless the I/O
/// permission bitmap in the TSS has these two bits clear, which it does only
/// because the kernel was asked for this device and agreed.
///
/// # Safety
/// The process must hold a port grant covering `CMOS_INDEX` and `CMOS_DATA`.
/// Without it these instructions fault, which is the mechanism working.
unsafe fn cmos_read(register: u8) -> u8 {
    let value: u8;
    // SAFETY: the caller guarantees the grant. `nomem` is not used: the ports
    // have side effects the compiler must not assume away, and the index write
    // must not be reordered past the data read.
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") CMOS_INDEX,
            in("al") register | CMOS_NMI_DISABLE,
            options(nostack, preserves_flags),
        );
        core::arch::asm!(
            "in al, dx",
            in("dx") CMOS_DATA,
            out("al") value,
            options(nostack, preserves_flags),
        );
    }
    value
}

/// Blocks until the granted device interrupts, three times over.
///
/// This is the first time a process outside the kernel is woken by hardware,
/// and — since the port grant — the first time one services the device that
/// woke it. The kernel no longer reads register C on anybody's behalf, so the
/// acknowledgement below is not a formality: without it the RTC considers its
/// interrupt outstanding and raises no second one, and this loop would block
/// forever on the next call.
fn await_interrupts(pid: u64, grant: u64) {
    let mut seen = 0u64;

    // The ports first. A driver that waits before it can service the device
    // gets one interrupt and then waits forever.
    match call(SYS_GRANT_PORTS, grant, TICKER_DEVICE) {
        Ok(count) if count >= 2 => {}
        Ok(_) => {
            say(pid, &[b"port grant was too small to drive the device"]);
            exit(18);
        }
        Err(SyscallError::NotPermitted) => {
            // The expected answer for every process that is not the driver.
            say(pid, &[b"no interrupt grant, as expected"]);
            return;
        }
        Err(error) => {
            say(pid, &[b"port grant failed: ", error.name().as_bytes()]);
            exit(19);
        }
    }
    say(pid, &[b"granted the rtc's ports, driving it from ring 3"]);

    for _ in 0..INTERRUPTS_TO_AWAIT {
        match call(SYS_IRQ_WAIT, grant, TICKER_DEVICE) {
            Ok(count) => {
                if count == 0 {
                    // The call blocks until there is something to report, so a
                    // count of zero would mean it returned without one.
                    say(pid, &[b"WOKEN WITH NO INTERRUPT TO SHOW FOR IT"]);
                    exit(16);
                }
                seen += count;

                // Service the device. Nothing in the kernel does this now, so
                // the next interrupt exists only because of this read.
                // SAFETY: the port grant above succeeded, which is exactly the
                // condition these instructions need.
                unsafe {
                    cmos_read(CMOS_REG_C);
                }
            }
            Err(error) => {
                say(pid, &[b"irq wait failed: ", error.name().as_bytes()]);
                exit(17);
            }
        }
    }

    let digit = [b'0' + (seen % 10) as u8];
    say(pid, &[b"woken by hardware ", &digit, b" time(s)"]);
}

/// Bytes to ask for. Not a round number of pages, deliberately: the reply has
/// to be the rounded-up mapping rather than the request, and a request that was
/// already page-aligned would not tell the two apart.
const DMA_REQUEST_BYTES: u64 = 5000;

/// Asks for a DMA buffer and proves it is real memory this process owns.
///
/// Three things are checked, and each one fails differently if the kernel got
/// it wrong. The mapping must cover what was asked for — a kernel that returned
/// the request unrounded would hand back a buffer whose last bytes are not
/// mapped. It must arrive zeroed, because a buffer still holding a previous
/// owner's bytes is a disclosure. And it must survive a write and a read back,
/// which is the part a mapping with the wrong permissions or the wrong physical
/// frames cannot fake.
fn take_dma_buffer(pid: u64) {
    let mut region = DmaRegion::EMPTY;
    let size = core::mem::size_of::<DmaRegion>() as u64;

    match call5(
        SYS_ALLOC_DMA,
        DMA_REQUEST_BYTES,
        (&raw mut region) as u64,
        size,
        0,
        0,
    ) {
        Ok(_) => {}
        Err(error) => {
            say(pid, &[b"dma refused: ", error.name().as_bytes()]);
            exit(11);
        }
    }

    if region.length < DMA_REQUEST_BYTES {
        say(pid, &[b"dma buffer is smaller than requested"]);
        exit(12);
    }
    // A bus address of zero would mean the kernel mapped page zero, and an
    // unaligned one would mean it handed over something that is not a frame.
    if region.bus == 0 || !region.bus.is_multiple_of(4096) {
        say(pid, &[b"dma bus address is not a frame"]);
        exit(13);
    }

    let buffer = region.virt as *mut u8;
    // Both ends, because a mapping that is short is a mapping whose last page
    // faults — and the fault would be at the end, not the beginning.
    let probes = [0usize, (region.length - 1) as usize];

    for &offset in &probes {
        // SAFETY: the kernel reported this range as mapped and writable for
        // this process, and `offset` is inside `region.length`.
        if unsafe { buffer.add(offset).read_volatile() } != 0 {
            say(pid, &[b"dma buffer arrived with somebody else's bytes"]);
            exit(14);
        }
    }

    for (index, &offset) in probes.iter().enumerate() {
        let value = 0xA5u8 ^ index as u8;
        // SAFETY: as above; the range was just read successfully.
        unsafe {
            buffer.add(offset).write_volatile(value);
            if buffer.add(offset).read_volatile() != value {
                say(pid, &[b"dma buffer did not keep what was written"]);
                exit(15);
            }
        }
    }

    say(pid, &[b"dma buffer verified, zeroed and writable"]);
}

/// Maps the framebuffer and draws on it, from ring 3.
///
/// This is the first time anything outside the kernel touches hardware. The
/// process never names a physical address: it asks for device zero, and the
/// kernel — which is the only thing that knows where device zero is — maps it.
fn drive_display(pid: u64, grant: u64) {
    let mut info = DeviceInfo::EMPTY;
    let size = core::mem::size_of::<DeviceInfo>() as u64;

    match call5(SYS_DEVICE_INFO, grant, 0, (&raw mut info) as u64, size, 0) {
        Ok(_) => {}
        Err(SyscallError::NotPermitted) => {
            // The expected answer for every process that is not the driver.
            say(pid, &[b"no device grant, as expected"]);
            return;
        }
        Err(error) => {
            say(pid, &[b"device info failed: ", error.name().as_bytes()]);
            exit(9);
        }
    }

    if info.kind != DeviceKind::Framebuffer as u32 || info.bytes_per_pixel != 4 {
        say(pid, &[b"device 0 is not a framebuffer this driver knows"]);
        return;
    }

    let base = match call5(SYS_MAP_DEVICE, grant, 0, 0, 0, 0) {
        Ok(base) => base,
        Err(error) => {
            say(pid, &[b"map failed: ", error.name().as_bytes()]);
            exit(10);
        }
    };

    let mut digits = [0u8; 18];
    say(
        pid,
        &[
            b"framebuffer mapped from ring 3 at ",
            hex(base, &mut digits),
        ],
    );

    draw_banner(base, &info);
    say(
        pid,
        &[b"drew to the framebuffer without entering the kernel"],
    );
}

/// Paints a band across the bottom of the screen.
///
/// Deliberately somewhere the kernel's own console does not write, so what
/// appears is unambiguously the work of a user-space process rather than a
/// kernel line that happened to scroll past.
fn draw_banner(base: u64, info: &DeviceInfo) {
    let height = info.height as usize;
    let width = info.width as usize;
    let stride = info.stride as usize;
    let band_height = 96usize;
    if height < band_height + 8 || width == 0 {
        return;
    }
    let top = height - band_height;

    for y in 0..band_height {
        // A vertical gradient, so a band that is drawn but wrong is still
        // obviously drawn.
        let level = (y * 255 / band_height) as u32;
        let colour = (level / 5) << 16 | (level / 2) << 8 | (0x40 + level / 2);
        for x in 0..width {
            // SAFETY: the mapping covers `stride * height` pixels and both
            // indices are inside it. The kernel mapped this range for this
            // process; nothing else in the address space overlaps it.
            unsafe {
                let pixel = (base as *mut u32).add((top + y) * stride + x);
                pixel.write_volatile(colour);
            }
        }
    }

    let text = b"USER SPACE DREW THIS";
    draw_text(base, stride, 24, top + 36, text, 0x00FF_FFFF);
}

/// The same 5x7 shapes the kernel console uses, at three times the size.
///
/// A copy of the outline rather than the table: a user-space process has no
/// business including a kernel module, and this draws twenty characters once.
fn draw_text(base: u64, stride: usize, x0: usize, y0: usize, text: &[u8], colour: u32) {
    const SCALE: usize = 3;
    for (index, &byte) in text.iter().enumerate() {
        let rows = kernel_glyph(byte);
        for (row, bits) in rows.iter().copied().enumerate() {
            for column in 0..5usize {
                if bits & (1 << (4 - column)) == 0 {
                    continue;
                }
                for sy in 0..SCALE {
                    for sx in 0..SCALE {
                        let x = x0 + index * 6 * SCALE + column * SCALE + sx;
                        let y = y0 + row * SCALE + sy;
                        // SAFETY: inside the mapped framebuffer; the caller
                        // bounded `y0` against the band it just filled.
                        unsafe {
                            (base as *mut u32)
                                .add(y * stride + x)
                                .write_volatile(colour);
                        }
                    }
                }
            }
        }
    }
}

/// Just the letters this banner needs.
const fn kernel_glyph(c: u8) -> [u8; 7] {
    match c {
        b'A' => [0x0e, 0x11, 0x11, 0x1f, 0x11, 0x11, 0x11],
        b'C' => [0x0f, 0x10, 0x10, 0x10, 0x10, 0x10, 0x0f],
        b'D' => [0x1e, 0x11, 0x11, 0x11, 0x11, 0x11, 0x1e],
        b'E' => [0x1f, 0x10, 0x10, 0x1e, 0x10, 0x10, 0x1f],
        b'H' => [0x11, 0x11, 0x11, 0x1f, 0x11, 0x11, 0x11],
        b'I' => [0x1f, 0x04, 0x04, 0x04, 0x04, 0x04, 0x1f],
        b'P' => [0x1e, 0x11, 0x11, 0x1e, 0x10, 0x10, 0x10],
        b'R' => [0x1e, 0x11, 0x11, 0x1e, 0x14, 0x12, 0x11],
        b'S' => [0x0f, 0x10, 0x10, 0x0e, 0x01, 0x01, 0x1e],
        b'T' => [0x1f, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04],
        b'U' => [0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0e],
        b'W' => [0x11, 0x11, 0x11, 0x15, 0x15, 0x15, 0x0a],
        b' ' => [0; 7],
        _ => [0x1f, 0x11, 0x02, 0x04, 0x08, 0x00, 0x08],
    }
}

/// Requests the server answers. Chosen so the reply is a transformation the
/// client can check rather than an echo, which a kernel that lost the message
/// could also produce.
const REQUEST: &[u8] = b"WHISEZ-PING";
const EXPECTED_REPLY: &[u8] = b"WHISEZ-PONG";

/// Answers one request per client, then stops.
fn serve(pid: u64, endpoint: u64) -> ! {
    let mut buffer = [0u8; 64];

    for _ in 0..CLIENTS {
        let len = match call5(
            SYS_RECEIVE,
            endpoint,
            buffer.as_mut_ptr() as u64,
            buffer.len() as u64,
            0,
            0,
        ) {
            Ok(len) => len as usize,
            Err(error) => {
                say(pid, &[b"receive failed: ", error.name().as_bytes()]);
                exit(4);
            }
        };

        say(pid, &[b"served request: ", &buffer[..len]]);

        // The transformation the client checks for. A server that replied with
        // the request unchanged would be indistinguishable from a kernel that
        // handed the buffer straight back.
        let mut answer = [0u8; 64];
        answer[..len].copy_from_slice(&buffer[..len]);
        if len == REQUEST.len() {
            answer[..len].copy_from_slice(EXPECTED_REPLY);
        }

        if let Err(error) = call5(
            SYS_REPLY,
            endpoint,
            answer.as_ptr() as u64,
            len as u64,
            0,
            0,
        ) {
            say(pid, &[b"reply failed: ", error.name().as_bytes()]);
            exit(5);
        }
    }

    say(pid, &[b"served every client"]);
    say(pid, &[b"all checks passed"]);
    exit(0)
}

/// Sends one request and checks the answer.
fn request(pid: u64, endpoint: u64) {
    let mut reply = [0u8; 64];

    let len = match call5(
        SYS_CALL,
        endpoint,
        REQUEST.as_ptr() as u64,
        REQUEST.len() as u64,
        reply.as_mut_ptr() as u64,
        reply.len() as u64,
    ) {
        Ok(len) => len as usize,
        Err(error) => {
            say(pid, &[b"call failed: ", error.name().as_bytes()]);
            exit(6);
        }
    };

    if &reply[..len] == EXPECTED_REPLY {
        say(
            pid,
            &[b"ipc round trip ok, server answered ", &reply[..len]],
        );
    } else {
        say(pid, &[b"IPC REPLY WRONG"]);
        exit(7);
    }

    // An endpoint this process does not own must refuse to be received from,
    // however it was obtained.
    match call5(SYS_RECEIVE, endpoint, reply.as_mut_ptr() as u64, 8, 0, 0) {
        Err(SyscallError::BadEndpoint) => {
            say(
                pid,
                &[b"refused as expected: receiving on an endpoint it does not own"],
            );
        }
        _ => {
            say(
                pid,
                &[b"SECURITY CHECK FAILED: received on another endpoint"],
            );
            exit(8);
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    log("[init] panic\n");
    exit(3)
}
