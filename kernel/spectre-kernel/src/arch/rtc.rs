//! The real-time clock's periodic interrupt — a device that interrupts.
//!
//! # Why this device
//!
//! Proving that a device interrupt reaches a user-space process needs a device
//! whose interrupt actually fires, unprompted, in a boot that nobody is sitting
//! in front of. That rules out the keyboard, which needs a keystroke, and the
//! disk, which needs a driver first. The RTC's periodic interrupt fires on its
//! own at a rate the kernel chooses, on every PC and in QEMU, which makes it the
//! one device that can demonstrate the path without something else existing
//! first.
//!
//! It is also on IRQ 8, and that is not incidental. Without an ACPI parser the
//! kernel cannot read the interrupt source overrides, and the most common
//! override on a PC moves ISA IRQ 0 — the PIT, the other candidate — onto I/O
//! APIC pin 2. Guessing wrong there produces a line that is routed and never
//! fires, which looks exactly like a broken delivery path. IRQ 8 is not
//! conventionally overridden, so pin 8 is the pin.
//!
//! # What is left here, and what left
//!
//! This file used to acknowledge the device: register C has to be read after
//! every interrupt or the RTC raises no further ones, and the interrupt handler
//! did it because ring 3 could not. `portauth.rs` is what removed that. The
//! driver holds ports 0x70 and 0x71 and reads register C itself, and the
//! kernel reads it for nobody — which is why three wakes in the boot log mean
//! something one wake would not: the second and third exist only because a
//! process outside the kernel serviced the device.
//!
//! What remains is arming: setting the rate in register A and the enable in
//! register B, once, when a process claims the line. That did not move with the
//! acknowledgement because it is not per-interrupt work — it happens inside
//! `unmask_device_line`, which also programs the I/O APIC, and splitting one
//! "start delivering" step across two privilege levels would reintroduce
//! exactly the ordering race that step exists to avoid. A driver that armed the
//! device before claiming the line would latch an interrupt against a masked
//! pin and never see another.
//!
//! So this file is a page shorter than it was and will get shorter again when
//! there is a way to arm a device and claim its line as one operation.

use super::cpu::{inb, outb};

/// Index port. Bit 7 disables NMI for the duration of the access.
const CMOS_INDEX: u16 = 0x70;
/// Data port.
const CMOS_DATA: u16 = 0x71;

/// Bit 7 of the index port. Set while configuring, cleared at the end.
///
/// An NMI arriving between the index write and the data access would leave the
/// index pointing somewhere the interrupted code did not choose, and NMI
/// handlers that touch the CMOS are exactly the ones that do this.
const NMI_DISABLE: u8 = 0x80;

/// Rate divider and base frequency.
const REG_A: u8 = 0x0A;
/// Interrupt enables.
const REG_B: u8 = 0x0B;
/// Interrupt flags. Reading it is what permits the next interrupt.
const REG_C: u8 = 0x0C;

/// Register B bit 6: periodic interrupt enable.
const REG_B_PERIODIC: u8 = 1 << 6;

/// Rate 10 of 15. The periodic rate is `32768 >> (rate - 1)`, so this is 64 Hz.
///
/// Fast enough that a boot test does not wait on it, slow enough that a process
/// woken by it gets to run between interrupts rather than being handed a
/// backlog immediately.
const RATE: u8 = 10;

/// The interrupt rate `RATE` selects, in hertz.
pub const HZ: u32 = 32768 >> (RATE - 1);

/// The ISA IRQ this device raises, which is also its I/O APIC pin.
pub const IRQ: u8 = 8;

/// Reads one CMOS register with NMI disabled.
///
/// # Safety
/// Interrupts must be off: the index and the data access are one operation, and
/// anything that runs between them and touches the CMOS corrupts both.
unsafe fn read(register: u8) -> u8 {
    // SAFETY: architectural CMOS ports, accessed in the required order.
    unsafe {
        outb(CMOS_INDEX, register | NMI_DISABLE);
        inb(CMOS_DATA)
    }
}

/// Writes one CMOS register with NMI disabled.
///
/// # Safety
/// As `read`.
unsafe fn write(register: u8, value: u8) {
    // SAFETY: as `read`.
    unsafe {
        outb(CMOS_INDEX, register | NMI_DISABLE);
        outb(CMOS_DATA, value);
    }
}

/// Restores NMI delivery, which every access above suppressed.
///
/// # Safety
/// Called after a run of CMOS accesses, with interrupts still off.
unsafe fn enable_nmi() {
    // SAFETY: writing an index without bit 7 re-enables NMI. Register D is
    // read-only status, so pointing at it leaves nothing armed.
    unsafe { outb(CMOS_INDEX, 0x0D) };
}

/// Starts the periodic interrupt.
///
/// Returns the rate it was set to.
///
/// # Safety
/// Called with interrupts disabled, from `unmask_device_line`, immediately
/// before the line is unmasked at the I/O APIC. That order is not incidental:
/// an interrupt from an armed device whose line is masked is discarded and its
/// flag latched, and the read of register C below is what clears the latch.
pub unsafe fn start_periodic() -> u32 {
    // SAFETY: interrupts are off, as required, and each pair below is one
    // uninterrupted index-then-data access.
    unsafe {
        // Rate first. The top nibble selects the 32.768 kHz base and must be
        // preserved, so this is a read-modify-write rather than a plain store —
        // writing the rate alone would also reprogram the time base.
        let a = read(REG_A);
        write(REG_A, (a & 0xF0) | RATE);

        let b = read(REG_B);
        write(REG_B, b | REG_B_PERIODIC);

        // Register C may already hold a flag from whatever the firmware did. An
        // unread flag means the device considers its interrupt outstanding and
        // raises no more, so the first real one would never arrive.
        let _ = read(REG_C);

        enable_nmi();
    }
    HZ
}

/// Stops the periodic interrupt.
///
/// # Safety
/// Interrupts must be off.
pub unsafe fn stop_periodic() {
    // SAFETY: as `start_periodic`.
    unsafe {
        let b = read(REG_B);
        write(REG_B, b & !REG_B_PERIODIC);
        enable_nmi();
    }
}
