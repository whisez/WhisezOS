//! Silencing the legacy 8259 interrupt controllers.
//!
//! # Why this has to happen before the first `sti`
//!
//! Two 8259s exist on every PC-compatible machine, QEMU included, and the
//! firmware leaves them live with their default vector bases: master at 8,
//! slave at 0x70. Vector 8 is `#DF`. Vector 13 is `#GP`. So an IRQ0 timer tick
//! arriving with interrupts enabled is delivered to the double-fault handler,
//! on the double-fault IST stack, with a garbage error code — and the handler
//! reports a double fault that never happened while the real cause is a clock.
//!
//! Masking alone would be enough while nothing uses the PICs, but masking does
//! not stop a spurious IRQ7 or IRQ15, which the 8259 raises on its own when a
//! line glitches. So they are remapped out of the exception range *and* masked:
//! remapped so anything that does arrive lands somewhere harmless, masked so
//! nothing routine arrives at all.
//!
//! The LAPIC is the interrupt controller from here on. These two are being put
//! beyond the point where they can cause trouble, not configured for use.

use super::cpu::{inb, outb};
use super::idt::vector;

const PIC1_COMMAND: u16 = 0x20;
const PIC1_DATA: u16 = 0x21;
const PIC2_COMMAND: u16 = 0xA0;
const PIC2_DATA: u16 = 0xA1;

/// ICW1: begin initialisation, expect ICW4.
const ICW1_INIT: u8 = 0x11;
/// ICW4: 8086/88 mode.
const ICW4_8086: u8 = 0x01;

/// Where the remapped PIC vectors land.
///
/// Above every exception vector and above the LAPIC's own vectors, in a range
/// nothing else claims. If one ever fires, `unexpected_device` reports it
/// instead of a fault handler misreading it.
pub const PIC1_VECTOR_BASE: u8 = vector::FIRST_DEVICE + 0x20;
pub const PIC2_VECTOR_BASE: u8 = PIC1_VECTOR_BASE + 8;

/// Remaps both controllers out of the exception range and masks every line.
///
/// # Safety
/// Called once during bring-up, with interrupts disabled.
pub unsafe fn disable() {
    // SAFETY: the 8259 register ports, written in the order the device's
    // initialisation sequence requires. Each write is acknowledged by the next
    // being accepted; there is no status register to poll.
    unsafe {
        // ICW1: start the sequence on both.
        outb(PIC1_COMMAND, ICW1_INIT);
        io_wait();
        outb(PIC2_COMMAND, ICW1_INIT);
        io_wait();

        // ICW2: the new vector bases.
        outb(PIC1_DATA, PIC1_VECTOR_BASE);
        io_wait();
        outb(PIC2_DATA, PIC2_VECTOR_BASE);
        io_wait();

        // ICW3: how the two are wired to each other. The slave hangs off the
        // master's IRQ2 line, which is why IRQ2 is never a real device.
        outb(PIC1_DATA, 1 << 2);
        io_wait();
        outb(PIC2_DATA, 2);
        io_wait();

        // ICW4: 8086 mode rather than the MCS-80 mode the chip powers up in.
        outb(PIC1_DATA, ICW4_8086);
        io_wait();
        outb(PIC2_DATA, ICW4_8086);
        io_wait();

        // Mask every line on both.
        outb(PIC1_DATA, 0xFF);
        outb(PIC2_DATA, 0xFF);
    }
}

/// A short delay between 8259 writes.
///
/// The chip is slower than the bus and can drop a byte written immediately
/// after the previous one. Port 0x80 is the POST diagnostic port: writing to it
/// has no effect on any machine made in decades and costs about a microsecond,
/// which is the conventional way to spend the time.
fn io_wait() {
    // SAFETY: port 0x80 is write-only diagnostics with no side effects.
    unsafe { outb(0x80, 0) };
}

/// Reads the in-service register of both controllers.
///
/// Used only to distinguish a genuine IRQ7 or IRQ15 from a spurious one, which
/// the 8259 does not otherwise signal.
#[must_use]
pub fn in_service() -> u16 {
    // SAFETY: OCW3 selects the ISR for the next read of the command port.
    unsafe {
        outb(PIC1_COMMAND, 0x0B);
        outb(PIC2_COMMAND, 0x0B);
        u16::from(inb(PIC1_COMMAND)) | (u16::from(inb(PIC2_COMMAND)) << 8)
    }
}
