//! Turning the machine off.
//!
//! Until this existed the only way to stop WhisezOS was the power button, which
//! is not a detail — a system that cannot be shut down is one that cannot be
//! used, and on real hardware it is how filesystems get corrupted.
//!
//! # Why this is the kernel's and not a driver's
//!
//! Every other device in this tree was pushed out to ring 3 on the argument
//! that a driver should hold one device and nothing else. Power is the
//! exception, and not for convenience: the register that turns the machine off
//! is at port 0x604, above the 1024-port window the I/O permission bitmap
//! covers, so `portauth` cannot grant it at all. That was a deliberate boundary
//! — everything above the window is denied by the segment limit rather than by
//! a bit — and shutting down the machine is exactly the kind of authority it
//! was drawn to keep.
//!
//! So this is a system call, checked against the same device grant everything
//! else is.
//!
//! # The address is a guess, and the guess is checked
//!
//! ACPI puts the power-management control register wherever the firmware's FADT
//! says, and there is no ACPI parser here yet. 0x604 is where QEMU's q35 puts
//! it and where every PIIX-derived chipset has put it for twenty years, so it
//! is the first thing tried; 0xB004 is the older Bochs address and is the
//! second.
//!
//! Neither is believed. The write either powers the machine off — in which case
//! nothing after it runs — or it does not, and the next line executes. That is
//! the whole verification: a shutdown that worked has no observer, and a
//! shutdown that did not is one that reported.

use super::cpu::outw;

/// Candidate PM1a control registers, in the order they are tried.
///
/// The value written is `SLP_EN` with `SLP_TYP` zero, which is soft-off on
/// every chipset that uses these addresses.
const CANDIDATES: [(u16, u16, &str); 2] = [
    (0x604, 0x2000, "acpi pm1a at 0x604"),
    (0xB004, 0x2000, "legacy bochs port at 0xb004"),
];

/// Asks the machine to power off. Returns only if it refused.
///
/// # Safety
/// Called with interrupts disabled, from the shutdown path, with no process
/// holding state that matters. Every write here is to a power-management
/// register; getting the address wrong writes to a port nothing decodes, which
/// is harmless and is why trying two costs nothing.
pub unsafe fn power_off() {
    for (port, value, _) in CANDIDATES {
        // SAFETY: the caller guarantees the context. A write to a port no
        // device decodes is discarded by the bus.
        unsafe { outw(port, value) };
    }
}

/// What was tried, for the log a failed shutdown leaves behind.
#[must_use]
pub fn attempted() -> &'static [(u16, u16, &'static str); 2] {
    &CANDIDATES
}
