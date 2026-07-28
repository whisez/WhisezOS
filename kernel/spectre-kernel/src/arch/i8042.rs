//! The keyboard and mouse controller, as far as the kernel is concerned.
//!
//! Which is barely at all. This file has no code that touches the device — it
//! holds the two IRQ numbers and the port range, because those are facts about
//! how the machine is wired and the kernel is what hands out wiring.
//!
//! Everything else is the driver's: the controller's command byte, enabling the
//! auxiliary port, telling the mouse to report, decoding scancodes, decoding
//! three-byte movement packets. All of that happens in ring 3 through the ports
//! granted here, and none of it is in the kernel, which is the arrangement the
//! whole device-authority line of work exists to make possible.
//!
//! # Two lines, one controller
//!
//! The i8042 is a single chip with two interrupt outputs: IRQ 1 when the
//! keyboard has a byte, IRQ 12 when the mouse does. Both are read from the same
//! data port, and which device a byte came from is decided by which interrupt
//! announced it. That is why they are separate lines rather than one — a driver
//! that could not tell them apart would have to guess, and guessing wrong turns
//! a mouse movement into a keystroke.
//!
//! # Two ports, granted separately, and why
//!
//! 0x60 and 0x64 are the whole controller: the data register and the
//! status/command register. The obvious grant is the range between them, and
//! `portauth` refuses it — 0x61 is the PIT gate, which the kernel keeps because
//! half the APIC timer calibration runs through it. So the controller is two
//! one-port grants rather than one five-port range, which is the denylist doing
//! exactly what it is for: a convenient range that quietly included something
//! the kernel needs was caught at the grant rather than discovered later as a
//! driver that could stop the system clock.
//!
//! There is still no way to grant the keyboard without the mouse. They are the
//! same two ports, which is a fact about a chip from 1984 rather than about
//! this code — the same shape of concession as the RTC sharing its ports with
//! the entire CMOS.

/// The data register. Both devices' bytes arrive here.
pub const DATA_PORT: u16 = 0x60;
/// The status register on read, the command register on write.
pub const COMMAND_PORT: u16 = 0x64;

/// The grants themselves live in `device.rs`, which is compiled by the host
/// test harness and cannot reach `arch`. `INPUT_PORTS` there must name the two
/// ports above, and this is the assertion that keeps the two in step.
const _: () = assert!(DATA_PORT == 0x60 && COMMAND_PORT == 0x64);

/// Keyboard interrupt. Pin 1 on the I/O APIC, which no conventional interrupt
/// source override moves.
pub const KEYBOARD_IRQ: u8 = 1;

/// Mouse interrupt, from the controller's auxiliary port.
pub const MOUSE_IRQ: u8 = 12;
