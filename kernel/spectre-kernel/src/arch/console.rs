//! The kernel's early console: one 16550 UART, no allocation, no interrupts.
//!
//! Every line the kernel prints during bring-up goes here, and the QEMU boot
//! test asserts on exactly this output. That makes the format part of the
//! contract rather than decoration: a line that changes shape breaks the test,
//! which is the intended pressure — a boot log nobody checks is a boot log that
//! silently stops being true.
//!
//! # The panic path deliberately bypasses the lock
//!
//! `emergency_write` takes no lock. A panic that happens while the console lock
//! is held — a fault inside a `kprintln!`, say — would otherwise deadlock trying
//! to report itself, and a kernel that cannot print its own panic is a kernel
//! debugged by guesswork. Interleaved output is a far smaller problem than no
//! output, and by the time this runs the system is already over.

use core::fmt::{self, Write};

use spin::Mutex;

use super::serial::{Uart, X86Ports, COM1};

/// 115200 8N1 — QEMU's default, and universal on real serial hardware.
pub const BAUD: u32 = 115_200;

static CONSOLE: Mutex<Option<Uart<X86Ports>>> = Mutex::new(None);

/// Brings up COM1. Safe to call more than once; later calls are ignored so a
/// re-init cannot reset the port mid-line.
pub fn init() -> bool {
    let mut guard = CONSOLE.lock();
    if guard.is_some() {
        return true;
    }
    let mut uart = Uart::new(X86Ports, COM1);
    match uart.init(BAUD) {
        Ok(()) => {
            *guard = Some(uart);
            true
        }
        // No UART at COM1. Nothing to say and nowhere to say it; the caller
        // carries on, because a headless board without a serial port is still a
        // board that should boot.
        Err(_) => false,
    }
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments<'_>) {
    if let Some(uart) = CONSOLE.lock().as_mut() {
        let _ = uart.write_fmt(args);
    }
}

/// Writes without taking the console lock. For the panic path only.
///
/// # Safety
/// May interleave with a concurrent `kprintln!` on another processor. Acceptable
/// only when the system is already going down.
pub unsafe fn emergency_write(args: fmt::Arguments<'_>) {
    let mut uart = Uart::new(X86Ports, COM1);
    // Re-initialising is deliberate: the panic may have come from a state where
    // the port was never brought up, or was left mid-configuration.
    let _ = uart.init(BAUD);
    let _ = uart.write_fmt(args);
}

#[macro_export]
macro_rules! kprint {
    ($($arg:tt)*) => ($crate::arch::console::_print(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! kprintln {
    () => ($crate::kprint!("\r\n"));
    // CRLF, not LF: a real terminal on the other end of a serial line does not
    // do the carriage return for you, and every line after the first starts
    // wherever the previous one ended.
    ($($arg:tt)*) => ($crate::kprint!("{}\r\n", format_args!($($arg)*)));
}
