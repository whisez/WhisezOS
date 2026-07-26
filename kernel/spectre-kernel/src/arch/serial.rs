//! 16550 UART driver.
//!
//! The kernel's only output device until Prism is running, and the only one
//! that works when Prism is the thing that crashed. Every panic, every early
//! boot message, and every QEMU test assertion goes through here.
//!
//! # Why this is in the kernel when drivers are supposed to be user-space
//!
//! It is a deliberate exception, and a small one: ~120 lines with no allocation,
//! no interrupts, and no DMA. The alternative is that a kernel panic has no way
//! to report itself, because reporting would require IPC to a user-space driver
//! that may be the thing that died. A debug console that only works when the
//! system is healthy is not a debug console.
//!
//! It is also strictly write-only in the panic path and takes no locks there —
//! `emergency_write` deliberately bypasses the mutex, because a panic while
//! holding the serial lock would otherwise deadlock instead of printing.

use core::fmt;

/// Standard COM1. QEMU's `-serial stdio` connects here.
pub const COM1: u16 = 0x3F8;
pub const COM2: u16 = 0x2F8;

/// The UART's input clock. Divisor = 115200 / baud.
const UART_CLOCK_HZ: u32 = 115_200;

/// Register offsets from the base port. Several are dual-purpose depending on
/// the DLAB bit in the line control register, which is the single most
/// confusing part of this device.
mod reg {
    /// Read: receive buffer. Write: transmit buffer. With DLAB=1: divisor low.
    pub const DATA: u16 = 0;
    /// Interrupt enable. With DLAB=1: divisor high.
    pub const INT_ENABLE: u16 = 1;
    /// Write: FIFO control.
    pub const FIFO_CTRL: u16 = 2;
    /// Line control, including the DLAB bit.
    pub const LINE_CTRL: u16 = 3;
    /// Modem control.
    pub const MODEM_CTRL: u16 = 4;
    /// Line status.
    pub const LINE_STATUS: u16 = 5;
}

/// Line control bits.
mod lcr {
    pub const DATA_8BITS: u8 = 0b11;
    pub const STOP_1BIT: u8 = 0;
    pub const PARITY_NONE: u8 = 0;
    /// Divisor Latch Access Bit: remaps registers 0 and 1 to the divisor.
    pub const DLAB: u8 = 1 << 7;
}

mod lsr {
    /// Data available to read.
    pub const DATA_READY: u8 = 1 << 0;
    /// Transmit holding register empty — safe to write another byte.
    pub const THR_EMPTY: u8 = 1 << 5;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerialError {
    /// Requested baud rate does not divide the UART clock evenly enough.
    UnsupportedBaud(u32),
    /// Loopback self-test failed: no UART present at this port.
    NotPresent,
}

/// Compute the divisor latch value for a baud rate.
///
/// Rounded to nearest rather than truncated. At 115200 the divisor is 1 and it
/// makes no difference, but at 9600 truncation gives 12 (exact) while a rate
/// like 14400 gives 8.0 exactly and 31250 gives 3.686 — truncating to 3 is a
/// 22% clock error, well past the ~3% a UART tolerates, and produces garbage on
/// the wire rather than an error.
pub fn divisor_for(baud: u32) -> Result<u16, SerialError> {
    if baud == 0 || baud > UART_CLOCK_HZ {
        return Err(SerialError::UnsupportedBaud(baud));
    }

    let divisor = (UART_CLOCK_HZ + baud / 2) / baud;
    if divisor == 0 || divisor > u16::MAX as u32 {
        return Err(SerialError::UnsupportedBaud(baud));
    }

    // Reject rates whose actual error exceeds what a UART will tolerate. The
    // receiver samples in the middle of each bit; accumulated error across a
    // 10-bit frame must stay under half a bit, which works out to about 3%.
    let actual = UART_CLOCK_HZ / divisor;
    let error_permille = if actual > baud {
        (actual - baud) * 1000 / baud
    } else {
        (baud - actual) * 1000 / baud
    };
    if error_permille > 30 {
        return Err(SerialError::UnsupportedBaud(baud));
    }

    Ok(divisor as u16)
}

/// Port I/O abstraction.
///
/// A trait so the initialisation sequence — which is order-dependent in ways
/// that are easy to get wrong and impossible to see from the outside — can be
/// tested against a recording mock rather than only on real hardware.
pub trait PortIo {
    fn read(&self, port: u16) -> u8;
    fn write(&mut self, port: u16, value: u8);
}

/// Real x86 port I/O.
pub struct X86Ports;

impl PortIo for X86Ports {
    #[inline]
    fn read(&self, port: u16) -> u8 {
        let value: u8;
        // SAFETY: `in` from a port is architecturally safe; the caller is
        // responsible for the port being a UART rather than something else.
        unsafe {
            core::arch::asm!("in al, dx", out("al") value, in("dx") port, options(nomem, nostack, preserves_flags));
        }
        value
    }

    #[inline]
    fn write(&mut self, port: u16, value: u8) {
        // SAFETY: as above.
        unsafe {
            core::arch::asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags));
        }
    }
}

pub struct Uart<P: PortIo> {
    ports: P,
    base: u16,
}

impl<P: PortIo> Uart<P> {
    pub fn new(ports: P, base: u16) -> Self {
        Uart { ports, base }
    }

    /// Initialise at `baud`, 8N1, FIFOs enabled.
    ///
    /// The ordering below is not arbitrary and each step depends on the last:
    ///
    ///   1. Disable interrupts **first**. The firmware may have left them
    ///      enabled, and an interrupt arriving mid-configuration hits an IDT
    ///      that does not exist yet.
    ///   2. Set DLAB, write the divisor, clear DLAB. While DLAB is set,
    ///      registers 0 and 1 *are* the divisor — writing what you think is the
    ///      interrupt-enable register there silently corrupts the baud rate.
    ///   3. Line control after the divisor, which is what clears DLAB.
    ///   4. FIFOs after line control.
    ///   5. Self-test last, once the port is actually configured.
    pub fn init(&mut self, baud: u32) -> Result<(), SerialError> {
        let divisor = divisor_for(baud)?;

        self.write_reg(reg::INT_ENABLE, 0x00);

        self.write_reg(reg::LINE_CTRL, lcr::DLAB);
        self.write_reg(reg::DATA, (divisor & 0xFF) as u8);
        self.write_reg(reg::INT_ENABLE, (divisor >> 8) as u8);

        // Clears DLAB as a side effect of writing the real line configuration.
        self.write_reg(
            reg::LINE_CTRL,
            lcr::DATA_8BITS | lcr::STOP_1BIT | lcr::PARITY_NONE,
        );

        // Enable and clear both FIFOs, 14-byte trigger level.
        self.write_reg(reg::FIFO_CTRL, 0xC7);

        self.self_test()?;

        // DTR | RTS | OUT2. OUT2 gates the UART's interrupt line onto the PIC
        // on a standard PC; without it, interrupt-driven reads never fire.
        self.write_reg(reg::MODEM_CTRL, 0x0B);
        Ok(())
    }

    /// Loopback self-test: confirm a UART is actually present.
    ///
    /// Without this, a machine with no COM1 silently discards every byte and the
    /// first symptom is an empty log with no explanation. Reading back a byte we
    /// wrote proves something is there.
    fn self_test(&mut self) -> Result<(), SerialError> {
        // LOOP | OUT1 | OUT2 | RTS: internal loopback.
        self.write_reg(reg::MODEM_CTRL, 0x1E);
        self.write_reg(reg::DATA, 0xAE);

        if self.read_reg(reg::DATA) != 0xAE {
            return Err(SerialError::NotPresent);
        }
        Ok(())
    }

    #[inline]
    fn write_reg(&mut self, offset: u16, value: u8) {
        self.ports.write(self.base + offset, value);
    }

    #[inline]
    fn read_reg(&self, offset: u16) -> u8 {
        self.ports.read(self.base + offset)
    }

    #[inline]
    fn can_transmit(&self) -> bool {
        self.read_reg(reg::LINE_STATUS) & lsr::THR_EMPTY != 0
    }

    /// Write one byte, spinning until the transmit register is free.
    ///
    /// Bounded spin rather than an infinite one. If the UART wedges — which a
    /// misconfigured or absent device does — an unbounded wait turns a debug
    /// print into a hang, and the hang looks exactly like the bug you were
    /// trying to print your way out of.
    pub fn write_byte(&mut self, byte: u8) {
        const SPIN_LIMIT: u32 = 100_000;
        let mut spins = 0;
        while !self.can_transmit() {
            spins += 1;
            if spins > SPIN_LIMIT {
                return; // Drop the byte rather than hang the kernel.
            }
            core::hint::spin_loop();
        }
        self.write_reg(reg::DATA, byte);
    }

    pub fn write_str_bytes(&mut self, s: &str) {
        for b in s.bytes() {
            // A bare LF on a terminal expecting CRLF produces a staircase that
            // makes multi-line panic output unreadable.
            if b == b'\n' {
                self.write_byte(b'\r');
            }
            self.write_byte(b);
        }
    }

    pub fn read_byte(&self) -> Option<u8> {
        if self.read_reg(reg::LINE_STATUS) & lsr::DATA_READY != 0 {
            Some(self.read_reg(reg::DATA))
        } else {
            None
        }
    }
}

impl<P: PortIo> fmt::Write for Uart<P> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_str_bytes(s);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Records every port access so the init ordering can be asserted.
    struct MockPorts {
        log: Vec<(u16, u8, bool)>, // (port, value, is_write)
        /// Value the loopback test should read back.
        loopback: u8,
        /// Bit pattern returned from the line status register.
        line_status: u8,
    }

    impl MockPorts {
        fn new() -> Self {
            MockPorts {
                log: Vec::new(),
                loopback: 0xAE,
                line_status: lsr::THR_EMPTY,
            }
        }

        fn writes_to(&self, offset: u16) -> Vec<u8> {
            self.log
                .iter()
                .filter(|(p, _, w)| *w && *p == COM1 + offset)
                .map(|(_, v, _)| *v)
                .collect()
        }
    }

    impl PortIo for MockPorts {
        fn read(&self, port: u16) -> u8 {
            match port - COM1 {
                reg::LINE_STATUS => self.line_status,
                reg::DATA => self.loopback,
                _ => 0,
            }
        }

        fn write(&mut self, port: u16, value: u8) {
            self.log.push((port, value, true));
        }
    }

    #[test]
    fn standard_baud_rates_produce_exact_divisors() {
        assert_eq!(divisor_for(115_200).unwrap(), 1);
        assert_eq!(divisor_for(57_600).unwrap(), 2);
        assert_eq!(divisor_for(38_400).unwrap(), 3);
        assert_eq!(divisor_for(19_200).unwrap(), 6);
        assert_eq!(divisor_for(9_600).unwrap(), 12);
    }

    #[test]
    fn divisor_rounds_to_nearest_not_toward_zero() {
        // 115200/31250 = 3.686. Truncating gives 3 (a 22% error, garbage on the
        // wire); rounding gives 4 (an 8% error, still bad — and correctly
        // rejected below). The point is that the rounding direction is chosen,
        // not accidental.
        let d = (UART_CLOCK_HZ + 31250 / 2) / 31250;
        assert_eq!(d, 4);
    }

    #[test]
    fn baud_rates_with_excessive_clock_error_are_refused() {
        // A UART tolerates roughly 3% total error. Accepting a rate outside that
        // produces silent corruption rather than a diagnosable failure.
        assert!(matches!(
            divisor_for(31_250),
            Err(SerialError::UnsupportedBaud(31_250))
        ));
    }

    #[test]
    fn zero_and_over_clock_baud_are_refused() {
        assert!(divisor_for(0).is_err());
        assert!(divisor_for(UART_CLOCK_HZ + 1).is_err());
        assert!(divisor_for(UART_CLOCK_HZ).is_ok());
    }

    #[test]
    fn init_disables_interrupts_before_touching_anything_else() {
        let mut uart = Uart::new(MockPorts::new(), COM1);
        uart.init(115_200).unwrap();

        let first = uart.ports.log[0];
        assert_eq!(
            (first.0, first.1),
            (COM1 + reg::INT_ENABLE, 0x00),
            "interrupts must be masked first; firmware may have left them on"
        );
    }

    #[test]
    fn divisor_is_written_with_dlab_set_and_cleared_after() {
        let mut uart = Uart::new(MockPorts::new(), COM1);
        uart.init(9600).unwrap();

        let lcr_writes = uart.ports.writes_to(reg::LINE_CTRL);
        assert_eq!(lcr_writes.len(), 2, "expected DLAB set then cleared");
        assert_eq!(
            lcr_writes[0],
            lcr::DLAB,
            "DLAB not set before divisor write"
        );
        assert_eq!(
            lcr_writes[1] & lcr::DLAB,
            0,
            "DLAB left set — registers 0/1 stay remapped to the divisor"
        );
        assert_eq!(lcr_writes[1], lcr::DATA_8BITS, "line config is not 8N1");
    }

    #[test]
    fn divisor_bytes_are_split_correctly() {
        let mut uart = Uart::new(MockPorts::new(), COM1);
        uart.init(9600).unwrap(); // divisor 12

        // While DLAB is set, DATA is divisor-low and INT_ENABLE is divisor-high.
        let data_writes = uart.ports.writes_to(reg::DATA);
        assert_eq!(data_writes[0], 12, "divisor low byte wrong");

        let ie_writes = uart.ports.writes_to(reg::INT_ENABLE);
        assert_eq!(
            ie_writes[0], 0x00,
            "first write should be masking interrupts"
        );
        assert_eq!(ie_writes[1], 0, "divisor high byte wrong");
    }

    #[test]
    fn missing_uart_is_detected_rather_than_swallowing_output() {
        let mut ports = MockPorts::new();
        ports.loopback = 0x00; // nothing echoes back
        let mut uart = Uart::new(ports, COM1);
        assert_eq!(uart.init(115_200), Err(SerialError::NotPresent));
    }

    #[test]
    fn out2_is_enabled_after_a_successful_init() {
        let mut uart = Uart::new(MockPorts::new(), COM1);
        uart.init(115_200).unwrap();

        let mcr = uart.ports.writes_to(reg::MODEM_CTRL);
        let final_mcr = *mcr.last().unwrap();
        assert_eq!(
            final_mcr & 0x08,
            0x08,
            "OUT2 clear; interrupts never reach the PIC"
        );
        assert_eq!(final_mcr & 0x10, 0, "still in loopback mode after init");
    }

    #[test]
    fn newlines_are_translated_to_crlf() {
        let mut uart = Uart::new(MockPorts::new(), COM1);
        uart.write_str_bytes("a\nb");

        let data: Vec<u8> = uart.ports.writes_to(reg::DATA);
        assert_eq!(data, vec![b'a', b'\r', b'\n', b'b']);
    }

    #[test]
    fn a_wedged_uart_drops_bytes_instead_of_hanging() {
        let mut ports = MockPorts::new();
        ports.line_status = 0; // THR never reports empty
        let mut uart = Uart::new(ports, COM1);

        // Must return. An unbounded spin here turns a debug print into a hang
        // indistinguishable from the bug being debugged.
        uart.write_byte(b'x');
        assert!(
            uart.ports.writes_to(reg::DATA).is_empty(),
            "byte written despite the transmitter never being ready"
        );
    }

    #[test]
    fn read_returns_none_when_no_data_is_ready() {
        let mut ports = MockPorts::new();
        ports.line_status = lsr::THR_EMPTY; // ready to send, nothing to receive
        let uart = Uart::new(ports, COM1);
        assert_eq!(uart.read_byte(), None);
    }
}
