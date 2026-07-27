//! PS/2 mouse packet decoding.
//!
//! # Why the preview decodes mouse packets itself
//!
//! The firmware this preview runs on does not provide a pointing device. QEMU's
//! bundled OVMF exposes exactly one `EFI_SIMPLE_POINTER_PROTOCOL` and one
//! `EFI_ABSOLUTE_POINTER_PROTOCOL`, and neither has a device path: they are the
//! console splitter's own virtual instances, with the aggregate mode block still
//! at its compiled-in template (`AbsoluteMax` = 0x10000 on every axis). The
//! splitter has no children because the build ships no PS/2 or USB mouse driver
//! at all, so `GetState` returns `NOT_READY` forever no matter how much the user
//! moves the mouse. That is not something an application can fix by binding a
//! different protocol — there is no data to bind to.
//!
//! So when the firmware offers nothing usable, the preview talks to the i8042
//! auxiliary port directly. The port I/O and the controller handshake live in
//! `demo.rs`; this module is the part with the interesting failure modes — the
//! three-byte packet format, its sign and overflow bits, and resynchronisation
//! after a dropped byte — kept free of I/O so the host harness can test it.
//!
//! Byte 0 carries the buttons and the sign and overflow bits, byte 1 the X
//! delta, byte 2 the Y delta. Bit 3 of byte 0 is defined to always read as 1,
//! which is the only thing that makes resynchronisation possible: after a lost
//! byte the stream is misaligned, and that bit is how a decoder finds the start
//! of the next packet instead of reporting garbage motion forever.

#![allow(dead_code)]

use crate::pointer::Buttons;

/// Bit 3 of the first byte is specified to always be set.
const SYNC_BIT: u8 = 1 << 3;
const LEFT_BIT: u8 = 1 << 0;
const RIGHT_BIT: u8 = 1 << 1;
const X_SIGN_BIT: u8 = 1 << 4;
const Y_SIGN_BIT: u8 = 1 << 5;
const X_OVERFLOW_BIT: u8 = 1 << 6;
const Y_OVERFLOW_BIT: u8 = 1 << 7;

/// A decoded movement report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packet {
    /// Movement in screen coordinates: X to the right, Y **down**.
    pub dx: i32,
    pub dy: i32,
    pub buttons: Buttons,
}

/// Byte-at-a-time decoder for the standard 3-byte PS/2 mouse packet.
#[derive(Debug, Clone, Copy, Default)]
pub struct PacketDecoder {
    bytes: [u8; 3],
    index: usize,
    /// Packets discarded because their movement fields overflowed, and bytes
    /// discarded while hunting for the sync bit. Surfaced for diagnostics: a
    /// steadily climbing count means something else is racing us for the port.
    pub dropped: u32,
}

impl PacketDecoder {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bytes: [0; 3],
            index: 0,
            dropped: 0,
        }
    }

    /// Feeds one byte from the auxiliary port. Returns a packet on the third
    /// byte of a well-formed group.
    pub fn push(&mut self, byte: u8) -> Option<Packet> {
        // Resynchronise: a first byte without the sync bit means the stream is
        // misaligned, so drop bytes until one that could start a packet.
        if self.index == 0 && byte & SYNC_BIT == 0 {
            self.dropped += 1;
            return None;
        }

        self.bytes[self.index] = byte;
        self.index += 1;
        if self.index < 3 {
            return None;
        }
        self.index = 0;

        let [flags, x, y] = self.bytes;

        // An overflowed axis carries no usable magnitude. Reporting it anyway
        // would fling the cursor across the screen on exactly the fast motions
        // where accuracy matters most, so the packet is discarded — the next one
        // is 8 ms away.
        if flags & (X_OVERFLOW_BIT | Y_OVERFLOW_BIT) != 0 {
            self.dropped += 1;
            return None;
        }

        let dx = x as i32 - if flags & X_SIGN_BIT != 0 { 256 } else { 0 };
        let dy = y as i32 - if flags & Y_SIGN_BIT != 0 { 256 } else { 0 };

        Some(Packet {
            dx,
            // PS/2 reports Y growing upwards; the framebuffer grows downwards.
            dy: -dy,
            buttons: Buttons {
                left: flags & LEFT_BIT != 0,
                right: flags & RIGHT_BIT != 0,
            },
        })
    }

    /// How many bytes into the current packet the decoder is.
    #[must_use]
    pub const fn phase(&self) -> usize {
        self.index
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed(decoder: &mut PacketDecoder, bytes: &[u8]) -> Option<Packet> {
        let mut last = None;
        for &byte in bytes {
            if let Some(packet) = decoder.push(byte) {
                last = Some(packet);
            }
        }
        last
    }

    #[test]
    fn a_packet_is_only_reported_on_its_third_byte() {
        let mut decoder = PacketDecoder::new();
        assert_eq!(decoder.push(SYNC_BIT), None);
        assert_eq!(decoder.push(5), None);
        assert!(decoder.push(3).is_some());
    }

    #[test]
    fn positive_movement_decodes_with_the_y_axis_flipped() {
        let mut decoder = PacketDecoder::new();
        // PS/2 Y grows upwards, the screen grows downwards.
        let packet = feed(&mut decoder, &[SYNC_BIT, 12, 7]).unwrap();
        assert_eq!(packet.dx, 12);
        assert_eq!(packet.dy, -7);
    }

    #[test]
    fn sign_bits_produce_negative_deltas() {
        let mut decoder = PacketDecoder::new();
        let packet = feed(
            &mut decoder,
            &[SYNC_BIT | X_SIGN_BIT | Y_SIGN_BIT, 0xF4, 0xF9],
        )
        .unwrap();
        assert_eq!(packet.dx, -12);
        assert_eq!(packet.dy, 7, "negative PS/2 Y is downwards on screen");
    }

    #[test]
    fn the_extremes_of_the_delta_range_decode_exactly() {
        let mut decoder = PacketDecoder::new();
        let packet = feed(&mut decoder, &[SYNC_BIT, 0x7F, 0x7F]).unwrap();
        assert_eq!((packet.dx, packet.dy), (127, -127));

        let packet = feed(
            &mut decoder,
            &[SYNC_BIT | X_SIGN_BIT | Y_SIGN_BIT, 0x80, 0x80],
        )
        .unwrap();
        assert_eq!((packet.dx, packet.dy), (-128, 128));
    }

    #[test]
    fn buttons_are_read_from_the_flag_byte() {
        let mut decoder = PacketDecoder::new();
        let packet = feed(&mut decoder, &[SYNC_BIT | LEFT_BIT, 0, 0]).unwrap();
        assert!(packet.buttons.left && !packet.buttons.right);

        let packet = feed(&mut decoder, &[SYNC_BIT | RIGHT_BIT, 0, 0]).unwrap();
        assert!(packet.buttons.right && !packet.buttons.left);

        let packet = feed(&mut decoder, &[SYNC_BIT | LEFT_BIT | RIGHT_BIT, 0, 0]).unwrap();
        assert!(packet.buttons.left && packet.buttons.right);
    }

    #[test]
    fn overflowed_packets_are_discarded_rather_than_flinging_the_cursor() {
        let mut decoder = PacketDecoder::new();
        assert_eq!(
            feed(&mut decoder, &[SYNC_BIT | X_OVERFLOW_BIT, 0xFF, 0]),
            None
        );
        assert_eq!(
            feed(&mut decoder, &[SYNC_BIT | Y_OVERFLOW_BIT, 0, 0xFF]),
            None
        );
        assert_eq!(decoder.dropped, 2);

        // The decoder is still aligned afterwards.
        let packet = feed(&mut decoder, &[SYNC_BIT, 4, 4]).unwrap();
        assert_eq!(packet.dx, 4);
    }

    #[test]
    fn a_byte_without_the_sync_bit_cannot_start_a_packet() {
        let mut decoder = PacketDecoder::new();
        assert_eq!(decoder.push(0x00), None);
        assert_eq!(decoder.push(0x07), None);
        assert_eq!(decoder.dropped, 2);
        assert_eq!(decoder.phase(), 0, "still waiting for a real first byte");
    }

    #[test]
    fn the_stream_resynchronises_after_a_lost_byte() {
        // The failure this guards: another driver on the same controller eats a
        // byte, the decoder stays misaligned, and every later packet reports
        // nonsense movement.
        let mut decoder = PacketDecoder::new();
        decoder.push(SYNC_BIT);
        decoder.push(9); // third byte never arrives

        // A fresh, well-formed packet arrives while the decoder is misaligned.
        // The stale byte completes one bogus group, then alignment recovers.
        feed(&mut decoder, &[SYNC_BIT, 6, 6]);
        let packet = feed(&mut decoder, &[SYNC_BIT, 6, 6]).unwrap();
        assert_eq!((packet.dx, packet.dy), (6, -6));
    }

    #[test]
    fn a_long_run_of_packets_decodes_without_drift() {
        let mut decoder = PacketDecoder::new();
        let mut total = 0i32;
        for _ in 0..500 {
            let packet = feed(&mut decoder, &[SYNC_BIT, 3, 0]).unwrap();
            total += packet.dx;
        }
        assert_eq!(total, 1500);
        assert_eq!(decoder.dropped, 0);
    }

    #[test]
    fn garbage_between_packets_does_not_corrupt_the_next_one() {
        let mut decoder = PacketDecoder::new();
        for byte in [0x00u8, 0x01, 0x02, 0x04, 0x05] {
            assert_eq!(decoder.push(byte), None);
        }
        let packet = feed(&mut decoder, &[SYNC_BIT | LEFT_BIT, 10, 20]).unwrap();
        assert_eq!((packet.dx, packet.dy), (10, -20));
        assert!(packet.buttons.left);
        assert_eq!(decoder.dropped, 5);
    }
}
