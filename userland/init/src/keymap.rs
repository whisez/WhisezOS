//! Scancode set 1 to characters.
//!
//! # Why set 1 and not set 2
//!
//! The keyboard speaks set 2. The i8042 translates it to set 1 when the
//! translation bit in its configuration byte is set, which is what firmware
//! leaves it as and what `i8042_init` deliberately does not change — changing
//! it as a side effect of enabling two interrupts would silently switch which
//! set arrives, and a driver decoding the wrong one produces plausible but
//! wrong keys.
//!
//! So this decodes set 1, and the driver reports which set it is receiving so a
//! machine that differs says so rather than typing nonsense.
//!
//! # A release is a press with the top bit set
//!
//! That is the whole of the release encoding, and it is why counting bytes
//! counts every key twice. `decode` answers `None` for a release: a shell wants
//! the character, and the only release that matters is a modifier's, which is
//! handled separately.
//!
//! # What is deliberately not here
//!
//! No dead keys, no compose, no layout beyond US. A Turkish keyboard on this
//! machine produces the wrong letters, and the fix is a layout table rather
//! than more code — the shape here is one array per shift state, which is what
//! a second layout would add to rather than change.

#![allow(dead_code)]

/// Bit 7 of a scancode: this is a release, not a press.
pub const RELEASE: u8 = 0x80;

/// The prefix byte for the extended keys — arrows, right-hand modifiers. The
/// byte after it is a different key from the same code without it.
pub const EXTENDED: u8 = 0xE0;

/// Scancodes worth naming.
pub mod code {
    pub const ESCAPE: u8 = 0x01;
    pub const BACKSPACE: u8 = 0x0E;
    pub const TAB: u8 = 0x0F;
    pub const ENTER: u8 = 0x1C;
    pub const LEFT_CONTROL: u8 = 0x1D;
    pub const LEFT_SHIFT: u8 = 0x2A;
    pub const RIGHT_SHIFT: u8 = 0x36;
    pub const LEFT_ALT: u8 = 0x38;
    pub const SPACE: u8 = 0x39;
    pub const CAPS_LOCK: u8 = 0x3A;
}

/// Unshifted characters, indexed by scancode. Zero means "not a character".
const UNSHIFTED: [u8; 0x40] = [
    0, 0, b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0', b'-', b'=', 0, 0, b'q', b'w',
    b'e', b'r', b't', b'y', b'u', b'i', b'o', b'p', b'[', b']', 0, 0, b'a', b's', b'd', b'f', b'g',
    b'h', b'j', b'k', b'l', b';', b'\'', b'`', 0, b'\\', b'z', b'x', b'c', b'v', b'b', b'n', b'm',
    b',', b'.', b'/', 0, b'*', 0, b' ', 0, 0, 0, 0, 0, 0,
];

/// The same keys with shift held.
const SHIFTED: [u8; 0x40] = [
    0, 0, b'!', b'@', b'#', b'$', b'%', b'^', b'&', b'*', b'(', b')', b'_', b'+', 0, 0, b'Q', b'W',
    b'E', b'R', b'T', b'Y', b'U', b'I', b'O', b'P', b'{', b'}', 0, 0, b'A', b'S', b'D', b'F', b'G',
    b'H', b'J', b'K', b'L', b':', b'"', b'~', 0, b'|', b'Z', b'X', b'C', b'V', b'B', b'N', b'M',
    b'<', b'>', b'?', 0, b'*', 0, b' ', 0, 0, 0, 0, 0, 0,
];

/// What a keystroke turned into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    /// A printable character.
    Char(u8),
    Enter,
    Backspace,
    /// Nothing a shell acts on: a release, a modifier, or a key with no
    /// character.
    None,
}

/// Which modifiers are held.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Modifiers {
    pub shift: bool,
    pub caps: bool,
}

impl Modifiers {
    /// Whether letters should come out upper case.
    ///
    /// Caps lock and shift cancel rather than combine, which is what every
    /// keyboard does and what a plain `||` would get wrong.
    #[must_use]
    pub const fn upper(&self) -> bool {
        self.shift != self.caps
    }
}

/// Feeds one scancode, updating the modifiers and returning what it produced.
///
/// The extended prefix is handled by the caller: this sees only the second
/// byte, and none of the extended keys produce characters, so a caller that
/// forgets is wrong in a way that types an arrow key as a letter.
pub fn decode(scancode: u8, modifiers: &mut Modifiers) -> Key {
    let released = scancode & RELEASE != 0;
    let code = scancode & !RELEASE;

    match code {
        code::LEFT_SHIFT | code::RIGHT_SHIFT => {
            // Tracked on both edges, unlike everything else. A shift whose
            // release is ignored is a keyboard that stays capitalised.
            modifiers.shift = !released;
            return Key::None;
        }
        // Caps lock toggles on press and does nothing on release. Toggling on
        // both would leave it exactly as it started.
        code::CAPS_LOCK if !released => {
            modifiers.caps = !modifiers.caps;
            return Key::None;
        }
        _ => {}
    }

    if released {
        return Key::None;
    }

    match code {
        code::ENTER => Key::Enter,
        code::BACKSPACE => Key::Backspace,
        _ => {
            let index = code as usize;
            if index >= UNSHIFTED.len() {
                return Key::None;
            }
            // Case is the letters' business only. Shift on a digit gives a
            // symbol, and caps lock must not: a keyboard where caps lock turns
            // 1 into ! is one nobody has used.
            let letter = UNSHIFTED[index].is_ascii_alphabetic();
            let upper = if letter {
                modifiers.upper()
            } else {
                modifiers.shift
            };
            let byte = if upper {
                SHIFTED[index]
            } else {
                UNSHIFTED[index]
            };
            if byte == 0 {
                Key::None
            } else {
                Key::Char(byte)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn press(scancode: u8, m: &mut Modifiers) -> Key {
        decode(scancode, m)
    }

    #[test]
    fn letters_and_digits_come_out_unshifted() {
        let mut m = Modifiers::default();
        assert_eq!(press(0x1E, &mut m), Key::Char(b'a'));
        assert_eq!(press(0x02, &mut m), Key::Char(b'1'));
        assert_eq!(press(code::SPACE, &mut m), Key::Char(b' '));
    }

    #[test]
    fn a_release_produces_nothing() {
        // The whole of the release encoding, and the reason counting bytes
        // counts every key twice.
        let mut m = Modifiers::default();
        assert_eq!(press(0x1E | RELEASE, &mut m), Key::None);
    }

    #[test]
    fn shift_capitalises_letters_and_shifts_symbols() {
        let mut m = Modifiers::default();
        assert_eq!(press(code::LEFT_SHIFT, &mut m), Key::None);
        assert!(m.shift);
        assert_eq!(press(0x1E, &mut m), Key::Char(b'A'));
        assert_eq!(press(0x02, &mut m), Key::Char(b'!'));
    }

    #[test]
    fn releasing_shift_stops_capitalising() {
        // A shift whose release is ignored is a keyboard that stays
        // capitalised, which is why modifiers are the one thing tracked on
        // both edges.
        let mut m = Modifiers::default();
        press(code::LEFT_SHIFT, &mut m);
        press(code::LEFT_SHIFT | RELEASE, &mut m);
        assert!(!m.shift);
        assert_eq!(press(0x1E, &mut m), Key::Char(b'a'));
    }

    #[test]
    fn both_shift_keys_work() {
        let mut m = Modifiers::default();
        press(code::RIGHT_SHIFT, &mut m);
        assert_eq!(press(0x1E, &mut m), Key::Char(b'A'));
    }

    #[test]
    fn caps_lock_toggles_on_press_only() {
        // Toggling on release as well would leave it exactly as it started,
        // which is a caps lock that appears not to work at all.
        let mut m = Modifiers::default();
        press(code::CAPS_LOCK, &mut m);
        assert!(m.caps);
        press(code::CAPS_LOCK | RELEASE, &mut m);
        assert!(m.caps);
        assert_eq!(press(0x1E, &mut m), Key::Char(b'A'));
    }

    #[test]
    fn caps_lock_does_not_shift_digits() {
        // A keyboard where caps lock turns 1 into ! is one nobody has used.
        let mut m = Modifiers::default();
        press(code::CAPS_LOCK, &mut m);
        assert_eq!(press(0x02, &mut m), Key::Char(b'1'));
    }

    #[test]
    fn shift_and_caps_lock_cancel_rather_than_combine() {
        // What every keyboard does, and what a plain `||` gets wrong.
        let mut m = Modifiers::default();
        press(code::CAPS_LOCK, &mut m);
        press(code::LEFT_SHIFT, &mut m);
        assert_eq!(press(0x1E, &mut m), Key::Char(b'a'));
    }

    #[test]
    fn enter_and_backspace_are_not_characters() {
        let mut m = Modifiers::default();
        assert_eq!(press(code::ENTER, &mut m), Key::Enter);
        assert_eq!(press(code::BACKSPACE, &mut m), Key::Backspace);
    }

    #[test]
    fn a_scancode_past_the_table_is_not_a_character() {
        // The tables cover 0x00 to 0x3F. Anything above is a function key or a
        // keypad key, and indexing past the end would be a panic in a process
        // that has nowhere to report one.
        let mut m = Modifiers::default();
        for code in 0x40u8..0x7F {
            assert_eq!(press(code, &mut m), Key::None, "scancode {code:#04x}");
        }
    }

    #[test]
    fn every_table_entry_has_a_shifted_counterpart() {
        // A gap in one table and not the other produces a key that types
        // something unshifted and nothing with shift held, which reads as a
        // keyboard that intermittently ignores a key.
        for index in 0..UNSHIFTED.len() {
            assert_eq!(
                UNSHIFTED[index] == 0,
                SHIFTED[index] == 0,
                "scancode {index:#04x} is in one table and not the other"
            );
        }
    }

    #[test]
    fn the_two_tables_are_the_same_length() {
        assert_eq!(UNSHIFTED.len(), SHIFTED.len());
    }
}
