//! The shell's text buffer and its commands.
//!
//! Everything here is arithmetic over a character grid: no drawing, no
//! syscalls, no hardware. The session owns those and asks this what the screen
//! should say. That split is what lets a shell — the part most likely to be
//! wrong in ways a person notices — be covered by ordinary host tests rather
//! than by squinting at a screenshot.
//!
//! # A ring, not a scrolling copy
//!
//! Lines are written into a fixed array and the top moves. Copying every line
//! up on each newline is the obvious alternative and costs a full buffer move
//! per line; a rotating start costs an addition. Neither matters at this size,
//! and the ring is the one that stays right when the buffer grows.
//!
//! # No allocator
//!
//! Every buffer here is fixed and every overflow truncates rather than growing.
//! A shell that can be made to allocate by typing is a shell that can be made
//! to run out of memory by typing.

#![allow(dead_code)]

/// Characters across.
pub const COLUMNS: usize = 78;
/// Lines of history kept.
///
/// Fifteen, not seventeen. The window has to hold the history *and* the prompt
/// below it, and at seventeen the prompt row fell outside the rectangle the
/// session clears each frame — so every cursor it drew stayed, and the command
/// line filled up with blocks.
pub const ROWS: usize = 15;
/// Longest command that can be typed.
pub const INPUT_LIMIT: usize = COLUMNS - 2;

/// What the session should do after a command ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Nothing beyond what was printed.
    None,
    /// Repaint the whole desktop; the console asked for a clear.
    Redraw,
    /// Read this sector from the disk and print it.
    ReadSector(u64),
    /// Print how long the session has been up.
    ///
    /// The console has no clock, and giving it one would mean giving it a
    /// syscall — which is the thing that keeps every rule in this file
    /// testable without a machine. So it says what it wants and the session
    /// answers.
    Uptime,
}

/// A scrolling text area and the line being typed into it.
pub struct Console {
    lines: [[u8; COLUMNS]; ROWS],
    /// How many characters of each line are real. The rest is not blanked, so
    /// the length is the only thing that says where a line ends.
    lengths: [usize; ROWS],
    /// Which row is the oldest. The ring's start.
    top: usize,
    used: usize,
    input: [u8; INPUT_LIMIT],
    input_len: usize,
}

impl Default for Console {
    fn default() -> Self {
        Self::new()
    }
}

impl Console {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            lines: [[b' '; COLUMNS]; ROWS],
            lengths: [0; ROWS],
            top: 0,
            used: 0,
            input: [0; INPUT_LIMIT],
            input_len: 0,
        }
    }

    /// The lines currently on screen, oldest first.
    ///
    /// Returned through a closure rather than as a slice because the ring wraps
    /// and the visible lines are not contiguous.
    pub fn each_line(&self, mut f: impl FnMut(usize, &[u8])) {
        for index in 0..self.used {
            let row = (self.top + index) % ROWS;
            f(index, &self.lines[row][..self.lengths[row]]);
        }
    }

    /// What is being typed, including nothing.
    #[must_use]
    pub fn input(&self) -> &[u8] {
        &self.input[..self.input_len]
    }

    /// Appends a line, dropping the oldest if the buffer is full.
    pub fn print(&mut self, text: &[u8]) {
        let row = if self.used < ROWS {
            let row = (self.top + self.used) % ROWS;
            self.used += 1;
            row
        } else {
            // Full: the oldest line becomes the newest and the start moves.
            let row = self.top;
            self.top = (self.top + 1) % ROWS;
            row
        };

        let take = text.len().min(COLUMNS);
        self.lines[row][..take].copy_from_slice(&text[..take]);
        self.lengths[row] = take;
    }

    /// Empties the history. The line being typed is left alone: clearing the
    /// screen while somebody is halfway through a word should not eat the word.
    pub fn clear(&mut self) {
        self.top = 0;
        self.used = 0;
    }

    /// Adds a typed character, ignoring anything past the limit.
    pub fn type_char(&mut self, byte: u8) {
        if self.input_len < INPUT_LIMIT {
            self.input[self.input_len] = byte;
            self.input_len += 1;
        }
    }

    /// Removes the last typed character.
    pub fn backspace(&mut self) {
        self.input_len = self.input_len.saturating_sub(1);
    }

    /// Runs whatever has been typed and clears the input.
    pub fn enter(&mut self) -> Action {
        let mut line = [0u8; INPUT_LIMIT];
        let length = self.input_len;
        line[..length].copy_from_slice(&self.input[..length]);
        self.input_len = 0;

        // Echo it, so the history reads like a transcript rather than like a
        // list of answers to questions nobody can see.
        let mut echoed = [b' '; COLUMNS];
        echoed[0] = b'>';
        let take = length.min(COLUMNS - 2);
        echoed[2..2 + take].copy_from_slice(&line[..take]);
        self.print(&echoed[..2 + take]);

        self.run(&line[..length])
    }

    /// Interprets one command.
    fn run(&mut self, line: &[u8]) -> Action {
        let line = trim(line);
        if line.is_empty() {
            return Action::None;
        }

        let (word, rest) = split_word(line);
        match word {
            b"help" => {
                self.print(b"help              this list");
                self.print(b"clear             empty the screen");
                self.print(b"devices           what the kernel found");
                self.print(b"uptime            since the session started");
                self.print(b"read <sector>     read one 512-byte sector");
                self.print(b"echo <text>       print it back");
                Action::None
            }
            b"clear" => {
                self.clear();
                Action::Redraw
            }
            b"devices" => {
                self.print(b"0  framebuffer  1280x800");
                self.print(b"1  ticker       rtc, 64 hz");
                self.print(b"2  keyboard     i8042");
                self.print(b"3  mouse        i8042 aux");
                self.print(b"4  disk         virtio-blk, 16 mib");
                self.print(b"5  sound        virtio-snd, 1 out 1 in");
                Action::None
            }
            b"echo" => {
                self.print(rest);
                Action::None
            }
            b"read" => match parse_number(rest) {
                Some(sector) => Action::ReadSector(sector),
                None => {
                    self.print(b"read: expected a sector number");
                    Action::None
                }
            },
            b"uptime" => Action::Uptime,
            _ => {
                let mut message = [b' '; COLUMNS];
                let prefix = b"unknown command: ";
                message[..prefix.len()].copy_from_slice(prefix);
                let take = word.len().min(COLUMNS - prefix.len());
                message[prefix.len()..prefix.len() + take].copy_from_slice(&word[..take]);
                self.print(&message[..prefix.len() + take]);
                self.print(b"try: help");
                Action::None
            }
        }
    }
}

/// Drops leading and trailing spaces.
#[must_use]
pub fn trim(mut line: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = line {
        line = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = line {
        line = rest;
    }
    line
}

/// Splits the first word off, returning it and whatever follows.
#[must_use]
pub fn split_word(line: &[u8]) -> (&[u8], &[u8]) {
    match line.iter().position(|byte| *byte == b' ') {
        Some(at) => (&line[..at], trim(&line[at..])),
        None => (line, &[]),
    }
}

/// Reads a decimal number, refusing anything that is not entirely digits.
///
/// Refusing rather than stopping at the first non-digit: `read 12x` is a typo,
/// and answering it with sector 12 is doing something the person did not ask
/// for.
#[must_use]
pub fn parse_number(text: &[u8]) -> Option<u64> {
    if text.is_empty() {
        return None;
    }
    let mut value = 0u64;
    for byte in text {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(u64::from(byte - b'0'))?;
    }
    Some(value)
}

/// Writes `value` into `out` as decimal, returning the digits.
pub fn decimal(value: u64, out: &mut [u8; 20]) -> &[u8] {
    if value == 0 {
        out[0] = b'0';
        return &out[..1];
    }
    let mut digits = 0;
    let mut remaining = value;
    while remaining > 0 {
        out[digits] = b'0' + (remaining % 10) as u8;
        remaining /= 10;
        digits += 1;
    }
    out[..digits].reverse();
    &out[..digits]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn last_line(console: &Console) -> std::vec::Vec<u8> {
        let mut last = std::vec::Vec::new();
        console.each_line(|_, line| {
            last.clear();
            last.extend_from_slice(line);
        });
        last
    }

    fn type_line(console: &mut Console, text: &str) -> Action {
        for byte in text.bytes() {
            console.type_char(byte);
        }
        console.enter()
    }

    #[test]
    fn typing_and_backspace_build_a_line() {
        let mut console = Console::new();
        for byte in b"helo" {
            console.type_char(*byte);
        }
        console.backspace();
        console.type_char(b'p');
        assert_eq!(console.input(), b"help");
    }

    #[test]
    fn backspace_on_an_empty_line_does_nothing() {
        // `saturating_sub` rather than a subtraction that would wrap to a
        // length past the end of the buffer.
        let mut console = Console::new();
        console.backspace();
        assert_eq!(console.input(), b"");
    }

    #[test]
    fn typing_past_the_limit_truncates_rather_than_growing() {
        // A shell that can be made to allocate by typing is one that can be
        // made to run out of memory by typing.
        let mut console = Console::new();
        for _ in 0..INPUT_LIMIT * 2 {
            console.type_char(b'x');
        }
        assert_eq!(console.input().len(), INPUT_LIMIT);
    }

    #[test]
    fn a_command_is_echoed_before_its_output() {
        // So the history reads like a transcript rather than a list of answers
        // to questions nobody can see.
        let mut console = Console::new();
        type_line(&mut console, "devices");
        let mut first = std::vec::Vec::new();
        console.each_line(|index, line| {
            if index == 0 {
                first.extend_from_slice(line);
            }
        });
        assert_eq!(first, b"> devices");
    }

    #[test]
    fn an_unknown_command_says_so_and_names_it() {
        let mut console = Console::new();
        type_line(&mut console, "frobnicate");
        let mut found = false;
        console.each_line(|_, line| {
            if line.starts_with(b"unknown command: frobnicate") {
                found = true;
            }
        });
        assert!(found, "the command was not named back");
    }

    #[test]
    fn clearing_the_history_leaves_a_half_typed_line_alone() {
        // Clearing the screen while somebody is halfway through a word should
        // not eat the word. `enter` clears the input because the line has been
        // run; `clear` is a different operation and must not.
        let mut console = Console::new();
        type_line(&mut console, "devices");
        console.type_char(b'a');
        console.type_char(b'b');

        console.clear();

        let mut lines = 0;
        console.each_line(|_, _| lines += 1);
        assert_eq!(lines, 0, "history survived a clear");
        assert_eq!(console.input(), b"ab", "a half-typed line was eaten");
    }

    #[test]
    fn the_history_drops_the_oldest_line_rather_than_growing() {
        let mut console = Console::new();
        for index in 0..ROWS * 3 {
            let mut text = [b' '; 8];
            text[0] = b'0' + (index % 10) as u8;
            console.print(&text[..1]);
        }
        let mut count = 0;
        console.each_line(|_, _| count += 1);
        assert_eq!(count, ROWS);
        // The newest line is the last one printed, which is what a ring that
        // rotated its start correctly produces.
        assert_eq!(last_line(&console), [b'0' + ((ROWS * 3 - 1) % 10) as u8]);
    }

    #[test]
    fn uptime_is_asked_for_rather_than_answered() {
        // The console has no clock. Giving it one would mean giving it a
        // syscall, and every rule in this file is testable precisely because it
        // has none.
        let mut console = Console::new();
        assert_eq!(type_line(&mut console, "uptime"), Action::Uptime);
    }

    #[test]
    fn read_takes_a_sector_number() {
        let mut console = Console::new();
        assert_eq!(type_line(&mut console, "read 41"), Action::ReadSector(41));
    }

    #[test]
    fn read_without_a_number_is_refused_rather_than_guessed() {
        let mut console = Console::new();
        assert_eq!(type_line(&mut console, "read"), Action::None);
        assert_eq!(type_line(&mut console, "read xyz"), Action::None);
    }

    #[test]
    fn a_number_with_trailing_rubbish_is_not_a_number() {
        // `read 12x` is a typo, and answering it with sector 12 is doing
        // something the person did not ask for.
        assert_eq!(parse_number(b"12x"), None);
        assert_eq!(parse_number(b"12"), Some(12));
        assert_eq!(parse_number(b""), None);
    }

    #[test]
    fn a_number_too_large_to_hold_is_refused_rather_than_wrapped() {
        assert_eq!(parse_number(b"99999999999999999999999"), None);
    }

    #[test]
    fn clear_asks_for_a_redraw() {
        // The console cannot draw. Saying so is how the session knows the
        // screen underneath it is stale.
        let mut console = Console::new();
        assert_eq!(type_line(&mut console, "clear"), Action::Redraw);
    }

    #[test]
    fn surrounding_spaces_do_not_change_a_command() {
        let mut console = Console::new();
        assert_eq!(
            type_line(&mut console, "   read   7  "),
            Action::ReadSector(7)
        );
    }

    #[test]
    fn an_empty_line_does_nothing() {
        let mut console = Console::new();
        assert_eq!(type_line(&mut console, ""), Action::None);
        assert_eq!(type_line(&mut console, "     "), Action::None);
    }

    #[test]
    fn echo_prints_what_follows_it() {
        let mut console = Console::new();
        type_line(&mut console, "echo hello there");
        assert_eq!(last_line(&console), b"hello there");
    }

    #[test]
    fn decimal_renders_the_numbers_it_is_given() {
        let mut out = [0u8; 20];
        assert_eq!(decimal(0, &mut out), b"0");
        let mut out = [0u8; 20];
        assert_eq!(decimal(1, &mut out), b"1");
        let mut out = [0u8; 20];
        assert_eq!(decimal(4096, &mut out), b"4096");
        let mut out = [0u8; 20];
        assert_eq!(decimal(u64::MAX, &mut out), b"18446744073709551615");
    }
}
