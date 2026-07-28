//! A small, allocation-free text editor for the desktop Notepad window.
//!
//! The editor owns only text state. Disk I/O stays in the session, so every
//! edit operation can be verified by the host test harness without a VM.

#![allow(dead_code)]

use crate::keymap::Key;

/// Matches the fixed extent used by the mounted desktop filesystem.
pub const CAPACITY: usize = 4096;
pub const NAME_CAPACITY: usize = 50;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    None,
    Redraw,
    Save,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ready,
    Modified,
    Saved,
    SaveFailed,
    Full,
}

pub struct Editor {
    bytes: [u8; CAPACITY],
    length: usize,
    cursor: usize,
    file_id: Option<u16>,
    name: [u8; NAME_CAPACITY],
    name_len: usize,
    dirty: bool,
    status: Status,
}

impl Default for Editor {
    fn default() -> Self {
        Self::new()
    }
}

impl Editor {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bytes: [0; CAPACITY],
            length: 0,
            cursor: 0,
            file_id: None,
            name: [0; NAME_CAPACITY],
            name_len: 0,
            dirty: false,
            status: Status::Ready,
        }
    }

    pub fn open(&mut self, file_id: u16, name: &[u8], text: &[u8]) {
        self.bytes.fill(0);
        self.name.fill(0);
        self.length = text.len().min(CAPACITY);
        self.bytes[..self.length].copy_from_slice(&text[..self.length]);
        self.cursor = 0;
        self.file_id = Some(file_id);
        self.name_len = name.len().min(NAME_CAPACITY);
        self.name[..self.name_len].copy_from_slice(&name[..self.name_len]);
        self.dirty = false;
        self.status = Status::Ready;
    }

    #[must_use]
    pub fn text(&self) -> &[u8] {
        &self.bytes[..self.length]
    }

    #[must_use]
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    #[must_use]
    pub const fn file_id(&self) -> Option<u16> {
        self.file_id
    }

    #[must_use]
    pub const fn dirty(&self) -> bool {
        self.dirty
    }

    #[must_use]
    pub const fn status(&self) -> Status {
        self.status
    }

    pub fn saved(&mut self, ok: bool) {
        self.dirty = !ok;
        self.status = if ok {
            Status::Saved
        } else {
            Status::SaveFailed
        };
    }

    pub fn apply(&mut self, key: Key) -> Action {
        match key {
            Key::Char(byte) => self.insert(byte),
            Key::Enter => self.insert(b'\n'),
            Key::Backspace => self.backspace(),
            Key::Delete => self.delete(),
            Key::Left => self.move_left(),
            Key::Right => self.move_right(),
            Key::Up => self.move_vertical(false),
            Key::Down => self.move_vertical(true),
            Key::Home => self.move_home(),
            Key::End => self.move_end(),
            Key::Save => return Action::Save,
            Key::None => return Action::None,
        }
        Action::Redraw
    }

    fn insert(&mut self, byte: u8) {
        if self.length == CAPACITY {
            self.status = Status::Full;
            return;
        }
        self.bytes
            .copy_within(self.cursor..self.length, self.cursor + 1);
        self.bytes[self.cursor] = byte;
        self.cursor += 1;
        self.length += 1;
        self.changed();
    }

    fn backspace(&mut self) {
        if self.cursor == 0 {
            return;
        }
        self.bytes
            .copy_within(self.cursor..self.length, self.cursor - 1);
        self.cursor -= 1;
        self.length -= 1;
        self.bytes[self.length] = 0;
        self.changed();
    }

    fn delete(&mut self) {
        if self.cursor == self.length {
            return;
        }
        self.bytes
            .copy_within(self.cursor + 1..self.length, self.cursor);
        self.length -= 1;
        self.bytes[self.length] = 0;
        self.changed();
    }

    fn changed(&mut self) {
        self.dirty = true;
        self.status = Status::Modified;
    }

    fn move_left(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    fn move_right(&mut self) {
        self.cursor = (self.cursor + 1).min(self.length);
    }

    fn line_bounds(&self, at: usize) -> (usize, usize) {
        let mut start = at.min(self.length);
        while start > 0 && self.bytes[start - 1] != b'\n' {
            start -= 1;
        }
        let mut end = at.min(self.length);
        while end < self.length && self.bytes[end] != b'\n' {
            end += 1;
        }
        (start, end)
    }

    fn move_home(&mut self) {
        self.cursor = self.line_bounds(self.cursor).0;
    }

    fn move_end(&mut self) {
        self.cursor = self.line_bounds(self.cursor).1;
    }

    fn move_vertical(&mut self, down: bool) {
        let (start, end) = self.line_bounds(self.cursor);
        let column = self.cursor - start;
        if down {
            if end == self.length {
                return;
            }
            let next_start = end + 1;
            let next_end = self.line_bounds(next_start).1;
            self.cursor = next_start + column.min(next_end - next_start);
        } else {
            if start == 0 {
                return;
            }
            let previous_end = start - 1;
            let previous_start = self.line_bounds(previous_end).0;
            self.cursor = previous_start + column.min(previous_end - previous_start);
        }
    }

    /// Places the caret at a visible row and column.
    pub fn place(&mut self, wanted_row: usize, wanted_column: usize) {
        let mut row = 0usize;
        let mut start = 0usize;
        while row < wanted_row {
            let Some(relative) = self.bytes[start..self.length]
                .iter()
                .position(|byte| *byte == b'\n')
            else {
                self.cursor = self.length;
                return;
            };
            start += relative + 1;
            row += 1;
        }
        let end = self.line_bounds(start).1;
        self.cursor = start + wanted_column.min(end - start);
    }

    #[must_use]
    pub fn line(&self, wanted: usize) -> Option<&[u8]> {
        let mut row = 0usize;
        let mut start = 0usize;
        loop {
            let end = self.line_bounds(start).1;
            if row == wanted {
                return Some(&self.bytes[start..end]);
            }
            if end == self.length {
                return None;
            }
            start = end + 1;
            row += 1;
        }
    }

    #[must_use]
    pub fn cursor_line_column(&self) -> (usize, usize) {
        let mut row = 0usize;
        let mut start = 0usize;
        for (index, byte) in self.bytes[..self.cursor].iter().enumerate() {
            if *byte == b'\n' {
                row += 1;
                start = index + 1;
            }
        }
        (row, self.cursor - start)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inserts_in_the_middle_and_deletes_on_both_sides() {
        let mut editor = Editor::new();
        editor.open(7, b"TEST.TXT", b"ac");
        editor.apply(Key::Right);
        editor.apply(Key::Char(b'b'));
        assert_eq!(editor.text(), b"abc");
        editor.apply(Key::Backspace);
        assert_eq!(editor.text(), b"ac");
        editor.apply(Key::Delete);
        assert_eq!(editor.text(), b"a");
    }

    #[test]
    fn arrows_preserve_the_column_where_possible() {
        let mut editor = Editor::new();
        editor.open(3, b"LINES.TXT", b"first\nx\nthird");
        editor.place(2, 4);
        editor.apply(Key::Up);
        assert_eq!(editor.cursor_line_column(), (1, 1));
        editor.apply(Key::Up);
        assert_eq!(editor.cursor_line_column(), (0, 1));
        editor.apply(Key::Down);
        assert_eq!(editor.cursor_line_column(), (1, 1));
    }

    #[test]
    fn save_is_a_request_and_success_clears_dirty() {
        let mut editor = Editor::new();
        editor.open(1, b"NOTE.TXT", b"");
        editor.apply(Key::Char(b'a'));
        assert!(editor.dirty());
        assert_eq!(editor.apply(Key::Save), Action::Save);
        editor.saved(true);
        assert!(!editor.dirty());
        assert_eq!(editor.status(), Status::Saved);
    }

    #[test]
    fn clicking_past_a_short_line_stops_at_its_end() {
        let mut editor = Editor::new();
        editor.open(2, b"CLICK.TXT", b"one\ntwo");
        editor.place(0, 40);
        assert_eq!(editor.cursor_line_column(), (0, 3));
    }
}
