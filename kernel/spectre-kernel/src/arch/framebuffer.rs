//! The kernel's on-screen console.
//!
//! Everything the kernel says already goes to the serial port, which is the
//! console that works when nothing else does. This is the one a person can look
//! at: the same lines, on the display the firmware left running.
//!
//! # No mode set, no driver, no GPU
//!
//! The loader hands over the framebuffer the firmware already configured —
//! base address, geometry, stride — and this writes pixels into it. There is no
//! device driver here and there will never be one: the graphics stack is a
//! user-space process, and this exists for the window before any user-space
//! process is running, and for after one has crashed.
//!
//! # It scrolls, because the arithmetic said it could
//!
//! Wrapping to the top would be cheaper and was the first thing here. It is
//! also the wrong trade: a boot produces about seventy-five lines and a
//! 1280x800 screen holds forty-seven, so wrapping throws away the beginning —
//! which is the part that says what the machine is and whether the handoff was
//! sane.
//!
//! Scrolling costs one move of the text area per line, which at this geometry
//! is under four megabytes; the thirty-odd scrolls a boot needs come to about a
//! hundred megabytes of copying, once, through a cacheable mapping. That is
//! milliseconds. The serial log remains the full record either way.
//!
//! # The mapping is write-back, and that is a compromise
//!
//! The kernel's identity map covers the first four gigabytes in 2 MiB pages, so
//! the framebuffer is already mapped — as ordinary cacheable memory. A
//! framebuffer wants write-combining, and getting it means splitting a large
//! page to change the cache type of the range. On QEMU the difference is
//! invisible. On real hardware it is slow rather than wrong, and it is the same
//! page-splitting work a memory-mapped device driver will need, so it is left
//! for when that arrives rather than done twice.

use core::fmt;

use spin::Mutex;

use crate::boot_info::Framebuffer;
use crate::font::{self, GLYPH_HEIGHT, GLYPH_WIDTH};

/// Pixel doubling. At 1280x800 this gives about 100 columns of readable text;
/// unscaled, a 5x7 glyph is too small to read on a real display.
const SCALE: usize = 2;
/// Blank rows between text lines.
const LINE_GAP: usize = 2;
/// Left and right margin.
const MARGIN: usize = 12;
/// Height of the banner across the top.
const HEADER_HEIGHT: usize = 34;

/// Rows at the bottom the kernel console will not touch.
///
/// This is the first line drawn between kernel and user space, and it is drawn
/// in pixels. A user-space display driver maps this same framebuffer and writes
/// to it; with no compositor and nothing arbitrating, the only thing keeping
/// the two from scrolling over each other is an agreement about who writes
/// where. The kernel takes the top and leaves this band alone.
///
/// A placeholder for the arrangement that replaces it — the compositor owning
/// the display outright, and this console being what it falls back to — but a
/// placeholder that is honest about which side owns which pixels.
pub const USER_BAND_HEIGHT: usize = 104;

const CELL_WIDTH: usize = GLYPH_WIDTH * SCALE;
const CELL_HEIGHT: usize = GLYPH_HEIGHT * SCALE + LINE_GAP;

/// Longest line held before it is drawn.
///
/// Output arrives as fragments, but colour is chosen per line from its prefix,
/// so a line is buffered until its newline. Anything longer is drawn in pieces,
/// which costs nothing but the colour of the overflow.
const LINE_BUFFER: usize = 160;

mod colour {
    /// `0x00RRGGBB`. The framebuffer is 32 bits per pixel with the top byte
    /// unused, which is what every UEFI GOP mode this runs on reports.
    pub const BACKGROUND: u32 = 0x0004_0810;
    pub const HEADER: u32 = 0x0019_E6FF;
    pub const HEADER_TEXT: u32 = 0x000A_1420;
    pub const KERNEL: u32 = 0x00A8_D8F0;
    pub const USER: u32 = 0x00E8_F4FF;
    pub const LOADER: u32 = 0x0070_90A8;
    pub const WARNING: u32 = 0x00FF_C14D;
    pub const FAILURE: u32 = 0x00FF_5C5C;
    pub const GOOD: u32 = 0x0052_FFAE;
}

struct Console {
    base: *mut u32,
    width: usize,
    height: usize,
    /// Pixels, not bytes, per scanline. They differ on most real hardware.
    stride: usize,
    /// Next cell to draw into.
    column: usize,
    row: usize,
    line: [u8; LINE_BUFFER],
    line_len: usize,
}

// SAFETY: the pointer is a physical framebuffer address the loader reported and
// the identity map covers. It is only ever written through the mutex below, and
// nothing else in the kernel touches that range.
unsafe impl Send for Console {}

static CONSOLE: Mutex<Option<Console>> = Mutex::new(None);

/// Brings up the on-screen console, if the handoff described a framebuffer.
///
/// Returns whether there is a screen to write to.
///
/// # Safety
/// `fb` must describe the framebuffer the firmware left running, and physical
/// memory must be identity mapped.
pub unsafe fn init(fb: &Framebuffer) -> bool {
    if !fb.is_present() || fb.bytes_per_pixel != 4 || fb.byte_len().is_none() {
        return false;
    }

    let mut console = Console {
        base: fb.base as *mut u32,
        width: fb.width as usize,
        height: fb.height as usize,
        stride: fb.stride as usize,
        column: 0,
        row: 0,
        line: [0; LINE_BUFFER],
        line_len: 0,
    };
    if console.rows() == 0 || console.columns() == 0 {
        return false;
    }

    console.clear();
    console.draw_header();
    *CONSOLE.lock() = Some(console);
    true
}

impl Console {
    const fn columns(&self) -> usize {
        (self.width.saturating_sub(MARGIN * 2)) / CELL_WIDTH
    }

    const fn rows(&self) -> usize {
        self.height
            .saturating_sub(HEADER_HEIGHT + LINE_GAP + USER_BAND_HEIGHT)
            / CELL_HEIGHT
    }

    fn put(&mut self, x: usize, y: usize, colour: u32) {
        if x >= self.width || y >= self.height {
            return;
        }
        // SAFETY: bounds checked against the geometry the loader reported, and
        // the whole framebuffer is inside the identity map.
        unsafe { self.base.add(y * self.stride + x).write_volatile(colour) };
    }

    fn fill(&mut self, x: usize, y: usize, w: usize, h: usize, colour: u32) {
        for row in y..(y + h).min(self.height) {
            for column in x..(x + w).min(self.width) {
                self.put(column, row, colour);
            }
        }
    }

    fn clear(&mut self) {
        // Only the kernel's own area. The band below belongs to whichever
        // process was granted the display, and clearing it here would erase
        // that process's work.
        let (w, h) = (self.width, self.height);
        self.fill(
            0,
            0,
            w,
            h.saturating_sub(USER_BAND_HEIGHT),
            colour::BACKGROUND,
        );
    }

    fn draw_header(&mut self) {
        let width = self.width;
        self.fill(0, 0, width, HEADER_HEIGHT, colour::HEADER);
        self.draw_text(
            MARGIN,
            (HEADER_HEIGHT - GLYPH_HEIGHT * SCALE) / 2,
            b"WHISEZOS MICROKERNEL",
            colour::HEADER_TEXT,
        );
    }

    fn draw_text(&mut self, x: usize, y: usize, text: &[u8], colour: u32) {
        for (index, &byte) in text.iter().enumerate() {
            let rows = font::glyph(font::normalise(byte));
            for (row, bits) in rows.iter().copied().enumerate() {
                for column in 0..5usize {
                    if bits & (1 << (4 - column)) == 0 {
                        continue;
                    }
                    for sy in 0..SCALE {
                        for sx in 0..SCALE {
                            self.put(
                                x + index * CELL_WIDTH + column * SCALE + sx,
                                y + row * SCALE + sy,
                                colour,
                            );
                        }
                    }
                }
            }
        }
    }

    /// Chooses a colour from what the line says about itself.
    ///
    /// A warning that looks like every other line is a warning nobody reads,
    /// and on a screen that wraps, colour is the only thing that survives.
    fn colour_for(line: &[u8]) -> u32 {
        const fn contains(haystack: &[u8], needle: &[u8]) -> bool {
            if needle.len() > haystack.len() {
                return false;
            }
            let mut start = 0;
            while start + needle.len() <= haystack.len() {
                let mut i = 0;
                while i < needle.len() && haystack[start + i] == needle[i] {
                    i += 1;
                }
                if i == needle.len() {
                    return true;
                }
                start += 1;
            }
            false
        }

        if contains(line, b"FAILED")
            || contains(line, b"DEADLOCK")
            || contains(line, b"REJECTED")
            || contains(line, b"LEAK")
            || contains(line, b"fatal")
            || contains(line, b"panic")
        {
            colour::FAILURE
        } else if contains(line, b"WARNING") {
            colour::WARNING
        } else if contains(line, b"complete") || contains(line, b"balanced") {
            colour::GOOD
        } else if contains(line, b"[init") {
            colour::USER
        } else if contains(line, b"[boot]") {
            colour::LOADER
        } else {
            colour::KERNEL
        }
    }

    fn newline(&mut self) {
        let colour = Self::colour_for(&self.line[..self.line_len]);
        let x = MARGIN;
        let y = HEADER_HEIGHT + LINE_GAP + self.row * CELL_HEIGHT;
        let len = self.line_len.min(self.columns());
        let mut text = [0u8; LINE_BUFFER];
        text[..len].copy_from_slice(&self.line[..len]);
        self.draw_text(x, y, &text[..len], colour);

        self.line_len = 0;
        self.column = 0;
        self.row += 1;
        if self.row >= self.rows() {
            self.scroll();
            self.row = self.rows() - 1;
        }
    }

    /// Moves the text area up by one line and clears the row it frees.
    ///
    /// The header is not part of the move: it is drawn once and stays.
    fn scroll(&mut self) {
        let top = HEADER_HEIGHT + LINE_GAP;
        let bottom = top + self.rows() * CELL_HEIGHT;

        for y in (top + CELL_HEIGHT)..bottom {
            for x in 0..self.width {
                // SAFETY: both offsets are inside the framebuffer — `y` is
                // below `bottom`, which the row count keeps inside the screen,
                // and the source row is `CELL_HEIGHT` above it.
                unsafe {
                    let value = self.base.add(y * self.stride + x).read_volatile();
                    self.base
                        .add((y - CELL_HEIGHT) * self.stride + x)
                        .write_volatile(value);
                }
            }
        }

        let width = self.width;
        self.fill(
            0,
            bottom - CELL_HEIGHT,
            width,
            CELL_HEIGHT,
            colour::BACKGROUND,
        );
    }

    fn write_byte(&mut self, byte: u8) {
        match byte {
            b'\n' => self.newline(),
            // The serial console needs carriage returns; the screen does not.
            b'\r' => {}
            _ => {
                if self.line_len == LINE_BUFFER || self.column == self.columns() {
                    self.newline();
                }
                self.line[self.line_len] = byte;
                self.line_len += 1;
                self.column += 1;
            }
        }
    }
}

impl fmt::Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            self.write_byte(byte);
        }
        Ok(())
    }
}

/// Mirrors console output to the screen, if there is one.
pub fn write(args: fmt::Arguments<'_>) {
    if let Some(console) = CONSOLE.lock().as_mut() {
        let _ = fmt::Write::write_fmt(console, args);
    }
}

/// Whether anything is being drawn.
#[must_use]
pub fn is_active() -> bool {
    CONSOLE.lock().is_some()
}
