//! Pointer input model for the preview shell.
//!
//! Split out from `demo.rs` for two reasons. The first is that this is the part
//! that was actually broken: the shell latched both mouse buttons through a
//! single `left_down` flag, so a right-click was reported whenever the *left*
//! button had been released, and never when the right button was pressed on its
//! own. The second is that none of this needs UEFI to be exercised — feeding a
//! sequence of readings through `Cursor` and `ButtonEdges` on the host catches
//! that class of bug without booting anything.
//!
//! The other half of the fix lives in `demo.rs`: firmware may expose a pointer
//! as either `EFI_SIMPLE_POINTER_PROTOCOL` (relative deltas, needs the VM to
//! grab the host mouse) or `EFI_ABSOLUTE_POINTER_PROTOCOL` (a tablet-style
//! digitiser reporting a position). This module accepts both shapes so the
//! caller can merge every device it finds into one cursor.

#![allow(dead_code)]

/// Software cursor footprint, in pixels.
pub const CURSOR_WIDTH: usize = 34;
pub const CURSOR_HEIGHT: usize = 48;

/// A single reading from one pointing device, normalised away from the two
/// different UEFI protocol shapes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Motion {
    /// `EFI_SIMPLE_POINTER_PROTOCOL`: movement since the previous read.
    Relative { dx: i32, dy: i32 },
    /// `EFI_ABSOLUTE_POINTER_PROTOCOL`: a position inside the digitiser's own
    /// coordinate space, which is *not* the screen's and has to be rescaled.
    Absolute {
        x: u64,
        y: u64,
        min: (u64, u64),
        max: (u64, u64),
    },
}

/// Button state as reported by a device on one read.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Buttons {
    pub left: bool,
    pub right: bool,
}

impl Buttons {
    #[must_use]
    pub const fn or(self, other: Self) -> Self {
        Self {
            left: self.left || other.left,
            right: self.right || other.right,
        }
    }
}

/// Press events derived from two consecutive `Buttons` samples.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Clicks {
    pub left: bool,
    pub right: bool,
}

impl Clicks {
    #[must_use]
    pub const fn any(self) -> bool {
        self.left || self.right
    }
}

/// Rising-edge detector, one latch per button.
#[derive(Debug, Clone, Copy, Default)]
pub struct ButtonEdges {
    held: Buttons,
}

impl ButtonEdges {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            held: Buttons {
                left: false,
                right: false,
            },
        }
    }

    /// Feeds the current sample and returns the buttons that went down on this
    /// transition. Holding a button reports exactly one click, not one per poll.
    pub fn update(&mut self, now: Buttons) -> Clicks {
        let clicks = Clicks {
            left: now.left && !self.held.left,
            right: now.right && !self.held.right,
        };
        self.held = now;
        clicks
    }
}

/// Screen-space cursor position, clamped to the framebuffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cursor {
    pub x: usize,
    pub y: usize,
    width: usize,
    height: usize,
}

impl Cursor {
    /// Starts at the centre of the screen so the cursor is visible on the first
    /// frame even before any device has reported anything.
    #[must_use]
    pub const fn centered(width: usize, height: usize) -> Self {
        Self {
            x: width / 2,
            y: height / 2,
            width,
            height,
        }
    }

    /// Applies one reading. Returns whether the cursor actually moved, so the
    /// caller can skip the blit when it did not.
    pub fn apply(&mut self, motion: Motion) -> bool {
        let (nx, ny) = match motion {
            Motion::Relative { dx, dy } => (
                offset(self.x, clamp_delta(dx), self.width),
                offset(self.y, clamp_delta(dy), self.height),
            ),
            Motion::Absolute { x, y, min, max } => (
                rescale(x, min.0, max.0, self.width),
                rescale(y, min.1, max.1, self.height),
            ),
        };

        let moved = nx != self.x || ny != self.y;
        self.x = nx;
        self.y = ny;
        moved
    }

    #[must_use]
    pub const fn position(&self) -> (usize, usize) {
        (self.x, self.y)
    }
}

/// A wild delta from a misbehaving device should not teleport the cursor across
/// the screen; a real mouse never reports more than a few dozen counts per poll.
fn clamp_delta(raw: i32) -> isize {
    raw.clamp(-64, 64) as isize
}

fn offset(value: usize, delta: isize, extent: usize) -> usize {
    let limit = extent.saturating_sub(1);
    if delta < 0 {
        value.saturating_sub(delta.unsigned_abs()).min(limit)
    } else {
        value.saturating_add(delta as usize).min(limit)
    }
}

/// Maps a digitiser axis onto a screen axis.
///
/// A tablet that reports a degenerate range (`max <= min`) is not usable for
/// positioning — OVMF does this for an axis a device does not have, notably Z.
/// Mapping to the centre keeps the cursor somewhere sane instead of pinning it
/// to a corner or dividing by zero.
fn rescale(value: u64, min: u64, max: u64, extent: usize) -> usize {
    let limit = extent.saturating_sub(1);
    if max <= min {
        return limit / 2;
    }
    let span = max - min;
    let clamped = value.clamp(min, max) - min;
    ((clamped * limit as u64) / span) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn right_button_click_is_not_derived_from_the_left_latch() {
        // The regression this module exists for. Pressing only the right button
        // must report a right click, and must not report a left one.
        let mut edges = ButtonEdges::new();
        let clicks = edges.update(Buttons {
            left: false,
            right: true,
        });
        assert!(clicks.right);
        assert!(!clicks.left);
    }

    #[test]
    fn releasing_the_left_button_does_not_fabricate_a_right_click() {
        let mut edges = ButtonEdges::new();
        edges.update(Buttons {
            left: true,
            right: false,
        });
        let clicks = edges.update(Buttons::default());
        assert!(!clicks.left);
        assert!(!clicks.right);
    }

    #[test]
    fn holding_a_button_reports_exactly_one_click() {
        let mut edges = ButtonEdges::new();
        let down = Buttons {
            left: true,
            right: false,
        };
        assert!(edges.update(down).left);
        for _ in 0..10 {
            assert!(!edges.update(down).left, "auto-repeat while held");
        }
        edges.update(Buttons::default());
        assert!(edges.update(down).left, "click again after release");
    }

    #[test]
    fn both_buttons_track_independently() {
        let mut edges = ButtonEdges::new();
        edges.update(Buttons {
            left: true,
            right: false,
        });
        let clicks = edges.update(Buttons {
            left: true,
            right: true,
        });
        assert!(clicks.right, "right press while left is held");
        assert!(!clicks.left, "left was already down");
    }

    #[test]
    fn merging_devices_keeps_any_pressed_button() {
        let a = Buttons {
            left: true,
            right: false,
        };
        let b = Buttons {
            left: false,
            right: true,
        };
        assert_eq!(
            a.or(b),
            Buttons {
                left: true,
                right: true
            }
        );
    }

    #[test]
    fn cursor_starts_centered() {
        assert_eq!(Cursor::centered(800, 600).position(), (400, 300));
    }

    #[test]
    fn relative_motion_accumulates_and_clamps_to_the_screen() {
        let mut cursor = Cursor::centered(800, 600);
        assert!(cursor.apply(Motion::Relative { dx: 10, dy: -10 }));
        assert_eq!(cursor.position(), (410, 290));

        for _ in 0..100 {
            cursor.apply(Motion::Relative { dx: 64, dy: 64 });
        }
        assert_eq!(cursor.position(), (799, 599), "clamped to the last pixel");

        for _ in 0..100 {
            cursor.apply(Motion::Relative { dx: -64, dy: -64 });
        }
        assert_eq!(cursor.position(), (0, 0), "no wrap-around at the origin");
    }

    #[test]
    fn oversized_deltas_cannot_teleport_the_cursor() {
        let mut cursor = Cursor::centered(800, 600);
        cursor.apply(Motion::Relative {
            dx: i32::MAX,
            dy: i32::MIN,
        });
        assert_eq!(cursor.position(), (464, 236));
    }

    #[test]
    fn a_stationary_reading_reports_no_movement() {
        let mut cursor = Cursor::centered(800, 600);
        assert!(!cursor.apply(Motion::Relative { dx: 0, dy: 0 }));
    }

    #[test]
    fn absolute_readings_map_onto_the_whole_screen() {
        let mut cursor = Cursor::centered(800, 600);
        let corners = [
            ((0, 0), (0, 0)),
            ((32767, 32767), (799, 599)),
            ((16383, 16383), (399, 299)),
        ];
        for ((x, y), expected) in corners {
            cursor.apply(Motion::Absolute {
                x,
                y,
                min: (0, 0),
                max: (32767, 32767),
            });
            assert_eq!(cursor.position(), expected);
        }
    }

    #[test]
    fn absolute_readings_outside_the_reported_range_are_clamped() {
        let mut cursor = Cursor::centered(800, 600);
        cursor.apply(Motion::Absolute {
            x: 99_999,
            y: 0,
            min: (100, 100),
            max: (900, 900),
        });
        assert_eq!(cursor.position(), (799, 0));
    }

    #[test]
    fn a_degenerate_axis_parks_the_cursor_instead_of_dividing_by_zero() {
        // OVMF reports min == max for an axis the device does not have.
        let mut cursor = Cursor::centered(800, 600);
        cursor.apply(Motion::Absolute {
            x: 5,
            y: 5,
            min: (0, 0),
            max: (0, 0),
        });
        assert_eq!(cursor.position(), (399, 299));
    }
}
