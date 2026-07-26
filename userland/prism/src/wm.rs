//! Window manager: lifecycle state machine and animation dispatch.
//!
//! The compositor is a user-space process holding exactly three capabilities:
//! the GPU driver endpoint, the input endpoint, and a display-controller MMIO
//! window. It cannot read another process's memory, cannot touch the disk, and
//! cannot open a socket. A compromised compositor can show you a fake login
//! screen — which is why the login screen runs in a *separate* process with the
//! display capability temporarily transferred, and why the lock screen's
//! unlock path never crosses this process.

use crate::anim::{ns_from_ms, Animation, Bezier, Quality, Repeat};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleState {
    Opening,
    Normal,
    Dragging,
    Minimising,
    Minimised,
    Restoring,
    Closing,
    /// Terminal state; the window's resources are released on the next frame.
    Gone,
}

/// Durations, in one place so a theme can override them coherently.
///
/// These are tuned against the 100 ms perceptual threshold: a window must show
/// *some* response within 100 ms of the click or it feels broken, but the
/// animation may continue past that. Every open animation therefore covers more
/// than half its visual distance in the first 100 ms (see `Bezier::SPECTRE_OUT`)
/// even though it runs for 280 ms total.
pub mod timing {
    use super::ns_from_ms;
    pub const OPEN_NS: u64 = ns_from_ms(280);
    pub const CLOSE_NS: u64 = ns_from_ms(340);
    pub const MINIMISE_NS: u64 = ns_from_ms(380);
    pub const RESTORE_NS: u64 = ns_from_ms(300);
    /// Drag trail decay after the pointer stops.
    pub const TRAIL_DECAY_NS: u64 = ns_from_ms(180);
}

pub struct Window {
    pub id: WindowId,
    pub state: LifecycleState,
    pub rect: Rect,
    pub depth_layer: f32,
    pub focused: bool,
    /// Windows from WinBridge get the "W" badge and are otherwise identical.
    pub foreign: bool,
    transition: Option<Transition>,
    border_pulse: Animation,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Rect {
    pub x: f32,
    pub y: f32,
    pub w: f32,
    pub h: f32,
}

impl Rect {
    pub fn centre(&self) -> (f32, f32) {
        (self.x + self.w * 0.5, self.y + self.h * 0.5)
    }
}

struct Transition {
    kind: LifecycleState,
    progress: Animation,
    /// Screen-space origin for open/close warps.
    singularity: (f32, f32),
}

impl Window {
    pub fn new(id: WindowId, rect: Rect, now_ns: u64, singularity: (f32, f32)) -> Self {
        Window {
            id,
            state: LifecycleState::Opening,
            rect,
            depth_layer: 0.0,
            focused: true,
            foreign: false,
            transition: Some(Transition {
                kind: LifecycleState::Opening,
                progress: Animation {
                    start_ns: now_ns,
                    duration_ns: timing::OPEN_NS,
                    curve: Bezier::SPECTRE_OUT,
                    from: 0.0,
                    to: 1.0,
                    repeat: Repeat::Once,
                },
                singularity,
            }),
            border_pulse: crate::anim::border_pulse(now_ns),
        }
    }

    /// Request a state change.
    ///
    /// Interruption handling is the point of this function. A user who clicks
    /// close while a window is still opening must get a close, immediately,
    /// from wherever the open animation currently is — not a queued close after
    /// the open finishes, and not a snap to fully-open followed by a close.
    /// Both of those are what you get from the naive implementation, and both
    /// feel broken.
    pub fn request(&mut self, target: LifecycleState, now_ns: u64) -> bool {
        use LifecycleState::*;

        let valid = matches!(
            (self.state, target),
            (Opening, Normal | Closing | Dragging)
                | (Normal, Dragging | Minimising | Closing)
                | (Dragging, Normal | Closing)
                | (Minimising, Minimised | Restoring | Closing)
                | (Minimised, Restoring | Closing)
                | (Restoring, Normal | Minimising | Closing)
                | (Closing, Gone)
        );

        if !valid {
            return false;
        }

        let current_progress = self
            .transition
            .as_ref()
            .map(|t| t.progress.sample(now_ns))
            .unwrap_or(1.0);

        let (duration, curve) = match target {
            Opening | Restoring => (timing::RESTORE_NS, Bezier::SPECTRE_OUT),
            Closing => (timing::CLOSE_NS, Bezier::SPECTRE_IN),
            Minimising => (timing::MINIMISE_NS, Bezier::SPECTRE_IN_OUT),
            _ => (0, Bezier::LINEAR),
        };

        // Scale the duration by how far we have to travel. Interrupting a
        // 90%-open window into a close should take ~90% of the close duration,
        // not the full duration — otherwise the interruption looks slower than
        // the uninterrupted case.
        let remaining = if matches!(target, Closing | Minimising) {
            current_progress
        } else {
            1.0 - current_progress
        };
        let scaled = (duration as f32 * remaining.clamp(0.15, 1.0)) as u64;

        let singularity = self
            .transition
            .as_ref()
            .map(|t| t.singularity)
            .unwrap_or_else(|| self.rect.centre());

        self.transition = if duration == 0 {
            None
        } else {
            Some(Transition {
                kind: target,
                progress: Animation {
                    start_ns: now_ns,
                    duration_ns: scaled,
                    curve,
                    from: current_progress,
                    to: if matches!(target, Closing | Minimising) {
                        0.0
                    } else {
                        1.0
                    },
                    repeat: Repeat::Once,
                },
                singularity,
            })
        };

        self.state = target;
        true
    }

    /// Advance the state machine. Returns true if this window still needs to be
    /// redrawn next frame — the compositor uses this to skip entirely static
    /// frames, which is what lets an idle desktop drop to ~0.2% CPU despite
    /// nominally running at 144 Hz.
    pub fn tick(&mut self, now_ns: u64) -> bool {
        let Some(t) = &self.transition else {
            // A focused window still animates its border pulse.
            return self.focused;
        };

        if !t.progress.is_complete(now_ns) {
            return true;
        }

        self.state = match t.kind {
            LifecycleState::Opening | LifecycleState::Restoring => LifecycleState::Normal,
            LifecycleState::Minimising => LifecycleState::Minimised,
            LifecycleState::Closing => LifecycleState::Gone,
            other => other,
        };
        self.transition = None;
        true
    }

    /// Uniforms for `window_warp.vert`.
    pub fn warp_mode(&self) -> f32 {
        match self.state {
            LifecycleState::Opening | LifecycleState::Restoring => 1.0,
            LifecycleState::Closing => 2.0,
            LifecycleState::Minimising => 3.0,
            LifecycleState::Dragging => 4.0,
            _ => 0.0,
        }
    }

    pub fn progress(&self, now_ns: u64) -> f32 {
        self.transition
            .as_ref()
            .map(|t| t.progress.sample(now_ns))
            .unwrap_or(1.0)
    }

    pub fn glow_intensity(&self, now_ns: u64, quality: Quality) -> f32 {
        if quality == Quality::Minimal || !self.focused {
            return 0.45;
        }
        self.border_pulse.sample(now_ns)
    }
}

/// Frame-level decision: does anything need redrawing?
pub fn needs_redraw(windows: &mut [Window], now_ns: u64) -> bool {
    let mut any = false;
    for w in windows.iter_mut() {
        any |= w.tick(now_ns);
    }
    any
}

/// Reap windows that finished closing.
pub fn reap(windows: &mut Vec<Window>) -> usize {
    let before = windows.len();
    windows.retain(|w| w.state != LifecycleState::Gone);
    before - windows.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use LifecycleState::*;

    fn win(now: u64) -> Window {
        Window::new(
            WindowId(1),
            Rect {
                x: 0.0,
                y: 0.0,
                w: 800.0,
                h: 600.0,
            },
            now,
            (400.0, 300.0),
        )
    }

    #[test]
    fn open_completes_into_normal() {
        let mut w = win(0);
        assert_eq!(w.state, Opening);
        w.tick(timing::OPEN_NS + 1);
        assert_eq!(w.state, Normal);
    }

    #[test]
    fn close_during_open_is_accepted_immediately() {
        let mut w = win(0);
        let mid = timing::OPEN_NS / 2;
        assert!(w.request(Closing, mid));
        assert_eq!(w.state, Closing);
    }

    #[test]
    fn interrupted_close_starts_from_current_position_not_zero() {
        let mut w = win(0);
        let mid = timing::OPEN_NS / 2;
        let progress_at_interrupt = w.progress(mid);
        w.request(Closing, mid);
        // The very next sample must be continuous with where we were.
        let after = w.progress(mid);
        assert!(
            (after - progress_at_interrupt).abs() < 1e-3,
            "discontinuity: {progress_at_interrupt} -> {after}"
        );
    }

    #[test]
    fn interrupting_early_shortens_the_close() {
        let mut w = win(0);
        // Interrupt at 10% open: the close should be much shorter than a full
        // close, because there is far less to animate away.
        w.request(Closing, timing::OPEN_NS / 10);
        let d = w.transition.as_ref().unwrap().progress.duration_ns;
        assert!(
            d < timing::CLOSE_NS / 2,
            "close took {d}ns, expected much less"
        );
    }

    #[test]
    fn illegal_transitions_are_refused() {
        let mut w = win(0);
        w.tick(timing::OPEN_NS + 1);
        assert_eq!(w.state, Normal);
        // Cannot go straight from Normal to Gone.
        assert!(!w.request(Gone, 0));
        assert_eq!(w.state, Normal);
        // Cannot restore a window that is not minimised.
        assert!(!w.request(Restoring, 0));
    }

    #[test]
    fn closing_is_terminal_and_cannot_be_cancelled() {
        let mut w = win(0);
        w.request(Closing, 0);
        assert!(!w.request(Normal, 0), "a closing window must not come back");
        assert!(!w.request(Dragging, 0));
    }

    #[test]
    fn minimise_reaches_minimised_then_restores() {
        let mut w = win(0);
        w.tick(timing::OPEN_NS + 1);
        w.request(Minimising, 1_000);
        w.tick(1_000 + timing::MINIMISE_NS + 1);
        assert_eq!(w.state, Minimised);
        assert!(w.request(Restoring, 2_000_000_000));
    }

    #[test]
    fn idle_unfocused_window_needs_no_redraw() {
        let mut w = win(0);
        w.tick(timing::OPEN_NS + 1);
        w.focused = false;
        assert!(
            !w.tick(timing::OPEN_NS + 2),
            "static window forced a redraw"
        );
    }

    #[test]
    fn focused_window_keeps_animating_its_border() {
        let mut w = win(0);
        w.tick(timing::OPEN_NS + 1);
        w.focused = true;
        assert!(w.tick(timing::OPEN_NS + 2));
    }

    #[test]
    fn minimal_quality_disables_the_pulse() {
        let mut w = win(0);
        w.tick(timing::OPEN_NS + 1);
        assert_eq!(w.glow_intensity(999_999_999, Quality::Minimal), 0.45);
    }

    #[test]
    fn gone_windows_are_reaped() {
        let mut windows = vec![win(0), win(0)];
        windows[0].request(Closing, 0);
        windows[0].tick(timing::CLOSE_NS * 2);
        assert_eq!(reap(&mut windows), 1);
        assert_eq!(windows.len(), 1);
    }
}
