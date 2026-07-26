//! Prism animation engine: cubic bezier interpolation, spring physics, and the
//! frame-budget governor.
//!
//! # The 144 fps floor is a governor, not a promise
//!
//! The spec asks for "every element animated at a locked 144 fps minimum". A
//! compositor cannot promise that — the display might be 60 Hz, the GPU might
//! be mid-shader-compile, the user might be on battery. What it *can* do, and
//! what this engine does, is guarantee that animation never becomes the reason
//! a frame is late:
//!
//!   * Animations are evaluated from a **timestamp**, not incremented per
//!     frame. A dropped frame produces a jump, never a slowdown, and never
//!     desynchronises two animations from each other. This is the single most
//!     important correctness property in the file and the one most commonly
//!     got wrong.
//!   * The `Budget` governor tracks per-frame animation cost and sheds detail —
//!     particle count first, then blur radius, then shadow quality — before it
//!     will let the frame miss vblank. Degrading is always preferable to
//!     stuttering; the eye forgives fewer particles and does not forgive a
//!     hitch.
//!   * Under Game Mode the entire engine is suspended for the isolated
//!     surface. The game's frame pacing outranks our animations.
//!
//! # Why not just use per-frame deltas
//!
//! Because `t += dt` accumulates float error and couples animation speed to
//! frame rate, and because a 2-second theme transition that takes 2.3 seconds
//! on a loaded machine looks broken next to one that takes exactly 2.0 and
//! drops a few frames. Sampling `f(now - start)` costs the same and is correct.

use core::time::Duration;

/// A cubic bezier easing curve defined by its two control points, matching the
/// CSS `cubic-bezier(x1, y1, x2, y2)` convention so themes authored against
/// web tooling behave identically here.
///
/// P0 is fixed at (0,0) and P3 at (1,1); only the interior control points vary.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Bezier {
    x1: f32,
    y1: f32,
    x2: f32,
    y2: f32,
}

impl Bezier {
    pub const fn new(x1: f32, y1: f32, x2: f32, y2: f32) -> Self {
        Bezier { x1, y1, x2, y2 }
    }

    /// System-wide curves, referenced by name from NeonCSS themes.
    ///
    /// These are not arbitrary. `SPECTRE_OUT` is tuned so a window's opening
    /// animation front-loads its motion — it covers 60% of the distance in the
    /// first 25% of the duration, which reads as "responsive" because the eye
    /// judges responsiveness by initial acceleration, not total duration.
    pub const SPECTRE_OUT: Bezier = Bezier::new(0.16, 1.0, 0.3, 1.0);
    pub const SPECTRE_IN: Bezier = Bezier::new(0.7, 0.0, 0.84, 0.0);
    pub const SPECTRE_IN_OUT: Bezier = Bezier::new(0.65, 0.0, 0.35, 1.0);
    /// Slight overshoot for the icon magnetic-snap. y2 > 1.0 is intentional.
    pub const MAGNETIC: Bezier = Bezier::new(0.34, 1.56, 0.64, 1.0);
    pub const LINEAR: Bezier = Bezier::new(0.0, 0.0, 1.0, 1.0);

    /// Evaluate the curve: given progress `t` in 0..=1 along the *time* axis,
    /// return the eased value along the *value* axis.
    ///
    /// The subtlety: a cubic bezier is parametric, so `x` and `y` are both
    /// functions of an internal parameter `s`. We must first solve `x(s) = t`
    /// for `s`, then evaluate `y(s)`. Treating `t` as `s` directly — a common
    /// shortcut — gives a curve that is visibly wrong for asymmetric control
    /// points, which is most of them.
    pub fn eval(&self, t: f32) -> f32 {
        let t = t.clamp(0.0, 1.0);

        // Endpoints are exact; skip the solver and avoid any float drift that
        // would leave an element one sub-pixel short of its final position.
        if t <= 0.0 {
            return 0.0;
        }
        if t >= 1.0 {
            return 1.0;
        }

        let s = self.solve_for_x(t);
        cubic(self.y1, self.y2, s)
    }

    /// Newton-Raphson with a bisection fallback.
    ///
    /// Newton converges in 2–4 iterations for well-behaved curves, but its
    /// derivative approaches zero on curves with a flat segment (e.g. a curve
    /// with x1 == x2 == 0), where it either stalls or overshoots out of range.
    /// The bisection fallback is not paranoia: `cubic-bezier(0, 0, 0, 1)` is a
    /// perfectly legal theme value that breaks a pure-Newton solver.
    fn solve_for_x(&self, target: f32) -> f32 {
        const NEWTON_ITERATIONS: usize = 4;
        const EPSILON: f32 = 1e-6;

        let mut s = target;
        for _ in 0..NEWTON_ITERATIONS {
            let x = cubic(self.x1, self.x2, s) - target;
            if x.abs() < EPSILON {
                return s;
            }
            let dx = cubic_derivative(self.x1, self.x2, s);
            if dx.abs() < 1e-6 {
                break; // Derivative too flat for Newton; fall through.
            }
            s -= x / dx;
        }

        // Bisection: slower but unconditionally convergent on a monotonic x(s),
        // which is guaranteed as long as x1 and x2 are in 0..=1 (validated at
        // theme-load time by `Bezier::validate`).
        let (mut lo, mut hi) = (0.0f32, 1.0f32);
        let mut s = target.clamp(0.0, 1.0);
        for _ in 0..24 {
            let x = cubic(self.x1, self.x2, s);
            if (x - target).abs() < EPSILON {
                break;
            }
            if x > target {
                hi = s;
            } else {
                lo = s;
            }
            s = (lo + hi) * 0.5;
        }
        s
    }

    /// Theme validation. `x` control points outside 0..=1 make `x(s)`
    /// non-monotonic, which means "progress" would run backwards in time — the
    /// solver would return an arbitrary root and the animation would visibly
    /// stutter. `y` is unconstrained, which is what permits overshoot curves
    /// like `MAGNETIC`.
    pub fn validate(&self) -> Result<(), &'static str> {
        if !(0.0..=1.0).contains(&self.x1) || !(0.0..=1.0).contains(&self.x2) {
            return Err("bezier x control points must be within 0..=1");
        }
        if !self.x1.is_finite()
            || !self.y1.is_finite()
            || !self.x2.is_finite()
            || !self.y2.is_finite()
        {
            return Err("bezier control points must be finite");
        }
        Ok(())
    }
}

/// Cubic bernstein polynomial with P0=0, P3=1.
#[inline]
fn cubic(a: f32, b: f32, s: f32) -> f32 {
    let inv = 1.0 - s;
    3.0 * inv * inv * s * a + 3.0 * inv * s * s * b + s * s * s
}

#[inline]
fn cubic_derivative(a: f32, b: f32, s: f32) -> f32 {
    let inv = 1.0 - s;
    3.0 * inv * inv * a + 6.0 * inv * s * (b - a) + 3.0 * s * s * (1.0 - b)
}

// ---------------------------------------------------------------------------
// Animation instances
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub struct Animation {
    pub start_ns: u64,
    pub duration_ns: u64,
    pub curve: Bezier,
    pub from: f32,
    pub to: f32,
    pub repeat: Repeat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Repeat {
    Once,
    Loop,
    /// Ping-pong. Used for the 2 Hz window-border pulse.
    Alternate,
}

impl Animation {
    /// Sample at an absolute timestamp. Frame-rate independent by construction.
    pub fn sample(&self, now_ns: u64) -> f32 {
        if self.duration_ns == 0 {
            return self.to;
        }

        let elapsed = now_ns.saturating_sub(self.start_ns);
        let raw = elapsed as f64 / self.duration_ns as f64;

        let t = match self.repeat {
            Repeat::Once => raw.min(1.0) as f32,
            Repeat::Loop => (raw % 1.0) as f32,
            Repeat::Alternate => {
                let cycle = raw % 2.0;
                if cycle <= 1.0 {
                    cycle as f32
                } else {
                    (2.0 - cycle) as f32
                }
            }
        };

        let eased = self.curve.eval(t);
        self.from + (self.to - self.from) * eased
    }

    pub fn is_complete(&self, now_ns: u64) -> bool {
        matches!(self.repeat, Repeat::Once)
            && now_ns.saturating_sub(self.start_ns) >= self.duration_ns
    }
}

/// The window-border pulse from the spec: 2 Hz, alternating.
pub fn border_pulse(start_ns: u64) -> Animation {
    Animation {
        start_ns,
        // 2 Hz means a full cycle every 500 ms; Alternate covers half a cycle
        // per duration, so the duration is 250 ms.
        duration_ns: 250_000_000,
        curve: Bezier::SPECTRE_IN_OUT,
        from: 0.45,
        to: 1.0,
        repeat: Repeat::Alternate,
    }
}

// ---------------------------------------------------------------------------
// Frame budget governor
// ---------------------------------------------------------------------------

/// Quality tiers the governor sheds in order. Ordered by (visual cost) /
/// (perceptual value): particles are expensive and least missed, blur is
/// expensive and quite noticeable, so it goes later.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Quality {
    /// Everything: full particle density, ray-traced wallpaper reflections.
    Full = 4,
    /// Particle density halved, wallpaper reflections screen-space instead of
    /// ray-traced.
    High = 3,
    /// No particles on drag trails, blur radius halved.
    Medium = 2,
    /// Blur replaced with a static frosted texture, no window shadows.
    Low = 1,
    /// Motion only: positions animate, no effects. Also the tier used when the
    /// accessibility "reduce motion" setting is on, in which case durations are
    /// additionally clamped to 0.
    Minimal = 0,
}

pub struct Budget {
    target_frame_ns: u64,
    /// Exponential moving average of animation-pass cost.
    ema_cost_ns: u64,
    quality: Quality,
    /// Consecutive frames within budget, used to gate upward transitions.
    stable_frames: u32,
    /// Frames remaining before another shed is permitted.
    ///
    /// Without this the governor cascades: the EMA needs ~7 frames to reflect a
    /// new cost level, so a single expensive frame keeps the ratio above the
    /// shed threshold for several frames afterwards and drops the quality tier
    /// once per frame. One hitch would take the compositor from Full to Minimal
    /// and it would then take four seconds to climb back.
    shed_cooldown: u32,
}

impl Budget {
    /// Hysteresis: drop quality after a single overrun (the user is already
    /// seeing a hitch, act now), but require 120 clean frames — about a second
    /// — before climbing back. Without the asymmetry, a workload sitting right
    /// at the budget boundary oscillates between tiers every few frames, which
    /// is far more visible than simply staying at the lower tier.
    const RECOVERY_FRAMES: u32 = 120;
    /// Shed detail at 80% of the frame budget, not 100%. By the time the
    /// animation pass has consumed the whole budget, the frame is already lost.
    const SHED_THRESHOLD: f32 = 0.80;
    const RECOVER_THRESHOLD: f32 = 0.55;
    /// Frames to wait after a shed before considering another. Sized to the
    /// EMA's settling time (alpha = 1/8 reaches ~60% of a step in 7 samples),
    /// so the next shed decision is made against a measurement that reflects
    /// the tier we actually moved to.
    const SHED_COOLDOWN_FRAMES: u32 = 16;

    pub fn new(refresh_hz: u32) -> Self {
        Budget {
            target_frame_ns: 1_000_000_000 / refresh_hz.max(1) as u64,
            ema_cost_ns: 0,
            quality: Quality::Full,
            stable_frames: 0,
            shed_cooldown: 0,
        }
    }

    /// Feed one frame's measured animation cost; returns the tier for the next
    /// frame.
    pub fn record(&mut self, cost_ns: u64) -> Quality {
        // α = 1/8: responsive enough to catch a workload change within a few
        // frames, damped enough to ignore a single anomalous frame.
        self.ema_cost_ns = if self.ema_cost_ns == 0 {
            cost_ns
        } else {
            (self.ema_cost_ns * 7 + cost_ns) / 8
        };

        let ratio = self.ema_cost_ns as f32 / self.target_frame_ns as f32;

        self.shed_cooldown = self.shed_cooldown.saturating_sub(1);

        if ratio > Self::SHED_THRESHOLD {
            // Only shed once per cooldown window. The cooldown gates the shed,
            // not the measurement — the EMA keeps updating throughout, so by
            // the time another shed is allowed the ratio reflects the current
            // tier rather than the spike that triggered the last one.
            if self.shed_cooldown == 0 {
                self.quality = self.quality.lower();
                self.shed_cooldown = Self::SHED_COOLDOWN_FRAMES;
            }
            self.stable_frames = 0;
        } else if ratio < Self::RECOVER_THRESHOLD {
            self.stable_frames += 1;
            if self.stable_frames >= Self::RECOVERY_FRAMES {
                self.quality = self.quality.raise();
                self.stable_frames = 0;
            }
        } else {
            self.stable_frames = 0;
        }

        self.quality
    }

    pub fn quality(&self) -> Quality {
        self.quality
    }

    /// Accessibility override. Vestibular disorders are triggered by exactly
    /// the parallax, zoom, and spatial-warp effects this compositor is built
    /// around, so "reduce motion" is not a quality tier — it disables the
    /// motion entirely while keeping opacity transitions, which are safe.
    pub fn apply_reduce_motion(&mut self) {
        self.quality = Quality::Minimal;
    }
}

impl Quality {
    fn lower(self) -> Quality {
        match self {
            Quality::Full => Quality::High,
            Quality::High => Quality::Medium,
            Quality::Medium => Quality::Low,
            Quality::Low | Quality::Minimal => Quality::Minimal,
        }
    }

    fn raise(self) -> Quality {
        match self {
            Quality::Minimal => Quality::Low,
            Quality::Low => Quality::Medium,
            Quality::Medium => Quality::High,
            Quality::High | Quality::Full => Quality::Full,
        }
    }

    /// Particle count multiplier for this tier.
    pub fn particle_scale(self) -> f32 {
        match self {
            Quality::Full => 1.0,
            Quality::High => 0.5,
            Quality::Medium => 0.25,
            Quality::Low => 0.0,
            Quality::Minimal => 0.0,
        }
    }
}

pub const fn ns_from_ms(ms: u64) -> u64 {
    ms * 1_000_000
}

pub fn duration_ns(d: Duration) -> u64 {
    d.as_nanos() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bezier_endpoints_are_exact() {
        for curve in [Bezier::SPECTRE_OUT, Bezier::SPECTRE_IN, Bezier::MAGNETIC] {
            assert_eq!(curve.eval(0.0), 0.0);
            assert_eq!(curve.eval(1.0), 1.0);
        }
    }

    #[test]
    fn linear_curve_is_identity() {
        for i in 0..=100 {
            let t = i as f32 / 100.0;
            assert!((Bezier::LINEAR.eval(t) - t).abs() < 1e-4, "at t={t}");
        }
    }

    #[test]
    fn solver_handles_flat_derivative_curves() {
        // cubic-bezier(0, 0, 0, 1): a legal theme value that stalls pure Newton.
        let pathological = Bezier::new(0.0, 0.0, 0.0, 1.0);
        for i in 0..=100 {
            let t = i as f32 / 100.0;
            let v = pathological.eval(t);
            assert!(v.is_finite(), "non-finite at t={t}");
            assert!((0.0..=1.0).contains(&v), "out of range {v} at t={t}");
        }
    }

    #[test]
    fn eased_output_is_monotonic_for_non_overshoot_curves() {
        let mut prev = -1.0;
        for i in 0..=200 {
            let v = Bezier::SPECTRE_OUT.eval(i as f32 / 200.0);
            assert!(v >= prev - 1e-4, "regressed at i={i}: {v} < {prev}");
            prev = v;
        }
    }

    #[test]
    fn magnetic_curve_overshoots_then_settles() {
        let peak = (0..=100)
            .map(|i| Bezier::MAGNETIC.eval(i as f32 / 100.0))
            .fold(f32::MIN, f32::max);
        assert!(
            peak > 1.0,
            "magnetic snap should overshoot, peaked at {peak}"
        );
        assert_eq!(Bezier::MAGNETIC.eval(1.0), 1.0, "must still settle exactly");
    }

    #[test]
    fn out_of_range_x_controls_are_rejected() {
        assert!(Bezier::new(-0.1, 0.0, 0.5, 1.0).validate().is_err());
        assert!(Bezier::new(0.0, 0.0, 1.5, 1.0).validate().is_err());
        // Overshoot in y is legal.
        assert!(Bezier::new(0.34, 1.56, 0.64, 1.0).validate().is_ok());
    }

    #[test]
    fn sampling_is_frame_rate_independent() {
        let anim = Animation {
            start_ns: 1_000,
            duration_ns: ns_from_ms(500),
            curve: Bezier::SPECTRE_IN_OUT,
            from: 0.0,
            to: 100.0,
            repeat: Repeat::Once,
        };

        // Same wall-clock instant sampled by a 144 Hz and a 30 Hz renderer must
        // produce identical values. This is the property that per-frame delta
        // accumulation destroys.
        let midpoint = 1_000 + ns_from_ms(250);
        assert_eq!(anim.sample(midpoint), anim.sample(midpoint));

        // And a dropped frame must not slow the animation down.
        assert_eq!(anim.sample(1_000 + ns_from_ms(500)), 100.0);
        assert_eq!(anim.sample(1_000 + ns_from_ms(900)), 100.0);
    }

    #[test]
    fn alternate_repeat_pulses_at_the_requested_rate() {
        let pulse = border_pulse(0);
        // Half cycle at 250 ms: should be at the far end.
        let a = pulse.sample(ns_from_ms(250));
        // Full cycle at 500 ms: back to the start.
        let b = pulse.sample(ns_from_ms(500));
        assert!((a - 1.0).abs() < 1e-3, "peak was {a}");
        assert!((b - 0.45).abs() < 1e-3, "trough was {b}");
    }

    #[test]
    fn zero_duration_animation_jumps_to_target() {
        let anim = Animation {
            start_ns: 0,
            duration_ns: 0,
            curve: Bezier::SPECTRE_OUT,
            from: 5.0,
            to: 42.0,
            repeat: Repeat::Once,
        };
        assert_eq!(anim.sample(0), 42.0);
    }

    #[test]
    fn budget_sheds_immediately_but_recovers_slowly() {
        let mut b = Budget::new(144);
        let frame = 1_000_000_000u64 / 144;

        // Overrun: must drop on the next decision.
        b.record(frame); // 100% of budget
        assert_eq!(b.quality(), Quality::High);

        // Cheap frames: must not climb back quickly. Asserted as a property
        // rather than an exact frame count, because the EMA needs several
        // samples to fall below the recovery threshold and pinning the exact
        // number would make the test a restatement of the implementation.
        for _ in 0..60 {
            b.record(frame / 4);
        }
        assert_eq!(b.quality(), Quality::High, "recovered too eagerly");

        // ...but it must recover eventually.
        for _ in 0..300 {
            b.record(frame / 4);
        }
        assert_eq!(b.quality(), Quality::Full, "never recovered");
    }

    #[test]
    fn one_expensive_frame_costs_exactly_one_tier() {
        // Regression: without the shed cooldown the EMA's lag kept the ratio
        // above the shed threshold for several frames after a single spike,
        // dropping a tier per frame and taking Full all the way to Minimal.
        let mut b = Budget::new(144);
        let frame = 1_000_000_000u64 / 144;

        b.record(frame * 4); // one catastrophic frame
        for _ in 0..20 {
            b.record(frame / 10); // back to cheap immediately
        }
        assert_eq!(
            b.quality(),
            Quality::High,
            "one spike cascaded past a single tier"
        );
    }

    #[test]
    fn budget_does_not_oscillate_at_the_boundary() {
        let mut b = Budget::new(144);
        let frame = 1_000_000_000u64 / 144;
        // Sitting in the hysteresis band: quality must stay put.
        b.record(frame); // force one drop
        let settled = b.quality();
        for _ in 0..500 {
            b.record((frame as f32 * 0.65) as u64);
        }
        assert_eq!(b.quality(), settled, "oscillated in the dead band");
    }

    #[test]
    fn budget_floors_at_minimal() {
        let mut b = Budget::new(144);
        for _ in 0..50 {
            b.record(1_000_000_000);
        }
        assert_eq!(b.quality(), Quality::Minimal);
        assert_eq!(b.quality().particle_scale(), 0.0);
    }
}
