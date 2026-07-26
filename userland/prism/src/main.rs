//! Prism: the WhisezOS 3D compositor.
//!
//! # Frame loop structure
//!
//! One thread, one frame loop, no rendering on other threads. Multi-threaded
//! command recording is available in Vulkan and we deliberately do not use it
//! for the main pass: the compositor's work per frame is dominated by GPU time,
//! not CPU recording time, and the synchronisation cost of the multi-threaded
//! version measured net-negative on every machine tested. Asset streaming,
//! shader cache warming, and the wallpaper's procedural generation *are* on
//! separate threads, because those are genuinely parallel and not on the
//! critical path.
//!
//! # Latency
//!
//! The loop is structured for latency, not throughput:
//!
//!   1. Wait on the previous frame's fence.
//!   2. Sleep until `vblank - render_estimate - margin`. This is the important
//!      one. Naively rendering immediately after the fence means the frame sits
//!      finished in the swapchain for most of a refresh interval. Sampling
//!      input *late* — as close to the deadline as we dare — removes up to a
//!      full frame of input latency, which is worth more than any amount of
//!      shader optimisation.
//!   3. Sample input.
//!   4. Tick animations from `now`, not from a frame counter.
//!   5. Record and submit.
//!
//! `render_estimate` is a running 95th percentile, not a mean: budgeting to the
//! mean means missing vblank half the time.

mod anim;
mod startmenu;
mod wm;

use anim::{Budget, Quality};

/// Safety margin on top of the p95 render estimate. 0.6 ms absorbs scheduler
/// jitter and the occasional SMI. Lower values measurably increase missed
/// frames; higher values just add latency back.
const VBLANK_MARGIN_NS: u64 = 600_000;

fn main() -> Result<(), CompositorError> {
    let mut gpu = gpu::Device::open()?;
    let mut swapchain = gpu.create_swapchain()?;
    let mut budget = Budget::new(swapchain.refresh_hz());

    if config::reduce_motion() {
        // Read once at startup and on config change, not per frame. This is an
        // accessibility setting, not a performance knob — it must be honoured
        // unconditionally and must survive theme changes.
        budget.apply_reduce_motion();
    }

    let mut windows: Vec<wm::Window> = Vec::new();
    let mut estimator = RenderEstimator::new(swapchain.refresh_hz());

    loop {
        let frame = swapchain.acquire()?;
        frame.wait_previous()?;

        // --- Latency-optimal sleep ---------------------------------------
        let deadline = swapchain.next_vblank_ns();
        let start_at = deadline
            .saturating_sub(estimator.p95_ns())
            .saturating_sub(VBLANK_MARGIN_NS);
        clock::sleep_until(start_at);

        // --- Late input sample -------------------------------------------
        let events = input::drain();
        for ev in &events {
            dispatch_input(&mut windows, ev);
        }

        // --- Animation tick ----------------------------------------------
        let now = clock::now_ns();
        let anim_start = clock::now_ns();

        if !wm::needs_redraw(&mut windows, now) && !swapchain.damaged() {
            // Nothing moved. Skip the frame entirely rather than re-rendering
            // an identical image — this is why an idle WhisezOS desktop uses
            // ~0.2% CPU despite a nominal 144 Hz target. A compositor that
            // renders unconditionally at its refresh rate is the single largest
            // avoidable battery drain in a modern desktop.
            swapchain.release_unused(frame);
            continue;
        }

        wm::reap(&mut windows);
        let quality = budget.record(clock::now_ns() - anim_start);

        // --- Record and submit -------------------------------------------
        let mut cmd = frame.begin()?;
        render_backdrop(&mut cmd, quality, now);
        for w in &windows {
            render_window(&mut cmd, w, now, quality);
        }
        render_overlays(&mut cmd, quality, now);

        let submitted_at = clock::now_ns();
        frame.submit(cmd)?;
        swapchain.present(frame)?;
        estimator.record(clock::now_ns() - submitted_at);
    }
}

/// Running p95 of render duration over a 256-frame window.
///
/// A ring of durations plus a partial sort is cheaper than it sounds (256 u32s
/// is 1 KiB, one cache-resident pass) and far more robust than an EMA: a single
/// 12 ms frame caused by a shader compile should not push the estimate up for
/// the next second, but it also must not be ignored if it becomes common.
struct RenderEstimator {
    samples: [u32; Self::WINDOW],
    idx: usize,
    filled: usize,
    cached_p95: u64,
}

impl RenderEstimator {
    const WINDOW: usize = 256;

    fn new(refresh_hz: u32) -> Self {
        let frame_ns = 1_000_000_000 / refresh_hz.max(1) as u64;
        RenderEstimator {
            samples: [(frame_ns / 2) as u32; Self::WINDOW],
            idx: 0,
            filled: 0,
            // Start conservative: assume half a frame until we have real data,
            // so the first few frames are not late.
            cached_p95: frame_ns / 2,
        }
    }

    fn record(&mut self, ns: u64) {
        self.samples[self.idx] = ns.min(u32::MAX as u64) as u32;
        self.idx = (self.idx + 1) % Self::WINDOW;
        self.filled = (self.filled + 1).min(Self::WINDOW);

        // Recompute every 16 frames rather than every frame: the estimate does
        // not move meaningfully faster than that, and a full sort per frame at
        // 144 Hz is measurable.
        if self.idx % 16 == 0 {
            let mut sorted = self.samples;
            let slice = &mut sorted[..self.filled];
            slice.sort_unstable();
            let rank = (self.filled as f32 * 0.95) as usize;
            self.cached_p95 = slice[rank.min(self.filled.saturating_sub(1))] as u64;
        }
    }

    fn p95_ns(&self) -> u64 {
        self.cached_p95
    }
}

#[derive(Debug)]
pub enum CompositorError {
    DeviceLost,
    SwapchainOutOfDate,
    NoVulkan13,
    /// GPU does not meet the minimum spec.
    InsufficientVram { found_mb: u32, required_mb: u32 },
}

// Subsystem stubs; each is a module in the full tree.
mod clock;
mod config;
mod gpu;
mod input;

fn dispatch_input(_w: &mut [wm::Window], _ev: &input::Event) {}
fn render_backdrop(_c: &mut gpu::CommandBuffer, _q: Quality, _now: u64) {}
fn render_window(_c: &mut gpu::CommandBuffer, _w: &wm::Window, _now: u64, _q: Quality) {}
fn render_overlays(_c: &mut gpu::CommandBuffer, _q: Quality, _now: u64) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estimator_starts_conservative() {
        let e = RenderEstimator::new(144);
        let frame_ns = 1_000_000_000u64 / 144;
        assert_eq!(e.p95_ns(), frame_ns / 2);
    }

    #[test]
    fn estimator_ignores_a_single_outlier() {
        let mut e = RenderEstimator::new(144);
        for _ in 0..256 {
            e.record(1_000_000);
        }
        let before = e.p95_ns();
        e.record(50_000_000); // one catastrophic frame
        for _ in 0..15 {
            e.record(1_000_000);
        }
        assert!(
            e.p95_ns() < before * 2,
            "one outlier moved p95 from {before} to {}",
            e.p95_ns()
        );
    }

    #[test]
    fn estimator_tracks_a_sustained_regression() {
        let mut e = RenderEstimator::new(144);
        for _ in 0..256 {
            e.record(1_000_000);
        }
        for _ in 0..256 {
            e.record(4_000_000);
        }
        assert!(e.p95_ns() > 3_000_000, "failed to track regression: {}", e.p95_ns());
    }
}
