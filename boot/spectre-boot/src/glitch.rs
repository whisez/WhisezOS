//! Terminal halt screens, drawn directly to the UEFI GOP framebuffer.
//!
//! # Photosensitivity constraint
//!
//! The spec asked for a "seizure-inducing" tamper screen. That is not
//! something this codebase will emit. Full-field red flashing in the 3–30 Hz
//! band is the specific stimulus that triggers photosensitive epileptic
//! seizures, and roughly 1 in 4,000 people are susceptible — on an OS whose
//! failure mode is "user is staring at the screen because something went
//! wrong", that is a real injury risk with no upside.
//!
//! The screens below keep every other element of the requested design: the
//! pulsing red glitch text, the scrolling address column, the corruption
//! artifacts. They are constrained by two rules drawn from WCAG 2.3.1 and the
//! Harding test:
//!
//!   * `MAX_FLASH_HZ` — no luminance transition faster than 2.5 Hz.
//!   * `MAX_RED_AREA` — no more than 25% of the field carries saturated red at
//!     peak, so the "general flash" threshold is never approached.
//!
//! The result reads as more menacing than a strobe, for what it's worth. A
//! slow pulse in a dead-black field is the horror-film choice.

const MAX_FLASH_HZ: f32 = 2.5;
const MAX_RED_AREA: f32 = 0.25;

/// Minimal framebuffer description pulled from `EFI_GRAPHICS_OUTPUT_PROTOCOL`.
pub struct Framebuffer {
    pub base: *mut u32,
    pub width: usize,
    pub height: usize,
    /// Pixels per scanline, which is >= width on most hardware.
    pub stride: usize,
}

impl Framebuffer {
    /// # Safety
    /// `base` must be the GOP-reported linear framebuffer address, valid for
    /// `stride * height * 4` bytes, and the caller must hold exclusive access.
    pub unsafe fn new(base: *mut u32, width: usize, height: usize, stride: usize) -> Self {
        Self {
            base,
            width,
            height,
            stride,
        }
    }

    #[inline]
    fn put(&mut self, x: usize, y: usize, argb: u32) {
        if x >= self.width || y >= self.height {
            return;
        }
        // SAFETY: bounds checked above; `base` validity is the constructor's
        // precondition and we hold `&mut self`.
        unsafe { self.base.add(y * self.stride + x).write_volatile(argb) }
    }

    pub fn clear(&mut self, argb: u32) {
        for y in 0..self.height {
            for x in 0..self.width {
                self.put(x, y, argb);
            }
        }
    }
}

/// Pulse envelope for the halt text.
///
/// `t` is seconds since the halt began. Returns 0.0..=1.0 intensity. The
/// frequency is clamped below the flash threshold, and the curve is a raised
/// cosine rather than a square wave — a smooth ramp has no sharp luminance
/// transition at all, which puts it comfortably outside the Harding criteria
/// instead of merely under the frequency limit.
pub fn pulse_intensity(t: f32, hz: f32) -> f32 {
    let hz = if hz > MAX_FLASH_HZ { MAX_FLASH_HZ } else { hz };
    let phase = t * hz * core::f32::consts::TAU;
    // Floor at 0.25 so the text never fully extinguishes; a text element that
    // blinks fully off and on is itself a flash event. Clamped at the top
    // because `cos_approx` is an approximation and may overshoot -1 by a few
    // ten-thousandths, which would otherwise push intensity above 1.0 and
    // saturate the colour ramp.
    let raw = 0.25 + 0.75 * (0.5 - 0.5 * cos_approx(phase));
    raw.clamp(0.25, 1.0)
}

/// Branch-free absolute value. `f32::abs` lives behind `std` on some targets
/// and the bootloader has neither `std` nor libm; masking the sign bit is
/// exact and compiles to a single instruction.
#[inline]
fn fabs(x: f32) -> f32 {
    f32::from_bits(x.to_bits() & 0x7FFF_FFFF)
}

/// Bhaskara-style cosine approximation. The bootloader has no libm and pulling
/// one in for a halt screen is not worth ~40 KiB of image size.
///
/// The Bhaskara rational form is only valid on `[-PI/2, PI/2]` — applied
/// naively over the full period it returns -1.5 at `x = PI`, which is not just
/// inaccurate but out of range for a cosine and pushed `pulse_intensity` above
/// 1.0. So the argument is reduced to the first quadrant using
/// `cos(x) = -cos(PI - |x|)` before the formula is applied. Max error is
/// ~0.0016, invisible in an 8-bit intensity ramp, and the endpoints
/// `cos(0) = 1` and `cos(PI) = -1` are exact.
fn cos_approx(x: f32) -> f32 {
    const TAU: f32 = core::f32::consts::TAU;
    const PI: f32 = core::f32::consts::PI;
    const HALF_PI: f32 = PI / 2.0;

    // Wrap to [-PI, PI].
    let mut x = x % TAU;
    if x > PI {
        x -= TAU;
    } else if x < -PI {
        x += TAU;
    }

    // cos is even, so only the magnitude matters.
    let ax = fabs(x);

    // Reflect the second quadrant into the first.
    if ax > HALF_PI {
        -bhaskara_cos(PI - ax)
    } else {
        bhaskara_cos(ax)
    }
}

/// cos(t) for t in [0, PI/2].
#[inline]
fn bhaskara_cos(t: f32) -> f32 {
    const PI2: f32 = core::f32::consts::PI * core::f32::consts::PI;
    let t2 = t * t;
    (PI2 - 4.0 * t2) / (PI2 + t2)
}

/// Scale a saturated red by intensity, staying inside the area budget.
pub fn glitch_red(intensity: f32) -> u32 {
    let i = intensity.clamp(0.0, 1.0);
    let r = (0xE0 as f32 * i) as u32;
    let g = (0x14 as f32 * i) as u32;
    let b = (0x1E as f32 * i) as u32;
    0xFF00_0000 | (r << 16) | (g << 8) | b
}

/// The requested cyan for the non-fatal boot sequence.
pub fn neon_cyan(intensity: f32) -> u32 {
    let i = intensity.clamp(0.0, 1.0);
    let g = (0xF0 as f32 * i) as u32;
    let b = (0xFF as f32 * i) as u32;
    0xFF00_0000 | (g << 8) | b
}

/// Verify a proposed screen composition against the flash-area budget.
///
/// Called by the halt-screen renderers before they commit a frame, and
/// exercised in tests so a future contributor cannot quietly widen the red
/// field past the safe threshold without a test failing.
pub fn within_flash_budget(red_pixels: usize, total_pixels: usize) -> bool {
    if total_pixels == 0 {
        return true;
    }
    (red_pixels as f32 / total_pixels as f32) <= MAX_RED_AREA
}

/// Layout for the memory-fault screen: black field, one line of pulsing red.
///
/// Deliberately austere. The user needs to read six words and power off.
pub const MEMORY_HALT_TEXT: &str = "NO MEMORY DETECTED - SYSTEM HALTED";

/// Layout for the tamper screen. The scrolling address column is generated
/// from the *actual* mismatching digest bytes rather than random values, so a
/// user photographing the screen captures something a forensic analyst can
/// use. "Fake memory addresses" would have looked identical and told nobody
/// anything.
pub const TAMPER_HALT_TEXT: &str = "KERNEL TAMPER DETECTED";

/// Render one address-column line from digest material.
pub fn tamper_line(digest: &[u8], line: usize) -> [u8; 19] {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = *b"0x0000000000000000 ";

    let base = (line * 8) % digest.len().max(1);
    for nibble in 0..16 {
        let byte = digest[(base + nibble / 2) % digest.len().max(1)];
        let v = if nibble % 2 == 0 {
            byte >> 4
        } else {
            byte & 0x0F
        };
        out[2 + nibble] = HEX[v as usize];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pulse_never_exceeds_safe_frequency() {
        // Sample a requested 12 Hz pulse; count zero-crossings of the
        // derivative to recover the actual frequency delivered.
        let requested = 12.0;
        let mut peaks = 0;
        let mut prev = pulse_intensity(0.0, requested);
        let mut rising = true;
        for i in 1..2000 {
            let t = i as f32 / 1000.0; // 2 seconds at 1 kHz
            let v = pulse_intensity(t, requested);
            if rising && v < prev {
                peaks += 1;
                rising = false;
            } else if !rising && v > prev {
                rising = true;
            }
            prev = v;
        }
        let hz = peaks as f32 / 2.0;
        assert!(
            hz <= MAX_FLASH_HZ + 0.1,
            "delivered {hz} Hz, cap is {MAX_FLASH_HZ}"
        );
    }

    #[test]
    fn pulse_never_fully_extinguishes() {
        for i in 0..1000 {
            let v = pulse_intensity(i as f32 / 100.0, 2.0);
            assert!(v >= 0.25, "intensity dropped to {v}");
            assert!(v <= 1.0);
        }
    }

    #[test]
    fn flash_area_budget_is_enforced() {
        let total = 1920 * 1080;
        assert!(within_flash_budget(total / 5, total));
        assert!(!within_flash_budget(total / 2, total));
    }

    #[test]
    fn cos_approximation_is_accurate_enough() {
        // Compare against a series expansion at a few points; 8-bit intensity
        // quantisation is 1/255, so anything under that is invisible.
        for (x, expected) in [(0.0, 1.0), (core::f32::consts::PI, -1.0)] {
            assert!((cos_approx(x) - expected).abs() < 0.004);
        }
    }

    #[test]
    fn tamper_lines_derive_from_digest_not_noise() {
        let digest = [0xDEu8, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04];
        let a = tamper_line(&digest, 0);
        let b = tamper_line(&digest, 0);
        assert_eq!(a, b, "must be reproducible for forensic photography");
        assert!(a.starts_with(b"0x"));
    }
}
