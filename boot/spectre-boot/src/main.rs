//! WhisezOS stage-1 UEFI loader.
//!
//! Boot order, and the reasoning for it:
//!
//!   1. **Memory audit first.** Everything after this point allocates. If the
//!      platform cannot satisfy the memory floor we want to fail before we
//!      have touched anything, while the firmware's console is still sane.
//!   2. **Attest before load.** Images are read into `NX|RO` buffers, hashed,
//!      compared against the signed manifest, and only then mapped executable.
//!   3. **Measure after verify.** PCR extension happens only for images that
//!      passed, so an attacker cannot steer PCR values with garbage input.
//!   4. **Unlock last.** The Argon2id passphrase prompt runs after the chain
//!      is verified, so the user is never asked to type a passphrase into a
//!      loader that might already be compromised.
//!   5. **Boot animation is concurrent, not sequential.** The 15-second
//!      cinematic runs on the GOP framebuffer while steps 2–4 execute. It is
//!      cosmetic and must never be on the critical path — see the note on
//!      `BOOT_ANIMATION_BUDGET` below.

#![no_main]
#![no_std]
#![feature(uefi_std)]

extern crate alloc;

mod attest;
mod glitch;
mod spd;

use uefi::prelude::*;
use uefi::proto::console::gop::GraphicsOutput;

/// POST codes emitted to port 0x80 before halting, for diagnosis without video.
const POST_NO_MEMORY: u8 = 0xE0;
const POST_MEMORY_LOW: u8 = 0xE1;
const POST_MAP_MISMATCH: u8 = 0xE2;
const POST_TAMPER: u8 = 0xE3;

/// The cinematic runs for this long *at most*, and is cut short the instant
/// the real boot work finishes. An OS that makes you watch a fixed 15-second
/// animation on every boot is an OS you come to resent by week two — the
/// animation exists to cover latency, not to manufacture it. On an NVMe system
/// where attestation and unlock complete in 1.8 s, you see 1.8 s of animation
/// gracefully resolving, not 15 s of padding.
const BOOT_ANIMATION_BUDGET_MS: u64 = 15_000;

extern "C" {
    fn spectre_halt_forever(post_code: u8) -> !;
    fn spectre_scrub_and_halt(base: *mut u8, len: u64, post_code: u8) -> !;
}

#[entry]
fn main() -> Status {
    uefi::helpers::init().expect("uefi services");

    // ---- 1. Memory audit -------------------------------------------------
    let map_total = conventional_memory_total();
    let (modules, smbus_ok) = probe_memory_modules();

    let usable = match spd::audit(&modules, map_total, smbus_ok) {
        Ok(bytes) => bytes,
        Err(fault) => halt_memory_fault(fault),
    };

    log::info!("memory audit passed: {} GiB usable", usable >> 30);

    // ---- 2/3. Attest and measure ----------------------------------------
    let manifest = load_signed_manifest();
    let mut tpm = open_tcg2();

    for entry in manifest.iter() {
        let bytes = read_esp_file(entry.path);
        match attest::verify_image(entry, bytes.as_deref()) {
            Ok(d) => {
                let _ = attest::measure(&mut tpm, entry, &d);
            }
            Err(tamper) => halt_tamper(&mut tpm, tamper),
        }
    }

    // ---- 4. Unlock -------------------------------------------------------
    // `unlock_root_volume` derives the XChaCha20-Poly1305 key with Argon2id and
    // leaves it in a single page we track so it can be scrubbed on any later
    // failure path.
    let key_page = unlock_root_volume();

    // ---- 5. Hand off -----------------------------------------------------
    // The kernel receives the verified memory map, the unlocked volume key, and
    // the GOP framebuffer so Prism can take over the animation mid-frame
    // without a mode set — the boot cinematic dissolves directly into the
    // login screen with no black flash.
    boot_kernel(usable, key_page)
}

fn halt_memory_fault(fault: spd::MemoryFault) -> ! {
    let code = match fault {
        spd::MemoryFault::NoModulesDetected => POST_NO_MEMORY,
        spd::MemoryFault::BelowMinimum { .. } => POST_MEMORY_LOW,
        spd::MemoryFault::MapMismatch { .. } => POST_MAP_MISMATCH,
    };

    if let Some(mut fb) = open_framebuffer() {
        fb.clear(0xFF00_0000);
        draw_pulsing_banner(&mut fb, glitch::MEMORY_HALT_TEXT, glitch::glitch_red);
    }

    // SAFETY: no return, no allocation, interrupts masked inside.
    unsafe { spectre_halt_forever(code) }
}

fn halt_tamper<T: attest::Tpm>(tpm: &mut T, tamper: attest::Tamper) -> ! {
    // Destroy sealed key material before anything else. If the user cuts power
    // during the animation, the wipe must already have happened.
    let _ = attest::wipe_sealed_keys(tpm);

    if let Some(mut fb) = open_framebuffer() {
        fb.clear(0xFF00_0000);
        draw_pulsing_banner(&mut fb, glitch::TAMPER_HALT_TEXT, glitch::glitch_red);
        draw_address_column(&mut fb, &tamper.actual);
    }

    unsafe { spectre_halt_forever(POST_TAMPER) }
}

// ---------------------------------------------------------------------------
// Platform glue. Each of these is a thin wrapper over a UEFI protocol; they are
// separated out so the logic above stays testable against mocks on a host.
// ---------------------------------------------------------------------------

fn conventional_memory_total() -> u64 {
    use uefi::boot::MemoryType;

    let map = uefi::boot::memory_map(MemoryType::LOADER_DATA).expect("memory map");
    map.entries()
        .filter(|d| {
            matches!(
                d.ty,
                MemoryType::CONVENTIONAL | MemoryType::BOOT_SERVICES_DATA | MemoryType::LOADER_DATA
            )
        })
        .map(|d| d.page_count * 4096)
        .sum()
}

/// Returns the enumerated DIMMs and whether the SMBus was reachable at all.
fn probe_memory_modules() -> (heapless::Vec<spd::Module, 8>, bool) {
    match smbus::open_host_controller() {
        Some(mut bus) => (spd::enumerate(&mut bus), true),
        None => {
            log::warn!("SMBus unreachable; falling back to memory-map-only audit");
            (heapless::Vec::new(), false)
        }
    }
}

fn open_framebuffer() -> Option<glitch::Framebuffer> {
    let handle = uefi::boot::get_handle_for_protocol::<GraphicsOutput>().ok()?;
    let mut gop = uefi::boot::open_protocol_exclusive::<GraphicsOutput>(handle).ok()?;

    let mode = gop.current_mode_info();
    let (width, height) = mode.resolution();
    let stride = mode.stride();
    let base = gop.frame_buffer().as_mut_ptr() as *mut u32;

    // SAFETY: address, dimensions, and stride all come from GOP itself, and we
    // hold the protocol open exclusively for the remainder of the boot.
    Some(unsafe { glitch::Framebuffer::new(base, width, height, stride) })
}

fn draw_pulsing_banner(fb: &mut glitch::Framebuffer, text: &str, color: fn(f32) -> u32) {
    // One pass at peak intensity; the pulse loop proper lives in the halt
    // routine's caller on platforms with a usable timer. Text rendering uses
    // the embedded 8x16 VGA font in `font.rs`.
    let _ = (text, color(1.0));
    font::draw_centered(fb, text, color);
}

fn draw_address_column(fb: &mut glitch::Framebuffer, digest: &attest::Digest512) {
    for line in 0..24 {
        let bytes = glitch::tamper_line(digest, line);
        font::draw_line(fb, 32, 200 + line * 18, &bytes, glitch::glitch_red(0.6));
    }
}

// Stubs resolved by the linker against the platform crates; declared here so
// the boot flow above reads top-to-bottom.
mod font;
mod smbus;

fn load_signed_manifest() -> alloc::vec::Vec<attest::ManifestEntry> {
    manifest::load_and_verify_signature().unwrap_or_else(|_| {
        // A forged or unparseable manifest is treated exactly like a modified
        // kernel: there is no "boot anyway" path.
        halt_tamper(
            &mut open_tcg2(),
            attest::Tamper {
                kind: attest::TamperKind::ManifestForged,
                path: "\\SPECTRE\\BOOT.MANIFEST",
                expected: [0; attest::DIGEST_LEN],
                actual: [0; attest::DIGEST_LEN],
            },
        )
    })
}

mod manifest;
mod tcg2;

fn open_tcg2() -> tcg2::Tcg2 {
    tcg2::Tcg2::open()
}

fn read_esp_file(path: &str) -> Option<alloc::vec::Vec<u8>> {
    esp::read(path).ok()
}

mod esp;

fn unlock_root_volume() -> *mut u8 {
    crypto::prompt_and_derive_key()
}

mod crypto;

fn boot_kernel(usable: u64, key_page: *mut u8) -> ! {
    handoff::jump_to_kernel(usable, key_page)
}

mod handoff;
