//! Host-side verification harness.
//!
//! Compiles the pure-logic modules of WhisezOS against `std` and runs their
//! test suites. The modules are included by `#[path]`, not copied, so this
//! tests the real shipped source.
//!
//! What this does NOT do: boot anything. The kernel and bootloader crates need
//! their platform layer (`arch`, `thread`, `percpu`, page tables, IDT, context
//! switch) before an image exists to boot. This harness verifies the logic that
//! sits above that layer.

// Included production modules intentionally expose entry points that the host
// harness does not call. Deprecation warnings are tracked in the production
// crate; duplicating them here obscures the test signal.
#![allow(dead_code, deprecated)]

// --- shims for platform services the logic modules call ------------------
// Deterministic stand-ins. Each one is only enough to let the logic under test
// run; none of them pretends to be the real implementation.

pub mod entropy {
    use std::sync::atomic::{AtomicU64, Ordering};

    static STATE: AtomicU64 = AtomicU64::new(0x2545_F491_4F6C_DD1D);

    /// xorshift64* — deterministic, decent distribution, no dependencies.
    /// Real builds use RDSEED via `arch::entropy`.
    fn next() -> u64 {
        let mut x = STATE.load(Ordering::Relaxed);
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        STATE.store(x, Ordering::Relaxed);
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub fn csprng_u128(nonce: u64) -> u128 {
        let hi = next() ^ nonce;
        let lo = next();
        ((hi as u128) << 64) | lo as u128
    }

    pub fn fill_csprng(out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            let v = next().to_le_bytes();
            let n = chunk.len();
            chunk.copy_from_slice(&v[..n]);
        }
    }
}

pub mod time {
    use std::sync::atomic::{AtomicU64, Ordering};

    static NOW_MS: AtomicU64 = AtomicU64::new(0);

    pub fn now_ms() -> u64 {
        NOW_MS.load(Ordering::Relaxed)
    }

    /// Test hook: drive the clock explicitly so time-dependent logic is
    /// deterministic instead of racing a real clock.
    pub fn set_now_ms(v: u64) {
        NOW_MS.store(v, Ordering::Relaxed);
    }
}

// --- modules under test ---------------------------------------------------

#[path = "../../userland/prism/src/anim.rs"]
pub mod anim;

#[path = "../../userland/prism/src/wm.rs"]
pub mod wm;

#[path = "../../userland/prism/src/startmenu.rs"]
pub mod startmenu;

#[path = "../../userland/spectreshield/src/heuristic.rs"]
pub mod heuristic;

#[path = "../../userland/winbridge/src/pe.rs"]
pub mod pe;

#[path = "../../fs/spectrefs/src/blake3.rs"]
pub mod blake3;

#[path = "../../fs/spectrefs/src/layout.rs"]
pub mod layout;

#[path = "../../boot/spectre-boot/src/glitch.rs"]
pub mod glitch;

#[path = "../../boot/spectre-boot/src/attest.rs"]
pub mod attest;

#[path = "../../boot/spectre-boot/src/spd.rs"]
pub mod spd;

#[path = "../../kernel/spectre-kernel/src/elf.rs"]
pub mod elf;

/// The loader-to-kernel ABI. Compiled here as well as in both binaries, so a
/// layout change that breaks the handoff fails a host test rather than a boot.
#[path = "../../kernel/spectre-kernel/src/boot_info.rs"]
pub mod boot_info;

/// The syscall ABI, compiled here as well as in the kernel and in init — the
/// three places that have to agree about it.
#[path = "../../kernel/spectre-kernel/src/abi.rs"]
pub mod abi;

#[path = "../../kernel/spectre-kernel/src/device.rs"]
pub mod device;

#[path = "../../kernel/spectre-kernel/src/dma.rs"]
pub mod dma;

#[path = "../../kernel/spectre-kernel/src/irq.rs"]
pub mod irq;

#[path = "../../kernel/spectre-kernel/src/pci.rs"]
pub mod pci;

#[path = "../../kernel/spectre-kernel/src/portauth.rs"]
pub mod portauth;

#[path = "../../kernel/spectre-kernel/src/font.rs"]
pub mod font;

#[path = "../../kernel/spectre-kernel/src/rendezvous.rs"]
pub mod rendezvous;

#[path = "../../kernel/spectre-kernel/src/roundrobin.rs"]
pub mod roundrobin;

#[path = "../../kernel/spectre-kernel/src/virtio.rs"]
pub mod virtio;

#[path = "../../kernel/spectre-kernel/src/vmspace.rs"]
pub mod vmspace;

#[path = "../../kernel/spectre-kernel/src/usercopy.rs"]
pub mod usercopy;

#[path = "../../boot/spectre-boot/src/pointer.rs"]
pub mod pointer;

#[path = "../../boot/spectre-boot/src/ps2.rs"]
pub mod ps2;

#[path = "../../boot/spectre-boot/src/setup.rs"]
pub mod setup;

#[path = "../../boot/spectre-boot/src/shell.rs"]
pub mod shell;

#[path = "../../kernel/spectre-kernel/src/cap.rs"]
pub mod cap;

#[path = "../../kernel/spectre-kernel/src/sched.rs"]
pub mod sched;

#[path = "../../kernel/spectre-kernel/src/vault.rs"]
pub mod vault;

#[path = "../../kernel/spectre-kernel/src/ipc.rs"]
pub mod ipc;

#[path = "../../kernel/spectre-kernel/src/gamemode.rs"]
pub mod gamemode;

// Platform stand-ins, re-exported at crate root so the `crate::arch::...` paths
// in the modules above resolve without editing them.
mod shims;

pub use shims::{compact, debug, forensic, gpu, net, notify, percpu, thread};

/// `arch` is split out from the other shims because most of it is real,
/// testable code (`addr`, `paging`) rather than a stand-in.
#[path = "arch_host.rs"]
pub mod arch;
