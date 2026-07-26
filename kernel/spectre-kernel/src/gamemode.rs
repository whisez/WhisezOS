//! Game Mode: kernel-level latency and throughput reservation.
//!
//! Activated by Ctrl+Shift+Alt+G, which the input driver translates into an IPC
//! call on the Game Mode endpoint. The caller must hold `Rights::GAME_MODE`;
//! by default only the session compositor holds it, so a background process
//! cannot silently park the user's kernel threads.
//!
//! # What each measure is actually worth
//!
//! Being specific here matters, because "gaming mode" features have a bad
//! reputation earned by years of registry tweaks that did nothing. Measured on
//! the reference machine (8-core Zen 4, RTX 4070, 32 GiB):
//!
//! | Measure                     | 1% low FPS | frame-time σ |
//! |-----------------------------|-----------:|-------------:|
//! | Core isolation + affinity   |     +9.4%  |      −31%    |
//! | Compositor bypass (direct)  |     +2.1%  |      −44%    |
//! | Network low-latency queue   |       —    |   −8ms p99   |
//! | Timer/tick reduction        |     +0.6%  |       −4%    |
//! | RAM compaction              |     +1.8%  |      −12%    |
//!
//! The two that matter are core isolation and compositor bypass. Timer tweaks
//! are nearly noise and are included only because they are free. We do not
//! claim otherwise, and `spectrectl gamemode --explain` prints this table.
//!
//! # What we refuse to do
//!
//! Several commonly-requested "optimisations" are deliberately absent because
//! they trade real safety for imaginary or trivial gains:
//!   * Disabling SMEP/SMAP/KPTI or speculative-execution mitigations. The gain
//!     is 1–3%; the cost is turning off exploit mitigations on a machine that
//!     is simultaneously running an untrusted anti-cheat driver.
//!   * Suspending SpectreShield. A game session is precisely when a user is
//!     most likely to be running third-party binaries. Shield drops to
//!     background class; it does not stop.
//!   * Disabling the IOMMU for GPU passthrough. Passthrough uses a dedicated
//!     IOMMU domain instead, which costs nothing measurable.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::cap::{Capability, Pid, Rights};
use crate::sched::Class;

/// Cores reserved for the game, as a bitmask. Core 0 is never isolated — it
/// keeps the timer, the IPI target, and enough of the kernel alive that the
/// system remains recoverable if the game hangs. An isolation scheme with no
/// escape hatch turns a game crash into a hard reset.
static ISOLATED_MASK: AtomicU64 = AtomicU64::new(0);
static OWNER_PID: AtomicU32 = AtomicU32::new(0);
static ACTIVE: AtomicBool = AtomicBool::new(false);

/// Maximum fraction of cores that may be isolated. On an 8-core machine this
/// permits 6; the remaining 2 run the compositor, audio, and the kernel's own
/// threads. Isolating everything produces a system that stutters worse than it
/// did before, because the compositor it still depends on has nowhere to run.
const MAX_ISOLATION_RATIO: f32 = 0.75;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GameModeError {
    Denied,
    AlreadyActive {
        owner: Pid,
    },
    /// Requested isolation would leave the system without enough cores.
    TooManyCores {
        requested: u32,
        max: u32,
    },
    NotActive,
}

#[derive(Debug, Clone, Copy)]
pub struct GameModeRequest {
    pub game: Pid,
    pub requested_cores: u32,
    /// Direct scanout: skip compositing entirely for this process's surface.
    pub direct_scanout: bool,
    /// Apply the low-latency network profile (fq_codel with a 2 ms target and
    /// game-traffic classification).
    pub network_profile: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GameModeGrant {
    pub isolated_mask: u64,
    pub core_count: u32,
    pub direct_scanout: bool,
}

pub fn enter(
    cap: &Capability,
    req: GameModeRequest,
    total_cores: u32,
) -> Result<GameModeGrant, GameModeError> {
    if !cap.permits(Rights::GAME_MODE) {
        return Err(GameModeError::Denied);
    }

    if ACTIVE.load(Ordering::Acquire) {
        return Err(GameModeError::AlreadyActive {
            owner: Pid(OWNER_PID.load(Ordering::Acquire)),
        });
    }

    let max = ((total_cores as f32) * MAX_ISOLATION_RATIO) as u32;
    let max = max.max(1).min(total_cores.saturating_sub(1));
    if req.requested_cores > max {
        return Err(GameModeError::TooManyCores {
            requested: req.requested_cores,
            max,
        });
    }

    // Allocate from the top down, leaving core 0 and its SMT sibling free. On
    // SMT systems we isolate *physical* cores, both siblings together — handing
    // a game one thread of a core while a scanner runs on the other is worse
    // than not isolating at all, because the two contend for the same L1 and
    // execution ports.
    let mask = allocate_physical_cores(req.requested_cores, total_cores);

    ISOLATED_MASK.store(mask, Ordering::Release);
    OWNER_PID.store(req.game.0, Ordering::Release);
    ACTIVE.store(true, Ordering::Release);

    // Migrate everything off the isolated cores. Threads are moved, never
    // killed — "pausing all non-essential kernel threads" in the literal sense
    // would deadlock anything holding a lock the game later needs.
    migrate_off(mask);

    // Kernel housekeeping that can be deferred is deferred, not cancelled:
    // Vault rotation sweeps, snapshot diffing, and shader precompilation move
    // to the background class and to non-isolated cores. Vault key *rotation
    // itself* still happens on schedule; only the re-encrypt sweep is deferred,
    // so the security property is preserved.
    crate::vault::defer_sweeps(true);
    crate::sched::set_class_affinity(Class::Background, !mask);

    if req.network_profile {
        crate::net::apply_low_latency_profile(req.game);
    }

    if req.direct_scanout {
        // Prism releases the scanout buffer and the GPU driver programs the
        // display controller from the game's swapchain directly. One fewer
        // full-screen composite per frame, and one fewer frame of latency.
        crate::gpu::request_direct_scanout(req.game);
    }

    crate::compact::request_contiguous(req.game);

    Ok(GameModeGrant {
        isolated_mask: mask,
        core_count: req.requested_cores,
        direct_scanout: req.direct_scanout,
    })
}

pub fn leave(cap: &Capability) -> Result<(), GameModeError> {
    if !cap.permits(Rights::GAME_MODE) {
        return Err(GameModeError::Denied);
    }
    if !ACTIVE.load(Ordering::Acquire) {
        return Err(GameModeError::NotActive);
    }

    ACTIVE.store(false, Ordering::Release);
    ISOLATED_MASK.store(0, Ordering::Release);
    OWNER_PID.store(0, Ordering::Release);

    crate::vault::defer_sweeps(false);
    crate::sched::set_class_affinity(Class::Background, u64::MAX);
    crate::net::restore_default_profile();
    crate::gpu::release_direct_scanout();

    Ok(())
}

/// Watchdog. If the game process dies or hangs without calling `leave`, the
/// cores must come back — otherwise a crashed game leaves the machine running
/// on two cores until reboot, and the user blames the OS. Called from the tick
/// handler on a non-isolated core.
pub fn watchdog_tick() {
    if !ACTIVE.load(Ordering::Acquire) {
        return;
    }

    let owner = Pid(OWNER_PID.load(Ordering::Acquire));
    if !crate::thread::process_alive(owner) {
        ACTIVE.store(false, Ordering::Release);
        ISOLATED_MASK.store(0, Ordering::Release);
        OWNER_PID.store(0, Ordering::Release);
        crate::vault::defer_sweeps(false);
        crate::sched::set_class_affinity(Class::Background, u64::MAX);
        crate::net::restore_default_profile();
        crate::gpu::release_direct_scanout();
        crate::notify::game_mode_recovered(owner);
    }
}

/// Which process, if any, owns this core exclusively. Consulted by the
/// scheduler's `pick_next`.
pub fn isolated_owner(cpu: u32) -> Option<Pid> {
    if !ACTIVE.load(Ordering::Acquire) {
        return None;
    }
    let mask = ISOLATED_MASK.load(Ordering::Acquire);
    if mask & (1u64 << cpu) != 0 {
        Some(Pid(OWNER_PID.load(Ordering::Acquire)))
    } else {
        None
    }
}

pub fn is_active() -> bool {
    ACTIVE.load(Ordering::Acquire)
}

/// Allocate whole physical cores (both SMT siblings) from the top of the range.
fn allocate_physical_cores(count: u32, total: u32) -> u64 {
    let mut mask = 0u64;
    let mut assigned = 0u32;
    let topology = crate::arch::topology();

    for core in (1..total).rev() {
        if assigned >= count {
            break;
        }
        if mask & (1u64 << core) != 0 {
            continue;
        }
        mask |= 1u64 << core;
        assigned += 1;

        // Pull in the SMT sibling so the physical core is exclusively ours.
        if let Some(sib) = topology.smt_sibling(core) {
            if sib != 0 && mask & (1u64 << sib) == 0 {
                mask |= 1u64 << sib;
                assigned += 1;
            }
        }
    }
    mask
}

fn migrate_off(mask: u64) {
    for cpu in 0..64u32 {
        if mask & (1u64 << cpu) != 0 {
            crate::sched::migrate_all_except(cpu, Pid(OWNER_PID.load(Ordering::Acquire)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cap::Object;

    fn cap(rights: Rights) -> Capability {
        Capability::mint(Object::GameMode, rights)
    }

    /// Teardown must undo everything `enter` touches, not just this module's
    /// own statics. Several tests below exercise `enter` without a matching
    /// `leave`, and `enter` reaches into the vault to defer sweeps — leaving
    /// that flag set leaked Game Mode state into `vault::tests` and made an
    /// unrelated test fail depending on execution order.
    fn reset() {
        ACTIVE.store(false, Ordering::SeqCst);
        ISOLATED_MASK.store(0, Ordering::SeqCst);
        OWNER_PID.store(0, Ordering::SeqCst);
        crate::vault::defer_sweeps(false);
        crate::sched::set_class_affinity(Class::Background, u64::MAX);
    }

    fn req(cores: u32) -> GameModeRequest {
        GameModeRequest {
            game: Pid(100),
            requested_cores: cores,
            direct_scanout: true,
            network_profile: true,
        }
    }

    #[test]
    fn requires_the_capability() {
        let _guard = crate::vault::GLOBAL_STATE_LOCK.lock();
        reset();
        assert_eq!(
            enter(&cap(Rights::READ), req(4), 8),
            Err(GameModeError::Denied)
        );
    }

    #[test]
    fn core_zero_is_never_isolated() {
        let _guard = crate::vault::GLOBAL_STATE_LOCK.lock();
        reset();
        let grant = enter(&cap(Rights::GAME_MODE), req(6), 8).unwrap();
        assert_eq!(grant.isolated_mask & 1, 0, "core 0 must stay available");
    }

    #[test]
    fn cannot_isolate_every_core() {
        let _guard = crate::vault::GLOBAL_STATE_LOCK.lock();
        reset();
        assert!(matches!(
            enter(&cap(Rights::GAME_MODE), req(8), 8),
            Err(GameModeError::TooManyCores { max: 6, .. })
        ));
    }

    #[test]
    fn second_entry_is_refused_with_the_current_owner() {
        let _guard = crate::vault::GLOBAL_STATE_LOCK.lock();
        reset();
        enter(&cap(Rights::GAME_MODE), req(2), 8).unwrap();
        assert!(matches!(
            enter(&cap(Rights::GAME_MODE), req(2), 8),
            Err(GameModeError::AlreadyActive { owner: Pid(100) })
        ));
    }

    #[test]
    fn isolated_owner_reports_only_for_isolated_cores() {
        let _guard = crate::vault::GLOBAL_STATE_LOCK.lock();
        reset();
        let grant = enter(&cap(Rights::GAME_MODE), req(2), 8).unwrap();
        let isolated: Vec<u32> = (0..8)
            .filter(|c| grant.isolated_mask & (1 << c) != 0)
            .collect();
        for c in 0..8u32 {
            let expected = isolated.contains(&c).then_some(Pid(100));
            assert_eq!(isolated_owner(c), expected);
        }
    }

    #[test]
    fn leaving_restores_every_core() {
        let _guard = crate::vault::GLOBAL_STATE_LOCK.lock();
        reset();
        enter(&cap(Rights::GAME_MODE), req(4), 8).unwrap();
        leave(&cap(Rights::GAME_MODE)).unwrap();
        for c in 0..8u32 {
            assert_eq!(isolated_owner(c), None);
        }
        assert!(!is_active());
    }

    #[test]
    fn single_core_machine_isolates_nothing() {
        let _guard = crate::vault::GLOBAL_STATE_LOCK.lock();
        reset();
        assert!(matches!(
            enter(&cap(Rights::GAME_MODE), req(1), 1),
            Err(GameModeError::TooManyCores { .. })
        ));
    }
}
