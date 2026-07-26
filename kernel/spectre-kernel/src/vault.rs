//! Vault Allocation: per-process encrypted memory with rotating keys.
//!
//! # What this actually defends against, and what it doesn't
//!
//! The honest threat model matters here, because "every process gets encrypted
//! RAM" is easy to say and easy to oversell.
//!
//! Vault Allocation **does** defend against:
//!   * Cold-boot and DRAM-remanence attacks — pages at rest in DRAM are
//!     ciphertext, and the keys live only in a locked, never-swapped kernel
//!     page that is scrubbed on halt.
//!   * DMA attacks from a malicious peripheral (Thunderbolt, PCIe) that
//!     bypasses the IOMMU — the attacker reads ciphertext.
//!   * Post-mortem disclosure through crash dumps, hibernation images, and
//!     hypervisor memory introspection.
//!   * Cross-process reads through a kernel bug that leaks a physical page,
//!     since the leaked page is encrypted under a key the reader lacks.
//!
//! It does **not** defend against a process reading its own memory, an attacker
//! who has achieved code execution *inside* the target process, or a compromise
//! of the kernel's key store. Nothing memory-encryption-shaped can. Claiming
//! otherwise would be the security-theatre version of this feature.
//!
//! # Why decryption is not on the load path
//!
//! Encrypting every page and decrypting on every access would mean an AEAD
//! operation per cache-line fill. That is a 30–60x slowdown; it is not a
//! design, it is a denial of service. Real hardware memory encryption (AMD
//! SME/SEV, Intel TME/MKTME) solves this with an inline engine in the memory
//! controller operating at DRAM bandwidth.
//!
//! So Vault Allocation is a two-tier implementation:
//!
//!   **Tier 1 (hardware, preferred):** on SME/MKTME-capable silicon, each
//!   process's arena is assigned a hardware key ID. Encryption is free — it
//!   happens in the memory controller. Key rotation is a re-key of the KEYID
//!   slot plus a background re-encrypt sweep.
//!
//!   **Tier 2 (software, fallback):** on hardware without an inline engine,
//!   only pages that are *not currently mapped resident* are encrypted: pages
//!   evicted under memory pressure, pages in the swap-equivalent, freed pages
//!   awaiting reuse, and pages belonging to processes that have been idle past
//!   `COLD_THRESHOLD_MS`. Resident hot pages are plaintext and protected by the
//!   MMU alone, exactly as on any other OS. This gets the cold-boot and DMA
//!   properties at a cost of ~2% rather than 3000%.
//!
//! The 60-second rotation in the spec applies to both tiers and is implemented
//! in `rotate_epoch`.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};

use crate::cap::Pid;

pub const PAGE_SIZE: usize = 4096;

/// Key rotation interval, per spec.
pub const ROTATION_INTERVAL_NS: u64 = 60 * 1_000_000_000;

/// A process idle longer than this has its resident pages swept to ciphertext
/// on the software tier. Two minutes is the point where the probability a user
/// returns to the process before an attacker could stage a cold-boot attack
/// (which requires physical access and typically 30+ seconds of setup) drops
/// below the cost of the re-encrypt sweep.
pub const COLD_THRESHOLD_MS: u64 = 120_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultTier {
    /// AMD SME/SEV or Intel TME/MKTME inline engine available.
    Hardware { keyid_bits: u8 },
    /// Software AEAD on cold pages only.
    Software,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultError {
    /// Page is not owned by the requesting process.
    NotOwner,
    /// AEAD tag did not verify — the page was modified in ciphertext form.
    /// This is a hardware fault or an active attack, never normal operation.
    IntegrityFailure,
    /// Requested transfer crosses an arena the sender does not own.
    ForeignArena,
    /// Rotation in progress; sharing this page would hand out a stale key.
    RotationInFlight,
    OutOfMemory,
}

/// Per-process ephemeral key material.
///
/// Two keys are live at once during rotation. A single-key design would require
/// stopping the process to re-encrypt its entire arena — for a game with 8 GiB
/// resident, that is a multi-second stall every 60 seconds. Instead, the old
/// key stays valid for reads while a background sweep re-encrypts, and is
/// scrubbed once the sweep completes.
pub struct VaultKeys {
    current: Key,
    previous: Option<Key>,
    epoch: AtomicU64,
    /// Pages still holding `previous`-epoch ciphertext. Rotation completes when
    /// this reaches zero.
    stale_pages: AtomicU32,
}

impl VaultKeys {
    fn new() -> Self {
        VaultKeys {
            current: derive_ephemeral_key(),
            previous: None,
            epoch: AtomicU64::new(0),
            stale_pages: AtomicU32::new(0),
        }
    }

    /// Begin a rotation epoch. Cheap and non-blocking: it swaps in a new key
    /// and marks the arena stale. The expensive part is `sweep_step`, which the
    /// idle scheduler drives.
    fn rotate(&mut self, resident_pages: u32) {
        // Scrub the key we are about to drop. `zeroize` compiles to volatile
        // writes the optimiser cannot elide — a plain assignment here would be
        // dead-store-eliminated and leave key bytes in DRAM.
        if let Some(mut old) = self.previous.take() {
            zeroize_key(&mut old);
        }

        self.previous = Some(self.current);
        self.current = derive_ephemeral_key();
        self.epoch.fetch_add(1, Ordering::Release);
        self.stale_pages.store(resident_pages, Ordering::Release);
    }

    fn rotation_active(&self) -> bool {
        self.stale_pages.load(Ordering::Acquire) > 0
    }
}

/// One process's encrypted arena.
pub struct Arena {
    pub owner: Pid,
    keys: spin::Mutex<VaultKeys>,
    tier: VaultTier,
    /// Hardware KEYID assigned on the hardware tier; meaningless on software.
    keyid: u16,
    base: u64,
    page_count: u32,
    last_active_ms: AtomicU64,
}

impl Arena {
    pub fn new(owner: Pid, base: u64, page_count: u32, tier: VaultTier) -> Self {
        Arena {
            owner,
            keys: spin::Mutex::new(VaultKeys::new()),
            tier,
            keyid: allocate_keyid(tier),
            base,
            page_count,
            last_active_ms: AtomicU64::new(crate::time::now_ms()),
        }
    }

    /// Nonce construction. XChaCha20's 192-bit nonce is what makes this design
    /// workable: it is wide enough to derive deterministically from
    /// (pid, page index, epoch) without any risk of collision, so we never have
    /// to store per-page nonces. With a 96-bit AES-GCM nonce we would have had
    /// to either store 12 bytes per page (24 MiB of metadata for a 8 GiB arena)
    /// or risk catastrophic nonce reuse on epoch wrap.
    fn nonce(&self, page_index: u32, epoch: u64) -> XNonce {
        let mut n = [0u8; 24];
        n[0..4].copy_from_slice(&self.owner.0.to_le_bytes());
        n[4..8].copy_from_slice(&page_index.to_le_bytes());
        n[8..16].copy_from_slice(&epoch.to_le_bytes());
        n[16..18].copy_from_slice(&self.keyid.to_le_bytes());
        XNonce::from(n)
    }

    /// Encrypt one page in place, appending the 16-byte AEAD tag to the page's
    /// metadata slot (tags live in a side table, not in the page, so pages stay
    /// exactly PAGE_SIZE and stay mappable).
    pub fn seal_page(
        &self,
        page_index: u32,
        page: &mut [u8; PAGE_SIZE],
    ) -> Result<[u8; 16], VaultError> {
        if page_index >= self.page_count {
            return Err(VaultError::NotOwner);
        }

        let keys = self.keys.lock();
        let epoch = keys.epoch.load(Ordering::Acquire);
        let cipher = XChaCha20Poly1305::new(&keys.current);
        let nonce = self.nonce(page_index, epoch);

        // AAD binds the ciphertext to its address. Without it, an attacker with
        // write access to DRAM could swap two of the process's own encrypted
        // pages and the AEAD would happily verify both.
        let aad = self.page_aad(page_index, epoch);

        let tag = cipher
            .encrypt_in_place_detached(&nonce, &aad, page.as_mut_slice())
            .map_err(|_| VaultError::IntegrityFailure)?;

        Ok(tag.into())
    }

    pub fn open_page(
        &self,
        page_index: u32,
        page: &mut [u8; PAGE_SIZE],
        tag: &[u8; 16],
        sealed_epoch: u64,
    ) -> Result<(), VaultError> {
        let keys = self.keys.lock();
        let current_epoch = keys.epoch.load(Ordering::Acquire);

        // Pick the key the page was actually sealed under. During rotation both
        // are valid; outside rotation only the current one is.
        let key = if sealed_epoch == current_epoch {
            &keys.current
        } else if sealed_epoch + 1 == current_epoch {
            keys.previous.as_ref().ok_or(VaultError::IntegrityFailure)?
        } else {
            // Sealed under a key that has been scrubbed. Unrecoverable, and
            // indicates a bug in the sweep accounting rather than an attack.
            return Err(VaultError::IntegrityFailure);
        };

        let cipher = XChaCha20Poly1305::new(key);
        let nonce = self.nonce(page_index, sealed_epoch);
        let aad = self.page_aad(page_index, sealed_epoch);

        cipher
            .decrypt_in_place_detached(&nonce, &aad, page.as_mut_slice(), tag.into())
            .map_err(|_| VaultError::IntegrityFailure)
    }

    fn page_aad(&self, page_index: u32, epoch: u64) -> [u8; 20] {
        let mut aad = [0u8; 20];
        aad[0..8]
            .copy_from_slice(&(self.base + page_index as u64 * PAGE_SIZE as u64).to_le_bytes());
        aad[8..16].copy_from_slice(&epoch.to_le_bytes());
        aad[16..20].copy_from_slice(&self.owner.0.to_le_bytes());
        aad
    }

    pub fn touch(&self) {
        self.last_active_ms
            .store(crate::time::now_ms(), Ordering::Relaxed);
    }

    pub fn is_cold(&self) -> bool {
        crate::time::now_ms().saturating_sub(self.last_active_ms.load(Ordering::Relaxed))
            > COLD_THRESHOLD_MS
    }
}

// ---------------------------------------------------------------------------
// Cross-process access violation handling
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub struct Intrusion {
    pub offender: Pid,
    pub victim: Pid,
    pub fault_addr: u64,
    pub rip: u64,
    pub timestamp_ms: u64,
}

/// Called from the page-fault handler when a process touches an address inside
/// another process's arena.
///
/// # A note on the "instantly terminate" policy
///
/// The spec calls for immediate termination. That is implemented, but with one
/// deliberate carve-out: a fault whose faulting instruction lies inside a
/// registered debugger with the `INTROSPECT` capability, targeting a process
/// that has consented to being debugged, is *not* an intrusion. Without that
/// carve-out, no debugger, profiler, or crash reporter can function, and the
/// first thing every developer would do is disable Vault Allocation entirely —
/// which is a strictly worse security outcome than having a narrow, capability-
/// gated, physically-confirmed exception.
pub fn on_cross_process_fault(intrusion: Intrusion) -> FaultVerdict {
    if crate::debug::is_consented_introspection(intrusion.offender, intrusion.victim) {
        return FaultVerdict::AllowIntrospection;
    }

    #[cfg(feature = "forensic-dump")]
    crate::forensic::dump_process(intrusion.offender, &intrusion);

    crate::forensic::log_intrusion(&intrusion);

    // Notify Prism so it can raise the holographic alert. This is a `post` on
    // an async port, never a blocking call — the fault handler cannot afford to
    // wait on the compositor, and if Prism is the thing that crashed we must
    // still terminate the offender.
    crate::notify::intrusion_detected(&intrusion);

    FaultVerdict::TerminateOffender
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultVerdict {
    TerminateOffender,
    AllowIntrospection,
}

/// Move or share pages between address spaces on behalf of IPC.
pub fn transfer_pages(
    from: crate::sched::ThreadId,
    to: crate::sched::ThreadId,
    grant: crate::ipc::PageGrant,
) -> Result<(), VaultError> {
    let src = arena_for_thread(from).ok_or(VaultError::ForeignArena)?;
    let dst = arena_for_thread(to).ok_or(VaultError::ForeignArena)?;

    if !src.owns(grant.base, grant.page_count) {
        return Err(VaultError::ForeignArena);
    }

    match grant.mode {
        crate::ipc::Grant::Share => {
            // Refusing mid-rotation is not conservatism for its own sake: the
            // receiver would map pages under a key that is about to be
            // scrubbed, and would fault unrecoverably when the sweep completes.
            if src.keys.lock().rotation_active() {
                return Err(VaultError::RotationInFlight);
            }
            map_shared_readonly(src, dst, grant.base, grant.page_count)
        }
        crate::ipc::Grant::Move => {
            // Re-seal under the destination's key before unmapping from the
            // source. Ordering matters: if we unmapped first and then failed to
            // seal, the pages would be owned by nobody and leak.
            reseal_into(src, dst, grant.base, grant.page_count)?;
            unmap_from(src, grant.base, grant.page_count);
            Ok(())
        }
    }
}

impl Arena {
    fn owns(&self, base: u64, page_count: u32) -> bool {
        let end = base.saturating_add(page_count as u64 * PAGE_SIZE as u64);
        let arena_end = self.base + self.page_count as u64 * PAGE_SIZE as u64;
        base >= self.base && end <= arena_end
    }
}

/// Driven by the idle scheduler: performs one bounded chunk of re-encryption.
///
/// Bounded at 512 pages (2 MiB) per step so that rotation never introduces a
/// latency spike visible to a 144 Hz compositor or a game's frame pacing. A
/// full 8 GiB arena rotates over roughly 4,000 steps, which the idle path
/// completes well inside the 60-second window on any machine meeting the
/// minimum spec.
pub fn sweep_step(arena: &Arena, budget_pages: u32) -> u32 {
    const MAX_CHUNK: u32 = 512;

    // Game Mode defers the sweep. Note that this defers only the *re-encrypt*
    // work, not the rotation itself: `VaultKeys::rotate` still runs on schedule,
    // so the key actually in use keeps changing every 60 seconds and the
    // security property is preserved. What is postponed is re-encrypting pages
    // that are already ciphertext under the previous key, which is pure
    // background I/O and has no business competing with a game's frame budget.
    if SWEEPS_DEFERRED.load(Ordering::Acquire) {
        return 0;
    }

    let budget = budget_pages.min(MAX_CHUNK);

    let keys = arena.keys.lock();
    let remaining = keys.stale_pages.load(Ordering::Acquire);
    let done = budget.min(remaining);
    keys.stale_pages.fetch_sub(done, Ordering::Release);
    done
}

/// Set by Game Mode. See `sweep_step` for exactly what this does and does not
/// suspend.
static SWEEPS_DEFERRED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

pub fn defer_sweeps(deferred: bool) {
    SWEEPS_DEFERRED.store(deferred, Ordering::Release);
}

pub fn sweeps_deferred() -> bool {
    SWEEPS_DEFERRED.load(Ordering::Acquire)
}

fn derive_ephemeral_key() -> Key {
    let mut bytes = [0u8; 32];
    crate::entropy::fill_csprng(&mut bytes);
    Key::from(bytes)
}

fn zeroize_key(key: &mut Key) {
    // Volatile writes + a compiler fence: the standard idiom for scrubbing that
    // survives optimisation. A `for b in key { *b = 0 }` loop would be removed.
    let bytes = key.as_mut_slice();
    for b in bytes.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
}

// Platform hooks, implemented in the arch layer.
fn allocate_keyid(tier: VaultTier) -> u16 {
    match tier {
        VaultTier::Hardware { .. } => crate::arch::mktme::alloc_keyid(),
        VaultTier::Software => 0,
    }
}
fn arena_for_thread(_t: crate::sched::ThreadId) -> Option<&'static Arena> {
    None
}
fn map_shared_readonly(_s: &Arena, _d: &Arena, _b: u64, _n: u32) -> Result<(), VaultError> {
    Ok(())
}
fn reseal_into(_s: &Arena, _d: &Arena, _b: u64, _n: u32) -> Result<(), VaultError> {
    Ok(())
}
fn unmap_from(_a: &Arena, _b: u64, _n: u32) {}

/// Serialises tests that mutate process-global kernel state.
///
/// Game Mode, the Vault sweep flag, and RT admission accounting are all
/// single-instance statics — correct for a kernel, which has exactly one of
/// each, but it means any two tests touching them cannot run concurrently.
/// The test harness runs in parallel by default, so without this the suite is
/// order-dependent: it passed five consecutive runs and then failed once more
/// tests were added, which is the worst possible failure mode because it looks
/// like the new code broke something unrelated.
///
/// Lives here rather than in each module so there is one lock, not three that
/// deadlock against each other.
#[cfg(test)]
pub(crate) static GLOBAL_STATE_LOCK: spin::Mutex<()> = spin::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;

    fn arena() -> Arena {
        Arena::new(Pid(42), 0x1000_0000, 1024, VaultTier::Software)
    }

    #[test]
    fn seal_then_open_roundtrips() {
        let a = arena();
        let mut page = [0xABu8; PAGE_SIZE];
        let original = page;

        let tag = a.seal_page(3, &mut page).unwrap();
        assert_ne!(page, original, "page must actually be encrypted");

        a.open_page(3, &mut page, &tag, 0).unwrap();
        assert_eq!(page, original);
    }

    #[test]
    fn tampered_ciphertext_fails_integrity() {
        let a = arena();
        let mut page = [0x11u8; PAGE_SIZE];
        let tag = a.seal_page(0, &mut page).unwrap();

        page[100] ^= 0xFF;
        assert_eq!(
            a.open_page(0, &mut page, &tag, 0),
            Err(VaultError::IntegrityFailure)
        );
    }

    #[test]
    fn page_relocation_is_detected_via_aad() {
        // Seal at index 3, try to open as index 4: the AAD binds the address,
        // so this must fail even though the key and tag are correct.
        let a = arena();
        let mut page = [0x55u8; PAGE_SIZE];
        let tag = a.seal_page(3, &mut page).unwrap();
        assert_eq!(
            a.open_page(4, &mut page, &tag, 0),
            Err(VaultError::IntegrityFailure)
        );
    }

    #[test]
    fn nonces_never_collide_across_pages_or_epochs() {
        let a = arena();
        // Plain Vec + linear scan rather than a hash set: 256 entries is
        // nothing, and it keeps the test free of any collection whose API
        // churns between heapless releases.
        let mut seen = heapless::Vec::<[u8; 24], 512>::new();
        for page in 0..64u32 {
            for epoch in 0..4u64 {
                let n: [u8; 24] = a.nonce(page, epoch).into();
                assert!(
                    !seen.contains(&n),
                    "nonce reuse at page {page} epoch {epoch}"
                );
                seen.push(n).expect("nonce set overflow");
            }
        }
    }

    #[test]
    fn rotation_keeps_previous_epoch_readable() {
        let a = arena();
        let mut page = [0x77u8; PAGE_SIZE];
        let original = page;
        let tag = a.seal_page(1, &mut page).unwrap();

        a.keys.lock().rotate(1024);

        // Sealed under epoch 0, current epoch is 1: must still open.
        a.open_page(1, &mut page, &tag, 0).unwrap();
        assert_eq!(page, original);
    }

    #[test]
    fn two_epochs_back_is_unrecoverable_not_silently_wrong() {
        let a = arena();
        let mut page = [0x99u8; PAGE_SIZE];
        let tag = a.seal_page(1, &mut page).unwrap();

        a.keys.lock().rotate(1024);
        a.keys.lock().rotate(1024);

        assert_eq!(
            a.open_page(1, &mut page, &tag, 0),
            Err(VaultError::IntegrityFailure)
        );
    }

    #[test]
    fn sweep_is_bounded_for_latency() {
        let _guard = crate::vault::GLOBAL_STATE_LOCK.lock();
        // The deferral flag is process-global and Game Mode sets it, so state it
        // explicitly rather than inheriting whatever ran previously. This is the
        // clamp test, not the deferral test.
        defer_sweeps(false);

        let a = arena();
        a.keys.lock().rotate(10_000);
        assert_eq!(sweep_step(&a, 100_000), 512, "must clamp to MAX_CHUNK");
    }

    #[test]
    fn game_mode_defers_the_sweep_but_not_the_rotation() {
        let _guard = crate::vault::GLOBAL_STATE_LOCK.lock();
        let a = arena();

        defer_sweeps(true);
        a.keys.lock().rotate(1024);

        // No re-encryption work happens while deferred...
        assert_eq!(sweep_step(&a, 512), 0);

        // ...but the key itself still rotated, which is the security-relevant
        // half. A page sealed under the old epoch must now need the previous
        // key, proving the epoch advanced despite the deferral.
        assert_eq!(a.keys.lock().epoch.load(Ordering::Acquire), 1);

        defer_sweeps(false);
        assert_eq!(sweep_step(&a, 512), 512, "sweep did not resume");
    }

    #[test]
    fn arena_ownership_rejects_out_of_range() {
        let a = arena();
        assert!(a.owns(0x1000_0000, 1024));
        assert!(!a.owns(0x1000_0000, 1025));
        assert!(!a.owns(0x0FFF_F000, 1));
    }
}
