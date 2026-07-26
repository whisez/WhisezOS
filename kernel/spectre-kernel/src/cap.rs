//! Capability tokens.
//!
//! WhisezOS has no ambient authority. There is no `root`, no `CAP_SYS_ADMIN`,
//! no "the process is trusted because of who started it". A process can only
//! act on a resource it holds an unforgeable token for, and tokens are handed
//! out by the parent at spawn time from the parent's own set — a process can
//! never grant more than it holds.
//!
//! This is what makes the user-space driver model tractable. The USB stack is
//! a normal process; it is dangerous only in proportion to the capabilities
//! init handed it (one MMIO window, one IRQ line, one DMA region). A compromise
//! of the USB stack yields exactly those three things and nothing else — not
//! the disk, not the network, not other processes' memory.
//!
//! # Why 128 bits and not a table index
//!
//! Tokens are randomised 128-bit values rather than small integers indexing a
//! per-process table. Table indices are guessable and, more importantly, are
//! *stable across a fork*, which historically has been the source of a long
//! line of capability-confusion bugs. A random token cannot be guessed by a
//! process that was never given it, so the "did I actually receive this?"
//! question has a cryptographic answer rather than a bookkeeping one.

use core::sync::atomic::{AtomicU64, Ordering};

bitflags::bitflags! {
    /// Rights carried by a token. Rights are monotonically *reducible*: a
    /// process may derive a weaker token from one it holds, never a stronger
    /// one. This is enforced in `Capability::derive`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Rights: u32 {
        const READ         = 1 << 0;
        const WRITE        = 1 << 1;
        const EXECUTE      = 1 << 2;
        /// Permits sending IPC to the endpoint this token names.
        const SEND         = 1 << 3;
        /// Permits blocking to receive on the endpoint.
        const RECEIVE      = 1 << 4;
        /// Permits handing this token to another process.
        const DELEGATE     = 1 << 5;
        /// Permits mapping the physical range this token names (drivers).
        const MAP_MMIO     = 1 << 6;
        /// Permits programming a DMA engine at this range. Separate from
        /// MAP_MMIO because DMA bypasses the IOMMU domain boundary and is the
        /// single most dangerous right in the system.
        const DMA          = 1 << 7;
        /// Permits binding the IRQ vector this token names.
        const IRQ          = 1 << 8;
        /// Permits the Game Mode transition (core isolation, thread parking).
        const GAME_MODE    = 1 << 9;
        /// Permits reading another process's memory. Held only by the debugger
        /// and only after physical-presence confirmation.
        const INTROSPECT   = 1 << 10;
    }
}

/// The kernel object a token names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Object {
    Endpoint(EndpointId),
    MemoryRegion {
        base: u64,
        len: u64,
    },
    IrqVector(u8),
    Process(Pid),
    /// The global Game Mode arbiter.
    GameMode,
}

pub type EndpointId = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Pid(pub u32);

/// An unforgeable reference to an object, with rights.
///
/// `Copy` is deliberate: possession *is* the authority, and a process that
/// holds a token can already use it arbitrarily often. Making the type
/// non-Copy would imply a revocation model the kernel does not have at this
/// layer (revocation is per-object, via `Registry::revoke`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capability {
    token: u128,
    pub object: Object,
    pub rights: Rights,
}

/// Counter feeding the token CSPRNG. Seeded at boot from RDSEED (or the TPM's
/// RNG on platforms without it) — see `entropy::seed_capability_rng`.
static TOKEN_COUNTER: AtomicU64 = AtomicU64::new(0);

impl Capability {
    /// Mint a fresh token. Only callable from kernel space — there is no
    /// syscall that reaches this.
    pub(crate) fn mint(object: Object, rights: Rights) -> Self {
        Capability {
            token: next_token(),
            object,
            rights,
        }
    }

    /// Derive a weaker token for delegation to a child.
    ///
    /// Returns `None` if the caller does not hold `DELEGATE`, or if the
    /// requested rights are not a subset of what the caller holds. The subset
    /// check is the entire security property of this function; it is why
    /// `Rights` is a bitflag set and not an enum.
    pub fn derive(&self, requested: Rights) -> Option<Capability> {
        if !self.rights.contains(Rights::DELEGATE) {
            return None;
        }
        if !self.rights.contains(requested) {
            return None;
        }

        Some(Capability {
            // A derived token is a *new* random value, not the parent's. If it
            // reused the parent token, revoking the child would revoke the
            // parent, and a child could impersonate its parent to a third
            // party that had seen the parent's token.
            token: next_token(),
            object: self.object,
            rights: requested,
        })
    }

    /// Check a token against a required right, in constant time with respect
    /// to the token value.
    pub fn permits(&self, required: Rights) -> bool {
        self.rights.contains(required)
    }

    /// Opaque handle for user-space. The raw token never crosses the syscall
    /// boundary in a form user-space can enumerate.
    pub fn handle(&self) -> u64 {
        // Fold to 64 bits for the ABI; collision probability across the
        // lifetime of a boot is negligible (birthday bound at 2^32 live
        // tokens, versus a hard cap of 2^20 per process).
        (self.token as u64) ^ ((self.token >> 64) as u64)
    }
}

fn next_token() -> u128 {
    // ChaCha20-based CSPRNG keyed at boot; the counter here is the nonce input,
    // never the token itself. Using a raw counter as a token would make every
    // future token predictable from any single observed one.
    let n = TOKEN_COUNTER.fetch_add(1, Ordering::Relaxed);
    crate::entropy::csprng_u128(n)
}

/// Per-process capability set.
///
/// Backed by a small open-addressed map rather than a Vec scan: capability
/// lookup is on the IPC hot path, and a linear scan over a driver's ~200
/// tokens showed up as 4% of send latency in early profiling.
pub struct CapSet {
    entries: [Option<Capability>; Self::SLOTS],
    len: usize,
}

impl CapSet {
    const SLOTS: usize = 256;

    pub const fn new() -> Self {
        CapSet {
            entries: [None; Self::SLOTS],
            len: 0,
        }
    }

    pub fn insert(&mut self, cap: Capability) -> Option<u64> {
        if self.len == Self::SLOTS {
            return None;
        }
        let handle = cap.handle();
        let mut idx = (handle as usize) % Self::SLOTS;
        loop {
            match self.entries[idx] {
                None => {
                    self.entries[idx] = Some(cap);
                    self.len += 1;
                    return Some(handle);
                }
                Some(existing) if existing.handle() == handle => return Some(handle),
                Some(_) => idx = (idx + 1) % Self::SLOTS,
            }
        }
    }

    pub fn lookup(&self, handle: u64) -> Option<&Capability> {
        let mut idx = (handle as usize) % Self::SLOTS;
        for _ in 0..Self::SLOTS {
            match &self.entries[idx] {
                Some(cap) if cap.handle() == handle => return Some(cap),
                Some(_) => idx = (idx + 1) % Self::SLOTS,
                None => return None,
            }
        }
        None
    }

    /// Revoke every token naming `object`. Used when a driver crashes and its
    /// MMIO window must be reclaimed before the restarted instance gets it.
    pub fn revoke_object(&mut self, object: Object) -> usize {
        let mut revoked = 0;
        for slot in self.entries.iter_mut() {
            if matches!(slot, Some(c) if c.object == object) {
                *slot = None;
                revoked += 1;
                self.len -= 1;
            }
        }
        revoked
    }
}

impl Default for CapSet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cap(rights: Rights) -> Capability {
        Capability::mint(Object::Endpoint(1), rights)
    }

    #[test]
    fn derive_cannot_amplify_rights() {
        let weak = cap(Rights::READ | Rights::DELEGATE);
        assert!(weak.derive(Rights::WRITE).is_none());
        assert!(weak.derive(Rights::READ).is_some());
    }

    #[test]
    fn derive_requires_delegate_right() {
        let no_delegate = cap(Rights::READ | Rights::WRITE);
        assert!(no_delegate.derive(Rights::READ).is_none());
    }

    #[test]
    fn derived_token_differs_from_parent() {
        let parent = cap(Rights::READ | Rights::DELEGATE);
        let child = parent.derive(Rights::READ).unwrap();
        assert_ne!(parent.handle(), child.handle());
    }

    #[test]
    fn revocation_clears_all_tokens_for_an_object() {
        let mut set = CapSet::new();
        let a = Capability::mint(Object::IrqVector(11), Rights::IRQ);
        let b = Capability::mint(Object::IrqVector(11), Rights::IRQ);
        let other = Capability::mint(Object::IrqVector(12), Rights::IRQ);
        set.insert(a);
        set.insert(b);
        set.insert(other);

        assert_eq!(set.revoke_object(Object::IrqVector(11)), 2);
        assert!(set.lookup(a.handle()).is_none());
        assert!(set.lookup(other.handle()).is_some());
    }
}
