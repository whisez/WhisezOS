//! Physical and virtual address newtypes.
//!
//! These exist because `u64` is the wrong type for an address and mixing the
//! two is the most common class of bug in a memory manager. A physical frame
//! number and a virtual page number are both "some integer", and the compiler
//! will happily let you pass one where the other belongs — right up until the
//! machine triple-faults with no useful diagnostic.
//!
//! # Canonical addresses
//!
//! x86-64 does not have a flat 64-bit virtual address space. With 4-level
//! paging only the low 48 bits are translated, and bits 48–63 must all equal
//! bit 47 — the "canonical" requirement. An address that violates it raises
//! #GP on use, not #PF, which is a confusing failure to debug because it looks
//! like an instruction fault rather than a memory fault.
//!
//! `VirtAddr::new` therefore refuses non-canonical values rather than
//! truncating them. Truncation is what several kernels do and it silently turns
//! a pointer bug into a wild write to an unrelated mapping.

use core::fmt;

/// Levels of paging in use. Set once at boot from CR4.LA57.
///
/// LA57 (5-level paging, 57-bit virtual addresses) is present on Ice Lake and
/// later server parts. Supporting it is not optional for a system that claims
/// a 128-bit filesystem and large memory support: a machine with more than
/// 64 TiB of RAM cannot be addressed without it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PagingMode {
    Level4,
    Level5,
}

impl PagingMode {
    /// Number of virtual address bits the hardware translates.
    pub const fn virt_bits(self) -> u32 {
        match self {
            PagingMode::Level4 => 48,
            PagingMode::Level5 => 57,
        }
    }

    /// Index of the sign-extension bit.
    pub const fn sign_bit(self) -> u32 {
        self.virt_bits() - 1
    }

    pub const fn levels(self) -> usize {
        match self {
            PagingMode::Level4 => 4,
            PagingMode::Level5 => 5,
        }
    }
}

pub const PAGE_SIZE: u64 = 4096;
pub const PAGE_SHIFT: u32 = 12;

/// Largest physical address the architecture supports. 52 bits is the
/// architectural maximum for the physical address field in a page table entry;
/// actual CPUs report less via CPUID leaf 0x80000008.
pub const MAX_PHYS_BITS: u32 = 52;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PhysAddr(u64);

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VirtAddr(u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrError {
    /// Virtual address is not canonical for the active paging mode.
    NonCanonical(u64),
    /// Physical address has bits set above the supported width.
    PhysTooWide(u64),
    /// Address is not page-aligned where alignment was required.
    Misaligned(u64),
}

impl PhysAddr {
    /// Construct, rejecting addresses wider than the architectural limit.
    /// Physical zero. Never a valid allocation — the frame allocator reserves
    /// frame 0 precisely so a null physical address stays distinguishable from
    /// a real one — so it doubles as the empty value for a table root.
    pub const ZERO: PhysAddr = PhysAddr(0);

    pub const fn new(addr: u64) -> Result<Self, AddrError> {
        if addr >> MAX_PHYS_BITS != 0 {
            return Err(AddrError::PhysTooWide(addr));
        }
        Ok(PhysAddr(addr))
    }

    /// # Safety
    /// Caller guarantees `addr` fits the physical address width. Used on the
    /// page-table walk hot path where the value came out of a PTE and is
    /// therefore already masked.
    pub const unsafe fn new_unchecked(addr: u64) -> Self {
        PhysAddr(addr)
    }

    pub const fn as_u64(self) -> u64 {
        self.0
    }

    pub const fn frame_number(self) -> u64 {
        self.0 >> PAGE_SHIFT
    }

    pub const fn is_page_aligned(self) -> bool {
        self.0 & (PAGE_SIZE - 1) == 0
    }

    pub const fn align_down(self) -> PhysAddr {
        PhysAddr(self.0 & !(PAGE_SIZE - 1))
    }

    /// Round up to the next page boundary, saturating rather than wrapping.
    ///
    /// Wrapping here would turn "the last page of physical memory" into
    /// "physical address zero", which maps the real-mode IVT and is a
    /// spectacular way to corrupt a machine.
    pub const fn align_up(self) -> PhysAddr {
        let v = self.0.saturating_add(PAGE_SIZE - 1);
        PhysAddr(v & !(PAGE_SIZE - 1))
    }

    pub const fn offset_in_page(self) -> u64 {
        self.0 & (PAGE_SIZE - 1)
    }
}

impl VirtAddr {
    /// Construct, enforcing the canonical-address rule for `mode`.
    pub fn new(addr: u64, mode: PagingMode) -> Result<Self, AddrError> {
        if !Self::is_canonical(addr, mode) {
            return Err(AddrError::NonCanonical(addr));
        }
        Ok(VirtAddr(addr))
    }

    /// Is `addr` a valid canonical address under `mode`?
    ///
    /// The rule: bits above the sign bit must all equal the sign bit. Expressed
    /// as an arithmetic shift round trip, which is both branch-free and
    /// obviously correct — sign-extend from the sign bit and check nothing
    /// changed.
    pub fn is_canonical(addr: u64, mode: PagingMode) -> bool {
        let shift = 64 - mode.virt_bits();
        // Arithmetic shift right then left re-materialises the sign extension.
        ((addr << shift) as i64 >> shift) as u64 == addr
    }

    /// Sign-extend a truncated address into canonical form.
    ///
    /// Used when *constructing* a kernel address from page-table indices, where
    /// the indices legitimately produce a value missing its sign extension.
    /// Never use this to "fix" an address that came from user space — that
    /// hides the bug the canonical check exists to catch.
    pub const fn from_indices_sign_extended(addr: u64, mode: PagingMode) -> Self {
        let shift = 64 - mode.virt_bits();
        VirtAddr(((addr << shift) as i64 >> shift) as u64)
    }

    /// # Safety
    /// Caller guarantees canonicality.
    pub const unsafe fn new_unchecked(addr: u64) -> Self {
        VirtAddr(addr)
    }

    pub const fn as_u64(self) -> u64 {
        self.0
    }

    pub const fn as_ptr<T>(self) -> *const T {
        self.0 as *const T
    }

    pub const fn as_mut_ptr<T>(self) -> *mut T {
        self.0 as *mut T
    }

    pub const fn page_number(self) -> u64 {
        self.0 >> PAGE_SHIFT
    }

    pub const fn is_page_aligned(self) -> bool {
        self.0 & (PAGE_SIZE - 1) == 0
    }

    pub const fn offset_in_page(self) -> u64 {
        self.0 & (PAGE_SIZE - 1)
    }

    pub const fn align_down(self) -> VirtAddr {
        VirtAddr(self.0 & !(PAGE_SIZE - 1))
    }

    /// Page-table index at `level`, where level 1 is the PT (lowest) and level
    /// 4 (or 5 under LA57) is the top.
    ///
    /// Returns `None` for a level outside the active mode, which is what stops
    /// a 4-level walk from reading a nonexistent PML5 index.
    pub fn table_index(self, level: usize, mode: PagingMode) -> Option<u16> {
        if level == 0 || level > mode.levels() {
            return None;
        }
        let shift = PAGE_SHIFT + 9 * (level as u32 - 1);
        Some(((self.0 >> shift) & 0x1FF) as u16)
    }

    /// Is this address in the upper (kernel) half?
    ///
    /// WhisezOS splits at the sign bit: user space is the lower half, kernel
    /// the upper. This is checked on every capability-mediated mapping, because
    /// a user process being handed an upper-half mapping is a privilege
    /// escalation regardless of what the page-table permission bits say.
    pub fn is_kernel_half(self, mode: PagingMode) -> bool {
        (self.0 >> mode.sign_bit()) & 1 == 1
    }
}

impl fmt::Debug for PhysAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PhysAddr({:#018x})", self.0)
    }
}

impl fmt::Debug for VirtAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VirtAddr({:#018x})", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const L4: PagingMode = PagingMode::Level4;
    const L5: PagingMode = PagingMode::Level5;

    #[test]
    fn lower_half_addresses_are_canonical() {
        assert!(VirtAddr::is_canonical(0x0000_0000_0000_1000, L4));
        assert!(VirtAddr::is_canonical(0x0000_7FFF_FFFF_FFFF, L4));
    }

    #[test]
    fn upper_half_addresses_are_canonical() {
        assert!(VirtAddr::is_canonical(0xFFFF_8000_0000_0000, L4));
        assert!(VirtAddr::is_canonical(0xFFFF_FFFF_FFFF_FFFF, L4));
    }

    #[test]
    fn the_canonical_hole_is_rejected() {
        // The gap between the halves. These raise #GP on use, and truncating
        // them instead of rejecting turns a pointer bug into a wild write.
        assert!(!VirtAddr::is_canonical(0x0000_8000_0000_0000, L4));
        assert!(!VirtAddr::is_canonical(0xFFFF_7FFF_FFFF_FFFF, L4));
        assert!(!VirtAddr::is_canonical(0x1234_5678_9ABC_DEF0, L4));

        assert!(matches!(
            VirtAddr::new(0x0000_8000_0000_0000, L4),
            Err(AddrError::NonCanonical(_))
        ));
    }

    #[test]
    fn la57_widens_the_canonical_range() {
        // Canonical under 5-level paging, not under 4-level. Getting this
        // backwards means the kernel rejects valid addresses on new hardware.
        let addr = 0x0080_0000_0000_0000;
        assert!(VirtAddr::is_canonical(addr, L5));
        assert!(!VirtAddr::is_canonical(addr, L4));
    }

    #[test]
    fn sign_extension_produces_canonical_addresses() {
        // Building an address from indices with the top index set must land in
        // the upper half, not in the hole.
        let raw = 0x1FF << 39; // PML4 index 511
        let v = VirtAddr::from_indices_sign_extended(raw, L4);
        assert!(VirtAddr::is_canonical(v.as_u64(), L4));
        assert!(v.is_kernel_half(L4));
        assert_eq!(v.as_u64(), 0xFFFF_FF80_0000_0000);
    }

    #[test]
    fn table_indices_decompose_correctly() {
        // Hand-built address: PML4=1, PDPT=2, PD=3, PT=4, offset=0x123.
        let raw = (1u64 << 39) | (2u64 << 30) | (3u64 << 21) | (4u64 << 12) | 0x123;
        let v = VirtAddr::new(raw, L4).unwrap();

        assert_eq!(v.table_index(4, L4), Some(1));
        assert_eq!(v.table_index(3, L4), Some(2));
        assert_eq!(v.table_index(2, L4), Some(3));
        assert_eq!(v.table_index(1, L4), Some(4));
        assert_eq!(v.offset_in_page(), 0x123);
    }

    #[test]
    fn table_index_refuses_levels_outside_the_mode() {
        let v = VirtAddr::new(0x1000, L4).unwrap();
        assert_eq!(v.table_index(0, L4), None, "level 0 is not a table");
        assert_eq!(v.table_index(5, L4), None, "no PML5 in 4-level mode");
        assert!(
            v.table_index(5, L5).is_some(),
            "PML5 exists in 5-level mode"
        );
        assert_eq!(v.table_index(6, L5), None);
    }

    #[test]
    fn kernel_half_detection_matches_the_split() {
        assert!(!VirtAddr::new(0x0000_7FFF_FFFF_F000, L4)
            .unwrap()
            .is_kernel_half(L4));
        assert!(VirtAddr::new(0xFFFF_8000_0000_0000, L4)
            .unwrap()
            .is_kernel_half(L4));
    }

    #[test]
    fn physical_addresses_wider_than_52_bits_are_rejected() {
        // 0x000F_FFFF_FFFF_FFFF is exactly 2^52 - 1 — the widest *valid*
        // physical address, not an invalid one. Worth spelling out because the
        // literal has enough F's to read as "obviously too big" at a glance.
        assert_eq!(0x000F_FFFF_FFFF_FFFFu64, (1u64 << 52) - 1);
        assert!(PhysAddr::new((1 << 52) - 1).is_ok());

        assert!(PhysAddr::new(1 << 52).is_err());
        assert!(PhysAddr::new(u64::MAX).is_err());
    }

    #[test]
    fn align_up_saturates_instead_of_wrapping() {
        // The last page of the address space must not round up to zero — that
        // would point at the real-mode IVT.
        let near_top = PhysAddr::new((1 << 52) - 1).unwrap();
        let aligned = near_top.align_up();
        assert!(
            aligned.as_u64() >= near_top.align_down().as_u64(),
            "align_up wrapped: {aligned:?}"
        );
        assert_ne!(aligned.as_u64(), 0);
    }

    #[test]
    fn alignment_helpers_agree() {
        let p = PhysAddr::new(0x1234_5678).unwrap();
        assert_eq!(p.align_down().as_u64(), 0x1234_5000);
        assert_eq!(p.align_up().as_u64(), 0x1234_6000);
        assert!(p.align_down().is_page_aligned());
        assert!(p.align_up().is_page_aligned());
        assert_eq!(p.offset_in_page(), 0x678);
    }

    #[test]
    fn already_aligned_addresses_are_unchanged_by_align_up() {
        let p = PhysAddr::new(0x1000).unwrap();
        assert_eq!(p.align_up().as_u64(), 0x1000, "align_up over-rounded");
    }
}
