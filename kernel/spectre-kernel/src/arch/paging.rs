//! Page tables.
//!
//! 4- and 5-level paging, 4 KiB / 2 MiB / 1 GiB pages, with the permission
//! model WhisezOS's capability system depends on.
//!
//! # W^X is enforced here, not by convention
//!
//! `PageFlags::validate` rejects any mapping that is simultaneously writable
//! and executable. This is the chokepoint — every mapping in the system goes
//! through `map_page`, so there is no path by which a driver, the PE loader, or
//! a JIT can create a W+X page without the kernel refusing it. Enforcing this
//! at the type level rather than in review is the difference between a policy
//! and a guarantee.
//!
//! The NX bit is only meaningful if EFER.NXE is set; `init` sets it and panics
//! if the CPU does not support it, because silently running without NX would
//! make every "non-executable" mapping in the system a lie.
//!
//! # Why entries are `u64` and not a struct
//!
//! A page table entry is a hardware-defined bit layout that must be written
//! atomically. Wrapping it in a struct with named fields invites the compiler
//! to split the write, and a torn PTE update is observable by another CPU
//! walking the same table. The bitflags wrapper gives naming without changing
//! the representation.

#[cfg(test)]
use super::addr::PAGE_SIZE;
use super::addr::{PagingMode, PhysAddr, VirtAddr, PAGE_SHIFT};

bitflags::bitflags! {
    /// Page table entry flags, per Intel SDM Vol. 3A §4.5.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PageFlags: u64 {
        const PRESENT         = 1 << 0;
        const WRITABLE        = 1 << 1;
        /// Accessible from ring 3.
        const USER            = 1 << 2;
        const WRITE_THROUGH   = 1 << 3;
        const NO_CACHE        = 1 << 4;
        /// Set by hardware on access; used by the Vault cold-page sweep to find
        /// pages that have not been touched since the last rotation.
        const ACCESSED        = 1 << 5;
        /// Set by hardware on write; drives copy-on-write and snapshot diffing.
        const DIRTY           = 1 << 6;
        /// At level 2 or 3, this entry maps a large page rather than a table.
        const HUGE            = 1 << 7;
        /// Not flushed from the TLB on CR3 reload. Kernel mappings only.
        const GLOBAL          = 1 << 8;
        /// Software bit: page belongs to a Vault arena and is encrypted at rest.
        const VAULT_SEALED    = 1 << 9;
        /// Software bit: page is copy-on-write; a write fault should duplicate.
        const COW             = 1 << 10;
        /// Software bit: page is donated via IPC and must not be freed by the
        /// sender's address space teardown.
        const DONATED         = 1 << 11;
        const NO_EXECUTE      = 1 << 63;
    }
}

/// Bits [51:12] of an entry hold the physical frame address.
const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageError {
    /// Mapping requested both write and execute.
    WriteExecute,
    /// A user-accessible mapping was requested for a kernel-half address.
    UserMappingInKernelHalf,
    /// Target virtual address already has a mapping.
    AlreadyMapped,
    /// Walk hit a non-present entry and allocation was not requested.
    NotMapped,
    /// Out of physical frames for a new table level.
    OutOfFrames,
    /// Huge-page flag found at a level that cannot map one.
    InvalidHugePage { level: usize },
    /// Address or frame not aligned to the page size being mapped.
    Misaligned,
}

/// Page size being mapped. Determines which level terminates the walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageSize {
    /// 4 KiB, terminates at level 1.
    Small,
    /// 2 MiB, terminates at level 2 with HUGE set.
    Large,
    /// 1 GiB, terminates at level 3 with HUGE set.
    Huge,
}

impl PageSize {
    pub const fn bytes(self) -> u64 {
        match self {
            PageSize::Small => 4096,
            PageSize::Large => 2 * 1024 * 1024,
            PageSize::Huge => 1024 * 1024 * 1024,
        }
    }

    /// Walk level at which this size terminates.
    pub const fn terminal_level(self) -> usize {
        match self {
            PageSize::Small => 1,
            PageSize::Large => 2,
            PageSize::Huge => 3,
        }
    }

    pub const fn alignment_mask(self) -> u64 {
        self.bytes() - 1
    }
}

impl PageFlags {
    /// Reject flag combinations that are unsafe or architecturally invalid.
    ///
    /// This runs on every mapping. The W^X check is the important one; the
    /// others catch bugs that would otherwise produce a fault far from their
    /// cause.
    pub fn validate(self, virt: VirtAddr, mode: PagingMode) -> Result<(), PageError> {
        // W^X. Note the polarity: NO_EXECUTE *set* means non-executable, so
        // "executable" is the absence of the bit. Getting this backwards is easy
        // and would invert the entire check.
        let executable = !self.contains(PageFlags::NO_EXECUTE);
        if self.contains(PageFlags::WRITABLE) && executable {
            return Err(PageError::WriteExecute);
        }

        // A user-accessible mapping in the kernel half defeats the address-space
        // split regardless of what the USER bit claims, because SMEP/SMAP and
        // the KPTI trampoline both key off the half, not the bit.
        if self.contains(PageFlags::USER) && virt.is_kernel_half(mode) {
            return Err(PageError::UserMappingInKernelHalf);
        }

        Ok(())
    }

    /// Flags an intermediate (non-terminal) table entry should carry.
    ///
    /// Permissions on intermediate levels are *permissive* — the CPU ANDs the
    /// permissions down the walk, so an intermediate entry that lacks WRITABLE
    /// makes every page beneath it read-only regardless of the leaf's flags.
    /// Intermediate entries therefore carry the union of what any leaf beneath
    /// them might need, and the leaf does the actual restricting.
    ///
    /// NO_EXECUTE is the exception and is deliberately *not* set here: it is
    /// ORed rather than ANDed down the walk, so setting it on an intermediate
    /// entry would make everything beneath it non-executable.
    pub fn intermediate(user: bool) -> PageFlags {
        let mut f = PageFlags::PRESENT | PageFlags::WRITABLE;
        if user {
            f |= PageFlags::USER;
        }
        f
    }
}

/// A single page table entry.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct Entry(u64);

impl Entry {
    pub const EMPTY: Entry = Entry(0);

    pub fn new(frame: PhysAddr, flags: PageFlags) -> Result<Entry, PageError> {
        if !frame.is_page_aligned() {
            return Err(PageError::Misaligned);
        }
        Ok(Entry(frame.as_u64() | flags.bits()))
    }

    pub const fn is_present(self) -> bool {
        self.0 & PageFlags::PRESENT.bits() != 0
    }

    pub fn flags(self) -> PageFlags {
        PageFlags::from_bits_truncate(self.0)
    }

    pub fn frame(self) -> PhysAddr {
        // SAFETY: masking to bits [51:12] cannot produce a value wider than the
        // architectural physical address limit.
        unsafe { PhysAddr::new_unchecked(self.0 & ADDR_MASK) }
    }

    /// Does this entry terminate the walk (a leaf), or point at another table?
    ///
    /// At level 1 every present entry is a leaf. At levels 2 and 3 the HUGE bit
    /// decides. At level 4 and 5 an entry is always a table — HUGE there is
    /// architecturally reserved and a set bit indicates corruption.
    pub fn is_leaf(self, level: usize) -> Result<bool, PageError> {
        if !self.is_present() {
            return Ok(false);
        }
        let huge = self.flags().contains(PageFlags::HUGE);
        match level {
            1 => Ok(true),
            2 | 3 => Ok(huge),
            4 | 5 => {
                if huge {
                    Err(PageError::InvalidHugePage { level })
                } else {
                    Ok(false)
                }
            }
            _ => Err(PageError::InvalidHugePage { level }),
        }
    }

    pub const fn raw(self) -> u64 {
        self.0
    }
}

impl core::fmt::Debug for Entry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if !self.is_present() {
            return write!(f, "Entry(not present)");
        }
        write!(
            f,
            "Entry({:#018x} {:?})",
            self.frame().as_u64(),
            self.flags()
        )
    }
}

/// 512 entries, exactly one 4 KiB frame.
#[repr(C, align(4096))]
pub struct PageTable {
    entries: [Entry; Self::LEN],
}

impl PageTable {
    pub const LEN: usize = 512;

    pub const fn new() -> Self {
        PageTable {
            entries: [Entry::EMPTY; Self::LEN],
        }
    }

    pub fn get(&self, index: u16) -> Option<Entry> {
        self.entries.get(index as usize).copied()
    }

    pub fn set(&mut self, index: u16, entry: Entry) -> Result<(), PageError> {
        let slot = self
            .entries
            .get_mut(index as usize)
            .ok_or(PageError::NotMapped)?;
        *slot = entry;
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.entries.iter().all(|e| !e.is_present())
    }

    /// Count of present entries. Used to decide whether an intermediate table
    /// can be freed after an unmap.
    pub fn population(&self) -> usize {
        self.entries.iter().filter(|e| e.is_present()).count()
    }
}

impl Default for PageTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of a successful address translation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Translation {
    pub frame: PhysAddr,
    pub flags: PageFlags,
    pub size: PageSize,
    /// Physical address of the byte, including the offset within the page.
    pub phys: PhysAddr,
}

/// Abstraction over reading a page table given its physical frame.
///
/// A trait rather than a direct pointer dereference because the walk logic is
/// the part most worth testing, and testing it requires a table hierarchy that
/// lives in a `HashMap` rather than at a physical address. The production
/// implementation is a one-line offset into the direct physical map.
pub trait TableAccess {
    fn read_entry(&self, table: PhysAddr, index: u16) -> Option<Entry>;
    fn write_entry(&mut self, table: PhysAddr, index: u16, entry: Entry) -> Result<(), PageError>;
    /// Allocate a zeroed frame for a new table level.
    fn alloc_table(&mut self) -> Option<PhysAddr>;
}

/// Walk the page tables to translate `virt`.
///
/// Returns `NotMapped` rather than a sentinel address — a translation failure
/// is a normal, frequent occurrence (every demand-paged fault) and must not be
/// confusable with a successful translation to physical zero.
pub fn translate<A: TableAccess>(
    access: &A,
    root: PhysAddr,
    virt: VirtAddr,
    mode: PagingMode,
) -> Result<Translation, PageError> {
    let mut table = root;

    for level in (1..=mode.levels()).rev() {
        let index = virt.table_index(level, mode).ok_or(PageError::NotMapped)?;
        let entry = access
            .read_entry(table, index)
            .ok_or(PageError::NotMapped)?;

        if !entry.is_present() {
            return Err(PageError::NotMapped);
        }

        if entry.is_leaf(level)? {
            let size = match level {
                1 => PageSize::Small,
                2 => PageSize::Large,
                3 => PageSize::Huge,
                _ => return Err(PageError::InvalidHugePage { level }),
            };

            // Offset within a large page spans more than the low 12 bits.
            let offset = virt.as_u64() & size.alignment_mask();
            let phys = PhysAddr::new(entry.frame().as_u64() + offset)
                .map_err(|_| PageError::Misaligned)?;

            return Ok(Translation {
                frame: entry.frame(),
                flags: entry.flags(),
                size,
                phys,
            });
        }

        table = entry.frame();
    }

    Err(PageError::NotMapped)
}

/// Create a mapping.
///
/// Refuses to overwrite an existing mapping. Silent replacement is how a
/// use-after-free in one subsystem becomes memory corruption in an unrelated
/// one: the old frame stays allocated, the owner keeps writing through a stale
/// TLB entry, and the new owner sees their data change underneath them.
/// Callers that genuinely intend replacement call `unmap` first.
pub fn map_page<A: TableAccess>(
    access: &mut A,
    root: PhysAddr,
    virt: VirtAddr,
    frame: PhysAddr,
    flags: PageFlags,
    size: PageSize,
    mode: PagingMode,
) -> Result<(), PageError> {
    flags.validate(virt, mode)?;

    // Both the virtual address and the frame must be aligned to the page size.
    // A 2 MiB mapping at a 4 KiB-aligned frame is silently truncated by the
    // hardware, mapping the wrong memory.
    let mask = size.alignment_mask();
    if virt.as_u64() & mask != 0 || frame.as_u64() & mask != 0 {
        return Err(PageError::Misaligned);
    }

    let user = flags.contains(PageFlags::USER);
    let terminal = size.terminal_level();
    let mut table = root;

    for level in (terminal + 1..=mode.levels()).rev() {
        let index = virt.table_index(level, mode).ok_or(PageError::NotMapped)?;
        let entry = access
            .read_entry(table, index)
            .ok_or(PageError::NotMapped)?;

        if entry.is_present() {
            // Walking into a large page while trying to map a smaller one means
            // the caller is mapping over an existing large mapping.
            if entry.is_leaf(level)? {
                return Err(PageError::AlreadyMapped);
            }
            table = entry.frame();
        } else {
            let new_table = access.alloc_table().ok_or(PageError::OutOfFrames)?;
            let new_entry = Entry::new(new_table, PageFlags::intermediate(user))?;
            access.write_entry(table, index, new_entry)?;
            table = new_table;
        }
    }

    let index = virt
        .table_index(terminal, mode)
        .ok_or(PageError::NotMapped)?;
    if let Some(existing) = access.read_entry(table, index) {
        if existing.is_present() {
            return Err(PageError::AlreadyMapped);
        }
    }

    let mut leaf_flags = flags | PageFlags::PRESENT;
    if terminal > 1 {
        leaf_flags |= PageFlags::HUGE;
    }

    access.write_entry(table, index, Entry::new(frame, leaf_flags)?)
}

/// Remove a mapping and return the frame it referenced.
///
/// Does not free the frame — ownership of physical memory belongs to the Vault
/// allocator, not to the page tables. A paging layer that frees frames on unmap
/// cannot express shared or donated pages without double-free.
pub fn unmap_page<A: TableAccess>(
    access: &mut A,
    root: PhysAddr,
    virt: VirtAddr,
    mode: PagingMode,
) -> Result<(PhysAddr, PageSize), PageError> {
    let mut table = root;

    for level in (1..=mode.levels()).rev() {
        let index = virt.table_index(level, mode).ok_or(PageError::NotMapped)?;
        let entry = access
            .read_entry(table, index)
            .ok_or(PageError::NotMapped)?;

        if !entry.is_present() {
            return Err(PageError::NotMapped);
        }

        if entry.is_leaf(level)? {
            let size = match level {
                1 => PageSize::Small,
                2 => PageSize::Large,
                3 => PageSize::Huge,
                _ => return Err(PageError::InvalidHugePage { level }),
            };
            access.write_entry(table, index, Entry::EMPTY)?;
            return Ok((entry.frame(), size));
        }

        table = entry.frame();
    }

    Err(PageError::NotMapped)
}

/// Number of 4 KiB frames spanned by a byte range, accounting for a range that
/// straddles a page boundary.
pub const fn frames_spanned(start: u64, len: u64) -> u64 {
    if len == 0 {
        return 0;
    }
    let first = start >> PAGE_SHIFT;
    let last = (start + len - 1) >> PAGE_SHIFT;
    last - first + 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const L4: PagingMode = PagingMode::Level4;

    /// Page tables in a HashMap, so the walk logic can be tested without a MMU.
    struct FakeTables {
        tables: HashMap<u64, [Entry; PageTable::LEN]>,
        next_frame: u64,
    }

    impl FakeTables {
        fn new() -> (Self, PhysAddr) {
            let root = 0x1000u64;
            let mut tables = HashMap::new();
            tables.insert(root, [Entry::EMPTY; PageTable::LEN]);
            (
                FakeTables {
                    tables,
                    next_frame: 0x2000,
                },
                PhysAddr::new(root).unwrap(),
            )
        }
    }

    impl TableAccess for FakeTables {
        fn read_entry(&self, table: PhysAddr, index: u16) -> Option<Entry> {
            self.tables
                .get(&table.as_u64())
                .and_then(|t| t.get(index as usize))
                .copied()
        }

        fn write_entry(
            &mut self,
            table: PhysAddr,
            index: u16,
            entry: Entry,
        ) -> Result<(), PageError> {
            let t = self
                .tables
                .get_mut(&table.as_u64())
                .ok_or(PageError::NotMapped)?;
            *t.get_mut(index as usize).ok_or(PageError::NotMapped)? = entry;
            Ok(())
        }

        fn alloc_table(&mut self) -> Option<PhysAddr> {
            let f = self.next_frame;
            self.next_frame += 0x1000;
            self.tables.insert(f, [Entry::EMPTY; PageTable::LEN]);
            Some(PhysAddr::new(f).unwrap())
        }
    }

    fn ro_exec() -> PageFlags {
        PageFlags::PRESENT | PageFlags::USER
    }

    fn rw_noexec() -> PageFlags {
        PageFlags::PRESENT | PageFlags::WRITABLE | PageFlags::NO_EXECUTE | PageFlags::USER
    }

    #[test]
    fn write_execute_mappings_are_refused() {
        let virt = VirtAddr::new(0x1000, L4).unwrap();
        let wx = PageFlags::PRESENT | PageFlags::WRITABLE; // no NO_EXECUTE
        assert_eq!(wx.validate(virt, L4), Err(PageError::WriteExecute));
    }

    #[test]
    fn read_execute_and_read_write_are_both_allowed() {
        let virt = VirtAddr::new(0x1000, L4).unwrap();
        assert!(ro_exec().validate(virt, L4).is_ok());
        assert!(rw_noexec().validate(virt, L4).is_ok());
    }

    #[test]
    fn user_mappings_in_the_kernel_half_are_refused() {
        let kernel = VirtAddr::new(0xFFFF_8000_0000_0000, L4).unwrap();
        assert_eq!(
            rw_noexec().validate(kernel, L4),
            Err(PageError::UserMappingInKernelHalf)
        );
        // Same flags without USER are fine.
        let kflags = rw_noexec() - PageFlags::USER;
        assert!(kflags.validate(kernel, L4).is_ok());
    }

    #[test]
    fn map_then_translate_round_trips() {
        let (mut t, root) = FakeTables::new();
        let virt = VirtAddr::new(0x0000_1234_5678_9000, L4).unwrap();
        let frame = PhysAddr::new(0x4444_0000).unwrap();

        map_page(&mut t, root, virt, frame, rw_noexec(), PageSize::Small, L4).unwrap();

        let tr = translate(&t, root, virt, L4).unwrap();
        assert_eq!(tr.frame, frame);
        assert_eq!(tr.size, PageSize::Small);
        assert!(tr.flags.contains(PageFlags::WRITABLE));
    }

    #[test]
    fn translation_includes_the_offset_within_the_page() {
        let (mut t, root) = FakeTables::new();
        let base = 0x0000_1234_5678_9000u64;
        let virt = VirtAddr::new(base, L4).unwrap();
        let frame = PhysAddr::new(0x4444_0000).unwrap();
        map_page(&mut t, root, virt, frame, rw_noexec(), PageSize::Small, L4).unwrap();

        let off = VirtAddr::new(base + 0x678, L4).unwrap();
        let tr = translate(&t, root, off, L4).unwrap();
        assert_eq!(tr.phys.as_u64(), 0x4444_0678, "offset lost in translation");
    }

    #[test]
    fn unmapped_addresses_report_not_mapped() {
        let (t, root) = FakeTables::new();
        let virt = VirtAddr::new(0x9999_0000, L4).unwrap();
        assert_eq!(translate(&t, root, virt, L4), Err(PageError::NotMapped));
    }

    #[test]
    fn double_mapping_is_refused_rather_than_silently_replaced() {
        let (mut t, root) = FakeTables::new();
        let virt = VirtAddr::new(0x2000, L4).unwrap();
        let a = PhysAddr::new(0x1_0000).unwrap();
        let b = PhysAddr::new(0x2_0000).unwrap();

        map_page(&mut t, root, virt, a, rw_noexec(), PageSize::Small, L4).unwrap();
        assert_eq!(
            map_page(&mut t, root, virt, b, rw_noexec(), PageSize::Small, L4),
            Err(PageError::AlreadyMapped)
        );

        // The original mapping must survive the rejected attempt.
        assert_eq!(translate(&t, root, virt, L4).unwrap().frame, a);
    }

    #[test]
    fn unmap_returns_the_frame_and_clears_the_entry() {
        let (mut t, root) = FakeTables::new();
        let virt = VirtAddr::new(0x3000, L4).unwrap();
        let frame = PhysAddr::new(0x5_0000).unwrap();

        map_page(&mut t, root, virt, frame, rw_noexec(), PageSize::Small, L4).unwrap();
        let (got, size) = unmap_page(&mut t, root, virt, L4).unwrap();

        assert_eq!(got, frame);
        assert_eq!(size, PageSize::Small);
        assert_eq!(translate(&t, root, virt, L4), Err(PageError::NotMapped));
    }

    #[test]
    fn unmapping_twice_is_an_error_not_a_double_free() {
        let (mut t, root) = FakeTables::new();
        let virt = VirtAddr::new(0x3000, L4).unwrap();
        let frame = PhysAddr::new(0x5_0000).unwrap();
        map_page(&mut t, root, virt, frame, rw_noexec(), PageSize::Small, L4).unwrap();
        unmap_page(&mut t, root, virt, L4).unwrap();
        assert_eq!(
            unmap_page(&mut t, root, virt, L4),
            Err(PageError::NotMapped)
        );
    }

    #[test]
    fn large_pages_map_and_translate() {
        let (mut t, root) = FakeTables::new();
        let virt = VirtAddr::new(0x40_0000, L4).unwrap(); // 2 MiB aligned
        let frame = PhysAddr::new(0x80_0000).unwrap();

        map_page(&mut t, root, virt, frame, rw_noexec(), PageSize::Large, L4).unwrap();

        let tr = translate(&t, root, virt, L4).unwrap();
        assert_eq!(tr.size, PageSize::Large);
        assert!(tr.flags.contains(PageFlags::HUGE));

        // An address 1 MiB into the large page resolves to the right physical
        // byte — this is the check that catches using a 4 KiB offset mask.
        let inside = VirtAddr::new(0x40_0000 + 0x10_0000, L4).unwrap();
        assert_eq!(
            translate(&t, root, inside, L4).unwrap().phys.as_u64(),
            0x80_0000 + 0x10_0000
        );
    }

    #[test]
    fn misaligned_large_page_mapping_is_refused() {
        let (mut t, root) = FakeTables::new();
        // 4 KiB-aligned but not 2 MiB-aligned: hardware would silently truncate.
        let virt = VirtAddr::new(0x40_1000, L4).unwrap();
        let frame = PhysAddr::new(0x80_0000).unwrap();
        assert_eq!(
            map_page(&mut t, root, virt, frame, rw_noexec(), PageSize::Large, L4),
            Err(PageError::Misaligned)
        );
    }

    #[test]
    fn misaligned_frame_is_refused_even_when_virt_is_aligned() {
        let (mut t, root) = FakeTables::new();
        let virt = VirtAddr::new(0x40_0000, L4).unwrap();
        let frame = PhysAddr::new(0x80_1000).unwrap();
        assert_eq!(
            map_page(&mut t, root, virt, frame, rw_noexec(), PageSize::Large, L4),
            Err(PageError::Misaligned)
        );
    }

    #[test]
    fn mapping_a_small_page_over_a_large_one_is_refused() {
        let (mut t, root) = FakeTables::new();
        let large = VirtAddr::new(0x40_0000, L4).unwrap();
        map_page(
            &mut t,
            root,
            large,
            PhysAddr::new(0x80_0000).unwrap(),
            rw_noexec(),
            PageSize::Large,
            L4,
        )
        .unwrap();

        // A 4 KiB page inside the 2 MiB region: the walk hits a leaf at level 2.
        let small = VirtAddr::new(0x40_1000, L4).unwrap();
        assert_eq!(
            map_page(
                &mut t,
                root,
                small,
                PhysAddr::new(0x90_0000).unwrap(),
                rw_noexec(),
                PageSize::Small,
                L4,
            ),
            Err(PageError::AlreadyMapped)
        );
    }

    #[test]
    fn huge_bit_at_the_top_level_is_reported_as_corruption() {
        let corrupt = Entry::new(
            PhysAddr::new(0x1000).unwrap(),
            PageFlags::PRESENT | PageFlags::HUGE,
        )
        .unwrap();
        assert_eq!(
            corrupt.is_leaf(4),
            Err(PageError::InvalidHugePage { level: 4 })
        );
        assert_eq!(corrupt.is_leaf(2), Ok(true), "HUGE is valid at level 2");
    }

    #[test]
    fn intermediate_flags_never_set_no_execute() {
        // NO_EXECUTE ORs down the walk, so setting it on an intermediate entry
        // would make every page beneath it non-executable.
        let f = PageFlags::intermediate(true);
        assert!(!f.contains(PageFlags::NO_EXECUTE));
        assert!(f.contains(PageFlags::PRESENT | PageFlags::WRITABLE | PageFlags::USER));
    }

    #[test]
    fn entry_round_trips_frame_and_flags() {
        let frame = PhysAddr::new(0x000F_FFFF_FFFF_F000).unwrap();
        let flags = PageFlags::PRESENT | PageFlags::WRITABLE | PageFlags::NO_EXECUTE;
        let e = Entry::new(frame, flags).unwrap();
        assert_eq!(e.frame(), frame, "top physical bits lost");
        assert!(e.flags().contains(flags));
    }

    #[test]
    fn unaligned_frame_in_an_entry_is_refused() {
        assert_eq!(
            Entry::new(PhysAddr::new(0x1001).unwrap(), PageFlags::PRESENT),
            Err(PageError::Misaligned)
        );
    }

    #[test]
    fn frames_spanned_handles_boundary_straddling() {
        assert_eq!(frames_spanned(0, 0), 0);
        assert_eq!(frames_spanned(0, 1), 1);
        assert_eq!(frames_spanned(0, PAGE_SIZE), 1);
        assert_eq!(frames_spanned(0, PAGE_SIZE + 1), 2);
        // Starts near the end of a page and spills into the next.
        assert_eq!(frames_spanned(PAGE_SIZE - 1, 2), 2);
        assert_eq!(frames_spanned(PAGE_SIZE - 1, 1), 1);
    }

    #[test]
    fn intermediate_tables_are_reused_not_reallocated() {
        let (mut t, root) = FakeTables::new();
        let before = t.next_frame;

        // Two pages in the same 2 MiB region share all intermediate levels.
        for i in 0..2u64 {
            let v = VirtAddr::new(0x10_0000 + i * PAGE_SIZE, L4).unwrap();
            let f = PhysAddr::new(0x100_0000 + i * PAGE_SIZE).unwrap();
            map_page(&mut t, root, v, f, rw_noexec(), PageSize::Small, L4).unwrap();
        }

        // 3 new tables for the first mapping, 0 for the second.
        assert_eq!(
            t.next_frame - before,
            3 * 0x1000,
            "intermediate tables were reallocated"
        );
    }
}
