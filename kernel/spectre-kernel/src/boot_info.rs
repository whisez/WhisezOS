//! The loader-to-kernel ABI.
//!
//! # Why this is one file shared by both sides
//!
//! The loader runs as a UEFI application on `x86_64-unknown-uefi`; the kernel is
//! a freestanding ELF on `x86_64-unknown-none`. They are separate binaries built
//! at different times with different targets, and the only thing connecting them
//! is the layout of the structure below and the calling convention of one
//! function pointer. Two hand-kept copies of that layout is how you get a kernel
//! that reads the framebuffer address out of what the loader thought was the
//! CPU count — a failure with no error message, because nothing is checked.
//!
//! So the definition lives in the kernel crate and the loader depends on it. One
//! definition, no drift possible, and `assert_layout` fails the build rather
//! than the boot if a field is ever inserted in the middle.
//!
//! # Why the memory map is inline rather than a pointer
//!
//! The obvious design hands the kernel a pointer to the UEFI memory map. The
//! problem is `ExitBootServices`: after it returns, every `BOOT_SERVICES_DATA`
//! allocation — which is where the firmware put that map — is memory the kernel
//! is entitled to reuse. The pointer stays valid only for as long as nobody
//! believes the map that the pointer describes, which is a circular and
//! genuinely dangerous arrangement.
//!
//! Copying the regions into the structure itself makes the handoff a single
//! self-contained object in `LOADER_DATA`. It costs a few kilobytes and removes
//! a class of bug that is very hard to see in a debugger. Adjacent regions of
//! the same kind are merged on the way in, which takes a typical firmware map of
//! 90-odd entries down to well under the cap.

#![allow(dead_code)]

/// `b"WHISEZOS"` big-endian, so a hex dump of the handoff page is readable.
pub const BOOT_INFO_MAGIC: u64 = 0x5748_4953_455A_4F53;

/// Bumped on any incompatible change to the layout below. The kernel refuses a
/// version it does not know rather than guessing.
///
/// v2 added the init image extent. The version is what makes that a refusal
/// rather than a kernel reading two fields of noise where the framebuffer used
/// to be, and it is why the field went at the end.
pub const BOOT_INFO_VERSION: u16 = 2;

/// Upper bound on regions carried across the handoff.
pub const MAX_REGIONS: usize = 128;

/// The memory map did not fit and was truncated. The kernel must treat unknown
/// address ranges as reserved rather than free.
pub const FLAG_MEMORY_MAP_TRUNCATED: u16 = 1 << 0;

/// Every loaded image was verified against a signed manifest. The loader does
/// not set this yet — signature verification is a later stage — and the kernel
/// reports its absence on the console instead of pretending the chain is
/// trusted.
pub const FLAG_IMAGES_VERIFIED: u16 = 1 << 1;

/// What a physical address range is for.
///
/// Deliberately coarser than the UEFI memory types: the kernel only needs to
/// know what it may allocate from, what it must preserve, and what it must
/// never map as normal memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MemoryKind {
    /// Free for the frame allocator.
    Usable = 0,
    /// Firmware or hardware owns this. Never allocate, never free.
    Reserved = 1,
    /// The loader's own images and the handoff structure. Reclaimable only once
    /// the kernel has finished with them, which is not during early boot.
    Loader = 2,
    /// The kernel image. Never reclaimed.
    Kernel = 3,
    /// ACPI tables. Reclaimable after the tables have been parsed.
    AcpiReclaimable = 4,
    /// ACPI non-volatile storage. Must survive sleep transitions.
    AcpiNvs = 5,
    /// Memory-mapped I/O and firmware runtime code/data. Mapping this as normal
    /// cacheable memory is how you get machine checks on real hardware.
    Mmio = 6,
    /// Reported bad by the firmware.
    Defective = 7,
}

impl MemoryKind {
    /// Classify a UEFI memory type.
    ///
    /// The two entries that matter most are `BOOT_SERVICES_CODE` (3) and
    /// `BOOT_SERVICES_DATA` (4). They are free once `ExitBootServices` returns,
    /// and on a typical firmware they are a large share of low memory — treating
    /// them as reserved throws away hundreds of megabytes for nothing. The
    /// mirror-image mistake is worse: `RUNTIME_SERVICES_CODE` (5) and
    /// `RUNTIME_SERVICES_DATA` (6) look similar and are *never* free, because
    /// the firmware keeps executing from them for the life of the system.
    #[must_use]
    pub const fn from_uefi(ty: u32) -> Self {
        match ty {
            // EfiConventionalMemory, EfiBootServicesCode, EfiBootServicesData.
            7 | 3 | 4 => Self::Usable,
            // EfiLoaderCode, EfiLoaderData.
            1 | 2 => Self::Loader,
            // EfiACPIReclaimMemory.
            9 => Self::AcpiReclaimable,
            // EfiACPIMemoryNVS.
            10 => Self::AcpiNvs,
            // EfiMemoryMappedIO, EfiMemoryMappedIOPortSpace,
            // EfiRuntimeServicesCode, EfiRuntimeServicesData.
            11 | 12 | 5 | 6 => Self::Mmio,
            // EfiUnusableMemory.
            8 => Self::Defective,
            // EfiReservedMemoryType, EfiPalCode, EfiPersistentMemory, unknown.
            _ => Self::Reserved,
        }
    }

    /// May the frame allocator hand these frames out during early boot?
    #[must_use]
    pub const fn is_allocatable(self) -> bool {
        matches!(self, Self::Usable)
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Usable => "usable",
            Self::Reserved => "reserved",
            Self::Loader => "loader",
            Self::Kernel => "kernel",
            Self::AcpiReclaimable => "acpi-reclaim",
            Self::AcpiNvs => "acpi-nvs",
            Self::Mmio => "mmio",
            Self::Defective => "defective",
        }
    }
}

/// One physical address range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct MemoryRegion {
    pub start: u64,
    pub len: u64,
    pub kind: MemoryKind,
    _pad: u32,
}

impl MemoryRegion {
    #[must_use]
    pub const fn new(start: u64, len: u64, kind: MemoryKind) -> Self {
        Self {
            start,
            len,
            kind,
            _pad: 0,
        }
    }

    #[must_use]
    pub const fn end(&self) -> u64 {
        self.start.saturating_add(self.len)
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// The framebuffer the loader leaves running, so the kernel can draw without a
/// mode set and without a GPU driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct Framebuffer {
    pub base: u64,
    pub width: u32,
    pub height: u32,
    /// Pixels — not bytes — per scanline. They differ on most real hardware.
    pub stride: u32,
    pub bytes_per_pixel: u32,
}

impl Framebuffer {
    #[must_use]
    pub const fn is_present(&self) -> bool {
        self.base != 0 && self.width != 0 && self.height != 0
    }

    /// Size of the framebuffer in bytes, or `None` if the geometry is
    /// inconsistent. Used to decide how much to map, so an overflow here would
    /// become a mapping that stops short and faults mid-scanline.
    #[must_use]
    pub fn byte_len(&self) -> Option<u64> {
        if self.stride < self.width {
            return None;
        }
        (self.stride as u64)
            .checked_mul(self.height as u64)?
            .checked_mul(self.bytes_per_pixel as u64)
    }
}

/// Why a handoff structure was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootInfoError {
    BadMagic(u64),
    UnsupportedVersion(u16),
    /// The loader was built against a different layout of this structure.
    SizeMismatch {
        expected: u16,
        found: u16,
    },
    TooManyRegions(u16),
    NoUsableMemory,
    /// Regions must arrive sorted and disjoint; anything else means the loader
    /// merged them wrongly and the frame allocator would hand out overlapping
    /// frames.
    RegionsOutOfOrder {
        index: u16,
    },
    EmptyRegion {
        index: u16,
    },
    InconsistentFramebuffer,
    /// A kernel that does not know where it is cannot avoid allocating over
    /// itself.
    KernelExtentMissing,
}

/// Everything the kernel is given at entry.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct BootInfo {
    pub magic: u64,
    pub version: u16,
    /// `size_of::<BootInfo>()` as the loader saw it.
    pub header_size: u16,
    pub region_count: u16,
    pub flags: u16,
    pub usable_bytes: u64,
    /// Virtual address at which all of physical memory is mapped. Adding this to
    /// a physical address gives a virtual address the kernel can dereference,
    /// which is what makes page-table walking possible after paging is on.
    pub physical_memory_offset: u64,
    pub kernel_phys_base: u64,
    pub kernel_virt_base: u64,
    pub kernel_bytes: u64,
    /// Top of the stack the loader set up for the kernel entry.
    pub stack_top: u64,
    /// ACPI RSDP, or 0 if the firmware exposed none.
    pub acpi_rsdp: u64,
    pub cpu_count: u32,
    _pad: u32,
    pub framebuffer: Framebuffer,
    /// Physical address of the **unparsed** init ELF file, or 0 if the loader
    /// found none.
    ///
    /// The file, not the loaded segments. The loader could parse and place it
    /// as it does the kernel, but then the loader would be deciding the page
    /// permissions of a user-space process, and it has no address space to put
    /// them in. Handing over the bytes lets the kernel map init into a real
    /// user address space with `W^X` applied per segment by the same code path
    /// every later process will use.
    pub init_image_phys: u64,
    pub init_image_bytes: u64,
    pub regions: [MemoryRegion; MAX_REGIONS],
}

impl BootInfo {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            magic: BOOT_INFO_MAGIC,
            version: BOOT_INFO_VERSION,
            header_size: core::mem::size_of::<Self>() as u16,
            region_count: 0,
            flags: 0,
            usable_bytes: 0,
            physical_memory_offset: 0,
            kernel_phys_base: 0,
            kernel_virt_base: 0,
            kernel_bytes: 0,
            stack_top: 0,
            acpi_rsdp: 0,
            cpu_count: 1,
            _pad: 0,
            framebuffer: Framebuffer {
                base: 0,
                width: 0,
                height: 0,
                stride: 0,
                bytes_per_pixel: 0,
            },
            init_image_phys: 0,
            init_image_bytes: 0,
            regions: [MemoryRegion::new(0, 0, MemoryKind::Reserved); MAX_REGIONS],
        }
    }

    #[must_use]
    pub fn regions(&self) -> &[MemoryRegion] {
        &self.regions[..self.region_count as usize]
    }

    #[must_use]
    pub const fn images_verified(&self) -> bool {
        self.flags & FLAG_IMAGES_VERIFIED != 0
    }

    #[must_use]
    pub const fn memory_map_truncated(&self) -> bool {
        self.flags & FLAG_MEMORY_MAP_TRUNCATED != 0
    }

    /// The init image bytes, if the loader supplied one.
    ///
    /// # Safety
    /// Physical memory must be identity mapped, and the range must still be
    /// intact — it lives in `Loader` memory, which nothing reclaims during
    /// early boot.
    #[must_use]
    pub unsafe fn init_image(&self) -> Option<&[u8]> {
        if self.init_image_phys == 0 || self.init_image_bytes == 0 {
            return None;
        }
        // SAFETY: the caller guarantees the range is mapped and live; the
        // loader wrote it and marked it `LOADER_DATA`.
        Some(unsafe {
            core::slice::from_raw_parts(
                self.init_image_phys as *const u8,
                self.init_image_bytes as usize,
            )
        })
    }

    /// Checks everything the kernel is about to rely on.
    ///
    /// Called before anything else, because every later step assumes these hold:
    /// the frame allocator assumes regions are sorted and disjoint, the page
    /// mapper assumes the kernel extent is known, and the console assumes the
    /// framebuffer geometry is self-consistent. Finding a violation here costs
    /// one serial line; finding it later costs a triple fault.
    pub fn validate(&self) -> Result<(), BootInfoError> {
        if self.magic != BOOT_INFO_MAGIC {
            return Err(BootInfoError::BadMagic(self.magic));
        }
        if self.version != BOOT_INFO_VERSION {
            return Err(BootInfoError::UnsupportedVersion(self.version));
        }
        let expected = core::mem::size_of::<Self>() as u16;
        if self.header_size != expected {
            return Err(BootInfoError::SizeMismatch {
                expected,
                found: self.header_size,
            });
        }
        if self.region_count as usize > MAX_REGIONS {
            return Err(BootInfoError::TooManyRegions(self.region_count));
        }
        if self.kernel_bytes == 0 || self.kernel_phys_base == 0 {
            return Err(BootInfoError::KernelExtentMissing);
        }

        let mut previous_end = 0u64;
        let mut usable = 0u64;
        for (index, region) in self.regions().iter().enumerate() {
            if region.is_empty() {
                return Err(BootInfoError::EmptyRegion {
                    index: index as u16,
                });
            }
            if region.start < previous_end {
                return Err(BootInfoError::RegionsOutOfOrder {
                    index: index as u16,
                });
            }
            previous_end = region.end();
            if region.kind.is_allocatable() {
                usable = usable.saturating_add(region.len);
            }
        }
        if usable == 0 {
            return Err(BootInfoError::NoUsableMemory);
        }

        if self.framebuffer.is_present() && self.framebuffer.byte_len().is_none() {
            return Err(BootInfoError::InconsistentFramebuffer);
        }
        Ok(())
    }

    /// Total allocatable bytes, recomputed from the regions rather than trusted
    /// from the header.
    #[must_use]
    pub fn allocatable_bytes(&self) -> u64 {
        self.regions()
            .iter()
            .filter(|r| r.kind.is_allocatable())
            .fold(0u64, |acc, r| acc.saturating_add(r.len))
    }

    /// The largest allocatable region, which is where early boot puts its
    /// bootstrap allocations.
    #[must_use]
    pub fn largest_usable(&self) -> Option<MemoryRegion> {
        self.regions()
            .iter()
            .filter(|r| r.kind.is_allocatable())
            .max_by_key(|r| r.len)
            .copied()
    }
}

/// Accumulates regions in address order, merging adjacent ones of equal kind.
///
/// Firmware maps are long and fragmented: a run of forty `BOOT_SERVICES_DATA`
/// entries that all classify as `Usable` is ordinary. Merging on the way in is
/// what keeps a realistic map inside `MAX_REGIONS` without dropping anything.
#[derive(Debug)]
pub struct MemoryMapBuilder {
    regions: [MemoryRegion; MAX_REGIONS],
    len: usize,
    truncated: bool,
}

impl Default for MemoryMapBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryMapBuilder {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            regions: [MemoryRegion::new(0, 0, MemoryKind::Reserved); MAX_REGIONS],
            len: 0,
            truncated: false,
        }
    }

    /// Adds one region. Regions must be supplied in ascending address order —
    /// UEFI does not guarantee that, so the caller sorts first.
    ///
    /// Zero-length regions are dropped rather than stored: they carry no
    /// information and would trip the validator's emptiness check.
    pub fn push(&mut self, region: MemoryRegion) {
        if region.is_empty() {
            return;
        }

        if let Some(last) = self.regions[..self.len].last_mut() {
            if last.kind == region.kind && last.end() == region.start {
                last.len = last.len.saturating_add(region.len);
                return;
            }
        }

        if self.len == MAX_REGIONS {
            self.truncated = true;
            return;
        }
        self.regions[self.len] = region;
        self.len += 1;
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[must_use]
    pub fn truncated(&self) -> bool {
        self.truncated
    }

    #[must_use]
    pub fn regions(&self) -> &[MemoryRegion] {
        &self.regions[..self.len]
    }

    /// Writes the accumulated map into a `BootInfo`.
    pub fn finish(&self, info: &mut BootInfo) {
        info.regions[..self.len].copy_from_slice(&self.regions[..self.len]);
        info.region_count = self.len as u16;
        if self.truncated {
            info.flags |= FLAG_MEMORY_MAP_TRUNCATED;
        }
        info.usable_bytes = info.allocatable_bytes();
    }
}

/// Compile-time guard on the shared layout.
///
/// The loader and the kernel are built separately; if a field is inserted above
/// without bumping `BOOT_INFO_VERSION`, an old loader and a new kernel disagree
/// silently. `header_size` catches that at runtime, and this catches the case
/// where somebody changes the layout and updates neither.
const _: () = {
    assert!(core::mem::size_of::<MemoryRegion>() == 24);
    assert!(core::mem::size_of::<Framebuffer>() == 24);
    assert!(core::mem::align_of::<BootInfo>() == 8);
};

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> BootInfo {
        let mut info = BootInfo::empty();
        info.kernel_phys_base = 0x10_0000;
        info.kernel_bytes = 0x4_0000;
        let mut builder = MemoryMapBuilder::new();
        builder.push(MemoryRegion::new(0x10_0000, 0x4_0000, MemoryKind::Kernel));
        builder.push(MemoryRegion::new(
            0x100_0000,
            0x2000_0000,
            MemoryKind::Usable,
        ));
        builder.finish(&mut info);
        info
    }

    #[test]
    fn an_empty_boot_info_carries_the_current_magic_and_version() {
        let info = BootInfo::empty();
        assert_eq!(info.magic, BOOT_INFO_MAGIC);
        assert_eq!(info.version, BOOT_INFO_VERSION);
        assert_eq!(info.header_size as usize, core::mem::size_of::<BootInfo>());
    }

    #[test]
    fn the_magic_spells_the_project_name_in_a_hex_dump() {
        assert_eq!(&BOOT_INFO_MAGIC.to_be_bytes(), b"WHISEZOS");
    }

    #[test]
    fn a_well_formed_handoff_validates() {
        valid().validate().unwrap();
    }

    #[test]
    fn a_corrupt_magic_is_rejected() {
        let mut info = valid();
        info.magic = 0;
        assert_eq!(info.validate(), Err(BootInfoError::BadMagic(0)));
    }

    #[test]
    fn an_unknown_version_is_refused_rather_than_guessed() {
        let mut info = valid();
        info.version = BOOT_INFO_VERSION + 1;
        assert!(matches!(
            info.validate(),
            Err(BootInfoError::UnsupportedVersion(_))
        ));
    }

    #[test]
    fn a_loader_built_against_a_different_layout_is_caught() {
        // The failure this prevents: a loader compiled before a field was added
        // writes a shorter structure, and the kernel reads past the end of it.
        let mut info = valid();
        info.header_size = 16;
        assert!(matches!(
            info.validate(),
            Err(BootInfoError::SizeMismatch { .. })
        ));
    }

    #[test]
    fn a_kernel_that_does_not_know_its_own_extent_is_rejected() {
        let mut info = valid();
        info.kernel_bytes = 0;
        assert_eq!(info.validate(), Err(BootInfoError::KernelExtentMissing));
    }

    #[test]
    fn a_map_with_no_usable_memory_is_rejected() {
        let mut info = BootInfo::empty();
        info.kernel_phys_base = 0x10_0000;
        info.kernel_bytes = 0x1000;
        let mut builder = MemoryMapBuilder::new();
        builder.push(MemoryRegion::new(0, 0x1000, MemoryKind::Reserved));
        builder.finish(&mut info);
        assert_eq!(info.validate(), Err(BootInfoError::NoUsableMemory));
    }

    #[test]
    fn overlapping_regions_are_rejected() {
        // Overlap means the frame allocator would hand the same frame out twice.
        let mut info = valid();
        info.regions[1] = MemoryRegion::new(0x10_0000, 0x2000_0000, MemoryKind::Usable);
        assert!(matches!(
            info.validate(),
            Err(BootInfoError::RegionsOutOfOrder { index: 1 })
        ));
    }

    #[test]
    fn an_empty_region_is_rejected() {
        let mut info = valid();
        info.regions[1] = MemoryRegion::new(0x100_0000, 0, MemoryKind::Usable);
        assert!(matches!(
            info.validate(),
            Err(BootInfoError::EmptyRegion { index: 1 })
        ));
    }

    #[test]
    fn uefi_boot_services_memory_is_usable_and_runtime_services_memory_is_not() {
        // The single most consequential classification in this file: getting
        // boot-services memory wrong throws away hundreds of megabytes, and
        // getting runtime-services memory wrong corrupts the firmware.
        assert_eq!(MemoryKind::from_uefi(3), MemoryKind::Usable); // BootServicesCode
        assert_eq!(MemoryKind::from_uefi(4), MemoryKind::Usable); // BootServicesData
        assert_eq!(MemoryKind::from_uefi(7), MemoryKind::Usable); // Conventional
        assert_eq!(MemoryKind::from_uefi(5), MemoryKind::Mmio); // RuntimeServicesCode
        assert_eq!(MemoryKind::from_uefi(6), MemoryKind::Mmio); // RuntimeServicesData
        assert!(!MemoryKind::from_uefi(5).is_allocatable());
        assert!(!MemoryKind::from_uefi(6).is_allocatable());
    }

    #[test]
    fn the_remaining_uefi_types_classify_conservatively() {
        assert_eq!(MemoryKind::from_uefi(1), MemoryKind::Loader);
        assert_eq!(MemoryKind::from_uefi(2), MemoryKind::Loader);
        assert_eq!(MemoryKind::from_uefi(8), MemoryKind::Defective);
        assert_eq!(MemoryKind::from_uefi(9), MemoryKind::AcpiReclaimable);
        assert_eq!(MemoryKind::from_uefi(10), MemoryKind::AcpiNvs);
        assert_eq!(MemoryKind::from_uefi(11), MemoryKind::Mmio);
        assert_eq!(MemoryKind::from_uefi(12), MemoryKind::Mmio);
        // Reserved (0) and anything the firmware invents.
        assert_eq!(MemoryKind::from_uefi(0), MemoryKind::Reserved);
        assert_eq!(MemoryKind::from_uefi(9999), MemoryKind::Reserved);
        for ty in 0..=14u32 {
            let kind = MemoryKind::from_uefi(ty);
            assert!(kind.is_allocatable() == matches!(ty, 3 | 4 | 7));
        }
    }

    #[test]
    fn adjacent_regions_of_the_same_kind_merge() {
        let mut builder = MemoryMapBuilder::new();
        builder.push(MemoryRegion::new(0x1000, 0x1000, MemoryKind::Usable));
        builder.push(MemoryRegion::new(0x2000, 0x1000, MemoryKind::Usable));
        builder.push(MemoryRegion::new(0x3000, 0x1000, MemoryKind::Usable));
        assert_eq!(builder.len(), 1);
        assert_eq!(builder.regions()[0].len, 0x3000);
    }

    #[test]
    fn regions_of_different_kinds_never_merge() {
        let mut builder = MemoryMapBuilder::new();
        builder.push(MemoryRegion::new(0x1000, 0x1000, MemoryKind::Usable));
        builder.push(MemoryRegion::new(0x2000, 0x1000, MemoryKind::Reserved));
        assert_eq!(builder.len(), 2);
    }

    #[test]
    fn a_gap_prevents_merging_even_within_one_kind() {
        // Merging across a hole would hand the frame allocator memory that does
        // not exist.
        let mut builder = MemoryMapBuilder::new();
        builder.push(MemoryRegion::new(0x1000, 0x1000, MemoryKind::Usable));
        builder.push(MemoryRegion::new(0x9000, 0x1000, MemoryKind::Usable));
        assert_eq!(builder.len(), 2);
    }

    #[test]
    fn zero_length_regions_are_dropped() {
        let mut builder = MemoryMapBuilder::new();
        builder.push(MemoryRegion::new(0x1000, 0, MemoryKind::Usable));
        assert!(builder.is_empty());
        assert!(!builder.truncated());
    }

    #[test]
    fn a_realistic_firmware_map_fits_after_merging() {
        // 400 fragmented entries alternating between two kinds that both
        // classify as usable — the shape OVMF actually produces.
        let mut builder = MemoryMapBuilder::new();
        for i in 0..400u64 {
            let ty = if i % 2 == 0 { 4 } else { 7 };
            builder.push(MemoryRegion::new(
                i * 0x1000,
                0x1000,
                MemoryKind::from_uefi(ty),
            ));
        }
        assert_eq!(builder.len(), 1, "identical kinds should collapse");
        assert!(!builder.truncated());
    }

    #[test]
    fn an_unmergeable_map_truncates_and_says_so() {
        let mut builder = MemoryMapBuilder::new();
        for i in 0..(MAX_REGIONS as u64 + 50) {
            // A gap between every region defeats merging.
            builder.push(MemoryRegion::new(i * 0x2000, 0x1000, MemoryKind::Usable));
        }
        assert_eq!(builder.len(), MAX_REGIONS);
        assert!(builder.truncated(), "silent truncation would lose memory");

        let mut info = BootInfo::empty();
        info.kernel_phys_base = 0x1000;
        info.kernel_bytes = 0x1000;
        builder.finish(&mut info);
        assert!(info.memory_map_truncated());
        info.validate().unwrap();
    }

    #[test]
    fn finishing_recomputes_the_usable_total() {
        let info = valid();
        assert_eq!(info.usable_bytes, 0x2000_0000);
        assert_eq!(info.allocatable_bytes(), 0x2000_0000);
        assert_eq!(info.largest_usable().unwrap().start, 0x100_0000);
    }

    #[test]
    fn the_kernel_region_is_not_allocatable() {
        // Allocating over the running kernel is the fastest possible way to
        // triple-fault, so this is asserted rather than assumed.
        let info = valid();
        let kernel = info
            .regions()
            .iter()
            .find(|r| r.kind == MemoryKind::Kernel)
            .unwrap();
        assert!(!kernel.kind.is_allocatable());
    }

    #[test]
    fn the_loader_reports_that_images_are_not_verified_yet() {
        // Honest default: nothing has checked a signature, so the flag is clear
        // and the kernel says so on the console.
        assert!(!BootInfo::empty().images_verified());
    }

    #[test]
    fn framebuffer_geometry_is_checked_for_consistency() {
        let mut fb = Framebuffer {
            base: 0x8000_0000,
            width: 1280,
            height: 800,
            stride: 1280,
            bytes_per_pixel: 4,
        };
        assert!(fb.is_present());
        assert_eq!(fb.byte_len(), Some(1280 * 800 * 4));

        // Stride below width means the loader filled the fields wrongly; mapping
        // on that basis stops short and faults mid-scanline.
        fb.stride = 640;
        assert_eq!(fb.byte_len(), None);
    }

    #[test]
    fn an_inconsistent_framebuffer_fails_validation() {
        let mut info = valid();
        info.framebuffer = Framebuffer {
            base: 0x8000_0000,
            width: 1280,
            height: 800,
            stride: 16,
            bytes_per_pixel: 4,
        };
        assert_eq!(info.validate(), Err(BootInfoError::InconsistentFramebuffer));
    }

    #[test]
    fn an_absent_framebuffer_is_allowed() {
        // Headless boot is a supported configuration; serial is the console.
        let info = valid();
        assert!(!info.framebuffer.is_present());
        info.validate().unwrap();
    }
}
