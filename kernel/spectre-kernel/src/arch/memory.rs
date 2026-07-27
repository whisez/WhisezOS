//! Physical frame allocation and the kernel's first page tables.
//!
//! # What this replaces
//!
//! The kernel starts on the loader's page tables. UEFI guarantees those identity
//! map all of conventional memory, which is enough to run but not enough to keep:
//! they are `BOOT_SERVICES_DATA`, so the frame allocator is entitled to hand
//! them out and overwrite the tables the processor is currently walking. Building
//! our own is not an optimisation, it is what makes the memory map usable.
//!
//! # W^X from the first mapping
//!
//! `paging.rs` refuses any mapping that is both writable and executable, and
//! that refusal is worth nothing if the kernel's own image is mapped as one
//! writable executable blob. So the image is mapped by section, using symbols
//! the linker script exports: text executes and cannot be written, rodata can do
//! neither, and data and bss can be written but never executed.
//!
//! A 2 MiB page cannot express that split, so any 2 MiB chunk overlapping the
//! kernel image is broken into 4 KiB pages and mapped a page at a time. Every
//! other chunk of physical memory gets a single 2 MiB writable non-executable
//! entry, which is what keeps the table build to a few hundred allocations
//! instead of a hundred thousand.

use spin::Mutex;

use super::addr::{PagingMode, PhysAddr, VirtAddr, PAGE_SIZE};
use super::cpu;
use super::frame::{FrameAllocator, FrameError, Region};
use super::paging::{self, Entry, PageError, PageFlags, PageSize, PageTable, TableAccess};
use crate::boot_info::BootInfo;

/// Highest physical address the early allocator and identity map cover.
///
/// Four gigabytes. Beyond this the bitmap and the page tables both grow without
/// bound at boot, and nothing in stage 1 needs memory that high; the frames are
/// reported and left alone rather than silently claimed.
pub const EARLY_PHYS_LIMIT: u64 = 4 * 1024 * 1024 * 1024;

const MAX_FRAMES: u64 = EARLY_PHYS_LIMIT / PAGE_SIZE;
const BITMAP_WORDS: usize = (MAX_FRAMES / 64) as usize;

const LARGE_PAGE: u64 = 2 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryError {
    Frame(FrameError),
    Page(PageError),
    /// No frame left for an intermediate page table.
    OutOfFrames,
    /// `init` has not run, or ran and failed.
    NotInitialised,
    /// The linker symbols bounding the kernel image are inconsistent.
    BadKernelExtent,
}

impl From<FrameError> for MemoryError {
    fn from(e: FrameError) -> Self {
        Self::Frame(e)
    }
}

impl From<PageError> for MemoryError {
    fn from(e: PageError) -> Self {
        Self::Page(e)
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct MemoryStats {
    pub total_frames: u64,
    pub free_frames: u64,
    pub usable_bytes: u64,
}

static mut BITMAP: [u64; BITMAP_WORDS] = [0; BITMAP_WORDS];
static ALLOCATOR: Mutex<Option<FrameAllocator<'static>>> = Mutex::new(None);
static ROOT: Mutex<Option<PhysAddr>> = Mutex::new(None);

extern "C" {
    static __kernel_start: u8;
    static __text_end: u8;
    static __rodata_end: u8;
    static __kernel_end: u8;
}

/// Where each part of the loaded image sits, taken from the linker script.
#[derive(Debug, Clone, Copy)]
struct ImageLayout {
    start: u64,
    text_end: u64,
    rodata_end: u64,
    end: u64,
}

impl ImageLayout {
    fn current() -> Result<Self, MemoryError> {
        let layout = Self {
            start: core::ptr::addr_of!(__kernel_start) as u64,
            text_end: core::ptr::addr_of!(__text_end) as u64,
            rodata_end: core::ptr::addr_of!(__rodata_end) as u64,
            end: core::ptr::addr_of!(__kernel_end) as u64,
        };
        if layout.start >= layout.text_end
            || layout.text_end > layout.rodata_end
            || layout.rodata_end > layout.end
        {
            return Err(MemoryError::BadKernelExtent);
        }
        Ok(layout)
    }

    fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }

    /// Flags for the 4 KiB page starting at `addr`.
    ///
    /// The ordering of the comparisons is the whole point: a page is executable
    /// only if it is below `text_end`, and writable only if it is at or above
    /// `rodata_end`. No page can satisfy both, which is what makes the W^X check
    /// in `map_page` something the kernel image itself passes rather than
    /// something only user space is held to.
    fn flags_for(&self, addr: u64) -> PageFlags {
        if addr < self.text_end {
            // Executable, not writable. `NO_EXECUTE` absent is what makes it
            // executable; there is no positive "execute" bit on x86-64.
            PageFlags::PRESENT | PageFlags::GLOBAL
        } else if addr < self.rodata_end {
            PageFlags::PRESENT | PageFlags::NO_EXECUTE | PageFlags::GLOBAL
        } else {
            PageFlags::PRESENT | PageFlags::WRITABLE | PageFlags::NO_EXECUTE | PageFlags::GLOBAL
        }
    }
}

/// Identity-mapped view of physical memory.
///
/// Valid because the loader hands the kernel UEFI's identity mapping and the
/// table we build preserves it, so a physical address is dereferenceable as-is
/// for the whole of bring-up. `BootInfo::physical_memory_offset` exists for the
/// day this stops being true; while it is zero, the two views coincide.
struct IdentityAccess<'a> {
    allocator: &'a mut FrameAllocator<'static>,
    /// Frames handed out for intermediate tables, reported so the boot log shows
    /// what the mapping cost.
    tables_allocated: u64,
}

impl IdentityAccess<'_> {
    fn table(&self, phys: PhysAddr) -> Option<&PageTable> {
        if phys.as_u64() >= EARLY_PHYS_LIMIT {
            return None;
        }
        // SAFETY: physical memory is identity mapped, the address is page
        // aligned by construction, and `PageTable` is a plain 4 KiB array of
        // entries with no invalid bit patterns.
        unsafe { (phys.as_u64() as *const PageTable).as_ref() }
    }

    fn table_mut(&mut self, phys: PhysAddr) -> Option<&mut PageTable> {
        if phys.as_u64() >= EARLY_PHYS_LIMIT {
            return None;
        }
        // SAFETY: as above. Exclusivity holds because the only writer during
        // bring-up is this structure.
        unsafe { (phys.as_u64() as *mut PageTable).as_mut() }
    }
}

impl TableAccess for IdentityAccess<'_> {
    fn read_entry(&self, table: PhysAddr, index: u16) -> Option<Entry> {
        self.table(table)?.get(index)
    }

    fn write_entry(&mut self, table: PhysAddr, index: u16, entry: Entry) -> Result<(), PageError> {
        self.table_mut(table)
            .ok_or(PageError::NotMapped)?
            .set(index, entry)
    }

    fn alloc_table(&mut self) -> Option<PhysAddr> {
        let frame = self.allocator.alloc().ok()?;
        // A fresh frame holds whatever the firmware left there. An unzeroed page
        // table is read by the CPU as a table full of present entries pointing
        // at arbitrary physical addresses.
        let table = self.table_mut(frame)?;
        *table = PageTable::new();
        self.tables_allocated += 1;
        Some(frame)
    }
}

/// Builds the frame allocator from the handoff memory map.
///
/// # Safety
/// Called once, after `BootInfo::validate` has passed, before anything else
/// allocates.
pub unsafe fn init(boot: &BootInfo) -> Result<MemoryStats, MemoryError> {
    // SAFETY: single-threaded bring-up; no other reference to the bitmap exists.
    let bitmap: &'static mut [u64] = unsafe { &mut *core::ptr::addr_of_mut!(BITMAP) };

    let mut allocator = FrameAllocator::new(bitmap, 0, MAX_FRAMES);
    let mut usable_bytes = 0u64;

    for region in boot.regions() {
        if !region.kind.is_allocatable() {
            continue;
        }
        let start = region.start;
        let end = region.end().min(EARLY_PHYS_LIMIT);
        if end <= start {
            continue;
        }
        allocator.add_region(Region {
            start,
            len: end - start,
        })?;
        usable_bytes += end - start;
    }

    // The image is inside a region the loader marked usable only if the loader
    // got its own bookkeeping wrong; reserving it regardless costs nothing and
    // removes the possibility of allocating over the running kernel.
    let image = ImageLayout::current()?;
    allocator.reserve_region(Region {
        start: image.start,
        len: image.end - image.start,
    })?;

    // Frame 0 is never handed out. A null physical address is indistinguishable
    // from a failed allocation in far too much code to be worth the one frame.
    let _ = allocator.reserve_region(Region {
        start: 0,
        len: PAGE_SIZE,
    });

    let stats = MemoryStats {
        total_frames: allocator.total_frames(),
        free_frames: allocator.free_frames(),
        usable_bytes,
    };
    *ALLOCATOR.lock() = Some(allocator);
    Ok(stats)
}

/// Builds the kernel's own page tables and switches to them.
///
/// Returns the value written to CR3.
///
/// # Safety
/// `init` must have succeeded. The table built here maps all of physical memory
/// below `EARLY_PHYS_LIMIT`, which necessarily includes the running code, the
/// current stack, and the table itself — the three things a CR3 switch cannot
/// survive without.
pub unsafe fn activate_kernel_tables() -> Result<u64, MemoryError> {
    let mut guard = ALLOCATOR.lock();
    let allocator = guard.as_mut().ok_or(MemoryError::NotInitialised)?;
    let image = ImageLayout::current()?;

    let mut access = IdentityAccess {
        allocator,
        tables_allocated: 0,
    };
    let root = access.alloc_table().ok_or(MemoryError::OutOfFrames)?;

    let mut phys = 0u64;
    while phys < EARLY_PHYS_LIMIT {
        let chunk_end = phys + LARGE_PAGE;
        let overlaps_image = image.start < chunk_end && image.end > phys;

        if overlaps_image {
            let mut page = phys;
            while page < chunk_end {
                let flags = if image.contains(page) {
                    image.flags_for(page)
                } else {
                    PageFlags::PRESENT
                        | PageFlags::WRITABLE
                        | PageFlags::NO_EXECUTE
                        | PageFlags::GLOBAL
                };
                map(&mut access, root, page, flags, PageSize::Small)?;
                page += PAGE_SIZE;
            }
        } else {
            map(
                &mut access,
                root,
                phys,
                PageFlags::PRESENT
                    | PageFlags::WRITABLE
                    | PageFlags::NO_EXECUTE
                    | PageFlags::GLOBAL,
                PageSize::Large,
            )?;
        }
        phys = chunk_end;
    }

    // Frame 0 is left unmapped on purpose: a null dereference should fault
    // rather than quietly read the real-mode interrupt vector table.
    unmap_null(&mut access, root)?;

    *ROOT.lock() = Some(root);

    // SAFETY: the table maps every physical address below the limit with the
    // running code executable and the current stack writable, and the table
    // frames themselves are inside that range.
    unsafe { cpu::write_cr3(root.as_u64()) };
    Ok(root.as_u64())
}

fn map(
    access: &mut IdentityAccess<'_>,
    root: PhysAddr,
    phys: u64,
    flags: PageFlags,
    size: PageSize,
) -> Result<(), MemoryError> {
    let addr = PhysAddr::new(phys).map_err(|_| MemoryError::BadKernelExtent)?;
    let virt = VirtAddr::from_indices_sign_extended(phys, PagingMode::Level4);
    paging::map_page(access, root, virt, addr, flags, size, PagingMode::Level4)?;
    Ok(())
}

fn unmap_null(access: &mut IdentityAccess<'_>, root: PhysAddr) -> Result<(), MemoryError> {
    let virt = VirtAddr::from_indices_sign_extended(0, PagingMode::Level4);
    match paging::unmap_page(access, root, virt, PagingMode::Level4) {
        Ok(_) => Ok(()),
        // The first 2 MiB is mapped as one large page when the kernel does not
        // live there, and unmapping a 4 KiB page out of a large one is refused.
        // Splitting the large page for this would mean 512 entries to protect
        // one address; leaving it mapped is the lesser problem, and the page is
        // non-executable either way.
        Err(PageError::NotMapped) | Err(PageError::InvalidHugePage { .. }) => Ok(()),
        Err(e) => Err(MemoryError::Page(e)),
    }
}

/// Allocates one physical frame from the early allocator.
pub fn alloc_frame() -> Result<PhysAddr, MemoryError> {
    ALLOCATOR
        .lock()
        .as_mut()
        .ok_or(MemoryError::NotInitialised)?
        .alloc()
        .map_err(MemoryError::Frame)
}

/// Physical address of the active top-level table, once we own it.
pub fn kernel_root() -> Option<PhysAddr> {
    *ROOT.lock()
}

/// Frames still free, for reporting.
pub fn free_frames() -> u64 {
    ALLOCATOR.lock().as_ref().map_or(0, |a| a.free_frames())
}
