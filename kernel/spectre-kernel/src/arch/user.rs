//! Building a user address space and entering ring 3.
//!
//! # What an address space is here
//!
//! A fresh top-level table, plus one entry copied from the kernel's. The copied
//! entry is the identity map of the first 512 GiB, which is where the kernel's
//! code, stacks, and page tables live. Sharing it is what lets a `syscall` land
//! on kernel code without a trampoline, and it is safe to share because none of
//! those mappings carry the `USER` bit — ring 3 faults on every one of them.
//!
//! That is the pre-KPTI arrangement, and its weakness is worth naming: the
//! kernel is *mapped* in every address space, so a speculative side channel can
//! reach it even though an architectural access cannot. Fixing that means a
//! separate trampoline address space, which is work for after there is more
//! than one process to isolate.
//!
//! # W^X for the process, decided here
//!
//! The loader hands over the init ELF as bytes rather than as a placed image,
//! so this is the code that decides what each page of a user process may do. A
//! segment that is both writable and executable is refused outright rather than
//! being mapped read-only-ish and hoped about: `paging::map_page` would refuse
//! it anyway, and catching it here names the segment.

use crate::abi;
use crate::device;
use crate::elf::{Elf64, ElfError};
use crate::usercopy::UserRegion;

use super::addr::{PagingMode, PhysAddr, VirtAddr, PAGE_SIZE};
use super::cpu;
use super::gdt::GdtLayout;
use super::memory::{self, MemoryError};
use super::paging::{self, PageFlags, PageSize, TableAccess};
use super::segments;

/// Top of the initial user stack.
///
/// Directly below the region init is linked at, in the same 512 GiB slot, so a
/// user address space needs exactly one top-level entry of its own.
pub const USER_STACK_TOP: u64 = 0x0000_1000_0000_0000;
/// Initial user stack size. One page short of a hole below it, deliberately
/// unmapped, so an overflow faults instead of running into whatever is next.
pub const USER_STACK_BYTES: u64 = 64 * 1024;

/// Most regions a process can hold: one per loadable segment, the stack, every
/// device window it maps, and every DMA buffer it takes.
///
/// Twenty-four because init now drives four devices. Three loadable segments
/// and a stack, four device windows — framebuffer, disk, sound card, network —
/// and nine DMA buffers come to seventeen. The remaining slots leave room for
/// a driver to grow without failing halfway through queue setup.
///
/// At eight, the block driver was refused its last allocation partway through
/// bringing up a queue. That is the worst moment to run out: the device is half
/// configured and the process has no way to undo it.
pub const MAX_USER_REGIONS: usize = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserError {
    Elf(ElfError),
    Memory(MemoryError),
    /// A loadable segment asks to be both writable and executable.
    WriteExecuteSegment {
        index: usize,
    },
    /// A segment does not start on a page boundary.
    ///
    /// Permissions are a property of a page, so two segments sharing one page
    /// means that page needs the union of their rights — and the usual pair to
    /// share a page is text and rodata, or rodata and data. The second of those
    /// is a writable executable page arrived at by accident. Refusing the link
    /// is the only answer that does not quietly weaken `W^X`.
    UnalignedSegment {
        index: usize,
        vaddr: u64,
    },
    /// A segment lies in the kernel half, or would if it were mapped.
    SegmentInKernelHalf {
        vaddr: u64,
    },
    /// More loadable segments than `MAX_USER_REGIONS` has room for.
    TooManyRegions,
    /// No init image in the handoff.
    NoImage,
    /// A cross-space copy targeted a page the owning process may not write.
    DestinationNotWritable {
        vaddr: u64,
    },
}

impl From<MemoryError> for UserError {
    fn from(e: MemoryError) -> Self {
        Self::Memory(e)
    }
}

impl From<ElfError> for UserError {
    fn from(e: ElfError) -> Self {
        Self::Elf(e)
    }
}

/// A loaded, not yet running, user process.
#[derive(Debug, Clone, Copy)]
pub struct UserProcess {
    root: PhysAddr,
    pub entry: u64,
    pub stack_top: u64,
    regions: [UserRegion; MAX_USER_REGIONS],
    region_count: usize,
}

impl UserProcess {
    /// The top-level page table this process runs on.
    #[must_use]
    pub const fn root(&self) -> PhysAddr {
        self.root
    }

    /// The ranges this process may hand the kernel as pointers.
    #[must_use]
    pub fn regions(&self) -> &[UserRegion] {
        &self.regions[..self.region_count]
    }
}

/// Parses and maps an init image into a new address space.
///
/// # Safety
/// The early frame allocator must be initialised, physical memory identity
/// mapped, and `kernel_root` the table currently in `CR3`.
pub unsafe fn load(image: &[u8], kernel_root: PhysAddr) -> Result<UserProcess, UserError> {
    let elf = Elf64::parse(image)?;

    // Refuse the whole image before mapping any of it. A process that is half
    // loaded and then rejected has already had frames written on its behalf,
    // and unwinding that is more code than checking first.
    for (index, segment) in elf.segments().enumerate() {
        if segment.is_writable() && segment.is_executable() {
            return Err(UserError::WriteExecuteSegment { index });
        }
        if !VirtAddr::new(segment.virt, PagingMode::Level4)
            .is_ok_and(|v| !v.is_kernel_half(PagingMode::Level4))
        {
            return Err(UserError::SegmentInKernelHalf {
                vaddr: segment.virt,
            });
        }
        if !segment.virt.is_multiple_of(PAGE_SIZE) {
            return Err(UserError::UnalignedSegment {
                index,
                vaddr: segment.virt,
            });
        }
    }

    let mut regions = [UserRegion::new(0, 0); MAX_USER_REGIONS];
    let mut region_count = 0usize;

    let root = memory::with_table_access(|access| {
        let root = access.alloc_zeroed().ok_or(MemoryError::OutOfFrames)?;

        // Share the kernel's identity map. Entry 0 covers 0..512 GiB, which is
        // every address the kernel runs at; none of it is user-accessible.
        let kernel_entry = access
            .read_entry(kernel_root, 0)
            .ok_or(MemoryError::NotInitialised)?;
        access.write_entry(root, 0, kernel_entry)?;

        Ok(root)
    })?;

    for segment in elf.segments() {
        let flags = segment_flags(&segment);
        let contents = elf.contents(&segment);

        let mut offset = 0u64;
        while offset < segment.mem_size {
            let frame = memory::with_table_access(|access| {
                access.alloc_zeroed().ok_or(MemoryError::OutOfFrames)
            })?;

            // `alloc_table` zeroes the frame, which is exactly what a partially
            // filled page and the whole of `.bss` need.
            let take = core::cmp::min(PAGE_SIZE, segment.mem_size - offset);
            let from_file = contents.len().saturating_sub(offset as usize);
            let copy = core::cmp::min(take as usize, from_file);
            if copy > 0 {
                // SAFETY: `frame` is a freshly allocated page below the early
                // physical limit and therefore identity mapped, and `copy` is
                // bounded by both the page size and the remaining file bytes.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        contents.as_ptr().add(offset as usize),
                        frame.as_u64() as *mut u8,
                        copy,
                    );
                }
            }

            let virt = segment.virt + offset;
            memory::with_table_access(|access| {
                paging::map_page(
                    access,
                    root,
                    VirtAddr::from_indices_sign_extended(virt, PagingMode::Level4),
                    frame,
                    flags,
                    PageSize::Small,
                    PagingMode::Level4,
                )
                .map_err(MemoryError::Page)
            })?;
            offset += PAGE_SIZE;
        }

        if region_count == MAX_USER_REGIONS {
            return Err(UserError::TooManyRegions);
        }
        regions[region_count] = UserRegion::new(segment.virt, segment.mem_size);
        region_count += 1;
    }

    // Stack: writable, never executable, and user accessible.
    let stack_base = USER_STACK_TOP - USER_STACK_BYTES;
    let mut offset = 0u64;
    while offset < USER_STACK_BYTES {
        let frame = memory::with_table_access(|access| {
            access.alloc_zeroed().ok_or(MemoryError::OutOfFrames)
        })?;
        memory::with_table_access(|access| {
            paging::map_page(
                access,
                root,
                VirtAddr::from_indices_sign_extended(stack_base + offset, PagingMode::Level4),
                frame,
                PageFlags::PRESENT | PageFlags::USER | PageFlags::WRITABLE | PageFlags::NO_EXECUTE,
                PageSize::Small,
                PagingMode::Level4,
            )
            .map_err(MemoryError::Page)
        })?;
        offset += PAGE_SIZE;
    }

    if region_count == MAX_USER_REGIONS {
        return Err(UserError::TooManyRegions);
    }
    regions[region_count] = UserRegion::new(stack_base, USER_STACK_BYTES);
    region_count += 1;

    Ok(UserProcess {
        root,
        entry: elf.entry(),
        stack_top: USER_STACK_TOP,
        regions,
        region_count,
    })
}

/// Where device mappings go in a user address space.
///
/// Its own top-level slot, clear of the image at 16 TiB and of the stack below
/// it, so a device mapping can never land on something the process already has.
pub const DEVICE_WINDOW_BASE: u64 = 0x0000_2000_0000_0000;

/// Address space reserved per device, whatever the device's real size.
///
/// The window is carved into fixed slots rather than packed, so a second
/// mapping cannot be placed by arithmetic that depends on the first — and a
/// process cannot infer one device's size from another's address.
pub const DEVICE_SLOT_SIZE: u64 = 256 * 1024 * 1024;

/// The two user windows must not meet.
///
/// `dma.rs` reasons about this and asserts it against its own copy of the base,
/// because that file is host-testable and this one is not. This is the check
/// that the copy is the real number: if either window moves, one of the two
/// fails, and between them they cover both halves of the claim.
const _: () = assert!(
    DEVICE_WINDOW_BASE + (device::MAX_DEVICES as u64) * DEVICE_SLOT_SIZE
        < crate::dma::DMA_WINDOW_BASE
);

/// Maps a physical device range into a process, uncacheable.
///
/// # Why the cache bits are not optional
///
/// Device registers have side effects on access. Through a write-back mapping
/// the processor may satisfy a read from cache — returning a value the device
/// changed minutes ago — and may merge, reorder, or defer writes. For a
/// framebuffer that shows up as pixels appearing late or not at all; for a
/// controller's command register it shows up as a device that never receives
/// the command. `NO_CACHE` and `WRITE_THROUGH` together select the strongest
/// uncacheable type the page-table bits can express.
///
/// # Safety
/// `phys` must be a device range the kernel decided this process may have, and
/// `root` a live top-level table for a process that is not running. The caller
/// is what enforces the first of those; nothing here can tell a device from
/// somebody else's memory.
pub unsafe fn map_device(
    root: PhysAddr,
    phys: u64,
    length: u64,
    slot: u64,
) -> Result<(u64, u64), UserError> {
    if length == 0 {
        return Err(UserError::DestinationNotWritable { vaddr: phys });
    }
    // The window is carved into fixed slots rather than packed, so a second
    // mapping cannot be placed by arithmetic that depends on the first — and a
    // process cannot infer one device's size from another's address.
    let base = DEVICE_WINDOW_BASE + slot * DEVICE_SLOT_SIZE;
    if length > DEVICE_SLOT_SIZE {
        return Err(UserError::DestinationNotWritable { vaddr: phys });
    }

    let flags = PageFlags::PRESENT
        | PageFlags::USER
        | PageFlags::WRITABLE
        | PageFlags::NO_EXECUTE
        | PageFlags::NO_CACHE
        | PageFlags::WRITE_THROUGH
        // Not this process's memory. Teardown walks every leaf and returns it
        // to the allocator; without this the framebuffer's thousand frames are
        // marked free while the display is still reading from them.
        | PageFlags::DEVICE;

    let first = phys & !(PAGE_SIZE - 1);
    let last = (phys + length).div_ceil(PAGE_SIZE) * PAGE_SIZE;
    let mut offset = 0u64;
    while first + offset < last {
        let frame =
            PhysAddr::new(first + offset).map_err(|_| UserError::DestinationNotWritable {
                vaddr: first + offset,
            })?;
        memory::with_table_access(|access| {
            paging::map_page(
                access,
                root,
                VirtAddr::from_indices_sign_extended(base + offset, PagingMode::Level4),
                frame,
                flags,
                PageSize::Small,
                PagingMode::Level4,
            )
            .map_err(MemoryError::Page)
        })?;
        offset += PAGE_SIZE;
    }

    // The address the process sees points at the same byte the physical address
    // did, offset included — a device whose registers start mid-page would
    // otherwise be off by that offset.
    Ok((base + (phys - first), last - first))
}

/// Allocates a DMA buffer and maps it into `root`.
///
/// Returns the virtual base and the physical base. The physical one goes on to
/// user space, which is the concession `dma.rs` argues for; everything else
/// about this is ordinary memory.
///
/// # What this is *not*
///
/// Not `NO_CACHE`. A device window is uncacheable because a stale read of a
/// status register is a wrong answer; DMA memory is cache-coherent on x86-64 —
/// the hardware snoops — so making it uncacheable would slow every access the
/// driver makes for no correctness gain.
///
/// Not `DEVICE` either, which is the important one. That flag tells teardown to
/// leave a leaf alone because the frames belong to hardware. These frames came
/// from the allocator and must go back to it, so they are marked as what they
/// are and the frame ledger stays balanced when the process exits.
///
/// # Safety
/// `root` must be a live top-level table, and physical memory must be identity
/// mapped so the zeroing below can reach the frames.
pub unsafe fn map_dma(root: PhysAddr, plan: &crate::dma::Plan) -> Result<(u64, u64), UserError> {
    let phys = memory::alloc_contiguous_frames(plan.pages, 1)?;

    // Zeroed before the process can see it. A DMA buffer handed over with the
    // previous owner's bytes still in it is a process reading memory it was
    // never given, which is the same disclosure as an uninitialised page.
    // SAFETY: `alloc_contiguous_frames` just returned these frames as unused,
    // and the identity map covers them.
    unsafe {
        core::ptr::write_bytes(
            phys.as_u64() as *mut u8,
            0,
            (plan.pages * PAGE_SIZE) as usize,
        );
    }

    let flags = PageFlags::PRESENT | PageFlags::USER | PageFlags::WRITABLE | PageFlags::NO_EXECUTE;

    let mut offset = 0u64;
    while offset < plan.pages * PAGE_SIZE {
        let frame = PhysAddr::new(phys.as_u64() + offset).map_err(|_| {
            UserError::DestinationNotWritable {
                vaddr: phys.as_u64() + offset,
            }
        })?;
        memory::with_table_access(|access| {
            paging::map_page(
                access,
                root,
                VirtAddr::from_indices_sign_extended(plan.base + offset, PagingMode::Level4),
                frame,
                flags,
                PageSize::Small,
                PagingMode::Level4,
            )
            .map_err(MemoryError::Page)
        })?;
        offset += PAGE_SIZE;
    }

    Ok((plan.base, phys.as_u64()))
}

/// Copies bytes into another process's address space.
///
/// The kernel is running on some *other* address space when a message is
/// delivered — the sender's, usually — so the destination is reached by walking
/// the target's own page tables and writing through the identity map. That is
/// also the only way to do it without mapping two user spaces at once.
///
/// # Why the permissions are re-checked here
///
/// The target validated this range against its own regions when it made the
/// call, which establishes that the address belongs to it. It does not
/// establish that the address is *writable*: a process can perfectly well pass
/// a pointer into its own read-only text. Writing through the identity map
/// bypasses the user mapping's permissions entirely, so a kernel that did not
/// check here would let any process have its own `W^X` guarantee broken on
/// request.
///
/// # Safety
/// `root` must be a live top-level table for a process that is not running, and
/// physical memory must be identity mapped.
pub unsafe fn copy_into_space(root: PhysAddr, virt: u64, bytes: &[u8]) -> Result<(), UserError> {
    let mut written = 0usize;
    while written < bytes.len() {
        let address = virt + written as u64;
        let translation = memory::with_table_access(|access| {
            paging::translate(
                access,
                root,
                VirtAddr::from_indices_sign_extended(address, PagingMode::Level4),
                PagingMode::Level4,
            )
            .map_err(MemoryError::Page)
        })?;

        if !translation.flags.contains(PageFlags::WRITABLE)
            || !translation.flags.contains(PageFlags::USER)
        {
            return Err(UserError::DestinationNotWritable { vaddr: address });
        }

        // Stop at the end of the page the translation resolved to; the next
        // one may be somewhere else entirely.
        let page_bytes = translation.size.bytes();
        let offset_in_page = address & (page_bytes - 1);
        let room = (page_bytes - offset_in_page) as usize;
        let take = room.min(bytes.len() - written);

        // SAFETY: the destination is a physical address inside a page the
        // target owns and may write, identity mapped, and `take` is bounded by
        // the remaining space in that page.
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr().add(written),
                translation.phys.as_u64() as *mut u8,
                take,
            );
        }
        written += take;
    }
    Ok(())
}

/// Page flags for one loadable segment.
///
/// There is no execute bit on x86-64 — a page is executable unless `NO_EXECUTE`
/// is set — so "executable" here is expressed by the absence of a flag, which is
/// the single easiest thing in this file to get backwards.
fn segment_flags(segment: &crate::elf::Segment) -> PageFlags {
    let mut flags = PageFlags::PRESENT | PageFlags::USER;
    if segment.is_writable() {
        flags |= PageFlags::WRITABLE;
    }
    if !segment.is_executable() {
        flags |= PageFlags::NO_EXECUTE;
    }
    flags
}

/// Switches to `process` and returns to ring 3 at its entry point.
///
/// # Safety
/// `process` must have been produced by `load` against the currently active
/// kernel table, and the syscall MSRs must already be installed — the first
/// thing init does is issue a `syscall`.
pub unsafe fn enter(process: &UserProcess, layout: &GdtLayout, kernel_stack_top: u64) -> ! {
    // The stack the CPU switches to when an *exception* arrives from ring 3.
    // The syscall path uses its own per-CPU stack; this one is for faults, and
    // without it a page fault in user space would push its frame onto the user
    // stack the fault may well have been about.
    // SAFETY: single-threaded, and nothing else is using the TSS.
    unsafe {
        segments::set_kernel_stack(VirtAddr::from_indices_sign_extended(
            kernel_stack_top,
            PagingMode::Level4,
        ));
    }

    let user_cs = u64::from(layout.user_code.0);
    let user_ss = u64::from(layout.user_data.0);
    // RFLAGS with only bit 1 set: reserved-always-one, interrupts masked.
    // Interrupts stay off in ring 3 because there is no interrupt controller
    // and no timer yet; enabling them would let a stray legacy PIC line arrive
    // at a vector with nothing behind it.
    let rflags = 0x0000_0002u64;

    // SAFETY: the table maps the kernel's identity range at entry 0 and the
    // process's own pages, so execution continues after the CR3 load. The
    // `iretq` frame is built in the order the CPU pops it.
    unsafe {
        cpu::write_cr3(process.root.as_u64());
        core::arch::asm!(
            "push {ss}",
            "push {rsp}",
            "push {rflags}",
            "push {cs}",
            "push {rip}",
            "iretq",
            ss = in(reg) user_ss,
            rsp = in(reg) process.stack_top,
            rflags = in(reg) rflags,
            cs = in(reg) user_cs,
            rip = in(reg) process.entry,
            options(noreturn),
        )
    }
}

/// The running process, for the syscall path to validate pointers against.
///
/// One process, one slot: there is no scheduler yet, so "current" is not yet a
/// question. It becomes a per-CPU field the moment there is more than one.
static CURRENT: spin::Mutex<Option<UserProcess>> = spin::Mutex::new(None);

pub fn set_current(process: UserProcess) {
    *CURRENT.lock() = Some(process);
}

/// Runs `f` with the current process's permitted ranges.
pub fn with_current_regions<R>(f: impl FnOnce(&[UserRegion]) -> R) -> R {
    match CURRENT.lock().as_ref() {
        Some(process) => f(process.regions()),
        // No process means no permitted ranges, which makes every user pointer
        // invalid — the correct answer for a syscall that cannot have come from
        // anywhere legitimate.
        None => f(&[]),
    }
}

/// Longest single `SYS_LOG`, re-exported so the handler and the ABI cannot
/// disagree about it.
pub const MAX_LOG_BYTES: usize = abi::MAX_LOG_BYTES;
