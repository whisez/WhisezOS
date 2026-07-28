//! Memory a device can read, and the one address the kernel does tell.
//!
//! `device.rs` is built on a rule: a process names an index, never an address,
//! and `DeviceInfo` has nowhere to put a physical address because a driver has
//! no use for one. Direct memory access is where that stops being true. A
//! virtio queue is a structure in RAM whose *physical* address the driver writes
//! into a device register; the device has no page tables and no idea what a
//! virtual address is. Without that number there is no DMA at all.
//!
//! # What is actually conceded
//!
//! The driver learns the physical address of memory the kernel just allocated
//! for it, and nothing else. That is a much smaller statement than it looks.
//! The dangerous syscall is the one that lets a process *choose* a physical
//! address — that one covers the kernel image, the page tables, and every other
//! process. This one goes the other way: the kernel picks the frames, hands back
//! where they landed, and the process can express no opinion about it. Learning
//! where your own buffer is does not tell you where anything else is.
//!
//! It is worth being exact about the limit, though: a driver that lies to its
//! device can point the device at those frames and no others, because those are
//! the only frames whose address it was told. An IOMMU is what makes that a
//! guarantee rather than an argument, and there is no IOMMU here yet. This is
//! the shape the call will keep when there is one — the driver still asks for a
//! buffer and still gets back an address to program — with the returned number
//! becoming an IOMMU address instead of a physical one. Hence `bus` rather than
//! `phys` in what user space receives: the name is already the one that will
//! still be true.
//!
//! # Contiguous, because the device cannot scatter
//!
//! A scatter-gather list is a device feature, not a memory-management one, and
//! the first drivers here will not use it. So a buffer is one physically
//! contiguous run, which is why the size limit is small: contiguous allocation
//! gets harder as memory fragments, and a request that cannot be satisfied
//! should fail at a bound the caller can reason about rather than at whatever
//! the allocator happens to have left.

#![allow(dead_code)]

pub use crate::abi::DmaRegion;
use crate::abi::SyscallError;

/// Where DMA buffers appear in a process's address space.
///
/// Far above the device window at `0x0000_2000_0000_0000`, and far below the
/// kernel half. Chosen so the two windows cannot be confused by inspection: a
/// pointer that starts `0x2` is a device register, one that starts `0x3` is
/// memory, and neither can be reached by arithmetic from the other.
pub const DMA_WINDOW_BASE: u64 = 0x0000_3000_0000_0000;

/// Address space reserved per buffer, whatever the buffer's real size.
///
/// Fixed slots for the same reason `map_device` uses them: packed allocations
/// let a process work out one buffer's size from the next one's address, and
/// leave no unmapped gap between two buffers to catch a run off the end of the
/// first.
pub const DMA_SLOT_SIZE: u64 = 2 * 1024 * 1024;

/// Buffers one process may hold at once.
///
/// Six, because two drivers in one process need it. Each virtio driver holds a
/// virtqueue and a request area, and init also keeps a scratch buffer of its
/// own — the block and sound drivers together come to five.
///
/// The number started at two, chosen before there was any driver to size it
/// against. The block driver was refused its third buffer partway through
/// bringing up a queue, and since that process was also the IPC server, its
/// exit destroyed the endpoint and every other process failed with
/// `BadEndpoint`. One wrong constant, three unrelated-looking symptoms.
///
/// Each buffer costs a permitted region in the process's table, so this cannot
/// be raised without raising `MAX_USER_REGIONS` to match.
/// Disk (2), sound (4), and network (4) can coexist in the desktop session.
pub const MAX_DMA_REGIONS: u64 = 10;

/// Largest single buffer.
///
/// A slot's worth. Also, deliberately, one 2 MiB page's worth: a request this
/// size is the largest contiguous run the frame allocator is asked for anywhere,
/// and keeping it to a size the allocator already aligns for means DMA does not
/// become the reason contiguous allocation fails.
pub const MAX_DMA_BYTES: u64 = DMA_SLOT_SIZE;

/// Bytes per page.
const PAGE_SIZE: u64 = 4096;

/// Where a buffer will go and how big it will be, before anything is allocated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Plan {
    /// Virtual base. Page aligned by construction.
    pub base: u64,
    /// Frames to allocate contiguously.
    pub pages: u64,
    /// Bytes those frames cover.
    pub length: u64,
}

/// Works out the mapping for a request, or says why there will not be one.
///
/// Separated from the allocation so the arithmetic can be tested without a
/// frame allocator, and so every refusal happens before any frame is taken —
/// a plan that fails leaves nothing to undo.
pub fn plan(slot: u64, bytes: u64) -> Result<Plan, SyscallError> {
    if slot >= MAX_DMA_REGIONS {
        return Err(SyscallError::TooLong);
    }
    // Zero is not "allocate nothing", it is a request the caller got wrong: it
    // would produce a mapping of no pages and an address pointing at whatever
    // follows.
    if bytes == 0 {
        return Err(SyscallError::BadArgument);
    }
    if bytes > MAX_DMA_BYTES {
        return Err(SyscallError::TooLong);
    }

    let pages = bytes.div_ceil(PAGE_SIZE);
    Ok(Plan {
        base: DMA_WINDOW_BASE + slot * DMA_SLOT_SIZE,
        pages,
        length: pages * PAGE_SIZE,
    })
}

/// Whether an address is inside the DMA window at all.
///
/// Used to keep the window's own arithmetic honest in tests; the kernel checks
/// a process's recorded regions rather than this, because a region is proof the
/// process was actually given the mapping and an address range is not.
#[must_use]
pub const fn in_window(address: u64) -> bool {
    address >= DMA_WINDOW_BASE && address < DMA_WINDOW_BASE + MAX_DMA_REGIONS * DMA_SLOT_SIZE
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The device window, repeated here rather than imported.
    ///
    /// `arch::user` is x86-only and this test is not, so the number is copied
    /// rather than imported. What keeps the copy honest is a `const` assertion
    /// in `arch::user` itself, which compares the real constant against
    /// `DMA_WINDOW_BASE` and fails the kernel build if the two windows ever
    /// meet. Between them the claim holds from both directions.
    const DEVICE_WINDOW_BASE: u64 = 0x0000_2000_0000_0000;
    const DEVICE_WINDOW_BYTES: u64 = 8 * 256 * 1024 * 1024;

    #[test]
    fn a_plan_covers_at_least_what_was_asked_for() {
        for bytes in [1u64, 5, 4095, 4096, 4097, 8192, MAX_DMA_BYTES] {
            let plan = plan(0, bytes).unwrap();
            assert!(
                plan.length >= bytes,
                "{bytes} rounded down to {}",
                plan.length
            );
            assert_eq!(plan.length, plan.pages * PAGE_SIZE);
        }
    }

    #[test]
    fn a_plan_never_rounds_up_by_a_whole_page_unnecessarily() {
        // An exact multiple must not gain a page: the extra frame would be
        // charged to the process and never used.
        assert_eq!(plan(0, PAGE_SIZE).unwrap().pages, 1);
        assert_eq!(plan(0, 2 * PAGE_SIZE).unwrap().pages, 2);
    }

    #[test]
    fn zero_bytes_is_refused_rather_than_mapped() {
        assert_eq!(plan(0, 0), Err(SyscallError::BadArgument));
    }

    #[test]
    fn a_request_past_the_slot_size_is_refused() {
        assert_eq!(plan(0, MAX_DMA_BYTES + 1), Err(SyscallError::TooLong));
        assert_eq!(plan(0, u64::MAX), Err(SyscallError::TooLong));
    }

    #[test]
    fn a_slot_past_the_last_is_refused() {
        assert!(plan(MAX_DMA_REGIONS - 1, 4096).is_ok());
        assert_eq!(plan(MAX_DMA_REGIONS, 4096), Err(SyscallError::TooLong));
        assert_eq!(plan(u64::MAX, 4096), Err(SyscallError::TooLong));
    }

    #[test]
    fn slots_do_not_overlap() {
        // The whole point of fixed slots. If two slots could overlap, a second
        // buffer would silently alias the first and the device would scribble
        // over a queue that is in use.
        for a in 0..MAX_DMA_REGIONS {
            let first = plan(a, MAX_DMA_BYTES).unwrap();
            for b in (a + 1)..MAX_DMA_REGIONS {
                let second = plan(b, MAX_DMA_BYTES).unwrap();
                assert!(
                    first.base + first.length <= second.base,
                    "slot {a} runs into slot {b}"
                );
            }
        }
    }

    #[test]
    fn every_base_is_page_aligned() {
        for slot in 0..MAX_DMA_REGIONS {
            assert_eq!(plan(slot, 1).unwrap().base % PAGE_SIZE, 0);
        }
    }

    #[test]
    fn the_dma_window_does_not_touch_the_device_window() {
        // Two windows that met would let a driver walk off the end of its
        // framebuffer mapping straight into its own queue, with the page tables
        // raising no objection because both ranges are its own.
        let device_end = DEVICE_WINDOW_BASE + DEVICE_WINDOW_BYTES;
        assert!(
            DMA_WINDOW_BASE > device_end,
            "the DMA window starts inside the device window"
        );
    }

    #[test]
    fn the_whole_window_is_in_the_user_half() {
        // Anything at or above the sign-extension boundary is kernel space, and
        // a user mapping there would either fault or, worse, not.
        let end = DMA_WINDOW_BASE + MAX_DMA_REGIONS * DMA_SLOT_SIZE;
        assert!(end < 0x0000_8000_0000_0000);
        assert!(in_window(DMA_WINDOW_BASE));
        assert!(in_window(end - 1));
        assert!(!in_window(end));
        assert!(!in_window(DMA_WINDOW_BASE - 1));
    }

    #[test]
    fn what_user_space_receives_has_room_for_nothing_it_was_not_given() {
        // `DmaRegion` is three numbers the process is entitled to: where its
        // buffer is, what to tell the device, and how big it is. This is the
        // test that fails if a fourth is added without a reason.
        assert_eq!(core::mem::size_of::<DmaRegion>(), 24);
    }
}
