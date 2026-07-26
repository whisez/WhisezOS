//! Physical frame allocator.
//!
//! A bitmap allocator over the usable physical address space: one bit per
//! 4 KiB frame, set means allocated.
//!
//! # Why a bitmap and not a free list
//!
//! A free list gives O(1) single-frame allocation and is the obvious choice,
//! right up until something asks for *contiguous* frames. WhisezOS asks
//! constantly: DMA buffers for user-space drivers must be physically
//! contiguous, Game Mode's RAM compaction exists specifically to hand a game
//! large contiguous blocks, and 2 MiB/1 GiB page mappings need 512/262144
//! aligned consecutive frames. Finding a contiguous run in a free list means
//! sorting it; in a bitmap it is a scan, and a scan over `u64` words checks 64
//! frames per instruction.
//!
//! Cost is 1 bit per 4 KiB — 32 KiB of bitmap per GiB of RAM, or 1 MiB for a
//! 32 GiB machine. That is cheap enough not to think about.
//!
//! # The allocator does not own the memory it hands out
//!
//! `alloc` returns a frame number and marks it used. It does not zero the
//! frame, map it, or track who asked. Ownership lives in the Vault allocator
//! one layer up, which is what lets a page be donated across an IPC boundary
//! without the physical allocator needing to know. A frame allocator that also
//! tracks ownership cannot express shared or donated pages without inventing a
//! second refcount that will eventually disagree with the first.
//!
//! Zeroing is the caller's job and is deliberately not automatic: a frame about
//! to receive a full-page DMA write does not need zeroing, and doing it anyway
//! doubles the cost of every buffer allocation on the driver hot path. Frames
//! handed to a *new address space* are always zeroed by `Vault::provision`,
//! which is where the security requirement actually lives.

use super::addr::{PhysAddr, PAGE_SHIFT, PAGE_SIZE};

/// Frames per bitmap word.
const FRAMES_PER_WORD: u64 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// No single frame available.
    OutOfMemory,
    /// No run of the requested length and alignment exists. Distinguished from
    /// `OutOfMemory` because the caller's recovery differs: fragmentation is
    /// fixable by compaction, exhaustion is not.
    Fragmented { requested: u64, largest_run: u64 },
    /// Frame number lies outside the managed range.
    OutOfRange(u64),
    /// Freeing a frame that was already free — a double free.
    DoubleFree(u64),
    /// Region descriptor was malformed.
    BadRegion,
}

/// A usable physical memory region, from the UEFI memory map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Region {
    pub start: u64,
    pub len: u64,
}

impl Region {
    pub fn frames(&self) -> core::ops::Range<u64> {
        let first = self.start.div_ceil(PAGE_SIZE);
        let last = (self.start + self.len) / PAGE_SIZE;
        first..last.max(first)
    }
}

/// Bitmap-backed physical frame allocator.
///
/// The bitmap storage is supplied by the caller rather than allocated
/// internally, because at the point this is constructed there is no allocator
/// to allocate it with. The bootstrap sequence carves the bitmap out of the
/// first sufficiently large usable region, then marks those frames used.
pub struct FrameAllocator<'a> {
    bitmap: &'a mut [u64],
    /// Frame number corresponding to bit 0.
    base_frame: u64,
    /// Total frames covered by the bitmap.
    frame_count: u64,
    /// Frames currently allocated. Tracked incrementally; recomputing by
    /// popcount on every query is O(n) and this is read by the memory-pressure
    /// path on every allocation.
    used: u64,
    /// Rotating hint so sequential allocations do not rescan from zero. Without
    /// it, allocating N frames is O(N^2) — which is invisible in a test with 100
    /// frames and catastrophic when populating an 8 GiB arena.
    next_hint: u64,
}

impl<'a> FrameAllocator<'a> {
    /// Bitmap words needed to cover `frame_count` frames.
    pub const fn words_for(frame_count: u64) -> usize {
        frame_count.div_ceil(FRAMES_PER_WORD) as usize
    }

    /// Create an allocator with everything marked **used**.
    ///
    /// Starting fully-allocated and then explicitly freeing the usable regions
    /// is the safe direction. The opposite — start free, mark reserved regions
    /// used — hands out firmware memory, MMIO windows, and the kernel's own
    /// image if any region is missed from the reserve list. Being wrong in this
    /// direction produces an out-of-memory error; being wrong in the other
    /// direction produces silent corruption of ACPI tables.
    pub fn new(bitmap: &'a mut [u64], base_frame: u64, frame_count: u64) -> Self {
        bitmap.fill(u64::MAX);
        let used = frame_count;
        FrameAllocator {
            bitmap,
            base_frame,
            frame_count,
            used,
            next_hint: 0,
        }
    }

    /// Mark a region as available.
    pub fn add_region(&mut self, region: Region) -> Result<u64, FrameError> {
        let mut added = 0;
        for frame in region.frames() {
            if self.set_free(frame).is_ok() {
                added += 1;
            }
        }
        Ok(added)
    }

    /// Mark a region as permanently reserved (kernel image, framebuffer, ACPI).
    pub fn reserve_region(&mut self, region: Region) -> Result<u64, FrameError> {
        // Note the asymmetry with `add_region`: reservation rounds *outward*
        // (align the start down, the end up) so a reserved structure that does
        // not begin on a page boundary still has its whole first page withheld.
        // Rounding inward would hand out the page containing the start of the
        // ACPI RSDP.
        let first = region.start / PAGE_SIZE;
        let last = (region.start + region.len).div_ceil(PAGE_SIZE);

        let mut reserved = 0;
        for frame in first..last {
            if self.set_used(frame).is_ok() {
                reserved += 1;
            }
        }
        Ok(reserved)
    }

    fn index_of(&self, frame: u64) -> Result<(usize, u32), FrameError> {
        if frame < self.base_frame || frame >= self.base_frame + self.frame_count {
            return Err(FrameError::OutOfRange(frame));
        }
        let offset = frame - self.base_frame;
        Ok((
            (offset / FRAMES_PER_WORD) as usize,
            (offset % FRAMES_PER_WORD) as u32,
        ))
    }

    pub fn is_used(&self, frame: u64) -> Result<bool, FrameError> {
        let (word, bit) = self.index_of(frame)?;
        Ok(self.bitmap[word] & (1u64 << bit) != 0)
    }

    fn set_used(&mut self, frame: u64) -> Result<(), FrameError> {
        let (word, bit) = self.index_of(frame)?;
        let mask = 1u64 << bit;
        if self.bitmap[word] & mask == 0 {
            self.bitmap[word] |= mask;
            self.used += 1;
        }
        Ok(())
    }

    fn set_free(&mut self, frame: u64) -> Result<(), FrameError> {
        let (word, bit) = self.index_of(frame)?;
        let mask = 1u64 << bit;
        if self.bitmap[word] & mask != 0 {
            self.bitmap[word] &= !mask;
            self.used -= 1;
        }
        Ok(())
    }

    /// Allocate one frame.
    pub fn alloc(&mut self) -> Result<PhysAddr, FrameError> {
        let start_word = (self.next_hint / FRAMES_PER_WORD) as usize;
        let words = self.bitmap.len();

        // Scan from the hint, then wrap. Two passes rather than a modulo index
        // so the common case is a straight forward scan with no division.
        for pass in 0..2 {
            let (from, to) = if pass == 0 {
                (start_word, words)
            } else {
                (0, start_word.min(words))
            };

            for w in from..to {
                let word = self.bitmap[w];
                if word == u64::MAX {
                    continue;
                }
                let bit = (!word).trailing_zeros();
                let offset = w as u64 * FRAMES_PER_WORD + bit as u64;
                if offset >= self.frame_count {
                    break;
                }

                self.bitmap[w] |= 1u64 << bit;
                self.used += 1;
                self.next_hint = offset + 1;

                let frame = self.base_frame + offset;
                return PhysAddr::new(frame << PAGE_SHIFT)
                    .map_err(|_| FrameError::OutOfRange(frame));
            }
        }

        Err(FrameError::OutOfMemory)
    }

    /// Allocate `count` physically contiguous frames, aligned to
    /// `align_frames` (a power of two, in frames).
    ///
    /// `align_frames` matters for large-page mappings: a 2 MiB page needs 512
    /// frames aligned to a 512-frame boundary, and a run that is contiguous but
    /// misaligned is useless for that purpose. Returning it anyway would push
    /// the failure into `map_page`, far from the cause.
    pub fn alloc_contiguous(
        &mut self,
        count: u64,
        align_frames: u64,
    ) -> Result<PhysAddr, FrameError> {
        if count == 0 {
            return Err(FrameError::BadRegion);
        }
        let align = align_frames.max(1);
        debug_assert!(align.is_power_of_two(), "alignment must be a power of two");

        let mut best_run = 0u64;
        let mut candidate = self.base_frame.next_multiple_of(align);

        while candidate + count <= self.base_frame + self.frame_count {
            match self.first_used_in(candidate, count)? {
                None => {
                    for f in candidate..candidate + count {
                        self.set_used(f)?;
                    }
                    return PhysAddr::new(candidate << PAGE_SHIFT)
                        .map_err(|_| FrameError::OutOfRange(candidate));
                }
                Some(blocker) => {
                    best_run = best_run.max(blocker - candidate);
                    // Resume past the blocker, re-aligned. Advancing by one
                    // frame instead would make a failed search over a fragmented
                    // 32 GiB machine take minutes.
                    candidate = (blocker + 1).next_multiple_of(align);
                }
            }
        }

        Err(FrameError::Fragmented {
            requested: count,
            largest_run: best_run,
        })
    }

    /// First used frame in `[start, start+count)`, or `None` if all are free.
    fn first_used_in(&self, start: u64, count: u64) -> Result<Option<u64>, FrameError> {
        let mut frame = start;
        let end = start + count;

        while frame < end {
            let (word, bit) = self.index_of(frame)?;
            let w = self.bitmap[word];

            if w == 0 {
                // Whole word free; skip to the next word boundary.
                frame += FRAMES_PER_WORD - bit as u64;
                continue;
            }

            // Mask off bits before `bit` and beyond `end` within this word.
            let remaining = (end - frame).min(FRAMES_PER_WORD - bit as u64);
            let mask = if remaining >= 64 {
                u64::MAX
            } else {
                ((1u64 << remaining) - 1) << bit
            };
            let masked = w & mask;

            if masked != 0 {
                let found_bit = masked.trailing_zeros() as u64;
                return Ok(Some(frame - bit as u64 + found_bit));
            }

            frame += remaining;
        }

        Ok(None)
    }

    /// Free a previously allocated frame.
    ///
    /// Double frees are an error, not a no-op. A silently tolerated double free
    /// means the frame can be handed to two owners simultaneously, which is
    /// arbitrary memory corruption with no diagnostic. Better to fail here,
    /// where the caller is on the stack.
    pub fn free(&mut self, addr: PhysAddr) -> Result<(), FrameError> {
        let frame = addr.frame_number();
        if !self.is_used(frame)? {
            return Err(FrameError::DoubleFree(frame));
        }
        self.set_free(frame)?;

        // Bias the next allocation toward the freed frame: it is certainly free
        // and is likely still cache-warm.
        let offset = frame - self.base_frame;
        if offset < self.next_hint {
            self.next_hint = offset;
        }
        Ok(())
    }

    pub fn free_contiguous(&mut self, addr: PhysAddr, count: u64) -> Result<(), FrameError> {
        let first = addr.frame_number();
        // Validate the whole run before mutating anything, so a partially-bad
        // range does not leave the bitmap half-freed.
        for f in first..first + count {
            if !self.is_used(f)? {
                return Err(FrameError::DoubleFree(f));
            }
        }
        for f in first..first + count {
            self.set_free(f)?;
        }
        let offset = first - self.base_frame;
        if offset < self.next_hint {
            self.next_hint = offset;
        }
        Ok(())
    }

    pub fn used_frames(&self) -> u64 {
        self.used
    }

    pub fn free_frames(&self) -> u64 {
        self.frame_count - self.used
    }

    pub fn total_frames(&self) -> u64 {
        self.frame_count
    }

    /// Longest run of free frames. Drives Game Mode's compaction decision and
    /// the memory-pressure indicator on the System Dashboard.
    pub fn largest_free_run(&self) -> u64 {
        let mut best = 0u64;
        let mut current = 0u64;

        for offset in 0..self.frame_count {
            let (word, bit) = (
                (offset / FRAMES_PER_WORD) as usize,
                offset % FRAMES_PER_WORD,
            );
            if self.bitmap[word] & (1u64 << bit) == 0 {
                current += 1;
                best = best.max(current);
            } else {
                current = 0;
            }
        }
        best
    }

    /// Fragmentation as a percentage: how far the largest free run falls short
    /// of total free memory. 0 means perfectly compact.
    pub fn fragmentation_percent(&self) -> u32 {
        let free = self.free_frames();
        if free == 0 {
            return 0;
        }
        let largest = self.largest_free_run();
        (((free - largest) * 100) / free) as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 1024 frames starting at frame 0, all free.
    fn allocator(storage: &mut Vec<u64>, frames: u64) -> FrameAllocator<'_> {
        storage.clear();
        storage.resize(FrameAllocator::words_for(frames), 0);
        let mut a = FrameAllocator::new(storage, 0, frames);
        a.add_region(Region {
            start: 0,
            len: frames * PAGE_SIZE,
        })
        .unwrap();
        a
    }

    #[test]
    fn starts_fully_allocated_before_regions_are_added() {
        let mut storage = vec![0u64; FrameAllocator::words_for(128)];
        let a = FrameAllocator::new(&mut storage, 0, 128);
        assert_eq!(a.free_frames(), 0, "must start with nothing available");
        assert_eq!(a.used_frames(), 128);
    }

    #[test]
    fn adding_a_region_makes_frames_available() {
        let mut s = Vec::new();
        let a = allocator(&mut s, 256);
        assert_eq!(a.free_frames(), 256);
    }

    #[test]
    fn alloc_and_free_round_trip() {
        let mut s = Vec::new();
        let mut a = allocator(&mut s, 64);

        let f = a.alloc().unwrap();
        assert_eq!(a.free_frames(), 63);
        assert!(a.is_used(f.frame_number()).unwrap());

        a.free(f).unwrap();
        assert_eq!(a.free_frames(), 64);
        assert!(!a.is_used(f.frame_number()).unwrap());
    }

    #[test]
    fn double_free_is_an_error_not_a_no_op() {
        let mut s = Vec::new();
        let mut a = allocator(&mut s, 64);
        let f = a.alloc().unwrap();
        a.free(f).unwrap();
        assert!(matches!(a.free(f), Err(FrameError::DoubleFree(_))));
    }

    #[test]
    fn exhaustion_reports_out_of_memory() {
        let mut s = Vec::new();
        let mut a = allocator(&mut s, 8);
        for _ in 0..8 {
            a.alloc().unwrap();
        }
        assert_eq!(a.alloc(), Err(FrameError::OutOfMemory));
        assert_eq!(a.free_frames(), 0);
    }

    #[test]
    fn every_allocated_frame_is_distinct() {
        let mut s = Vec::new();
        let mut a = allocator(&mut s, 200);

        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            let f = a.alloc().unwrap();
            assert!(
                seen.insert(f.frame_number()),
                "frame handed out twice: {f:?}"
            );
        }
    }

    #[test]
    fn allocation_does_not_escape_the_managed_range() {
        let mut s = Vec::new();
        // 100 frames: not a multiple of 64, so the last bitmap word is partial.
        // Without the bounds check in `alloc`, the tail bits of that word look
        // free and the allocator hands out frames 100..128.
        let mut a = allocator(&mut s, 100);
        for _ in 0..100 {
            let f = a.alloc().unwrap();
            assert!(f.frame_number() < 100, "escaped range: {f:?}");
        }
        assert_eq!(a.alloc(), Err(FrameError::OutOfMemory));
    }

    #[test]
    fn contiguous_allocation_returns_a_real_run() {
        let mut s = Vec::new();
        let mut a = allocator(&mut s, 512);

        let base = a.alloc_contiguous(64, 1).unwrap();
        let first = base.frame_number();
        for f in first..first + 64 {
            assert!(
                a.is_used(f).unwrap(),
                "frame {f} in the run is not marked used"
            );
        }
        assert_eq!(a.free_frames(), 512 - 64);
    }

    #[test]
    fn contiguous_allocation_respects_alignment() {
        let mut s = Vec::new();
        let mut a = allocator(&mut s, 2048);

        // Occupy frame 0 so the naive answer (frame 0) is unavailable and the
        // allocator must find the next *aligned* run, not merely the next run.
        a.alloc().unwrap();

        let base = a.alloc_contiguous(512, 512).unwrap();
        assert_eq!(
            base.frame_number() % 512,
            0,
            "run at frame {} is not 2 MiB aligned",
            base.frame_number()
        );
    }

    #[test]
    fn fragmentation_is_reported_distinctly_from_exhaustion() {
        let mut s = Vec::new();
        let mut a = allocator(&mut s, 256);

        // Free every other frame: lots of memory, no run longer than 1.
        for f in 0..256u64 {
            if f % 2 == 0 {
                let (w, b) = a.index_of(f).unwrap();
                a.bitmap[w] |= 1 << b;
                a.used += 1;
            }
        }

        let err = a.alloc_contiguous(4, 1).unwrap_err();
        match err {
            FrameError::Fragmented {
                requested,
                largest_run,
            } => {
                assert_eq!(requested, 4);
                assert!(
                    largest_run < 4,
                    "largest run {largest_run} should be under 4"
                );
            }
            other => panic!("expected Fragmented, got {other:?}"),
        }

        // Single-frame allocation still succeeds — this is fragmentation, not
        // exhaustion, and the two need different recovery.
        assert!(a.alloc().is_ok());
    }

    #[test]
    fn contiguous_run_spanning_word_boundaries_is_found() {
        let mut s = Vec::new();
        let mut a = allocator(&mut s, 256);

        // Block frames 0..70 so the only viable run starts mid-word and the
        // 128-frame run must cross two word boundaries.
        for f in 0..70u64 {
            let (w, b) = a.index_of(f).unwrap();
            a.bitmap[w] |= 1 << b;
            a.used += 1;
        }

        let base = a.alloc_contiguous(128, 1).unwrap();
        assert!(base.frame_number() >= 70);
        for f in base.frame_number()..base.frame_number() + 128 {
            assert!(a.is_used(f).unwrap());
        }
    }

    #[test]
    fn contiguous_free_restores_every_frame() {
        let mut s = Vec::new();
        let mut a = allocator(&mut s, 512);
        let before = a.free_frames();

        let base = a.alloc_contiguous(100, 1).unwrap();
        a.free_contiguous(base, 100).unwrap();

        assert_eq!(a.free_frames(), before);
    }

    #[test]
    fn partial_bad_contiguous_free_leaves_the_bitmap_untouched() {
        let mut s = Vec::new();
        let mut a = allocator(&mut s, 128);
        let base = a.alloc_contiguous(10, 1).unwrap();
        let used_before = a.used_frames();

        // Ask to free 20 frames when only 10 were allocated: frames 10..20 are
        // free, so this must fail without half-freeing the valid part.
        assert!(a.free_contiguous(base, 20).is_err());
        assert_eq!(a.used_frames(), used_before, "bitmap was partially mutated");
    }

    #[test]
    fn reservation_rounds_outward() {
        let mut s = Vec::new();
        let mut a = allocator(&mut s, 64);

        // A structure at 0x1800 of length 0x100 lives entirely inside frame 1,
        // but neither end is page-aligned. Frame 1 must be withheld.
        a.reserve_region(Region {
            start: 0x1800,
            len: 0x100,
        })
        .unwrap();
        assert!(a.is_used(1).unwrap(), "partial page was not reserved");
        assert!(!a.is_used(2).unwrap(), "over-reserved into frame 2");
    }

    #[test]
    fn reservation_spanning_a_boundary_covers_both_frames() {
        let mut s = Vec::new();
        let mut a = allocator(&mut s, 64);
        // Straddles the frame 1 / frame 2 boundary.
        a.reserve_region(Region {
            start: 0x1FF0,
            len: 0x20,
        })
        .unwrap();
        assert!(a.is_used(1).unwrap());
        assert!(a.is_used(2).unwrap());
    }

    #[test]
    fn region_frames_round_inward() {
        // Available regions round the opposite way from reservations: a usable
        // region that starts mid-page must not contribute that partial page.
        let r = Region {
            start: 0x1800,
            len: 0x3000,
        };
        let frames: Vec<u64> = r.frames().collect();
        assert_eq!(
            frames,
            vec![2, 3],
            "partial pages leaked into the free pool"
        );
    }

    #[test]
    fn zero_length_region_yields_nothing() {
        let r = Region {
            start: 0x1000,
            len: 0,
        };
        assert_eq!(r.frames().count(), 0);
    }

    #[test]
    fn out_of_range_frames_are_rejected() {
        let mut s = Vec::new();
        let a = allocator(&mut s, 64);
        assert!(matches!(a.is_used(64), Err(FrameError::OutOfRange(64))));
        assert!(a.is_used(63).is_ok());
    }

    #[test]
    fn largest_free_run_tracks_reality() {
        let mut s = Vec::new();
        let mut a = allocator(&mut s, 128);
        assert_eq!(a.largest_free_run(), 128);

        // Split the space in half.
        let (w, b) = a.index_of(64).unwrap();
        a.bitmap[w] |= 1 << b;
        a.used += 1;
        assert_eq!(a.largest_free_run(), 64);
        assert_eq!(a.fragmentation_percent(), 49); // 63 of 127 free frames outside the run
    }

    #[test]
    fn fragmentation_is_zero_when_memory_is_compact() {
        let mut s = Vec::new();
        let a = allocator(&mut s, 128);
        assert_eq!(a.fragmentation_percent(), 0);
    }

    #[test]
    fn sequential_allocation_uses_the_hint_and_stays_linear() {
        let mut s = Vec::new();
        let mut a = allocator(&mut s, 4096);

        // Without the rotating hint this is O(n^2) and the allocator rescans
        // from frame 0 every time. The observable property is that frames come
        // out in ascending order.
        let mut prev = 0u64;
        for i in 0..4096 {
            let f = a.alloc().unwrap().frame_number();
            if i > 0 {
                assert!(f > prev, "hint did not advance: {prev} then {f}");
            }
            prev = f;
        }
    }

    #[test]
    fn freeing_rewinds_the_hint_so_memory_is_reused() {
        let mut s = Vec::new();
        let mut a = allocator(&mut s, 128);

        let first = a.alloc().unwrap();
        for _ in 0..50 {
            a.alloc().unwrap();
        }
        a.free(first).unwrap();

        // The next allocation should reuse the freed frame rather than marching
        // forward and leaving a hole.
        assert_eq!(a.alloc().unwrap().frame_number(), first.frame_number());
    }

    #[test]
    fn words_for_rounds_up() {
        assert_eq!(FrameAllocator::words_for(0), 0);
        assert_eq!(FrameAllocator::words_for(1), 1);
        assert_eq!(FrameAllocator::words_for(64), 1);
        assert_eq!(FrameAllocator::words_for(65), 2);
    }
}
