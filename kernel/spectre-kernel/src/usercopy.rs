//! Validating pointers user space hands the kernel.
//!
//! # Why this is its own module with its own tests
//!
//! Every argument that arrives as a pointer is a value a process chose, and the
//! kernel is about to dereference it with full privilege. The classic
//! confused-deputy bug is not exotic: a process passes a kernel address, the
//! kernel reads it because the kernel can, and the contents come back through
//! whatever the call returns. Nothing about that looks wrong at the call site.
//!
//! The checks are small and the failure modes are all arithmetic — a length
//! that wraps the address space, a range that starts inside a mapping and ends
//! outside it, an empty region compared with `<=` instead of `<`. That is
//! exactly the shape of thing to test exhaustively on a host rather than
//! discover from a kernel that read something it should not have.
//!
//! What this module does *not* do is check that the memory is mapped. It checks
//! that the range lies inside a region the process was given. Whether the pages
//! behind it are present is the page table's business, and a fault there is a
//! fault against the process, not a privilege violation.

#![allow(dead_code)]

use crate::abi::SyscallError;

/// A contiguous range of a process's address space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserRegion {
    pub start: u64,
    pub len: u64,
}

impl UserRegion {
    #[must_use]
    pub const fn new(start: u64, len: u64) -> Self {
        Self { start, len }
    }

    /// End address, saturating. A region that would wrap is truncated here so
    /// no caller has to reason about wrapping again.
    #[must_use]
    pub const fn end(&self) -> u64 {
        self.start.saturating_add(self.len)
    }

    #[must_use]
    pub const fn contains_range(&self, start: u64, len: u64) -> bool {
        // A zero-length region contains nothing, including a zero-length range.
        if self.len == 0 {
            return false;
        }
        match start.checked_add(len) {
            // `end` may equal `self.end()`: the last byte of a region is still
            // inside it. Using `<` here would make the final byte unusable.
            Some(end) => start >= self.start && end <= self.end(),
            None => false,
        }
    }
}

/// The lowest address the kernel half of a 48-bit address space starts at.
///
/// Anything at or above this is either kernel space or non-canonical. A user
/// pointer up here is not a mistake a correct program makes.
pub const KERNEL_HALF_START: u64 = 0xFFFF_8000_0000_0000;

/// Checks a `(pointer, length)` pair a process supplied.
///
/// `regions` is what the process is allowed to reach. The order of the checks
/// is chosen so the cheapest and most decisive come first, and so that a single
/// cause always produces the same error — a caller that gets `TooLong` should
/// never have to wonder whether the pointer was also bad.
pub fn validate_user_range(
    regions: &[UserRegion],
    ptr: u64,
    len: u64,
    limit: u64,
) -> Result<(), SyscallError> {
    if len > limit {
        return Err(SyscallError::TooLong);
    }
    // A zero-length read is not an error, but it is also not something to
    // validate a pointer for; refusing it keeps every later step working on a
    // non-empty range.
    if len == 0 {
        return Err(SyscallError::BadArgument);
    }
    let Some(end) = ptr.checked_add(len) else {
        return Err(SyscallError::BadPointer);
    };
    if ptr >= KERNEL_HALF_START || end > KERNEL_HALF_START {
        return Err(SyscallError::BadPointer);
    }
    if regions.iter().any(|r| r.contains_range(ptr, len)) {
        Ok(())
    } else {
        Err(SyscallError::BadPointer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IMAGE: UserRegion = UserRegion::new(0x1000_0000_0000, 0x4000);
    const STACK: UserRegion = UserRegion::new(0x1000_1000_0000, 0x4000);
    const LIMIT: u64 = 256;

    fn regions() -> [UserRegion; 2] {
        [IMAGE, STACK]
    }

    fn check(ptr: u64, len: u64) -> Result<(), SyscallError> {
        validate_user_range(&regions(), ptr, len, LIMIT)
    }

    #[test]
    fn a_range_inside_a_region_is_accepted() {
        assert_eq!(check(IMAGE.start, 16), Ok(()));
        assert_eq!(check(IMAGE.start + 0x100, 64), Ok(()));
        assert_eq!(check(STACK.start, 1), Ok(()));
    }

    #[test]
    fn the_last_byte_of_a_region_is_usable() {
        // An off-by-one here silently makes the final byte of every mapping
        // unreadable, which shows up as a mysterious failure on buffers that
        // happen to end at a page boundary.
        assert_eq!(check(IMAGE.end() - 1, 1), Ok(()));
        assert_eq!(check(IMAGE.end() - 16, 16), Ok(()));
    }

    #[test]
    fn a_range_running_one_byte_past_a_region_is_refused() {
        assert_eq!(check(IMAGE.end() - 15, 16), Err(SyscallError::BadPointer));
        assert_eq!(check(IMAGE.end(), 1), Err(SyscallError::BadPointer));
    }

    #[test]
    fn a_range_starting_before_a_region_is_refused() {
        assert_eq!(check(IMAGE.start - 1, 8), Err(SyscallError::BadPointer));
    }

    #[test]
    fn a_range_spanning_the_gap_between_two_regions_is_refused() {
        // Both endpoints are inside *a* region, but the memory between them is
        // not mapped to this process. Checking endpoints instead of containment
        // is the classic way to get this wrong.
        let span = STACK.start - IMAGE.start;
        assert_eq!(
            validate_user_range(&regions(), IMAGE.start, span + 8, u64::MAX),
            Err(SyscallError::BadPointer)
        );
    }

    #[test]
    fn a_kernel_pointer_is_refused() {
        // The confused-deputy case this module exists for.
        assert_eq!(check(KERNEL_HALF_START, 8), Err(SyscallError::BadPointer));
        assert_eq!(
            check(0xFFFF_FFFF_8000_0000, 8),
            Err(SyscallError::BadPointer)
        );
    }

    #[test]
    fn a_range_that_wraps_the_address_space_is_refused() {
        // `ptr + len` overflowing would otherwise produce a tiny `end` that
        // compares as being inside a low region.
        assert_eq!(
            validate_user_range(&regions(), u64::MAX - 4, 64, u64::MAX),
            Err(SyscallError::BadPointer)
        );
    }

    #[test]
    fn a_range_reaching_from_user_space_into_the_kernel_half_is_refused() {
        assert_eq!(
            validate_user_range(&regions(), KERNEL_HALF_START - 4, 64, u64::MAX),
            Err(SyscallError::BadPointer)
        );
    }

    #[test]
    fn a_length_over_the_limit_is_refused_before_the_pointer_is_examined() {
        // The limit exists so a user-chosen length cannot decide how much
        // kernel stack a call consumes, so it has to be checked first — even
        // for a pointer that is otherwise perfectly valid.
        assert_eq!(check(IMAGE.start, LIMIT + 1), Err(SyscallError::TooLong));
        assert_eq!(check(IMAGE.start, u64::MAX), Err(SyscallError::TooLong));
    }

    #[test]
    fn a_zero_length_range_is_rejected_as_a_bad_argument() {
        assert_eq!(check(IMAGE.start, 0), Err(SyscallError::BadArgument));
    }

    #[test]
    fn an_empty_region_contains_nothing() {
        // A process with no mappings must not be able to read address zero
        // because zero-length arithmetic happened to line up.
        let empty = [UserRegion::new(0x1000, 0)];
        assert_eq!(
            validate_user_range(&empty, 0x1000, 1, LIMIT),
            Err(SyscallError::BadPointer)
        );
        assert!(!UserRegion::new(0x1000, 0).contains_range(0x1000, 0));
    }

    #[test]
    fn a_process_with_no_regions_can_reach_nothing() {
        assert_eq!(
            validate_user_range(&[], IMAGE.start, 8, LIMIT),
            Err(SyscallError::BadPointer)
        );
    }

    #[test]
    fn a_region_whose_own_extent_would_wrap_does_not_admit_the_whole_space() {
        // `end()` saturates rather than wrapping, so a malformed region is
        // bounded rather than becoming a pass for every address.
        let huge = [UserRegion::new(u64::MAX - 8, 64)];
        assert_eq!(huge[0].end(), u64::MAX);
        assert_eq!(
            validate_user_range(&huge, 0x1000, 8, LIMIT),
            Err(SyscallError::BadPointer)
        );
    }
}
