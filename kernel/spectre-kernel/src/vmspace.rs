//! Tearing an address space down and getting the memory back.
//!
//! # Why this is generic and tested rather than written into the scheduler
//!
//! Destroying an address space is a walk that frees things, and the two ways to
//! get it wrong are both silent.
//!
//! Free too little and the system leaks: a process exits, its frames stay
//! marked used, and after enough process churn there is no memory left. Nothing
//! reports it, because leaked memory looks exactly like memory in use.
//!
//! Free too much is worse and quieter still. The top-level table of every user
//! address space contains an entry that is *not* the process's — the kernel's
//! own identity map, shared into every space so a system call can land on
//! kernel code without a trampoline. A walk that treats that entry like the
//! rest hands the kernel's page tables to the frame allocator, which then
//! issues them to the next process, which writes over them. The fault that
//! follows is somewhere else entirely, minutes later, with no connection to the
//! process that exited.
//!
//! So the walk is a free function over `TableAccess` with the shared entries
//! passed in explicitly, and the host tests check both directions: every frame
//! the space owned comes back exactly once, and nothing under a shared entry is
//! touched at all.

#![allow(dead_code)]

use crate::arch::addr::{PagingMode, PhysAddr};
use crate::arch::paging::{PageError, TableAccess};

/// Where reclaimed frames go.
///
/// A trait rather than a direct call into the frame allocator so the walk can
/// be driven by a test that records what it was handed, which is the only way
/// to check "exactly once" rather than "at least once".
///
/// It is bounded together with `TableAccess` on the walk below rather than
/// passed separately, because in the kernel both are the same object: reading a
/// table and freeing a frame both go through the identity-mapped view that owns
/// the frame allocator. Two `&mut` to one allocator is not a thing that can be
/// arranged.
pub trait FrameSink {
    fn release(&mut self, frame: PhysAddr);
}

/// What a teardown recovered.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Reclaimed {
    /// Frames that held process data or code.
    pub leaf_frames: u64,
    /// Frames that held page tables, including the top-level table itself.
    pub table_frames: u64,
}

impl Reclaimed {
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.leaf_frames + self.table_frames
    }
}

/// Frees every frame an address space owns, leaving the shared entries alone.
///
/// `shared` names top-level indices whose subtrees belong to someone else. They
/// are skipped entirely: not walked, not freed, not cleared — the table holding
/// the entry is itself about to be freed, so clearing it would be writing to a
/// page on its way back to the allocator.
///
/// The root is freed last. Freeing it first would mean walking a table the
/// allocator is already entitled to hand out.
pub fn destroy<A: TableAccess + FrameSink>(
    access: &mut A,
    root: PhysAddr,
    shared: &[u16],
    mode: PagingMode,
) -> Result<Reclaimed, PageError> {
    let mut out = Reclaimed::default();
    let top = mode.levels();

    for index in 0..entries_per_table(mode) {
        if shared.contains(&index) {
            continue;
        }
        let Some(entry) = access.read_entry(root, index) else {
            continue;
        };
        if !entry.is_present() {
            continue;
        }
        if entry.is_leaf(top)? {
            // A leaf at the top level would be a 512 GiB page, which nothing
            // here maps. Treat it as data rather than as a table, because
            // walking it would read process memory as page-table entries.
            access.release(entry.frame());
            out.leaf_frames += 1;
            continue;
        }
        free_subtree(access, entry.frame(), top - 1, &mut out)?;
        access.release(entry.frame());
        out.table_frames += 1;
    }

    access.release(root);
    out.table_frames += 1;
    Ok(out)
}

/// Frees everything under `table`, but not `table` itself.
///
/// Recursion depth is bounded by the paging mode — four levels, or five with
/// `LA57` — so it is a handful of stack frames rather than something that needs
/// an explicit stack.
fn free_subtree<A: TableAccess + FrameSink>(
    access: &mut A,
    table: PhysAddr,
    level: usize,
    out: &mut Reclaimed,
) -> Result<(), PageError> {
    for index in 0..512u16 {
        let Some(entry) = access.read_entry(table, index) else {
            continue;
        };
        if !entry.is_present() {
            continue;
        }

        // Level 1 entries are always leaves; above that, the huge-page bit
        // decides. Asking `is_leaf` at level 1 is what reports a huge bit set
        // where it cannot be, which is corruption rather than a large page.
        if level == 1 || entry.is_leaf(level)? {
            access.release(entry.frame());
            out.leaf_frames += 1;
            continue;
        }

        free_subtree(access, entry.frame(), level - 1, out)?;
        access.release(entry.frame());
        out.table_frames += 1;
    }
    Ok(())
}

const fn entries_per_table(_mode: PagingMode) -> u16 {
    512
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::addr::VirtAddr;
    use crate::arch::paging::{map_page, Entry, PageFlags, PageSize, PageTable};
    use std::collections::{HashMap, HashSet};

    /// A page-table world backed by a map, with a frame allocator that hands out
    /// addresses in order and records what comes back.
    struct World {
        tables: HashMap<u64, PageTable>,
        next: u64,
        handed_out: HashSet<u64>,
        /// Every release, in order, so a double free is visible rather than
        /// merged into the set.
        released: Vec<u64>,
    }

    impl World {
        fn new() -> Self {
            Self {
                tables: HashMap::new(),
                next: 0x1000,
                handed_out: HashSet::new(),
                released: Vec::new(),
            }
        }

        fn alloc(&mut self) -> PhysAddr {
            let addr = self.next;
            self.next += 0x1000;
            self.tables.insert(addr, PageTable::new());
            self.handed_out.insert(addr);
            PhysAddr::new(addr).unwrap()
        }

        fn released_set(&self) -> HashSet<u64> {
            self.released.iter().copied().collect()
        }

        fn has_duplicates(&self) -> bool {
            self.released_set().len() != self.released.len()
        }
    }

    impl TableAccess for World {
        fn read_entry(&self, table: PhysAddr, index: u16) -> Option<Entry> {
            self.tables.get(&table.as_u64())?.get(index)
        }

        fn write_entry(
            &mut self,
            table: PhysAddr,
            index: u16,
            entry: Entry,
        ) -> Result<(), PageError> {
            self.tables
                .get_mut(&table.as_u64())
                .ok_or(PageError::NotMapped)?
                .set(index, entry)
        }

        fn alloc_table(&mut self) -> Option<PhysAddr> {
            Some(self.alloc())
        }
    }

    impl FrameSink for World {
        fn release(&mut self, frame: PhysAddr) {
            self.released.push(frame.as_u64());
        }
    }

    const MODE: PagingMode = PagingMode::Level4;

    fn user_rw() -> PageFlags {
        PageFlags::PRESENT | PageFlags::USER | PageFlags::WRITABLE | PageFlags::NO_EXECUTE
    }

    fn virt(addr: u64) -> VirtAddr {
        VirtAddr::from_indices_sign_extended(addr, MODE)
    }

    /// Builds a space with `count` pages mapped from `base`, returning the root.
    fn build(world: &mut World, base: u64, count: u64) -> PhysAddr {
        let root = world.alloc();
        for i in 0..count {
            let frame = world.alloc();
            map_page(
                world,
                root,
                virt(base + i * 0x1000),
                frame,
                user_rw(),
                PageSize::Small,
                MODE,
            )
            .unwrap();
        }
        root
    }

    #[test]
    fn every_frame_the_space_owned_comes_back_exactly_once() {
        let mut world = World::new();
        let root = build(&mut world, 0x1000_0000_0000, 8);
        let expected = world.handed_out.clone();

        let reclaimed = destroy(&mut world, root, &[], MODE).unwrap();

        assert!(!world.has_duplicates(), "a frame was released twice");
        assert_eq!(world.released_set(), expected, "leaked or invented a frame");
        assert_eq!(reclaimed.leaf_frames, 8);
        // Root plus one table per level below it: PDPT, PD, PT.
        assert_eq!(reclaimed.table_frames, 4);
        assert_eq!(reclaimed.total() as usize, expected.len());
    }

    #[test]
    fn a_shared_top_level_entry_is_left_completely_alone() {
        // The failure this exists for: the kernel's identity map is shared into
        // every address space, and freeing it hands the kernel's own page
        // tables to the allocator.
        let mut world = World::new();

        let kernel_root = build(&mut world, 0x20_0000, 4);
        let kernel_frames = world.handed_out.clone();
        let shared_entry = world.read_entry(kernel_root, 0).unwrap();

        let user_root = build(&mut world, 0x1000_0000_0000, 4);
        world.write_entry(user_root, 0, shared_entry).unwrap();

        destroy(&mut world, user_root, &[0], MODE).unwrap();

        for frame in &kernel_frames {
            assert!(
                !world.released_set().contains(frame),
                "released kernel frame {frame:#x}"
            );
        }
        // And the kernel's mapping still resolves afterwards.
        assert!(crate::arch::paging::translate(&world, kernel_root, virt(0x20_0000), MODE).is_ok());
    }

    #[test]
    fn without_the_shared_list_the_kernel_subtree_would_be_freed() {
        // The mirror of the test above, asserting that the protection comes
        // from the argument rather than from something else in the walk.
        let mut world = World::new();
        let kernel_root = build(&mut world, 0x20_0000, 2);
        let shared_entry = world.read_entry(kernel_root, 0).unwrap();

        let user_root = build(&mut world, 0x1000_0000_0000, 2);
        world.write_entry(user_root, 0, shared_entry).unwrap();

        destroy(&mut world, user_root, &[], MODE).unwrap();
        assert!(
            world
                .released_set()
                .contains(&shared_entry.frame().as_u64()),
            "expected the unprotected walk to free the shared subtree"
        );
    }

    #[test]
    fn an_empty_space_gives_back_just_its_root() {
        let mut world = World::new();
        let root = world.alloc();
        let reclaimed = destroy(&mut world, root, &[], MODE).unwrap();
        assert_eq!(reclaimed.leaf_frames, 0);
        assert_eq!(reclaimed.table_frames, 1);
        assert_eq!(world.released, vec![root.as_u64()]);
    }

    #[test]
    fn two_regions_far_apart_are_both_reclaimed() {
        // Separate top-level entries, which is the case a walk that stops at the
        // first populated index would get wrong.
        let mut world = World::new();
        let root = world.alloc();
        for base in [0x1000_0000_0000u64, 0x4000_0000_0000] {
            for i in 0..3 {
                let frame = world.alloc();
                map_page(
                    &mut world,
                    root,
                    virt(base + i * 0x1000),
                    frame,
                    user_rw(),
                    PageSize::Small,
                    MODE,
                )
                .unwrap();
            }
        }
        let expected = world.handed_out.clone();

        let reclaimed = destroy(&mut world, root, &[], MODE).unwrap();
        assert_eq!(reclaimed.leaf_frames, 6);
        assert_eq!(world.released_set(), expected);
        assert!(!world.has_duplicates());
    }

    #[test]
    fn large_pages_are_freed_as_data_not_walked_as_tables() {
        // Walking a 2 MiB page would read process memory as page-table entries
        // and hand whatever it found there to the allocator.
        let mut world = World::new();
        let root = world.alloc();
        let frame = PhysAddr::new(0x40_0000).unwrap();
        map_page(
            &mut world,
            root,
            virt(0x1000_0020_0000),
            frame,
            user_rw(),
            PageSize::Large,
            MODE,
        )
        .unwrap();

        let reclaimed = destroy(&mut world, root, &[], MODE).unwrap();
        assert_eq!(reclaimed.leaf_frames, 1);
        assert!(world.released_set().contains(&frame.as_u64()));
    }

    #[test]
    fn tearing_down_twice_would_double_free_and_the_recorder_proves_it() {
        // Not a supported operation — it is here to show the recorder can tell
        // the difference, so the "exactly once" assertions above mean something.
        let mut world = World::new();
        let root = build(&mut world, 0x1000_0000_0000, 2);

        destroy(&mut world, root, &[], MODE).unwrap();
        destroy(&mut world, root, &[], MODE).unwrap();
        assert!(world.has_duplicates());
    }
}
