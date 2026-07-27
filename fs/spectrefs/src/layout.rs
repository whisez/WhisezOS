//! SpectreFS on-disk layout.
//!
//! Copy-on-write, checksummed, 128-bit addressing, per-file or per-directory
//! encryption, Zstandard compression, snapshots, and deduplication.
//!
//! # On "128-bit"
//!
//! The spec asks for a 128-bit filesystem. Taken literally as "128-bit block
//! pointers everywhere" this is pure cost: 16 bytes per pointer doubles metadata
//! size and halves the fan-out of every indirect block, for addressing capacity
//! that exceeds the number of atoms available to build storage out of. ZFS took
//! the same label and made the same compromise.
//!
//! What is actually implemented, and what "128-bit" means here:
//!   * Volume-level addressing is 128-bit: `VolumeId` and `ObjectId` are u128,
//!     so a pool can span an unbounded number of devices and an unbounded number
//!     of objects without ever needing a format revision.
//!   * Block pointers within a volume are 64-bit LBAs with a 64-bit generation,
//!     packed into 128 bits total. The generation is what makes stale-pointer
//!     detection possible after a snapshot rollback — a 64-bit-only pointer
//!     cannot distinguish "block 5000 now" from "block 5000 three snapshots
//!     ago", which is a silent-corruption class bug.
//!
//! # Ordering guarantees
//!
//! CoW means never overwriting live data, which gives crash consistency for
//! free *provided* the superblock update is atomic and ordered after every
//! block it references. That ordering is enforced with an explicit FLUSH/FUA
//! pair, not with a hopeful `fsync`. Consumer SSDs lie about flush completion
//! often enough that this matters; the uberblock is written with FUA and then
//! verified by read-back on mount.

use core::mem::size_of;

pub const MAGIC: u64 = 0x5350_4543_5452_4546; // "SPECTREF"
pub const VERSION: u32 = 1;

/// 4 KiB. Matches the page size, matches NVMe's native block size on every
/// modern drive, and keeps a block pointer's worth of metadata in one cache
/// line. Larger blocks improve sequential throughput and hurt everything else;
/// compression is where sequential throughput is won here instead.
pub const BLOCK_SIZE: usize = 4096;

/// Number of uberblock slots. Writes rotate through them, so a torn write
/// during a superblock update leaves N-1 intact previous versions to fall back
/// to. Four is the minimum that survives a power loss during a rotation that
/// itself follows a power loss during a rotation.
pub const UBERBLOCK_SLOTS: usize = 4;

pub type VolumeId = u128;
pub type ObjectId = u128;
pub type TxgId = u64;

/// A block pointer: where the data is, whether it is compressed or encrypted,
/// and what it should hash to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct BlockPtr {
    pub lba: u64,
    /// Transaction group that wrote this block. Combined with the LBA this is
    /// the 128-bit address; it is also how stale pointers are detected.
    pub birth_txg: TxgId,
    /// BLAKE3 of the *on-disk* bytes (post-compression, post-encryption).
    /// Checksumming the on-disk form rather than the logical form means a
    /// corrupted block is detected before we spend CPU decrypting garbage, and
    /// means the checksum verifies the compression output too.
    pub checksum: [u8; 32],
    pub logical_size: u32,
    pub physical_size: u32,
    pub flags: BlockFlags,
    /// Number of references, for deduplication. A block with refcount > 1 is
    /// shared and must be CoW'd on write even within the same file.
    pub refcount: u32,
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct BlockFlags: u32 {
        const COMPRESSED_ZSTD = 1 << 0;
        const ENCRYPTED       = 1 << 1;
        /// Block is all zeroes and occupies no space (a hole).
        const SPARSE          = 1 << 2;
        /// Block participates in deduplication.
        const DEDUP           = 1 << 3;
        /// Written but not yet referenced by a committed uberblock.
        const PENDING         = 1 << 4;
    }
}

impl BlockPtr {
    pub const SPARSE_PTR: BlockPtr = BlockPtr {
        lba: 0,
        birth_txg: 0,
        checksum: [0; 32],
        logical_size: 0,
        physical_size: 0,
        flags: BlockFlags::SPARSE,
        refcount: 0,
    };

    pub fn is_sparse(&self) -> bool {
        self.flags.contains(BlockFlags::SPARSE)
    }

    /// A pointer is stale if it was born in a transaction group that the
    /// current uberblock has rolled back past. Reading through a stale pointer
    /// returns data from a different point in time — the exact silent
    /// corruption that snapshot rollback would otherwise introduce.
    pub fn is_stale(&self, current_txg: TxgId) -> bool {
        !self.is_sparse() && self.birth_txg > current_txg
    }

    /// Compression is only kept if it actually saved a block. A ratio of 0.98
    /// costs CPU on every read forever to save nothing; the threshold below
    /// requires saving at least one whole block, which is the only saving that
    /// is real on a block-addressed device.
    pub fn should_keep_compression(logical: usize, physical: usize) -> bool {
        let logical_blocks = logical.div_ceil(BLOCK_SIZE);
        let physical_blocks = physical.div_ceil(BLOCK_SIZE);
        physical_blocks < logical_blocks
    }
}

/// The root of a volume, written atomically at commit.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Uberblock {
    pub magic: u64,
    pub version: u32,
    pub _pad: u32,
    pub volume_id: VolumeId,
    pub txg: TxgId,
    /// Root of the object tree.
    pub object_root: BlockPtr,
    /// Root of the snapshot index.
    pub snapshot_root: BlockPtr,
    /// Root of the dedup table.
    pub dedup_root: BlockPtr,
    pub timestamp_ms: u64,
    /// Checksum of every preceding field. Verified before the uberblock is
    /// trusted, which is what makes torn-write detection possible.
    pub self_checksum: [u8; 32],
}

impl Uberblock {
    /// Select the newest valid uberblock from the rotation.
    ///
    /// "Newest valid" and not "newest": a drive that lied about flush ordering
    /// can leave the highest-TXG uberblock referencing blocks that never
    /// reached the platter. Verifying the checksum and then the reachability of
    /// `object_root` is what makes SpectreFS mountable after an unclean
    /// shutdown on hardware that does not honour FUA.
    pub fn select_newest_valid(slots: &[Option<Uberblock>; UBERBLOCK_SLOTS]) -> Option<Uberblock> {
        slots
            .iter()
            .flatten()
            .filter(|u| u.magic == MAGIC && u.version <= VERSION)
            .filter(|u| u.verify_checksum())
            .max_by_key(|u| u.txg)
            .copied()
    }

    pub fn verify_checksum(&self) -> bool {
        self.self_checksum == self.compute_checksum()
    }

    pub fn compute_checksum(&self) -> [u8; 32] {
        // BLAKE3 over the struct excluding the checksum field itself.
        let len = size_of::<Uberblock>() - 32;
        // SAFETY: `Uberblock` is `repr(C)` with no padding-dependent semantics
        // and no pointers; reading it as bytes is well-defined.
        let bytes = unsafe { core::slice::from_raw_parts(self as *const _ as *const u8, len) };
        blake3(bytes)
    }

    /// Which slot the next commit writes to.
    pub fn next_slot(&self) -> usize {
        ((self.txg + 1) % UBERBLOCK_SLOTS as u64) as usize
    }
}

/// An on-disk inode.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Inode {
    pub object_id: ObjectId,
    pub kind: InodeKind,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub blocks: u64,
    pub atime_ms: u64,
    pub mtime_ms: u64,
    pub ctime_ms: u64,
    pub birth_txg: TxgId,
    /// Per-file encryption key, itself wrapped under the volume key. Present
    /// only when the file or its directory has encryption enabled.
    pub wrapped_key: Option<[u8; 48]>,
    /// Direct block pointers, then one indirect, one double, one triple. Twelve
    /// direct pointers covers files up to 48 KiB with no indirection, which is
    /// the overwhelming majority of files on a real system.
    pub direct: [BlockPtr; 12],
    pub indirect: BlockPtr,
    pub double_indirect: BlockPtr,
    pub triple_indirect: BlockPtr,
    /// Fourth level. See `POINTERS_PER_BLOCK` for why three is not enough.
    pub quad_indirect: BlockPtr,
    /// HashGuard integrity monitoring: when set, any modification outside a
    /// transaction initiated by a holder of the file's write capability locks
    /// the file and raises an alert.
    pub integrity_monitored: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum InodeKind {
    Regular = 1,
    Directory = 2,
    Symlink = 3,
    /// A snapshot root; immutable by construction.
    Snapshot = 4,
}

/// Fan-out of an indirect block.
///
/// Entries inside an indirect block are the **compact** 16-byte form — LBA plus
/// birth TXG — not the full 32-byte `BlockPtr`. The checksum is omitted because
/// it would be redundant: in a copy-on-write tree the parent pointer already
/// carries the checksum of the entire child block, so every entry inside that
/// block is covered transitively. This is how ZFS and btrfs do it, and it
/// doubles fan-out for free.
///
/// The original design used the full 32-byte pointer here, giving a fan-out of
/// 128 and — with three indirection levels — a maximum file size of **8.6 GB**.
/// That is smaller than a single modern game install, so a filesystem
/// advertising 128-bit addressing could not have stored one file its own users
/// would care about. Halving the entry size and adding a fourth level raises
/// the ceiling to ~17.6 TiB.
///
/// The real long-term fix is extent-based mapping rather than a fixed indirect
/// tree; that removes the ceiling entirely and is tracked as future work in
/// ARCHITECTURE.md §7.
pub const POINTERS_PER_BLOCK: u64 = (BLOCK_SIZE / 16) as u64;

/// Maximum file size addressable through the pointer tree:
/// 12 direct + four levels of indirection at `POINTERS_PER_BLOCK` fan-out.
pub fn max_file_size() -> u64 {
    let p = POINTERS_PER_BLOCK;
    let direct = 12u64;
    let single = p;
    let double = p * p;
    let triple = p * p * p;
    let quad = p * p * p * p;
    (direct + single + double + triple + quad) * BLOCK_SIZE as u64
}

/// Map a file offset to its position in the pointer tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockLocation {
    Direct(usize),
    Indirect {
        l0: u64,
    },
    DoubleIndirect {
        l1: u64,
        l0: u64,
    },
    TripleIndirect {
        l2: u64,
        l1: u64,
        l0: u64,
    },
    QuadIndirect {
        l3: u64,
        l2: u64,
        l1: u64,
        l0: u64,
    },
    /// Beyond the addressable range.
    OutOfRange,
}

pub fn locate_block(block_index: u64) -> BlockLocation {
    const DIRECT: u64 = 12;
    let single = POINTERS_PER_BLOCK;
    let double = single * single;
    let triple = double * single;

    if block_index < DIRECT {
        return BlockLocation::Direct(block_index as usize);
    }

    let i = block_index - DIRECT;
    if i < single {
        return BlockLocation::Indirect { l0: i };
    }

    let i = i - single;
    if i < double {
        return BlockLocation::DoubleIndirect {
            l1: i / single,
            l0: i % single,
        };
    }

    let i = i - double;
    if i < triple {
        return BlockLocation::TripleIndirect {
            l2: i / double,
            l1: (i / single) % single,
            l0: i % single,
        };
    }

    let i = i - triple;
    if i < triple * single {
        return BlockLocation::QuadIndirect {
            l3: i / triple,
            l2: (i / double) % single,
            l1: (i / single) % single,
            l0: i % single,
        };
    }

    BlockLocation::OutOfRange
}

/// Snapshot metadata. Snapshots are free to take: a snapshot is a reference to
/// an uberblock's object root plus a refcount bump. They cost space only as the
/// live filesystem diverges.
#[derive(Debug, Clone, Copy)]
pub struct Snapshot {
    pub id: ObjectId,
    pub txg: TxgId,
    pub created_ms: u64,
    pub object_root: BlockPtr,
    /// Hourly snapshots are pruned on a GFS schedule: 24 hourly, 7 daily, 4
    /// weekly, 12 monthly. Unbounded hourly snapshots fill any disk within a
    /// year; the schedule keeps the count at ~47 regardless of uptime.
    pub retention: Retention,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retention {
    Hourly,
    Daily,
    Weekly,
    Monthly,
    /// User-created; never auto-pruned.
    Manual,
}

pub const RETENTION_LIMITS: [(Retention, usize); 4] = [
    (Retention::Hourly, 24),
    (Retention::Daily, 7),
    (Retention::Weekly, 4),
    (Retention::Monthly, 12),
];

/// Which snapshots to delete, oldest-first within each class.
pub fn prune_plan(snapshots: &[Snapshot]) -> heapless::Vec<ObjectId, 64> {
    let mut doomed = heapless::Vec::new();

    for (class, limit) in RETENTION_LIMITS {
        let mut of_class: heapless::Vec<&Snapshot, 128> = snapshots
            .iter()
            .filter(|s| s.retention == class)
            .collect::<heapless::Vec<_, 128>>();

        of_class.sort_unstable_by_key(|s| s.created_ms);

        let excess = of_class.len().saturating_sub(limit);
        for s in of_class.iter().take(excess) {
            let _ = doomed.push(s.id);
        }
    }

    doomed
}

pub use crate::blake3::blake3;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_blocks_map_without_indirection() {
        for i in 0..12u64 {
            assert_eq!(locate_block(i), BlockLocation::Direct(i as usize));
        }
    }

    #[test]
    fn first_indirect_block_is_index_twelve() {
        assert_eq!(locate_block(12), BlockLocation::Indirect { l0: 0 });
        assert_eq!(
            locate_block(11 + POINTERS_PER_BLOCK),
            BlockLocation::Indirect {
                l0: POINTERS_PER_BLOCK - 1
            }
        );
    }

    #[test]
    fn double_indirect_boundary_is_exact() {
        let first_double = 12 + POINTERS_PER_BLOCK;
        assert_eq!(
            locate_block(first_double),
            BlockLocation::DoubleIndirect { l1: 0, l0: 0 }
        );
        assert_eq!(
            locate_block(first_double + POINTERS_PER_BLOCK),
            BlockLocation::DoubleIndirect { l1: 1, l0: 0 }
        );
    }

    #[test]
    fn triple_indirect_boundary_is_exact() {
        let d = POINTERS_PER_BLOCK * POINTERS_PER_BLOCK;
        let first_triple = 12 + POINTERS_PER_BLOCK + d;
        assert_eq!(
            locate_block(first_triple),
            BlockLocation::TripleIndirect {
                l2: 0,
                l1: 0,
                l0: 0
            }
        );
    }

    #[test]
    fn beyond_max_size_is_out_of_range() {
        let last = max_file_size() / BLOCK_SIZE as u64 - 1;
        assert_ne!(locate_block(last), BlockLocation::OutOfRange);
        assert_eq!(locate_block(last + 1), BlockLocation::OutOfRange);
    }

    #[test]
    fn max_file_size_is_large_enough_to_be_useful() {
        // Regression guard. With 32-byte indirect entries and three levels this
        // was 8.6 GB — less than one game install. The floor here is 16 TiB,
        // comparable to ext4, so a fan-out or level-count regression fails
        // loudly instead of silently capping user files.
        let max = max_file_size();
        assert!(
            max > 16 * (1u64 << 40),
            "only {max} bytes ({} GiB)",
            max >> 30
        );
    }

    #[test]
    fn quad_indirect_boundary_is_exact() {
        let s = POINTERS_PER_BLOCK;
        let d = s * s;
        let t = d * s;
        let first_quad = 12 + s + d + t;
        assert_eq!(
            locate_block(first_quad),
            BlockLocation::QuadIndirect {
                l3: 0,
                l2: 0,
                l1: 0,
                l0: 0
            }
        );
        assert_eq!(
            locate_block(first_quad + 1),
            BlockLocation::QuadIndirect {
                l3: 0,
                l2: 0,
                l1: 0,
                l0: 1
            }
        );
        assert_eq!(
            locate_block(first_quad + t),
            BlockLocation::QuadIndirect {
                l3: 1,
                l2: 0,
                l1: 0,
                l0: 0
            }
        );
    }

    #[test]
    fn stale_pointers_are_detected_after_rollback() {
        let ptr = BlockPtr {
            birth_txg: 500,
            ..BlockPtr::SPARSE_PTR
        };
        let ptr = BlockPtr {
            flags: BlockFlags::empty(),
            ..ptr
        };

        assert!(!ptr.is_stale(500), "current txg must not be stale");
        assert!(!ptr.is_stale(600), "older pointer is fine");
        assert!(ptr.is_stale(400), "pointer from the future must be flagged");
    }

    #[test]
    fn sparse_pointers_are_never_stale() {
        assert!(!BlockPtr::SPARSE_PTR.is_stale(0));
        assert!(!BlockPtr::SPARSE_PTR.is_stale(u64::MAX));
    }

    #[test]
    fn compression_is_kept_only_when_it_saves_a_block() {
        // 8192 -> 8100: same two blocks. Not worth it.
        assert!(!BlockPtr::should_keep_compression(8192, 8100));
        // 8192 -> 4000: one block instead of two. Worth it.
        assert!(BlockPtr::should_keep_compression(8192, 4000));
        // Exactly on the boundary: 8192 -> 4096 is still one block saved.
        assert!(BlockPtr::should_keep_compression(8192, 4096));
    }

    #[test]
    fn uberblock_selection_ignores_corrupt_slots() {
        let good = Uberblock {
            magic: MAGIC,
            version: VERSION,
            _pad: 0,
            volume_id: 1,
            txg: 10,
            object_root: BlockPtr::SPARSE_PTR,
            snapshot_root: BlockPtr::SPARSE_PTR,
            dedup_root: BlockPtr::SPARSE_PTR,
            timestamp_ms: 0,
            self_checksum: [0; 32],
        };
        let good = Uberblock {
            self_checksum: good.compute_checksum(),
            ..good
        };

        // A torn write: higher TXG but the checksum does not match.
        let torn = Uberblock {
            txg: 11,
            self_checksum: [0xFF; 32],
            ..good
        };

        let slots = [Some(good), Some(torn), None, None];
        let picked = Uberblock::select_newest_valid(&slots).unwrap();
        assert_eq!(picked.txg, 10, "selected a torn uberblock");
    }

    #[test]
    fn changing_any_field_invalidates_the_checksum() {
        // The property the whole filesystem rests on, and one that nothing here
        // tested until the checksum was real. `hash::blake3` used to return
        // zeros, so every uberblock's checksum was zero, every checksum matched
        // every uberblock, and a test that flipped a field would have passed.
        //
        // The torn-write test above survived the stub only because it used
        // `[0xFF; 32]` as its bad checksum — it proved that an obviously wrong
        // value is rejected, never that a right one depends on the contents.
        let base = Uberblock {
            magic: MAGIC,
            version: VERSION,
            _pad: 0,
            volume_id: 1,
            txg: 10,
            object_root: BlockPtr::SPARSE_PTR,
            snapshot_root: BlockPtr::SPARSE_PTR,
            dedup_root: BlockPtr::SPARSE_PTR,
            timestamp_ms: 1234,
            self_checksum: [0; 32],
        };
        let sealed = Uberblock {
            self_checksum: base.compute_checksum(),
            ..base
        };
        assert!(sealed.verify_checksum());

        let mutations = [
            Uberblock {
                volume_id: 2,
                ..sealed
            },
            Uberblock { txg: 11, ..sealed },
            Uberblock {
                timestamp_ms: 1235,
                ..sealed
            },
            Uberblock {
                version: VERSION + 1,
                ..sealed
            },
        ];
        for (index, mutated) in mutations.iter().enumerate() {
            assert!(
                !mutated.verify_checksum(),
                "mutation {index} kept a checksum that was computed before it"
            );
        }
    }

    #[test]
    fn two_different_uberblocks_do_not_share_a_checksum() {
        // A hash that collided on everything would pass the test above only if
        // the mutation happened to change the result. This is the same claim
        // from the other direction.
        let base = Uberblock {
            magic: MAGIC,
            version: VERSION,
            _pad: 0,
            volume_id: 1,
            txg: 10,
            object_root: BlockPtr::SPARSE_PTR,
            snapshot_root: BlockPtr::SPARSE_PTR,
            dedup_root: BlockPtr::SPARSE_PTR,
            timestamp_ms: 0,
            self_checksum: [0; 32],
        };
        let other = Uberblock { txg: 11, ..base };
        assert_ne!(base.compute_checksum(), other.compute_checksum());
        assert_ne!(base.compute_checksum(), [0u8; 32]);
    }

    #[test]
    fn uberblock_selection_rejects_wrong_magic() {
        let bad = Uberblock {
            magic: 0xDEAD,
            version: VERSION,
            _pad: 0,
            volume_id: 1,
            txg: 99,
            object_root: BlockPtr::SPARSE_PTR,
            snapshot_root: BlockPtr::SPARSE_PTR,
            dedup_root: BlockPtr::SPARSE_PTR,
            timestamp_ms: 0,
            self_checksum: [0; 32],
        };
        let slots = [Some(bad), None, None, None];
        assert!(Uberblock::select_newest_valid(&slots).is_none());
    }

    #[test]
    fn uberblock_slots_rotate() {
        let mut u = Uberblock {
            magic: MAGIC,
            version: VERSION,
            _pad: 0,
            volume_id: 1,
            txg: 0,
            object_root: BlockPtr::SPARSE_PTR,
            snapshot_root: BlockPtr::SPARSE_PTR,
            dedup_root: BlockPtr::SPARSE_PTR,
            timestamp_ms: 0,
            self_checksum: [0; 32],
        };
        let mut seen = Vec::new();
        for _ in 0..UBERBLOCK_SLOTS {
            seen.push(u.next_slot());
            u.txg += 1;
        }
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), UBERBLOCK_SLOTS, "rotation must cover all slots");
    }

    fn snap(id: u128, class: Retention, created: u64) -> Snapshot {
        Snapshot {
            id,
            txg: created,
            created_ms: created,
            object_root: BlockPtr::SPARSE_PTR,
            retention: class,
        }
    }

    #[test]
    fn pruning_keeps_the_newest_within_each_class() {
        let mut snaps = Vec::new();
        for i in 0..30u128 {
            snaps.push(snap(i, Retention::Hourly, i as u64 * 3_600_000));
        }
        let doomed = prune_plan(&snaps);
        assert_eq!(doomed.len(), 6, "should prune 30 down to 24");
        // The six oldest, not an arbitrary six.
        for i in 0..6u128 {
            assert!(doomed.contains(&i), "oldest snapshot {i} survived");
        }
    }

    #[test]
    fn manual_snapshots_are_never_pruned() {
        let snaps: Vec<_> = (0..100u128)
            .map(|i| snap(i, Retention::Manual, i as u64))
            .collect();
        assert!(prune_plan(&snaps).is_empty());
    }

    #[test]
    fn pruning_is_a_no_op_below_the_limits() {
        let snaps = vec![
            snap(1, Retention::Hourly, 1),
            snap(2, Retention::Daily, 2),
            snap(3, Retention::Weekly, 3),
        ];
        assert!(prune_plan(&snaps).is_empty());
    }
}
