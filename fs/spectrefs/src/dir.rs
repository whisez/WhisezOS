//! The directory table: what is on the disk, by name.
//!
//! # Why this is not the rest of SpectreFS
//!
//! `layout.rs` describes a copy-on-write filesystem with uberblocks, indirect
//! block trees and snapshots, and none of it is mounted — it is a design with
//! tests, waiting for an allocator and a transaction group. A folder somebody
//! makes on the desktop does not need any of that, and waiting for all of it is
//! how the desktop ended up with no filesystem at all.
//!
//! So this is the smallest thing that is honestly a filesystem: a fixed table
//! of named entries, written to a known place on the disk, read back at boot.
//! No allocation, no indirection, no growth. It stores the names and the shape
//! of the tree; file contents come later, and until they do a file is a name
//! with a length of zero, which is why `Kind::File` exists but nothing writes
//! one yet.
//!
//! # What it costs to be this simple
//!
//! A fixed table means a fixed limit, and the limit is small. It also means the
//! whole table is rewritten to make one folder. Both are fine at this size and
//! neither is fine later; the format carries a version so that later can tell.

#![allow(dead_code)]

use crate::blake3;

/// Marks the table as ours. Different from `layout::MAGIC` on purpose: a reader
/// that finds this must not treat the disk as the full filesystem, and a reader
/// of the full filesystem must not treat this as one.
pub const MAGIC: [u8; 8] = *b"WHISEZD1";

/// Bumped when the on-disk shape changes. A table written by a newer version is
/// refused rather than misread — the failure mode of guessing is a folder tree
/// that is subtly wrong, which is worse than one that is missing.
pub const VERSION: u32 = 1;

/// A sector, which is the unit the block driver moves.
pub const SECTOR: usize = 512;

/// Sectors the table occupies, and where it starts.
///
/// Sector zero is left alone. It is what a partition table or a boot sector
/// would occupy on a disk this ever has to share, and the cost of skipping it
/// is one sector.
pub const TABLE_START: u64 = 1;
pub const TABLE_SECTORS: u64 = 8;

/// The longest name. Chosen so an entry is exactly 64 bytes, which puts eight
/// of them in a sector with nothing left over: 2 for the id, 2 for the parent,
/// one each for kind and length-of-name, and 8 for the file length.
pub const NAME_MAX: usize = 50;

/// The most entries the table holds.
pub const MAX_ENTRIES: usize = 60;

/// The root, which is not stored: every table has one and storing it would let
/// a table exist without it.
pub const ROOT: u16 = 0;

/// The first id a created entry can take. Zero is the root.
pub const FIRST_ID: u16 = 1;

/// Where file contents begin, and how much room each file gets.
///
/// # One fixed extent per id, rather than an allocator
///
/// A file's bytes live at `data_sector(id)` and nowhere else. No free list, no
/// fragmentation, no way for two files to be handed the same block — the whole
/// question that a real allocator exists to answer is removed by not asking it.
///
/// What it costs: every file reserves its room whether or not it uses any, and
/// no file can outgrow the extent. Both are real limits and both are stated
/// rather than discovered — `MAX_FILE_BYTES` is what a file may hold, and a
/// write past it is refused instead of running into the next file.
///
/// The gap before `DATA_START` is deliberate. The table needs room to grow and
/// a format that has to move every file to make it is a format nobody grows.
pub const DATA_START: u64 = 64;
pub const SECTORS_PER_FILE: u64 = 8;
pub const MAX_FILE_BYTES: usize = (SECTORS_PER_FILE as usize) * SECTOR;

/// Sectors a disk must have for this to fit.
pub const SECTORS_NEEDED: u64 =
    DATA_START + (MAX_ENTRIES as u64 + FIRST_ID as u64) * SECTORS_PER_FILE;

/// Where an entry's bytes live.
///
/// `None` for the root and for an id past what the table can hold: an id
/// outside the range has no extent, and returning one anyway would hand back a
/// sector belonging to something else.
#[must_use]
pub const fn data_sector(id: u16) -> Option<u64> {
    if id < FIRST_ID || id as usize >= FIRST_ID as usize + MAX_ENTRIES {
        return None;
    }
    Some(DATA_START + (id as u64) * SECTORS_PER_FILE)
}

/// What an entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Directory,
    File,
}

impl Kind {
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Directory => 1,
            Self::File => 2,
        }
    }

    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Directory),
            2 => Some(Self::File),
            _ => None,
        }
    }
}

/// What went wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The bytes are not a table. A blank disk lands here, and the caller
    /// formats rather than failing — which is why this is separate from
    /// `Corrupt`, where the bytes claim to be a table and are not consistent.
    NotFormatted,
    /// Right magic, wrong version.
    WrongVersion,
    /// The checksum does not match the entries. A torn write looks like this.
    Corrupt,
    /// The name is empty, too long, or has a byte a name may not have.
    BadName,
    /// Something with that name is already in that directory.
    Exists,
    /// The parent is not a directory in this table.
    NoParent,
    /// The table is full.
    Full,
    /// The buffer handed in is not the size of the table.
    BadBuffer,
    /// No entry with that id.
    NoEntry,
    /// The entry is a directory, and a directory has no contents to read or
    /// write — what is "in" it is the entries naming it as parent.
    NotAFile,
    /// More bytes than a file can hold.
    TooLong,
}

/// One entry. `#[repr(C)]` because it is written to a disk that outlives the
/// program that wrote it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Entry {
    pub id: u16,
    pub parent: u16,
    pub kind: u8,
    pub name_len: u8,
    pub name: [u8; NAME_MAX],
    /// Bytes, for a file. Always zero for a directory, and zero for every file
    /// until there is somewhere to put the contents.
    pub length: u64,
}

impl Entry {
    pub const EMPTY: Self = Self {
        id: 0,
        parent: 0,
        kind: 0,
        name_len: 0,
        name: [0; NAME_MAX],
        length: 0,
    };

    /// The name, without the padding.
    #[must_use]
    pub fn label(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
}

/// Whether a name may be used.
///
/// Refused: empty, too long, anything below a space, a delete, and the two
/// bytes a path would need to mean something — a name containing a separator is
/// a name that reads as a path later, and the entry it names becomes
/// unreachable by the path it appears to have.
#[must_use]
pub fn name_ok(name: &[u8]) -> bool {
    if name.is_empty() || name.len() > NAME_MAX {
        return false;
    }
    !name
        .iter()
        .any(|byte| *byte < 0x20 || *byte == 0x7F || *byte == b'/' || *byte == b'\\')
}

/// The table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Table {
    entries: [Entry; MAX_ENTRIES],
    count: usize,
    next_id: u16,
}

impl Default for Table {
    fn default() -> Self {
        Self::new()
    }
}

impl Table {
    /// An empty table: a root and nothing in it.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: [Entry::EMPTY; MAX_ENTRIES],
            count: 0,
            next_id: FIRST_ID,
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.count
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Every entry, in the order they were made.
    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entries[..self.count]
    }

    /// Whether an id names a directory. The root always does.
    #[must_use]
    pub fn is_directory(&self, id: u16) -> bool {
        if id == ROOT {
            return true;
        }
        self.entries()
            .iter()
            .any(|entry| entry.id == id && entry.kind == Kind::Directory.code())
    }

    /// The entries directly inside a directory.
    pub fn children(&self, parent: u16) -> impl Iterator<Item = &Entry> {
        self.entries().iter().filter(move |e| e.parent == parent)
    }

    /// The entry with this id.
    #[must_use]
    pub fn entry(&self, id: u16) -> Option<&Entry> {
        self.entries().iter().find(|entry| entry.id == id)
    }

    /// Records how many bytes a file holds.
    ///
    /// The bytes themselves are written by whoever owns the disk; this is the
    /// length that makes them readable afterwards. Kept together with the name
    /// so that a table which survives a restart describes files that do too — a
    /// file whose length lives anywhere else is a file that reads back as
    /// whatever the sector happened to contain.
    pub fn set_length(&mut self, id: u16, length: usize) -> Result<(), Error> {
        if length > MAX_FILE_BYTES {
            return Err(Error::TooLong);
        }
        let Some(index) = self.entries().iter().position(|entry| entry.id == id) else {
            return Err(Error::NoEntry);
        };
        if self.entries[index].kind != Kind::File.code() {
            return Err(Error::NotAFile);
        }
        self.entries[index].length = length as u64;
        Ok(())
    }

    /// Makes an entry, returning its id.
    ///
    /// Names are unique within a directory rather than across the table: two
    /// folders may each hold a `NOTES`, and refusing that would be a limit
    /// nobody expects from a tree.
    pub fn create(&mut self, parent: u16, name: &[u8], kind: Kind) -> Result<u16, Error> {
        if !name_ok(name) {
            return Err(Error::BadName);
        }
        if !self.is_directory(parent) {
            return Err(Error::NoParent);
        }
        if self.children(parent).any(|entry| entry.label() == name) {
            return Err(Error::Exists);
        }
        if self.count == MAX_ENTRIES {
            return Err(Error::Full);
        }
        // Ids are never reused, so the counter can run out before the table
        // does. Refusing here is the honest answer; the alternative is handing
        // back an id something else still refers to.
        if self.next_id == u16::MAX {
            return Err(Error::Full);
        }

        let mut entry = Entry {
            id: self.next_id,
            parent,
            kind: kind.code(),
            name_len: name.len() as u8,
            name: [0; NAME_MAX],
            length: 0,
        };
        entry.name[..name.len()].copy_from_slice(name);
        self.entries[self.count] = entry;
        self.count += 1;
        self.next_id += 1;
        Ok(entry.id)
    }

    /// The bytes of the table, ready for the disk.
    ///
    /// # The checksum covers the entries and the count
    ///
    /// Not the magic and not itself. A checksum over its own field cannot be
    /// computed, and one that does not cover the count would let a torn write
    /// leave a plausible header in front of entries that were never written.
    pub fn encode(&self, into: &mut [u8]) -> Result<(), Error> {
        if into.len() != Self::BYTES {
            return Err(Error::BadBuffer);
        }
        into.fill(0);
        into[0..8].copy_from_slice(&MAGIC);
        into[8..12].copy_from_slice(&VERSION.to_le_bytes());
        into[12..14].copy_from_slice(&(self.count as u16).to_le_bytes());
        into[14..16].copy_from_slice(&self.next_id.to_le_bytes());

        for (index, entry) in self.entries().iter().enumerate() {
            let at = Self::BODY + index * Self::ENTRY_BYTES;
            let field = &mut into[at..at + Self::ENTRY_BYTES];
            field[0..2].copy_from_slice(&entry.id.to_le_bytes());
            field[2..4].copy_from_slice(&entry.parent.to_le_bytes());
            field[4] = entry.kind;
            field[5] = entry.name_len;
            field[6..6 + NAME_MAX].copy_from_slice(&entry.name);
            field[6 + NAME_MAX..6 + NAME_MAX + 8].copy_from_slice(&entry.length.to_le_bytes());
        }

        let digest = blake3::blake3(&into[12..]);
        into[16..48].copy_from_slice(&digest);
        Ok(())
    }

    /// Reads a table back.
    pub fn decode(from: &[u8]) -> Result<Self, Error> {
        if from.len() != Self::BYTES {
            return Err(Error::BadBuffer);
        }
        if from[0..8] != MAGIC {
            return Err(Error::NotFormatted);
        }
        let version = u32::from_le_bytes([from[8], from[9], from[10], from[11]]);
        if version != VERSION {
            return Err(Error::WrongVersion);
        }

        // Checked before the count is trusted for anything, because the count
        // is inside what the checksum covers and a wrong one is how a torn
        // write shows up. The checksum's own bytes are zeroed to recompute it,
        // which is the state they were in when it was taken.
        let mut over = [0u8; Self::BYTES - 12];
        over.copy_from_slice(&from[12..]);
        over[4..36].fill(0);
        let mut stated = [0u8; 32];
        stated.copy_from_slice(&from[16..48]);
        if blake3::blake3(&over) != stated {
            return Err(Error::Corrupt);
        }

        let count = u16::from_le_bytes([from[12], from[13]]) as usize;
        if count > MAX_ENTRIES {
            return Err(Error::Corrupt);
        }
        let next_id = u16::from_le_bytes([from[14], from[15]]);

        let mut table = Self::new();
        table.count = count;
        table.next_id = next_id;
        for index in 0..count {
            let at = Self::BODY + index * Self::ENTRY_BYTES;
            let field = &from[at..at + Self::ENTRY_BYTES];
            let name_len = field[5] as usize;
            if name_len == 0 || name_len > NAME_MAX {
                return Err(Error::Corrupt);
            }
            if Kind::from_code(field[4]).is_none() {
                return Err(Error::Corrupt);
            }
            let mut entry = Entry {
                id: u16::from_le_bytes([field[0], field[1]]),
                parent: u16::from_le_bytes([field[2], field[3]]),
                kind: field[4],
                name_len: field[5],
                name: [0; NAME_MAX],
                length: u64::from_le_bytes([
                    field[6 + NAME_MAX],
                    field[7 + NAME_MAX],
                    field[8 + NAME_MAX],
                    field[9 + NAME_MAX],
                    field[10 + NAME_MAX],
                    field[11 + NAME_MAX],
                    field[12 + NAME_MAX],
                    field[13 + NAME_MAX],
                ]),
            };
            entry.name.copy_from_slice(&field[6..6 + NAME_MAX]);
            if !name_ok(entry.label()) {
                return Err(Error::Corrupt);
            }
            table.entries[index] = entry;
        }
        Ok(table)
    }

    /// Bytes one entry takes on the disk.
    pub const ENTRY_BYTES: usize = 6 + NAME_MAX + 8;
    /// Where the entries start. The header needs 48 bytes and this is 64, so
    /// that entries begin on an entry-sized boundary — otherwise every entry
    /// after the first few straddles two sectors, and a torn write damages two
    /// entries instead of one.
    pub const BODY: usize = 64;
    /// The whole table, which is what gets written.
    pub const BYTES: usize = (TABLE_SECTORS as usize) * SECTOR;
}

// The entries have to fit in the sectors set aside for them; an entry has to
// divide a sector, and the body has to begin on an entry boundary, so that no
// entry straddles two sectors and a torn write damages one rather than two.
//
// Const assertions rather than tests. These are all compile-time constants, so
// a test of them is a test that cannot fail — it reads as coverage and is not.
// Getting one wrong stops the build instead.
const _: () = assert!(Table::BODY + MAX_ENTRIES * Table::ENTRY_BYTES <= Table::BYTES);
const _: () = assert!(SECTOR.is_multiple_of(Table::ENTRY_BYTES));
const _: () = assert!(Table::BODY.is_multiple_of(Table::ENTRY_BYTES));
const _: () = assert!(Table::ENTRY_BYTES == 64);
const _: () = assert!(Table::BYTES == TABLE_SECTORS as usize * SECTOR);
// Sector zero is left for a partition table or a boot sector, and the boot test
// blanks it — a table starting there would be reformatted on every run.
const _: () = assert!(TABLE_START >= 1);

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded(table: &Table) -> [u8; Table::BYTES] {
        let mut bytes = [0u8; Table::BYTES];
        table.encode(&mut bytes).expect("encodes");
        bytes
    }

    #[test]
    fn no_two_files_share_a_sector() {
        // The whole reason there is no allocator: with one fixed extent per id,
        // two files landing on one block is not a bug that can happen. This is
        // the check that keeps it that way if the constants move.
        let mut seen: heapless::Vec<(u64, u64), MAX_ENTRIES> = heapless::Vec::new();
        for id in FIRST_ID..FIRST_ID + MAX_ENTRIES as u16 {
            let at = data_sector(id).expect("every id the table can hold has room");
            let end = at + SECTORS_PER_FILE;
            for (other_at, other_end) in &seen {
                assert!(
                    end <= *other_at || at >= *other_end,
                    "two files were given the same sectors"
                );
            }
            seen.push((at, end)).expect("fits");
        }
    }

    #[test]
    fn file_contents_do_not_land_on_the_table() {
        // Which would be a file that eats the directory listing it appears in.
        let first = data_sector(FIRST_ID).expect("has room");
        assert!(first >= TABLE_START + TABLE_SECTORS);
        assert!(first >= DATA_START);
    }

    #[test]
    fn an_id_with_no_extent_is_refused_rather_than_given_one_anyway() {
        // The root has no contents, and an id past the table has no room. Both
        // would otherwise be handed a sector belonging to something else.
        assert_eq!(data_sector(ROOT), None);
        assert_eq!(data_sector(FIRST_ID + MAX_ENTRIES as u16), None);
        assert_eq!(data_sector(u16::MAX), None);
    }

    #[test]
    fn everything_fits_on_a_disk_that_says_it_does() {
        let last = data_sector(FIRST_ID + MAX_ENTRIES as u16 - 1).expect("has room");
        assert!(last + SECTORS_PER_FILE <= SECTORS_NEEDED);
    }

    #[test]
    fn a_length_survives_the_trip() {
        let mut table = Table::new();
        let id = table.create(ROOT, b"NOTES.MD", Kind::File).expect("makes");
        table.set_length(id, 41).expect("records");
        let back = Table::decode(&encoded(&table)).expect("decodes");
        assert_eq!(back.entry(id).expect("is there").length, 41);
    }

    #[test]
    fn a_directory_has_no_contents_to_set_a_length_on() {
        // What is "in" a directory is the entries naming it as parent, and a
        // length on one would be a number describing nothing.
        let mut table = Table::new();
        let id = table
            .create(ROOT, b"NOTES", Kind::Directory)
            .expect("makes");
        assert_eq!(table.set_length(id, 10), Err(Error::NotAFile));
    }

    #[test]
    fn a_file_cannot_be_longer_than_its_extent() {
        // Refused rather than clamped: a length past the extent would read back
        // whatever the next file holds.
        let mut table = Table::new();
        let id = table.create(ROOT, b"BIG", Kind::File).expect("makes");
        assert_eq!(
            table.set_length(id, MAX_FILE_BYTES + 1),
            Err(Error::TooLong)
        );
        table
            .set_length(id, MAX_FILE_BYTES)
            .expect("the whole extent fits");
    }

    #[test]
    fn a_length_on_nothing_is_refused() {
        let mut table = Table::new();
        assert_eq!(table.set_length(999, 1), Err(Error::NoEntry));
    }

    #[test]
    fn a_blank_disk_is_not_a_broken_one() {
        // The difference decides whether the session formats or refuses, and
        // getting it wrong either way loses a disk or refuses a new one.
        let blank = [0u8; Table::BYTES];
        assert_eq!(Table::decode(&blank), Err(Error::NotFormatted));
    }

    #[test]
    fn an_empty_table_survives_the_trip() {
        let table = Table::new();
        let back = Table::decode(&encoded(&table)).expect("decodes");
        assert_eq!(back.len(), 0);
    }

    #[test]
    fn a_folder_survives_the_trip() {
        let mut table = Table::new();
        let id = table
            .create(ROOT, b"NOTES", Kind::Directory)
            .expect("makes");
        let back = Table::decode(&encoded(&table)).expect("decodes");
        assert_eq!(back.len(), 1);
        let entry = back.entries()[0];
        assert_eq!(entry.id, id);
        assert_eq!(entry.label(), b"NOTES");
        assert_eq!(entry.parent, ROOT);
        assert_eq!(Kind::from_code(entry.kind), Some(Kind::Directory));
    }

    #[test]
    fn folders_nest() {
        let mut table = Table::new();
        let outer = table
            .create(ROOT, b"OUTER", Kind::Directory)
            .expect("outer");
        let inner = table
            .create(outer, b"INNER", Kind::Directory)
            .expect("inner");
        let back = Table::decode(&encoded(&table)).expect("decodes");
        assert_eq!(back.children(ROOT).count(), 1);
        assert_eq!(back.children(outer).count(), 1);
        assert_eq!(back.children(outer).next().unwrap().id, inner);
    }

    #[test]
    fn the_same_name_twice_in_one_folder_is_refused() {
        let mut table = Table::new();
        table
            .create(ROOT, b"NOTES", Kind::Directory)
            .expect("first");
        assert_eq!(
            table.create(ROOT, b"NOTES", Kind::Directory),
            Err(Error::Exists)
        );
    }

    #[test]
    fn the_same_name_in_two_folders_is_allowed() {
        // A tree in which a name may exist once anywhere is not a tree.
        let mut table = Table::new();
        let a = table.create(ROOT, b"A", Kind::Directory).expect("a");
        let b = table.create(ROOT, b"B", Kind::Directory).expect("b");
        table.create(a, b"NOTES", Kind::Directory).expect("in a");
        table.create(b, b"NOTES", Kind::Directory).expect("in b");
    }

    #[test]
    fn a_name_cannot_hold_a_separator() {
        // Otherwise it reads as a path later and the entry becomes unreachable
        // by the path it appears to have.
        let mut table = Table::new();
        assert_eq!(
            table.create(ROOT, b"A/B", Kind::Directory),
            Err(Error::BadName)
        );
        assert_eq!(
            table.create(ROOT, b"A\\B", Kind::Directory),
            Err(Error::BadName)
        );
    }

    #[test]
    fn a_name_cannot_be_empty_or_control_bytes() {
        let mut table = Table::new();
        assert_eq!(
            table.create(ROOT, b"", Kind::Directory),
            Err(Error::BadName)
        );
        assert_eq!(
            table.create(ROOT, b"A\nB", Kind::Directory),
            Err(Error::BadName)
        );
        assert_eq!(
            table.create(ROOT, &[b'A'; NAME_MAX + 1], Kind::Directory),
            Err(Error::BadName)
        );
        // The longest allowed name is allowed, which is the boundary the two
        // above do not check.
        table
            .create(ROOT, &[b'A'; NAME_MAX], Kind::Directory)
            .expect("the longest name fits");
    }

    #[test]
    fn a_folder_cannot_live_inside_a_file() {
        let mut table = Table::new();
        let file = table.create(ROOT, b"README", Kind::File).expect("file");
        assert_eq!(
            table.create(file, b"INSIDE", Kind::Directory),
            Err(Error::NoParent)
        );
    }

    #[test]
    fn a_folder_cannot_live_inside_nothing() {
        let mut table = Table::new();
        assert_eq!(
            table.create(999, b"ORPHAN", Kind::Directory),
            Err(Error::NoParent)
        );
    }

    #[test]
    fn the_table_fills_up_and_says_so() {
        let mut table = Table::new();
        for index in 0..MAX_ENTRIES {
            let name = [b'A' + (index % 26) as u8, b'0' + (index / 26) as u8];
            table.create(ROOT, &name, Kind::Directory).expect("fits");
        }
        assert_eq!(
            table.create(ROOT, b"ONE-MORE", Kind::Directory),
            Err(Error::Full)
        );
        // And it still reads back, because a full table is a valid one.
        assert_eq!(
            Table::decode(&encoded(&table)).expect("decodes").len(),
            MAX_ENTRIES
        );
    }

    #[test]
    fn ids_are_not_reused() {
        // Two entries with one id is two names for one thing, and no way to
        // tell which the parent field of a third refers to.
        let mut table = Table::new();
        for index in 0..20u8 {
            table
                .create(
                    ROOT,
                    &[b'A', b'0' + index % 10, b'0' + index / 10],
                    Kind::Directory,
                )
                .expect("fits");
        }
        let ids: heapless::Vec<u16, MAX_ENTRIES> =
            table.entries().iter().map(|entry| entry.id).collect();
        for (index, id) in ids.iter().enumerate() {
            assert!(!ids[..index].contains(id), "an id came round again");
        }
    }

    #[test]
    fn a_flipped_byte_is_caught() {
        let mut table = Table::new();
        table
            .create(ROOT, b"NOTES", Kind::Directory)
            .expect("makes");
        let mut bytes = encoded(&table);
        // In the name, which is the part a checksum over the header alone would
        // have missed.
        bytes[Table::BODY + 6] ^= 0x01;
        assert_eq!(Table::decode(&bytes), Err(Error::Corrupt));
    }

    #[test]
    fn a_count_that_claims_more_than_was_written_is_caught() {
        // A torn write: the header landed and the entries did not.
        let mut table = Table::new();
        table
            .create(ROOT, b"NOTES", Kind::Directory)
            .expect("makes");
        let mut bytes = encoded(&table);
        bytes[12] = 9;
        assert_eq!(Table::decode(&bytes), Err(Error::Corrupt));
    }

    #[test]
    fn a_newer_version_is_refused_rather_than_guessed_at() {
        let table = Table::new();
        let mut bytes = encoded(&table);
        bytes[8] = VERSION as u8 + 1;
        assert_eq!(Table::decode(&bytes), Err(Error::WrongVersion));
    }
}
