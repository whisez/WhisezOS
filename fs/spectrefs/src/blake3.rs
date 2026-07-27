//! BLAKE3, because the checksum that was here returned zeros.
//!
//! # What it replaces
//!
//! `layout.rs` checksums every block and every uberblock, and the function it
//! called was:
//!
//! ```ignore
//! pub fn blake3(_bytes: &[u8]) -> [u8; 32] { [0; 32] }
//! ```
//!
//! Every checksum matched every block, so the integrity checking the filesystem
//! is built around verified nothing. Worse than absent: a corrupted block passed
//! and a caller reading `verify_checksum() == true` was told a truth about a
//! computation that never happened.
//!
//! # Why implement it rather than depend on it
//!
//! The kernel is `no_std` with no allocator, built for `x86_64-unknown-none`
//! with `-sse`. The published crate is excellent and wants neither of those
//! constraints tested against it here; and one of this project's dependencies
//! already crashed rustc on this target, which is the kind of surprise a
//! filesystem's checksum should not be exposed to. It is 300 lines of very
//! well-specified arithmetic, and the specification ships test vectors.
//!
//! # Correctness is asserted against the specification's own vectors
//!
//! The tests below are the official unkeyed vectors, at the input lengths that
//! exercise every structural case: less than one block, exactly one block, a
//! partial chunk, exactly one chunk, and multi-chunk inputs that force the
//! tree to merge at depth. An implementation can be wrong in ways that only
//! show at a chunk boundary, so a single vector proves very little and these
//! were chosen to cover each boundary rather than to be numerous.

#![allow(dead_code)]

/// The initialisation vector, which is the SHA-256 one.
const IV: [u32; 8] = [
    0x6A09_E667,
    0xBB67_AE85,
    0x3C6E_F372,
    0xA54F_F53A,
    0x510E_527F,
    0x9B05_688C,
    0x1F83_D9AB,
    0x5BE0_CD19,
];

/// How the message words are shuffled between rounds.
const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

/// Bytes per compression block.
const BLOCK_LEN: usize = 64;
/// Bytes per chunk. A chunk is sixteen blocks and is the unit the tree is
/// built from.
const CHUNK_LEN: usize = 1024;

mod flag {
    pub const CHUNK_START: u32 = 1 << 0;
    pub const CHUNK_END: u32 = 1 << 1;
    pub const PARENT: u32 = 1 << 2;
    pub const ROOT: u32 = 1 << 3;
}

/// The mixing function. Two message words per call, four state words touched.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

/// One round: four column mixes, then four diagonal mixes.
fn round(state: &mut [u32; 16], m: &[u32; 16]) {
    g(state, 0, 4, 8, 12, m[0], m[1]);
    g(state, 1, 5, 9, 13, m[2], m[3]);
    g(state, 2, 6, 10, 14, m[4], m[5]);
    g(state, 3, 7, 11, 15, m[6], m[7]);
    g(state, 0, 5, 10, 15, m[8], m[9]);
    g(state, 1, 6, 11, 12, m[10], m[11]);
    g(state, 2, 7, 8, 13, m[12], m[13]);
    g(state, 3, 4, 9, 14, m[14], m[15]);
}

fn permute(m: &mut [u32; 16]) {
    let original = *m;
    for (index, source) in MSG_PERMUTATION.iter().enumerate() {
        m[index] = original[*source];
    }
}

/// The compression function. Returns all sixteen state words; callers take the
/// first eight as a chaining value or as output.
fn compress(
    chaining_value: &[u32; 8],
    block_words: &[u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [u32; 16] {
    let mut state = [
        chaining_value[0],
        chaining_value[1],
        chaining_value[2],
        chaining_value[3],
        chaining_value[4],
        chaining_value[5],
        chaining_value[6],
        chaining_value[7],
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        counter as u32,
        (counter >> 32) as u32,
        block_len,
        flags,
    ];
    let mut block = *block_words;

    for index in 0..7 {
        round(&mut state, &block);
        // The last round does not permute: there is nothing after it to feed.
        if index < 6 {
            permute(&mut block);
        }
    }

    for index in 0..8 {
        state[index] ^= state[index + 8];
        state[index + 8] ^= chaining_value[index];
    }
    state
}

fn words_from_block(block: &[u8; BLOCK_LEN]) -> [u32; 16] {
    let mut words = [0u32; 16];
    for (index, word) in words.iter_mut().enumerate() {
        let start = index * 4;
        *word = u32::from_le_bytes([
            block[start],
            block[start + 1],
            block[start + 2],
            block[start + 3],
        ]);
    }
    words
}

fn first_eight(state: &[u32; 16]) -> [u32; 8] {
    let mut cv = [0u32; 8];
    cv.copy_from_slice(&state[..8]);
    cv
}

/// A compression that has not been performed yet.
///
/// Deferred because the root node is compressed differently from every other:
/// it carries `ROOT`, and until the whole input has been seen there is no way
/// to know which node is the root. Carrying the inputs rather than the result
/// is what lets the decision be made last.
#[derive(Clone, Copy)]
struct Output {
    input_chaining_value: [u32; 8],
    block_words: [u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
}

impl Output {
    fn chaining_value(&self) -> [u32; 8] {
        first_eight(&compress(
            &self.input_chaining_value,
            &self.block_words,
            self.counter,
            self.block_len,
            self.flags,
        ))
    }

    fn root_hash(&self) -> [u8; 32] {
        // The root is compressed with counter zero regardless of where it sat
        // in the tree, which is what makes the hash independent of how the
        // input was chunked.
        let state = compress(
            &self.input_chaining_value,
            &self.block_words,
            0,
            self.block_len,
            self.flags | flag::ROOT,
        );
        let mut out = [0u8; 32];
        for (index, word) in state[..8].iter().enumerate() {
            out[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        out
    }
}

/// One chunk being filled.
struct ChunkState {
    chaining_value: [u32; 8],
    counter: u64,
    block: [u8; BLOCK_LEN],
    block_len: u8,
    blocks_compressed: u8,
}

impl ChunkState {
    fn new(key: [u32; 8], counter: u64) -> Self {
        Self {
            chaining_value: key,
            counter,
            block: [0; BLOCK_LEN],
            block_len: 0,
            blocks_compressed: 0,
        }
    }

    fn len(&self) -> usize {
        BLOCK_LEN * self.blocks_compressed as usize + self.block_len as usize
    }

    /// `CHUNK_START` belongs only to the chunk's first block.
    fn start_flag(&self) -> u32 {
        if self.blocks_compressed == 0 {
            flag::CHUNK_START
        } else {
            0
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            // A full block is only compressed once something follows it, so the
            // last block of a chunk is still available to carry `CHUNK_END`.
            if self.block_len as usize == BLOCK_LEN {
                let words = words_from_block(&self.block);
                self.chaining_value = first_eight(&compress(
                    &self.chaining_value,
                    &words,
                    self.counter,
                    BLOCK_LEN as u32,
                    self.start_flag(),
                ));
                self.blocks_compressed += 1;
                self.block = [0; BLOCK_LEN];
                self.block_len = 0;
            }

            let room = BLOCK_LEN - self.block_len as usize;
            let take = room.min(input.len());
            self.block[self.block_len as usize..self.block_len as usize + take]
                .copy_from_slice(&input[..take]);
            self.block_len += take as u8;
            input = &input[take..];
        }
    }

    fn output(&self) -> Output {
        Output {
            input_chaining_value: self.chaining_value,
            block_words: words_from_block(&self.block),
            counter: self.counter,
            block_len: u32::from(self.block_len),
            flags: self.start_flag() | flag::CHUNK_END,
        }
    }
}

fn parent_output(left: [u32; 8], right: [u32; 8], key: [u32; 8]) -> Output {
    let mut block_words = [0u32; 16];
    block_words[..8].copy_from_slice(&left);
    block_words[8..].copy_from_slice(&right);
    Output {
        input_chaining_value: key,
        block_words,
        counter: 0,
        block_len: BLOCK_LEN as u32,
        flags: flag::PARENT,
    }
}

/// Chunks a single hash can cover.
///
/// The stack holds one chaining value per set bit in the chunk count, so 54
/// entries covers 2^54 chunks — about 18 exabytes, which is more than the
/// address space this filesystem describes.
const MAX_DEPTH: usize = 54;

/// An incremental hasher.
pub struct Hasher {
    chunk: ChunkState,
    key: [u32; 8],
    stack: [[u32; 8]; MAX_DEPTH],
    stack_len: usize,
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher {
    #[must_use]
    pub fn new() -> Self {
        Self {
            chunk: ChunkState::new(IV, 0),
            key: IV,
            stack: [[0; 8]; MAX_DEPTH],
            stack_len: 0,
        }
    }

    fn push(&mut self, cv: [u32; 8]) {
        self.stack[self.stack_len] = cv;
        self.stack_len += 1;
    }

    fn pop(&mut self) -> [u32; 8] {
        self.stack_len -= 1;
        self.stack[self.stack_len]
    }

    /// Merges finished subtrees.
    ///
    /// The rule is arithmetic rather than structural: after finishing chunk
    /// *n*, merge once for every trailing zero bit in the new total. That is
    /// exactly the set of subtrees that have just become complete, which is why
    /// the stack never needs to know the tree's shape.
    fn add_chunk_chaining_value(&mut self, mut cv: [u32; 8], mut total_chunks: u64) {
        while total_chunks & 1 == 0 {
            let left = self.pop();
            cv = parent_output(left, cv, self.key).chaining_value();
            total_chunks >>= 1;
        }
        self.push(cv);
    }

    pub fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.chunk.len() == CHUNK_LEN {
                let cv = self.chunk.output().chaining_value();
                let total = self.chunk.counter + 1;
                self.add_chunk_chaining_value(cv, total);
                self.chunk = ChunkState::new(self.key, total);
            }

            let room = CHUNK_LEN - self.chunk.len();
            let take = room.min(input.len());
            self.chunk.update(&input[..take]);
            input = &input[take..];
        }
    }

    /// The 32-byte hash of everything fed in so far.
    #[must_use]
    pub fn finalize(&self) -> [u8; 32] {
        let mut output = self.chunk.output();
        // Fold the stack right to left. Each step makes the accumulated
        // subtree the right child of the one below it, which is the order the
        // tree was built in.
        let mut remaining = self.stack_len;
        while remaining > 0 {
            remaining -= 1;
            output = parent_output(self.stack[remaining], output.chaining_value(), self.key);
        }
        output.root_hash()
    }
}

/// The 32-byte BLAKE3 hash of `bytes`.
#[must_use]
pub fn blake3(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(bytes);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The input the specification's test vectors use: byte *i* is `i % 251`.
    ///
    /// 251 is the largest prime below 256, which makes the pattern's period
    /// share no factor with any block or chunk length — so a bug that swaps two
    /// blocks, or drops one, cannot produce the same bytes by coincidence.
    fn vector_input(len: usize) -> std::vec::Vec<u8> {
        (0..len).map(|index| (index % 251) as u8).collect()
    }

    fn hex(bytes: &[u8; 32]) -> std::string::String {
        use std::fmt::Write;
        let mut out = std::string::String::new();
        for byte in bytes {
            let _ = write!(out, "{byte:02x}");
        }
        out
    }

    /// Official unkeyed vectors, at the lengths where a wrong implementation
    /// first diverges.
    ///
    /// One vector proves very little here: an implementation can be correct for
    /// a single block and wrong at every chunk boundary, or right for one chunk
    /// and wrong the moment the tree has to merge. These lengths are chosen so
    /// that each structural case has one — empty, sub-block, exact block,
    /// sub-chunk, exact chunk, and multi-chunk inputs that force merges at two
    /// different depths.
    const VECTORS: &[(usize, &str)] = &[
        (
            0,
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
        ),
        (
            1,
            "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
        ),
        (
            2,
            "7b7015bb92cf0b318037702a6cdd81dee41224f734684c2c122cd6359cb1ee63",
        ),
        (
            3,
            "e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f",
        ),
        (
            63,
            "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b",
        ),
        (
            64,
            "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98",
        ),
        (
            1023,
            "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11",
        ),
        (
            1024,
            "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7",
        ),
        (
            1025,
            "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444",
        ),
        (
            2048,
            "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a",
        ),
        // Length 2049 belongs here and is deliberately absent. The digest for
        // it was written from memory, most of it wrongly, and the honest repair
        // is to drop the entry rather than to paste in what this code computes
        // — a vector taken from the implementation asserts only that the
        // implementation agrees with itself. The case it would have covered, a
        // chunk boundary plus one byte, is covered by 1025.
        (
            3072,
            "b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd2",
        ),
    ];

    #[test]
    fn the_specification_vectors_match() {
        for (len, expected) in VECTORS {
            let actual = hex(&blake3(&vector_input(*len)));
            assert_eq!(&actual, expected, "length {len}");
        }
    }

    #[test]
    fn feeding_the_same_input_in_pieces_gives_the_same_hash() {
        // The incremental path and the one-shot path share almost no control
        // flow: one fills partial blocks, the other never does. An
        // implementation can be right for whole slices and wrong at every
        // resumption point.
        let input = vector_input(3000);
        let once = blake3(&input);

        for split in [1usize, 63, 64, 65, 1023, 1024, 1025, 2000] {
            let mut hasher = Hasher::new();
            hasher.update(&input[..split]);
            hasher.update(&input[split..]);
            assert_eq!(hasher.finalize(), once, "split at {split}");
        }
    }

    #[test]
    fn many_small_updates_agree_with_one_large_one() {
        let input = vector_input(2500);
        let mut hasher = Hasher::new();
        for byte in &input {
            hasher.update(&[*byte]);
        }
        assert_eq!(hasher.finalize(), blake3(&input));
    }

    #[test]
    fn a_single_changed_byte_changes_the_hash() {
        // The property the filesystem actually depends on. The stub this
        // replaces failed exactly here: every input hashed to zeros, so every
        // corrupted block verified.
        let mut input = vector_input(4096);
        let before = blake3(&input);
        input[2048] ^= 1;
        assert_ne!(blake3(&input), before);
    }

    #[test]
    fn the_hash_of_nothing_is_not_zero() {
        // The shape of the old stub's answer, asserted against directly so a
        // future stub cannot quietly reappear.
        assert_ne!(blake3(&[]), [0u8; 32]);
    }
}
