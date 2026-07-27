//! ELF64 program-header parsing, for loading the kernel image.
//!
//! Only what a loader needs: enough of the header to be sure the file is the
//! right kind of object for this machine, and the program headers describing
//! what to place where. Section headers, symbols, and relocations are ignored —
//! the kernel is linked to a fixed address by `kernel.ld`, so there is nothing
//! to relocate and nothing to resolve.
//!
//! # Why every field is bounds-checked
//!
//! This code runs before anything has verified the file. `\SPECTRE\KERNEL.ELF`
//! comes off a FAT partition that an attacker with physical access can rewrite,
//! and a program header is just three attacker-chosen `u64`s: a file offset, a
//! size, and a destination address. Trusting them means a truncated or hostile
//! image gets to name any source range in the loader's address space and any
//! destination in physical memory, and the copy happens before a single
//! signature has been checked.
//!
//! So: `p_offset + p_filesz` must fall inside the file, `p_memsz` must be at
//! least `p_filesz`, and the whole thing must be expressible without arithmetic
//! overflow. Every one of those is a rejected image rather than a clamped value,
//! because a loader that quietly repairs a malformed kernel is a loader that
//! boots something other than what was built.

#![allow(dead_code)]

/// `\x7FELF`.
const MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];
const CLASS_64: u8 = 2;
const DATA_LITTLE_ENDIAN: u8 = 1;
const TYPE_EXECUTABLE: u16 = 2;
const MACHINE_X86_64: u16 = 0x3E;
const PT_LOAD: u32 = 1;

const EHDR_SIZE: usize = 64;
const PHDR_SIZE: usize = 56;

/// Segment permission bits, as they appear in `p_flags`.
pub const PF_X: u32 = 1 << 0;
pub const PF_W: u32 = 1 << 1;
pub const PF_R: u32 = 1 << 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfError {
    /// Smaller than an ELF header.
    TooSmall,
    NotAnElfFile,
    /// 32-bit object, or a class byte we do not recognise.
    Not64Bit(u8),
    NotLittleEndian(u8),
    /// Relocatable, shared, or core file rather than an executable.
    NotExecutable(u16),
    WrongMachine(u16),
    /// Program header table is absent, misdeclared, or runs past the file.
    BadProgramHeaders,
    /// A segment's file contents lie outside the file.
    SegmentOutOfFile {
        index: u16,
    },
    /// `p_memsz < p_filesz`: the segment claims to occupy less memory than it
    /// has bytes, so copying it would write past its own end.
    SegmentShorterThanContents {
        index: u16,
    },
    /// Address arithmetic for a segment overflows.
    SegmentOverflow {
        index: u16,
    },
    /// No `PT_LOAD` segment: nothing to load.
    NoLoadableSegments,
    /// The entry point is outside every loadable segment, so jumping to it would
    /// execute unmapped memory.
    EntryOutsideImage {
        entry: u64,
    },
}

/// One `PT_LOAD` segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment {
    pub file_offset: u64,
    pub file_size: u64,
    /// Bytes to occupy in memory. Anything past `file_size` is `.bss` and must
    /// be zeroed — a kernel whose statics start as whatever the firmware left
    /// in that page fails in ways that change between boots.
    pub mem_size: u64,
    pub phys: u64,
    pub virt: u64,
    pub flags: u32,
    pub align: u64,
}

impl Segment {
    #[must_use]
    pub const fn is_executable(&self) -> bool {
        self.flags & PF_X != 0
    }

    #[must_use]
    pub const fn is_writable(&self) -> bool {
        self.flags & PF_W != 0
    }

    /// Bytes of `.bss` following the file-backed part.
    #[must_use]
    pub const fn zero_fill(&self) -> u64 {
        self.mem_size - self.file_size
    }

    #[must_use]
    pub const fn end(&self) -> u64 {
        self.phys + self.mem_size
    }
}

/// A validated ELF64 executable.
///
/// `PartialEq` so tests can assert directly on the parse `Result`; two
/// instances are equal when they describe the same bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Elf64<'a> {
    bytes: &'a [u8],
    entry: u64,
    phoff: usize,
    phnum: u16,
}

impl<'a> Elf64<'a> {
    /// Validates the header and the whole program header table up front.
    ///
    /// Checking everything here rather than lazily during iteration means a
    /// malformed image is rejected before any memory has been allocated for it,
    /// and the caller never has to handle a failure halfway through a copy.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ElfError> {
        if bytes.len() < EHDR_SIZE {
            return Err(ElfError::TooSmall);
        }
        if bytes[..4] != MAGIC {
            return Err(ElfError::NotAnElfFile);
        }
        if bytes[4] != CLASS_64 {
            return Err(ElfError::Not64Bit(bytes[4]));
        }
        if bytes[5] != DATA_LITTLE_ENDIAN {
            return Err(ElfError::NotLittleEndian(bytes[5]));
        }

        let e_type = u16(bytes, 16);
        if e_type != TYPE_EXECUTABLE {
            return Err(ElfError::NotExecutable(e_type));
        }
        let machine = u16(bytes, 18);
        if machine != MACHINE_X86_64 {
            return Err(ElfError::WrongMachine(machine));
        }

        let entry = u64(bytes, 24);
        let phoff = u64(bytes, 32);
        let phentsize = u16(bytes, 54);
        let phnum = u16(bytes, 56);

        if phnum == 0 || phentsize as usize != PHDR_SIZE {
            return Err(ElfError::BadProgramHeaders);
        }
        let table_len = (phnum as u64)
            .checked_mul(PHDR_SIZE as u64)
            .ok_or(ElfError::BadProgramHeaders)?;
        let table_end = phoff
            .checked_add(table_len)
            .ok_or(ElfError::BadProgramHeaders)?;
        if table_end > bytes.len() as u64 {
            return Err(ElfError::BadProgramHeaders);
        }

        let elf = Self {
            bytes,
            entry,
            phoff: phoff as usize,
            phnum,
        };
        elf.check_segments()?;
        Ok(elf)
    }

    fn check_segments(&self) -> Result<(), ElfError> {
        let mut loadable = 0usize;
        let mut entry_covered = false;

        for index in 0..self.phnum {
            let Some(segment) = self.raw_segment(index) else {
                continue;
            };
            loadable += 1;

            let file_end = segment
                .file_offset
                .checked_add(segment.file_size)
                .ok_or(ElfError::SegmentOverflow { index })?;
            if file_end > self.bytes.len() as u64 {
                return Err(ElfError::SegmentOutOfFile { index });
            }
            if segment.mem_size < segment.file_size {
                return Err(ElfError::SegmentShorterThanContents { index });
            }
            segment
                .phys
                .checked_add(segment.mem_size)
                .ok_or(ElfError::SegmentOverflow { index })?;
            segment
                .virt
                .checked_add(segment.mem_size)
                .ok_or(ElfError::SegmentOverflow { index })?;

            if self.entry >= segment.virt && self.entry < segment.virt + segment.mem_size {
                entry_covered = true;
            }
        }

        if loadable == 0 {
            return Err(ElfError::NoLoadableSegments);
        }
        if !entry_covered {
            return Err(ElfError::EntryOutsideImage { entry: self.entry });
        }
        Ok(())
    }

    fn raw_segment(&self, index: u16) -> Option<Segment> {
        let at = self.phoff + index as usize * PHDR_SIZE;
        if u32(self.bytes, at) != PT_LOAD {
            return None;
        }
        Some(Segment {
            flags: u32(self.bytes, at + 4),
            file_offset: u64(self.bytes, at + 8),
            virt: u64(self.bytes, at + 16),
            phys: u64(self.bytes, at + 24),
            file_size: u64(self.bytes, at + 32),
            mem_size: u64(self.bytes, at + 40),
            align: u64(self.bytes, at + 48),
        })
    }

    #[must_use]
    pub const fn entry(&self) -> u64 {
        self.entry
    }

    /// Every `PT_LOAD` segment, in program-header order.
    pub fn segments(&self) -> impl Iterator<Item = Segment> + '_ {
        (0..self.phnum).filter_map(move |i| self.raw_segment(i))
    }

    /// File bytes backing a segment. Validated during `parse`, so this cannot
    /// fail for a segment this instance produced.
    #[must_use]
    pub fn contents(&self, segment: &Segment) -> &'a [u8] {
        let start = segment.file_offset as usize;
        let end = start + segment.file_size as usize;
        &self.bytes[start..end]
    }

    /// Physical extent the image occupies once loaded: `(base, length)`.
    ///
    /// The loader allocates and the kernel reserves exactly this range, so it
    /// spans from the lowest segment address to the highest segment end,
    /// including the gaps between them — a hole left allocatable would be handed
    /// out and written over.
    #[must_use]
    pub fn physical_extent(&self) -> Option<(u64, u64)> {
        let mut low = u64::MAX;
        let mut high = 0u64;
        for segment in self.segments() {
            low = low.min(segment.phys);
            high = high.max(segment.end());
        }
        (low <= high).then_some((low, high - low))
    }
}

fn u16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

fn u64(bytes: &[u8], at: usize) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[at..at + 8]);
    u64::from_le_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal but genuine ELF64 executable in memory.
    struct Builder {
        segments: Vec<(u32, u64, u64, u64, u64)>,
        entry: u64,
        e_type: u16,
        machine: u16,
        class: u8,
        endian: u8,
        phentsize: u16,
    }

    impl Builder {
        fn new() -> Self {
            Self {
                segments: Vec::new(),
                entry: 0x1000,
                e_type: TYPE_EXECUTABLE,
                machine: MACHINE_X86_64,
                class: CLASS_64,
                endian: DATA_LITTLE_ENDIAN,
                phentsize: PHDR_SIZE as u16,
            }
        }

        /// `(flags, file_offset, file_size, addr, mem_size)`
        fn segment(mut self, flags: u32, offset: u64, filesz: u64, addr: u64, memsz: u64) -> Self {
            self.segments.push((flags, offset, filesz, addr, memsz));
            self
        }

        fn build(&self) -> Vec<u8> {
            let phoff = EHDR_SIZE;
            let body = phoff + self.segments.len() * PHDR_SIZE;
            let mut bytes = vec![0u8; body.max(0x4000)];

            bytes[..4].copy_from_slice(&MAGIC);
            bytes[4] = self.class;
            bytes[5] = self.endian;
            bytes[16..18].copy_from_slice(&self.e_type.to_le_bytes());
            bytes[18..20].copy_from_slice(&self.machine.to_le_bytes());
            bytes[24..32].copy_from_slice(&self.entry.to_le_bytes());
            bytes[32..40].copy_from_slice(&(phoff as u64).to_le_bytes());
            bytes[54..56].copy_from_slice(&self.phentsize.to_le_bytes());
            bytes[56..58].copy_from_slice(&(self.segments.len() as u16).to_le_bytes());

            for (i, (flags, offset, filesz, addr, memsz)) in self.segments.iter().enumerate() {
                let at = phoff + i * PHDR_SIZE;
                bytes[at..at + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
                bytes[at + 4..at + 8].copy_from_slice(&flags.to_le_bytes());
                bytes[at + 8..at + 16].copy_from_slice(&offset.to_le_bytes());
                bytes[at + 16..at + 24].copy_from_slice(&addr.to_le_bytes());
                bytes[at + 24..at + 32].copy_from_slice(&addr.to_le_bytes());
                bytes[at + 32..at + 40].copy_from_slice(&filesz.to_le_bytes());
                bytes[at + 40..at + 48].copy_from_slice(&memsz.to_le_bytes());
                bytes[at + 48..at + 56].copy_from_slice(&4096u64.to_le_bytes());
            }
            bytes
        }
    }

    fn typical() -> Vec<u8> {
        // Text, rodata, and a data segment with .bss behind it — the shape
        // kernel.ld produces.
        Builder::new()
            .segment(PF_R | PF_X, 0x1000, 0x800, 0x1000, 0x800)
            .segment(PF_R, 0x2000, 0x400, 0x2000, 0x400)
            .segment(PF_R | PF_W, 0x3000, 0x200, 0x3000, 0x900)
            .build()
    }

    #[test]
    fn a_well_formed_kernel_image_parses() {
        let bytes = typical();
        let elf = Elf64::parse(&bytes).unwrap();
        assert_eq!(elf.entry(), 0x1000);
        assert_eq!(elf.segments().count(), 3);
    }

    #[test]
    fn segments_report_their_permissions() {
        let bytes = typical();
        let elf = Elf64::parse(&bytes).unwrap();
        let segments: Vec<_> = elf.segments().collect();
        assert!(segments[0].is_executable() && !segments[0].is_writable());
        assert!(!segments[1].is_executable() && !segments[1].is_writable());
        assert!(segments[2].is_writable() && !segments[2].is_executable());
    }

    #[test]
    fn bss_size_is_the_difference_between_mem_and_file_size() {
        // The loader zeroes exactly this much; getting it wrong leaves kernel
        // statics holding whatever the firmware left in the page.
        let bytes = typical();
        let elf = Elf64::parse(&bytes).unwrap();
        let data = elf.segments().nth(2).unwrap();
        assert_eq!(data.zero_fill(), 0x700);
        assert_eq!(elf.segments().next().unwrap().zero_fill(), 0);
    }

    #[test]
    fn contents_return_exactly_the_file_backed_bytes() {
        let mut bytes = typical();
        bytes[0x1000] = 0xAB;
        bytes[0x17FF] = 0xCD;
        let elf = Elf64::parse(&bytes).unwrap();
        let text = elf.segments().next().unwrap();
        let body = elf.contents(&text);
        assert_eq!(body.len(), 0x800);
        assert_eq!(body[0], 0xAB);
        assert_eq!(body[0x7FF], 0xCD);
    }

    #[test]
    fn the_physical_extent_spans_every_segment_including_the_gaps() {
        // Leaving a gap allocatable means the frame allocator hands out memory
        // between two kernel segments.
        let bytes = typical();
        let elf = Elf64::parse(&bytes).unwrap();
        assert_eq!(elf.physical_extent(), Some((0x1000, 0x2900)));
    }

    #[test]
    fn a_short_file_is_rejected() {
        assert_eq!(Elf64::parse(&[0u8; 8]), Err(ElfError::TooSmall));
    }

    #[test]
    fn a_file_without_the_magic_is_rejected() {
        let mut bytes = typical();
        bytes[1] = b'X';
        assert_eq!(Elf64::parse(&bytes), Err(ElfError::NotAnElfFile));
    }

    #[test]
    fn a_32_bit_object_is_rejected() {
        let bytes = Builder {
            class: 1,
            ..Builder::new()
        }
        .segment(PF_R | PF_X, 0x1000, 0x10, 0x1000, 0x10)
        .build();
        assert_eq!(Elf64::parse(&bytes), Err(ElfError::Not64Bit(1)));
    }

    #[test]
    fn a_big_endian_object_is_rejected() {
        let bytes = Builder {
            endian: 2,
            ..Builder::new()
        }
        .segment(PF_R | PF_X, 0x1000, 0x10, 0x1000, 0x10)
        .build();
        assert_eq!(Elf64::parse(&bytes), Err(ElfError::NotLittleEndian(2)));
    }

    #[test]
    fn a_shared_object_is_rejected() {
        // A PIE kernel would need relocations applied, which this loader does
        // not do; loading one anyway jumps into unrelocated code.
        let bytes = Builder {
            e_type: 3,
            ..Builder::new()
        }
        .segment(PF_R | PF_X, 0x1000, 0x10, 0x1000, 0x10)
        .build();
        assert_eq!(Elf64::parse(&bytes), Err(ElfError::NotExecutable(3)));
    }

    #[test]
    fn an_object_for_another_machine_is_rejected() {
        let bytes = Builder {
            machine: 0xB7,
            ..Builder::new()
        }
        .segment(PF_R | PF_X, 0x1000, 0x10, 0x1000, 0x10)
        .build();
        assert_eq!(Elf64::parse(&bytes), Err(ElfError::WrongMachine(0xB7)));
    }

    #[test]
    fn an_unexpected_program_header_size_is_rejected() {
        // A different entry size means every field would be read at the wrong
        // offset, producing plausible-looking garbage addresses.
        let bytes = Builder {
            phentsize: 32,
            ..Builder::new()
        }
        .segment(PF_R | PF_X, 0x1000, 0x10, 0x1000, 0x10)
        .build();
        assert_eq!(Elf64::parse(&bytes), Err(ElfError::BadProgramHeaders));
    }

    #[test]
    fn a_program_header_table_past_the_end_of_the_file_is_rejected() {
        let mut bytes = typical();
        bytes[32..40].copy_from_slice(&0xFFFF_0000u64.to_le_bytes());
        assert_eq!(Elf64::parse(&bytes), Err(ElfError::BadProgramHeaders));
    }

    #[test]
    fn a_file_with_no_loadable_segments_is_rejected() {
        let mut bytes = typical();
        // Turn every PT_LOAD into PT_NULL.
        for i in 0..3 {
            let at = EHDR_SIZE + i * PHDR_SIZE;
            bytes[at..at + 4].copy_from_slice(&0u32.to_le_bytes());
        }
        assert_eq!(Elf64::parse(&bytes), Err(ElfError::NoLoadableSegments));
    }

    #[test]
    fn a_segment_reaching_past_the_end_of_the_file_is_rejected() {
        // The attack this closes: p_offset and p_filesz are attacker-chosen, so
        // an oversized segment reads whatever follows the image in the loader's
        // address space and copies it into the kernel.
        let bytes = Builder::new()
            .segment(PF_R | PF_X, 0x1000, 0x10, 0x1000, 0x10)
            .segment(PF_R, 0x3F00, 0x8000, 0x2000, 0x8000)
            .build();
        assert_eq!(
            Elf64::parse(&bytes),
            Err(ElfError::SegmentOutOfFile { index: 1 })
        );
    }

    #[test]
    fn a_segment_whose_offset_and_size_overflow_is_rejected() {
        let bytes = Builder::new()
            .segment(PF_R | PF_X, 0x1000, 0x10, 0x1000, 0x10)
            .segment(PF_R, u64::MAX - 4, 16, 0x2000, 16)
            .build();
        assert_eq!(
            Elf64::parse(&bytes),
            Err(ElfError::SegmentOverflow { index: 1 })
        );
    }

    #[test]
    fn a_segment_claiming_less_memory_than_it_has_bytes_is_rejected() {
        // Copying p_filesz bytes into a p_memsz-sized allocation writes past
        // the end of it.
        let bytes = Builder::new()
            .segment(PF_R | PF_X, 0x1000, 0x800, 0x1000, 0x800)
            .segment(PF_R, 0x2000, 0x400, 0x2000, 0x100)
            .build();
        assert_eq!(
            Elf64::parse(&bytes),
            Err(ElfError::SegmentShorterThanContents { index: 1 })
        );
    }

    #[test]
    fn a_segment_whose_destination_overflows_is_rejected() {
        let bytes = Builder::new()
            .segment(PF_R | PF_X, 0x1000, 0x10, 0x1000, 0x10)
            .segment(PF_R, 0x2000, 0x10, u64::MAX - 4, 0x10)
            .build();
        assert_eq!(
            Elf64::parse(&bytes),
            Err(ElfError::SegmentOverflow { index: 1 })
        );
    }

    #[test]
    fn an_entry_point_outside_every_segment_is_rejected() {
        // Jumping there would execute memory the loader never wrote.
        let bytes = Builder {
            entry: 0x9_0000,
            ..Builder::new()
        }
        .segment(PF_R | PF_X, 0x1000, 0x10, 0x1000, 0x10)
        .build();
        assert_eq!(
            Elf64::parse(&bytes),
            Err(ElfError::EntryOutsideImage { entry: 0x9_0000 })
        );
    }

    #[test]
    fn an_entry_point_at_the_very_end_of_a_segment_is_rejected() {
        // Off-by-one: `virt + mem_size` is one past the last valid byte.
        let bytes = Builder {
            entry: 0x1010,
            ..Builder::new()
        }
        .segment(PF_R | PF_X, 0x1000, 0x10, 0x1000, 0x10)
        .build();
        assert!(matches!(
            Elf64::parse(&bytes),
            Err(ElfError::EntryOutsideImage { .. })
        ));
    }
}
