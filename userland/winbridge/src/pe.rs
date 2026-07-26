//! PE32+ image loader.
//!
//! This is the one part of WinBridge that is genuinely tractable to write from
//! scratch -?" the PE format is documented, stable, and about 2,000 lines of
//! careful parsing. The parts that follow it (see `syscall.rs` and
//! ARCHITECTURE.md §6) are not.
//!
//! # Security posture
//!
//! Every field here comes from an untrusted file that the user double-clicked.
//! The loader is the attack surface for every malicious .exe the user will ever
//! encounter, so the rules are strict:
//!
//!   * No arithmetic on header fields without checked ops. Overflowing RVA
//!     arithmetic to produce an out-of-bounds write is the classic PE loader
//!     bug and has shipped in every major implementation at least once.
//!   * Section ranges are validated against both file size and image size
//!     before any mapping occurs.
//!   * Nothing is mapped W+X. Ever. Sections requesting both get W, and gain X
//!     only via an explicit `VirtualProtect` translation that is logged.
//!   * The loader itself runs in the WinBridge container, not in a privileged
//!     process, so a loader compromise yields the container's capabilities -?"
//!     a virtual C: drive and a virtual registry -?" and nothing else.

use core::mem::size_of;

pub const DOS_MAGIC: u16 = 0x5A4D; // "MZ"
pub const PE_MAGIC: u32 = 0x0000_4550; // "PE\0\0"
pub const OPT_MAGIC_PE32PLUS: u16 = 0x20B;

pub const MACHINE_AMD64: u16 = 0x8664;
pub const MACHINE_I386: u16 = 0x014C;
pub const MACHINE_ARM64: u16 = 0xAA64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeError {
    NotPe,
    /// 32-bit images need the WoW64 personality; refused by the 64-bit loader.
    WrongMachine(u16),
    /// Header fields describe a region outside the file.
    TruncatedHeader,
    /// A section's virtual or raw range overflows or leaves the image.
    BadSection {
        index: usize,
    },
    /// Sections overlap in virtual space.
    OverlappingSections {
        a: usize,
        b: usize,
    },
    /// Image requests a base that collides with the container's reserved range.
    BadImageBase,
    /// Relocations are stripped and the image cannot load at its preferred base.
    NotRelocatable,
    /// Section requests write and execute simultaneously.
    WriteExecute {
        index: usize,
    },
    UnsupportedSubsystem(u16),
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct CoffHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

#[derive(Debug, Clone, Copy)]
pub struct OptionalHeader {
    pub magic: u16,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub address_of_entry_point: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
}

/// `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE`. Absence means the image was not
/// built for ASLR. WhisezOS relocates it anyway -?" an application's opinion
/// about whether it wants ASLR is not binding on us -?" but records the fact,
/// because a non-ASLR image is a meaningful signal for SpectreShield's
/// heuristics.
pub const DLL_DYNAMIC_BASE: u16 = 0x0040;
pub const DLL_NX_COMPAT: u16 = 0x0100;

#[derive(Debug, Clone, Copy)]
pub struct Section {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub characteristics: u32,
}

pub const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub const SCN_MEM_READ: u32 = 0x4000_0000;
pub const SCN_MEM_WRITE: u32 = 0x8000_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Protection {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl Section {
    /// Translate PE section characteristics to page protection.
    ///
    /// The W^X enforcement lives here. Real-world PE files -?" particularly
    /// packed ones and anything built by older toolchains -?" routinely request
    /// RWX for a section. Windows honours it. We do not: the section is mapped
    /// RW, and if the code genuinely needs to execute from it, it must call
    /// `VirtualProtect`, which we translate into an explicit, logged
    /// transition. This breaks a small number of aggressive packers, which is
    /// an acceptable price and is exactly the population we least want running
    /// unconstrained.
    pub fn protection(&self) -> Result<Protection, ()> {
        let read = self.characteristics & SCN_MEM_READ != 0;
        let write = self.characteristics & SCN_MEM_WRITE != 0;
        let execute = self.characteristics & SCN_MEM_EXECUTE != 0;

        if write && execute {
            // Signal to the caller; the loader downgrades rather than failing.
            return Err(());
        }
        Ok(Protection {
            read,
            write,
            execute,
        })
    }

    pub fn name_str(&self) -> &str {
        let end = self.name.iter().position(|&b| b == 0).unwrap_or(8);
        core::str::from_utf8(&self.name[..end]).unwrap_or("<invalid>")
    }
}

/// A validated, not-yet-mapped image.
#[derive(Debug)]
pub struct ParsedImage<'a> {
    pub coff: CoffHeader,
    pub optional: OptionalHeader,
    pub sections: heapless::Vec<Section, 96>,
    pub bytes: &'a [u8],
    /// True if the image lacks DYNAMIC_BASE; forwarded to SpectreShield.
    pub aslr_opt_out: bool,
    /// True if a section requested W+X and was downgraded.
    pub had_wx_section: bool,
}

/// Parse and validate. Performs no mapping and no allocation of the image
/// itself -?" validation is complete before a single page is committed, so a
/// malformed image costs nothing but the parse.
pub fn parse(bytes: &[u8]) -> Result<ParsedImage<'_>, PeError> {
    // --- DOS header -------------------------------------------------------
    if bytes.len() < 0x40 {
        return Err(PeError::NotPe);
    }
    if read_u16(bytes, 0)? != DOS_MAGIC {
        return Err(PeError::NotPe);
    }

    let pe_offset = read_u32(bytes, 0x3C)? as usize;
    // `e_lfanew` is fully attacker-controlled and is the first place a naive
    // loader indexes out of bounds.
    if pe_offset.saturating_add(24) > bytes.len() {
        return Err(PeError::TruncatedHeader);
    }

    if read_u32(bytes, pe_offset)? != PE_MAGIC {
        return Err(PeError::NotPe);
    }

    // --- COFF header ------------------------------------------------------
    let coff_off = pe_offset + 4;
    let coff = CoffHeader {
        machine: read_u16(bytes, coff_off)?,
        number_of_sections: read_u16(bytes, coff_off + 2)?,
        time_date_stamp: read_u32(bytes, coff_off + 4)?,
        pointer_to_symbol_table: read_u32(bytes, coff_off + 8)?,
        number_of_symbols: read_u32(bytes, coff_off + 12)?,
        size_of_optional_header: read_u16(bytes, coff_off + 16)?,
        characteristics: read_u16(bytes, coff_off + 18)?,
    };

    if coff.machine != MACHINE_AMD64 {
        return Err(PeError::WrongMachine(coff.machine));
    }

    // 96 is the practical ceiling; PE permits 65535, which would let a 200-byte
    // file describe 65535 sections and exhaust the parser's budget.
    if coff.number_of_sections as usize > 96 {
        return Err(PeError::TruncatedHeader);
    }

    // --- Optional header --------------------------------------------------
    let opt_off = coff_off + size_of::<CoffHeader>();
    if coff.size_of_optional_header < 112 {
        return Err(PeError::TruncatedHeader);
    }

    let magic = read_u16(bytes, opt_off)?;
    if magic != OPT_MAGIC_PE32PLUS {
        return Err(PeError::WrongMachine(coff.machine));
    }

    let optional = OptionalHeader {
        magic,
        address_of_entry_point: read_u32(bytes, opt_off + 16)?,
        image_base: read_u64(bytes, opt_off + 24)?,
        section_alignment: read_u32(bytes, opt_off + 32)?,
        file_alignment: read_u32(bytes, opt_off + 36)?,
        size_of_image: read_u32(bytes, opt_off + 56)?,
        size_of_headers: read_u32(bytes, opt_off + 60)?,
        subsystem: read_u16(bytes, opt_off + 68)?,
        dll_characteristics: read_u16(bytes, opt_off + 70)?,
    };

    // Alignment must be a power of two and section >= file. Violating either
    // makes every subsequent RVA computation meaningless.
    if !optional.section_alignment.is_power_of_two()
        || !optional.file_alignment.is_power_of_two()
        || optional.section_alignment < optional.file_alignment
    {
        return Err(PeError::TruncatedHeader);
    }

    // Entry point must land inside the image. A zero entry point is legal for
    // a DLL but not for an executable.
    if optional.address_of_entry_point >= optional.size_of_image {
        return Err(PeError::TruncatedHeader);
    }

    // --- Sections ---------------------------------------------------------
    let sec_off = opt_off + coff.size_of_optional_header as usize;
    let mut sections = heapless::Vec::<Section, 96>::new();
    let mut had_wx = false;

    for i in 0..coff.number_of_sections as usize {
        let off = sec_off + i * 40;
        if off + 40 > bytes.len() {
            return Err(PeError::TruncatedHeader);
        }

        let mut name = [0u8; 8];
        name.copy_from_slice(&bytes[off..off + 8]);

        let section = Section {
            name,
            virtual_size: read_u32(bytes, off + 8)?,
            virtual_address: read_u32(bytes, off + 12)?,
            size_of_raw_data: read_u32(bytes, off + 16)?,
            pointer_to_raw_data: read_u32(bytes, off + 20)?,
            characteristics: read_u32(bytes, off + 36)?,
        };

        validate_section(&section, &optional, bytes.len(), i)?;

        if section.protection().is_err() {
            had_wx = true;
        }

        let _ = sections.push(section);
    }

    check_no_overlap(&sections, optional.section_alignment)?;

    Ok(ParsedImage {
        coff,
        optional,
        sections,
        bytes,
        aslr_opt_out: optional.dll_characteristics & DLL_DYNAMIC_BASE == 0,
        had_wx_section: had_wx,
    })
}

fn validate_section(
    s: &Section,
    opt: &OptionalHeader,
    file_len: usize,
    index: usize,
) -> Result<(), PeError> {
    // Raw data must lie within the file. `checked_add` rather than `+`: a
    // section claiming pointer_to_raw_data = 0xFFFFFF00 and size = 0x200 wraps
    // to a small number and passes a naive bounds check.
    let raw_end = (s.pointer_to_raw_data as u64)
        .checked_add(s.size_of_raw_data as u64)
        .ok_or(PeError::BadSection { index })?;
    if raw_end > file_len as u64 {
        return Err(PeError::BadSection { index });
    }

    // Virtual range must lie within the declared image size.
    let virt_end = (s.virtual_address as u64)
        .checked_add(s.virtual_size.max(s.size_of_raw_data) as u64)
        .ok_or(PeError::BadSection { index })?;
    if virt_end > opt.size_of_image as u64 {
        return Err(PeError::BadSection { index });
    }

    // Sections may not overlap the headers.
    if s.virtual_address < opt.size_of_headers {
        return Err(PeError::BadSection { index });
    }

    Ok(())
}

/// Sections must not overlap in virtual address space.
///
/// Overlapping sections are the mechanism behind several PE loader confusion
/// attacks: two sections claiming the same pages with different protections,
/// where the last one mapped wins and the analyst reading the header sees the
/// other. Windows tolerates this; we reject it.
fn check_no_overlap(sections: &[Section], alignment: u32) -> Result<(), PeError> {
    for i in 0..sections.len() {
        let a_start = align_down(sections[i].virtual_address, alignment) as u64;
        let a_end = align_up_u64(
            sections[i].virtual_address as u64
                + sections[i].virtual_size.max(sections[i].size_of_raw_data) as u64,
            alignment as u64,
        );

        for j in (i + 1)..sections.len() {
            let b_start = align_down(sections[j].virtual_address, alignment) as u64;
            let b_end = align_up_u64(
                sections[j].virtual_address as u64
                    + sections[j].virtual_size.max(sections[j].size_of_raw_data) as u64,
                alignment as u64,
            );

            if a_start < b_end && b_start < a_end {
                return Err(PeError::OverlappingSections { a: i, b: j });
            }
        }
    }
    Ok(())
}

fn align_down(v: u32, align: u32) -> u32 {
    v & !(align - 1)
}

fn align_up_u64(v: u64, align: u64) -> u64 {
    (v + align - 1) & !(align - 1)
}

fn read_u16(b: &[u8], off: usize) -> Result<u16, PeError> {
    b.get(off..off + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or(PeError::TruncatedHeader)
}

fn read_u32(b: &[u8], off: usize) -> Result<u32, PeError> {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or(PeError::TruncatedHeader)
}

fn read_u64(b: &[u8], off: usize) -> Result<u64, PeError> {
    b.get(off..off + 8)
        .map(|s| u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
        .ok_or(PeError::TruncatedHeader)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal valid PE32+ with one .text section.
    fn build_pe(mutate: impl Fn(&mut Vec<u8>)) -> Vec<u8> {
        let mut b = vec![0u8; 0x600];
        b[0..2].copy_from_slice(&DOS_MAGIC.to_le_bytes());
        b[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());

        let pe = 0x80usize;
        b[pe..pe + 4].copy_from_slice(&PE_MAGIC.to_le_bytes());

        let coff = pe + 4;
        b[coff..coff + 2].copy_from_slice(&MACHINE_AMD64.to_le_bytes());
        b[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes()); // 1 section
        b[coff + 16..coff + 18].copy_from_slice(&240u16.to_le_bytes()); // opt size

        let opt = coff + 20;
        b[opt..opt + 2].copy_from_slice(&OPT_MAGIC_PE32PLUS.to_le_bytes());
        b[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // entry
        b[opt + 24..opt + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
        b[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // sec align
        b[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes()); // file align
        b[opt + 56..opt + 60].copy_from_slice(&0x3000u32.to_le_bytes()); // image size
        b[opt + 60..opt + 64].copy_from_slice(&0x400u32.to_le_bytes()); // headers
        b[opt + 70..opt + 72].copy_from_slice(&(DLL_DYNAMIC_BASE | DLL_NX_COMPAT).to_le_bytes());

        let sec = opt + 240;
        b[sec..sec + 8].copy_from_slice(b".text\0\0\0");
        b[sec + 8..sec + 12].copy_from_slice(&0x100u32.to_le_bytes()); // vsize
        b[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // vaddr
        b[sec + 16..sec + 20].copy_from_slice(&0x200u32.to_le_bytes()); // raw size
        b[sec + 20..sec + 24].copy_from_slice(&0x400u32.to_le_bytes()); // raw ptr
        b[sec + 36..sec + 40].copy_from_slice(&(SCN_MEM_READ | SCN_MEM_EXECUTE).to_le_bytes());

        mutate(&mut b);
        b
    }

    #[test]
    fn valid_image_parses() {
        let bytes = build_pe(|_| {});
        let img = parse(&bytes).unwrap();
        assert_eq!(img.sections.len(), 1);
        assert_eq!(img.sections[0].name_str(), ".text");
        assert!(!img.aslr_opt_out);
    }

    #[test]
    fn non_pe_is_rejected() {
        assert_eq!(
            parse(b"not an executable at all").unwrap_err(),
            PeError::NotPe
        );
        assert_eq!(parse(&[]).unwrap_err(), PeError::NotPe);
    }

    #[test]
    fn wild_e_lfanew_does_not_index_out_of_bounds() {
        let bytes = build_pe(|b| {
            b[0x3C..0x40].copy_from_slice(&0xFFFF_FF00u32.to_le_bytes());
        });
        assert_eq!(parse(&bytes).unwrap_err(), PeError::TruncatedHeader);
    }

    #[test]
    fn raw_data_overflow_is_caught() {
        // pointer + size wraps u32; a naive check would pass this.
        let bytes = build_pe(|b| {
            let sec = 0x80 + 4 + 20 + 240;
            b[sec + 16..sec + 20].copy_from_slice(&0xFFFF_FF00u32.to_le_bytes());
            b[sec + 20..sec + 24].copy_from_slice(&0x200u32.to_le_bytes());
        });
        assert!(matches!(parse(&bytes), Err(PeError::BadSection { .. })));
    }

    #[test]
    fn section_outside_image_size_is_caught() {
        let bytes = build_pe(|b| {
            let sec = 0x80 + 4 + 20 + 240;
            b[sec + 12..sec + 16].copy_from_slice(&0x9000u32.to_le_bytes());
        });
        assert!(matches!(parse(&bytes), Err(PeError::BadSection { .. })));
    }

    #[test]
    fn section_overlapping_headers_is_caught() {
        let bytes = build_pe(|b| {
            let sec = 0x80 + 4 + 20 + 240;
            b[sec + 12..sec + 16].copy_from_slice(&0x100u32.to_le_bytes());
        });
        assert!(matches!(parse(&bytes), Err(PeError::BadSection { .. })));
    }

    #[test]
    fn absurd_section_count_is_refused() {
        let bytes = build_pe(|b| {
            let coff = 0x80 + 4;
            b[coff + 2..coff + 4].copy_from_slice(&0xFFFFu16.to_le_bytes());
        });
        assert_eq!(parse(&bytes).unwrap_err(), PeError::TruncatedHeader);
    }

    #[test]
    fn thirty_two_bit_images_are_refused_by_this_loader() {
        let bytes = build_pe(|b| {
            let coff = 0x80 + 4;
            b[coff..coff + 2].copy_from_slice(&MACHINE_I386.to_le_bytes());
        });
        assert_eq!(
            parse(&bytes).unwrap_err(),
            PeError::WrongMachine(MACHINE_I386)
        );
    }

    #[test]
    fn write_execute_section_is_flagged_not_honoured() {
        let bytes = build_pe(|b| {
            let sec = 0x80 + 4 + 20 + 240;
            b[sec + 36..sec + 40]
                .copy_from_slice(&(SCN_MEM_READ | SCN_MEM_WRITE | SCN_MEM_EXECUTE).to_le_bytes());
        });
        let img = parse(&bytes).unwrap();
        assert!(img.had_wx_section);
        assert!(img.sections[0].protection().is_err());
    }

    #[test]
    fn aslr_opt_out_is_recorded() {
        let bytes = build_pe(|b| {
            let opt = 0x80 + 4 + 20;
            b[opt + 70..opt + 72].copy_from_slice(&DLL_NX_COMPAT.to_le_bytes());
        });
        assert!(parse(&bytes).unwrap().aslr_opt_out);
    }

    #[test]
    fn non_power_of_two_alignment_is_refused() {
        let bytes = build_pe(|b| {
            let opt = 0x80 + 4 + 20;
            b[opt + 32..opt + 36].copy_from_slice(&0x1500u32.to_le_bytes());
        });
        assert_eq!(parse(&bytes).unwrap_err(), PeError::TruncatedHeader);
    }

    #[test]
    fn entry_point_outside_image_is_refused() {
        let bytes = build_pe(|b| {
            let opt = 0x80 + 4 + 20;
            b[opt + 16..opt + 20].copy_from_slice(&0x9_0000u32.to_le_bytes());
        });
        assert_eq!(parse(&bytes).unwrap_err(), PeError::TruncatedHeader);
    }
}
