//! The device table, and the authority to reach it.
//!
//! This is what a user-space driver stands on. The microkernel claim in
//! `ARCHITECTURE.md` — every driver except the GPU is an ordinary process — is
//! not a claim about code layout, it is a claim about privilege: a driver must
//! be able to touch its device's registers and nothing else. That needs a
//! kernel that can hand out one device without handing out memory.
//!
//! # A process names an index, never an address
//!
//! The obvious system call is `map(physical, length)`. It is also the end of
//! the security model: physical addresses include the kernel's own image, every
//! other process's pages, and the page tables. Validating the range against a
//! list of permitted devices would work, but then the process is still choosing
//! the address and the kernel is checking its arithmetic — a check that has to
//! be right every time against an argument chosen to make it wrong.
//!
//! So the kernel keeps the list, and a process asks for entry *n*. It cannot
//! express a request for anything not on the list, which is a stronger
//! statement than "requests for other things are refused".
//!
//! # The list is short and static
//!
//! Two entries: the framebuffer the firmware left running, and the ticker —
//! the RTC's periodic interrupt, which is a device consisting of nothing but
//! an interrupt and is therefore the one that can demonstrate interrupt
//! delivery before any real driver exists. Discovery — PCI enumeration, ACPI
//! tables — is what fills this in for real, and none of it exists yet. What
//! matters now is that the mechanism is the one that will still be right when
//! it does.
//!
//! # A device is a window, an interrupt, or both
//!
//! `extent` answers where a device's registers are and `line` answers which
//! interrupt it raises, and a device may have neither, either, or both. Both
//! are kernel-only for the same reason: they are facts about how the machine is
//! wired, and a process that could name one directly could name another
//! process's.

#![allow(dead_code)]

use spin::Mutex;

use crate::abi::SyscallError;
use crate::boot_info::BootInfo;

/// Devices the kernel can describe.
pub const MAX_DEVICES: usize = 8;

/// What a device is, so a driver can tell what it was handed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DeviceKind {
    /// Nothing here.
    None = 0,
    /// A linear framebuffer, already configured by the firmware.
    Framebuffer = 1,
    /// A periodic interrupt source with no registers worth mapping.
    ///
    /// The whole of this device is its interrupt, which is what makes it the
    /// one that can demonstrate delivery before any driver exists.
    Ticker = 2,
}

/// One device, as user space sees it.
///
/// `#[repr(C)]` because it is copied into a process's buffer; the layout is
/// part of the ABI, like `BootInfo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct DeviceInfo {
    pub kind: u32,
    pub _pad: u32,
    /// Bytes the mapping covers.
    pub length: u64,
    /// Geometry, meaningful for a framebuffer and zero otherwise. Not a
    /// physical address: a driver has no use for one, and telling it would be
    /// telling it where everything else is not.
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub bytes_per_pixel: u32,
}

impl DeviceInfo {
    pub const EMPTY: Self = Self {
        kind: DeviceKind::None as u32,
        _pad: 0,
        length: 0,
        width: 0,
        height: 0,
        stride: 0,
        bytes_per_pixel: 0,
    };
}

const _: () = assert!(core::mem::size_of::<DeviceInfo>() == 32);

/// The kernel's private half of an entry.
#[derive(Debug, Clone, Copy)]
struct Entry {
    info: DeviceInfo,
    /// Where it actually is. Never leaves the kernel.
    phys: u64,
    /// The interrupt line this device raises, if it raises one.
    ///
    /// Kernel-side like `phys`, and for the same reason: a line number is a
    /// property of how the machine is wired, and a process that could name one
    /// directly could name somebody else's.
    line: Option<usize>,
}

impl Entry {
    const EMPTY: Self = Self {
        info: DeviceInfo::EMPTY,
        phys: 0,
        line: None,
    };

    const fn is_present(&self) -> bool {
        self.info.kind != DeviceKind::None as u32
    }
}

struct Table {
    entries: [Entry; MAX_DEVICES],
    len: usize,
    /// The token that grants access to this table. Zero until issued.
    grant: u64,
}

static TABLE: Mutex<Table> = Mutex::new(Table {
    entries: [Entry::EMPTY; MAX_DEVICES],
    len: 0,
    grant: 0,
});

/// Fills the table from the handoff and issues the grant.
///
/// Returns the token a process must hold to use any of this. One token for the
/// whole table is coarser than the architecture's per-device capabilities, and
/// is where this becomes per-device once `cap.rs` links — the shape of the
/// system call does not change, only what the token names.
pub fn init(boot: &BootInfo, grant: u64) -> usize {
    let mut table = TABLE.lock();
    table.len = 0;
    table.grant = grant;

    if boot.framebuffer.is_present() {
        if let Some(length) = boot.framebuffer.byte_len() {
            table.entries[0] = Entry {
                info: DeviceInfo {
                    kind: DeviceKind::Framebuffer as u32,
                    _pad: 0,
                    length,
                    width: boot.framebuffer.width,
                    height: boot.framebuffer.height,
                    stride: boot.framebuffer.stride,
                    bytes_per_pixel: boot.framebuffer.bytes_per_pixel,
                },
                phys: boot.framebuffer.base,
                line: None,
            };
            table.len = 1;
        }
    }

    // The ticker. Always listed, because unlike the framebuffer it does not
    // depend on anything the firmware did — the RTC is on every machine this
    // targets, and its periodic interrupt is off until the kernel arms it.
    //
    // `length` is zero and there is nothing to map: this device is its
    // interrupt. `SYS_MAP_DEVICE` refuses a zero-length extent, which is the
    // right answer rather than a special case — there is no window here to map.
    let slot = table.len;
    table.entries[slot] = Entry {
        info: DeviceInfo {
            kind: DeviceKind::Ticker as u32,
            _pad: 0,
            length: 0,
            width: 0,
            height: 0,
            stride: 0,
            bytes_per_pixel: 0,
        },
        phys: 0,
        line: Some(TICKER_LINE),
    };
    table.len = slot + 1;

    table.len
}

/// The interrupt line the ticker is wired to.
///
/// Line zero because it is the first, and because `arch::start_device_interrupt`
/// takes the same number — one place decides, and both ends read it from here.
pub const TICKER_LINE: usize = 0;

/// Checks a grant and an index together.
///
/// One answer for "wrong token" and "no such device", for the same reason
/// `BadEndpoint` is one answer: telling a process that index seven exists but
/// it may not have it is telling it something a token is supposed to withhold.
fn lookup(grant: u64, index: u64) -> Result<Entry, SyscallError> {
    let table = TABLE.lock();
    if grant == 0 || grant != table.grant {
        return Err(SyscallError::NotPermitted);
    }
    let index = usize::try_from(index).map_err(|_| SyscallError::NotPermitted)?;
    if index >= table.len || !table.entries[index].is_present() {
        return Err(SyscallError::NotPermitted);
    }
    Ok(table.entries[index])
}

/// Describes device `index` to a holder of `grant`.
pub fn describe(grant: u64, index: u64) -> Result<DeviceInfo, SyscallError> {
    Ok(lookup(grant, index)?.info)
}

/// The interrupt line device `index` raises.
///
/// Kernel-only, like `extent`: the returned number is what a process is never
/// told, so that it can ask to wait for *its* device's interrupt and cannot
/// express a request to wait for anyone else's.
pub fn line(grant: u64, index: u64) -> Result<usize, SyscallError> {
    lookup(grant, index)?.line.ok_or(SyscallError::NotPermitted)
}

/// The physical extent of device `index`, for the mapper.
///
/// Kernel-only: the returned address is exactly what user space is never told.
pub fn extent(grant: u64, index: u64) -> Result<(u64, u64), SyscallError> {
    let entry = lookup(grant, index)?;
    Ok((entry.phys, entry.info.length))
}

/// How many devices the table holds.
#[must_use]
pub fn count() -> usize {
    TABLE.lock().len
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boot_info::Framebuffer;

    fn boot_with_framebuffer() -> BootInfo {
        let mut info = BootInfo::empty();
        info.framebuffer = Framebuffer {
            base: 0x8000_0000,
            width: 1280,
            height: 800,
            stride: 1280,
            bytes_per_pixel: 4,
        };
        info
    }

    const GRANT: u64 = 0xABCD_1234_5678_9EF0;

    #[test]
    fn a_framebuffer_in_the_handoff_becomes_the_first_device() {
        // Two devices: the framebuffer, and the ticker that is always listed.
        assert_eq!(init(&boot_with_framebuffer(), GRANT), 2);
        let info = describe(GRANT, 0).unwrap();
        assert_eq!(info.kind, DeviceKind::Framebuffer as u32);
        assert_eq!(info.width, 1280);
        assert_eq!(info.length, 1280 * 800 * 4);
    }

    #[test]
    fn the_ticker_is_listed_whatever_the_firmware_left_behind() {
        // Unlike the framebuffer it depends on nothing the firmware did, so it
        // is the one device a driver can always count on being there — and with
        // no framebuffer it moves to index zero rather than leaving a hole.
        assert_eq!(init(&BootInfo::empty(), GRANT), 1);
        let info = describe(GRANT, 0).unwrap();
        assert_eq!(info.kind, DeviceKind::Ticker as u32);
        assert_eq!(line(GRANT, 0), Ok(TICKER_LINE));
    }

    #[test]
    fn a_device_with_no_interrupt_has_no_line_to_wait_on() {
        // The framebuffer raises nothing, and asking to wait for its interrupt
        // must be refused rather than answered with line zero — which belongs
        // to a different device.
        init(&boot_with_framebuffer(), GRANT);
        assert_eq!(line(GRANT, 0), Err(SyscallError::NotPermitted));
        assert_eq!(line(GRANT, 1), Ok(TICKER_LINE));
    }

    #[test]
    fn a_line_needs_the_grant_like_everything_else() {
        init(&boot_with_framebuffer(), GRANT);
        assert_eq!(line(GRANT ^ 1, 1), Err(SyscallError::NotPermitted));
        assert_eq!(line(0, 1), Err(SyscallError::NotPermitted));
    }

    #[test]
    fn the_ticker_has_nothing_to_map() {
        // Its length is zero, and `map_device` refuses a zero-length extent —
        // so a driver that treats every device as mappable is told no rather
        // than handed an empty window it will write through.
        init(&boot_with_framebuffer(), GRANT);
        assert_eq!(extent(GRANT, 1), Ok((0, 0)));
    }

    #[test]
    fn the_wrong_token_is_refused() {
        init(&boot_with_framebuffer(), GRANT);
        assert_eq!(describe(GRANT ^ 1, 0), Err(SyscallError::NotPermitted));
        assert_eq!(extent(GRANT ^ 1, 0), Err(SyscallError::NotPermitted));
    }

    #[test]
    fn a_zero_token_is_refused_even_before_a_grant_is_issued() {
        // A process that was given nothing holds zero, and zero must never
        // match — including against a table whose grant has not been set.
        init(&BootInfo::empty(), 0);
        assert_eq!(describe(0, 0), Err(SyscallError::NotPermitted));
    }

    #[test]
    fn an_index_past_the_end_is_refused_the_same_way_as_a_bad_token() {
        // Distinguishing them would tell a process how many devices exist.
        init(&boot_with_framebuffer(), GRANT);
        assert_eq!(describe(GRANT, 2), Err(SyscallError::NotPermitted));
        assert_eq!(describe(GRANT, u64::MAX), Err(SyscallError::NotPermitted));
        assert_eq!(describe(GRANT ^ 1, 0), describe(GRANT, 99));
    }

    #[test]
    fn the_physical_address_is_kernel_only() {
        // `DeviceInfo` is what user space receives, and it has nowhere to put a
        // physical address. This is the test that fails if a field is added.
        init(&boot_with_framebuffer(), GRANT);
        let (phys, len) = extent(GRANT, 0).unwrap();
        assert_eq!(phys, 0x8000_0000);
        assert_eq!(len, 1280 * 800 * 4);

        let info = describe(GRANT, 0).unwrap();
        let bytes: [u8; core::mem::size_of::<DeviceInfo>()] = unsafe { core::mem::transmute(info) };
        let needle = phys.to_le_bytes();
        assert!(
            !bytes.windows(needle.len()).any(|w| w == needle),
            "the physical address leaked into what user space is given"
        );
    }

    #[test]
    fn an_inconsistent_framebuffer_is_not_listed() {
        // Stride below width means the geometry is wrong, and a length computed
        // from it would map less than the driver goes on to write.
        let mut boot = boot_with_framebuffer();
        boot.framebuffer.stride = 16;
        // One device left, and it is the ticker rather than a framebuffer whose
        // geometry does not add up.
        assert_eq!(init(&boot, GRANT), 1);
        assert_eq!(describe(GRANT, 0).unwrap().kind, DeviceKind::Ticker as u32);
    }
}
