//! Finding a virtio device's registers, so a driver can be told where they are.
//!
//! # Why the kernel reads this at all
//!
//! A modern virtio device does not put its registers at a fixed offset. It
//! scatters four structures — common configuration, the notification area, the
//! interrupt status byte, and the device-specific configuration — across its
//! BARs, and says where each one landed in a chain of vendor-specific PCI
//! capabilities. That chain is in configuration space, which `portauth.rs` keeps
//! out of ring 3 on purpose, so a driver cannot read it.
//!
//! This is the smallest thing the kernel can know about virtio and still hand a
//! driver something usable: five numbers, and no idea what any of them mean. It
//! does not know what a virtqueue is, what a block request looks like, or that
//! this particular device is a disk. Those are the driver's, and keeping them
//! there is the whole point of the arrangement.
//!
//! # The layout is a chain the device controls
//!
//! Same hazard as the capability list it lives in, one level down: the offsets
//! and lengths come from the device, and a device that reports a structure
//! extending past the end of its own BAR is asking the kernel to map memory
//! that is not its. Every field is checked against the BAR it names before it
//! is believed.
//!
//! # Legacy virtio is not here, deliberately
//!
//! The 0.9 transport puts its registers in a *port* BAR. PCI port windows are
//! assigned above 0x400, which is outside the I/O permission bitmap — so a
//! legacy virtio device is unreachable from ring 3 by construction, and making
//! it reachable would mean widening the bitmap to cover the whole port space.
//! That is exactly the trade `portauth.rs` argues against, so the transport
//! that fits the existing mechanism is the one supported. QEMU is asked for it
//! explicitly with `disable-legacy=on`.

#![allow(dead_code)]

use crate::pci::{self, Address, Capability, ConfigSpace};

/// The PCI vendor every virtio device reports.
pub const VENDOR: u16 = 0x1AF4;

/// Modern virtio device IDs are 0x1040 plus the device type.
pub const DEVICE_ID_BASE: u16 = 0x1040;
/// Device type 2: a block device.
pub const TYPE_BLOCK: u16 = 2;

/// `cfg_type` values inside a virtio vendor capability.
pub mod cfg {
    /// The common configuration structure: features, queue selection, status.
    pub const COMMON: u8 = 1;
    /// The notification area. Writing here tells the device a queue has work.
    pub const NOTIFY: u8 = 2;
    /// The interrupt status byte. Read to find out why an interrupt happened.
    pub const ISR: u8 = 3;
    /// Device-specific configuration — for a block device, its capacity.
    pub const DEVICE: u8 = 4;
}

/// Offsets inside a virtio vendor capability, from its start.
mod capoff {
    /// `cap_len`, the size of this capability in bytes.
    pub const CAP_LEN: u8 = 2;
    /// `cfg_type`, which says which of the four structures this describes.
    pub const CFG_TYPE: u8 = 3;
    /// Which BAR the structure is in.
    pub const BAR: u8 = 4;
    /// Offset within that BAR.
    pub const OFFSET: u8 = 8;
    /// Length of the structure.
    pub const LENGTH: u8 = 12;
    /// Only on a `NOTIFY` capability: the per-queue notification stride.
    pub const NOTIFY_MULTIPLIER: u8 = 16;
    /// Shortest capability that can hold a multiplier.
    pub const NOTIFY_MIN_LEN: u8 = 20;
}

/// Where one of the four structures lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Region {
    pub bar: u8,
    pub offset: u32,
    pub length: u32,
}

impl Region {
    #[must_use]
    pub const fn is_present(&self) -> bool {
        self.length != 0
    }

    /// One past the last byte, as a `u64` so a device reporting an offset and
    /// length that each fit in 32 bits but whose sum does not cannot wrap into
    /// looking small.
    #[must_use]
    pub const fn end(&self) -> u64 {
        self.offset as u64 + self.length as u64
    }
}

/// What a driver needs to be told to drive a virtio device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Layout {
    pub common: Region,
    pub notify: Region,
    /// Bytes between one queue's notification address and the next.
    pub notify_multiplier: u32,
    pub isr: Region,
    pub device: Region,
}

impl Layout {
    /// Whether every structure a driver cannot work without is present.
    ///
    /// The device-specific configuration is not in this list: a driver that
    /// does not need its device's capacity can work without it, and a device
    /// that omits it is unusual rather than broken.
    #[must_use]
    pub const fn is_usable(&self) -> bool {
        self.common.is_present() && self.notify.is_present() && self.isr.is_present()
    }

    /// Which BARs the layout refers to, as a bitmask.
    ///
    /// The driver needs each one mapped, and the kernel needs to know how many
    /// before it starts mapping.
    #[must_use]
    pub fn bars_used(&self) -> u8 {
        let mut mask = 0u8;
        for region in [self.common, self.notify, self.isr, self.device] {
            if region.is_present() && region.bar < 6 {
                mask |= 1 << region.bar;
            }
        }
        mask
    }
}

/// Why a device's reported layout was not believed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutError {
    /// No vendor capability described a structure a driver needs.
    Incomplete,
    /// A structure names a BAR index that does not exist.
    BadBar { cfg_type: u8, bar: u8 },
    /// A notify capability too short to hold the multiplier it must have.
    ///
    /// Its own declared length says where it ends, and reading past that reads
    /// the first bytes of the next capability — which is a plausible-looking
    /// number, not an obvious failure. Found by a test fixture that made this
    /// exact mistake.
    NotifyTooShort { cap_len: u8 },
    /// A structure claims to extend past the end of the BAR holding it.
    ///
    /// The numbers come from the device. Believing this one would mean mapping
    /// whatever physical memory follows the device's window, which is not the
    /// device's to give.
    PastEndOfBar {
        cfg_type: u8,
        end: u64,
        bar_size: u64,
    },
}

/// Reads the layout out of a device's capability list.
///
/// `bar_size` answers how large BAR *n* is, and returns `None` for a BAR that
/// is not implemented. It is a closure rather than a slice because sizing a BAR
/// needs a mutable borrow of configuration space, and this function only has a
/// shared one — so the caller sizes them first and answers from what it found.
///
/// # Safety
/// As `ConfigSpace::read`.
pub unsafe fn layout(
    space: &impl ConfigSpace,
    address: Address,
    capabilities: &[Capability],
    bar_size: impl Fn(u8) -> Option<u64>,
) -> Result<Layout, LayoutError> {
    let mut layout = Layout::default();

    for capability in capabilities {
        if capability.id != pci::CAP_VENDOR {
            continue;
        }
        // SAFETY: the caller guarantees the preconditions of `read`.
        let (type_dword, offset, length) = unsafe {
            (
                space.read(address, capability.offset + capoff::CFG_TYPE),
                space.read(address, capability.offset + capoff::OFFSET),
                space.read(address, capability.offset + capoff::LENGTH),
            )
        };
        // `CFG_TYPE` is offset 3 and `BAR` is offset 4, so the dword-granular
        // read selects the dword at capability.offset and cfg_type is its top
        // byte. The BAR index is the low byte of the next dword.
        let cfg_type = ((type_dword >> 24) & 0xFF) as u8;
        // SAFETY: as above.
        let bar = (unsafe { space.read(address, capability.offset + capoff::BAR) } & 0xFF) as u8;

        let region = Region {
            bar,
            offset,
            length,
        };
        if !region.is_present() {
            continue;
        }

        let Some(size) = bar_size(bar) else {
            return Err(LayoutError::BadBar { cfg_type, bar });
        };
        if region.end() > size {
            return Err(LayoutError::PastEndOfBar {
                cfg_type,
                end: region.end(),
                bar_size: size,
            });
        }

        match cfg_type {
            cfg::COMMON => layout.common = region,
            cfg::NOTIFY => {
                // SAFETY: as above. `CAP_LEN` is offset 2, so it is the third
                // byte of the dword at the capability's start.
                let cap_len =
                    ((unsafe { space.read(address, capability.offset + capoff::CAP_LEN) } >> 16)
                        & 0xFF) as u8;
                if cap_len < capoff::NOTIFY_MIN_LEN {
                    return Err(LayoutError::NotifyTooShort { cap_len });
                }
                layout.notify = region;
                // SAFETY: as above. Only a notify capability has this field,
                // which is why it is read here and not with the others — and
                // only after its declared length says the field is inside it.
                layout.notify_multiplier =
                    unsafe { space.read(address, capability.offset + capoff::NOTIFY_MULTIPLIER) };
            }
            cfg::ISR => layout.isr = region,
            cfg::DEVICE => layout.device = region,
            // Type 5 is the PCI configuration access window, and unknown types
            // are what a newer device reports. Neither is an error.
            _ => {}
        }
    }

    if !layout.is_usable() {
        return Err(LayoutError::Incomplete);
    }
    Ok(layout)
}

/// Whether a PCI header describes a virtio device of the given type.
#[must_use]
pub fn is_virtio(header: &pci::Header, device_type: u16) -> bool {
    header.vendor == VENDOR && header.device == DEVICE_ID_BASE + device_type
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pci::offset;

    const AT: Address = Address::new(0, 3, 0);

    /// A configuration space holding one virtio device's capabilities.
    struct FakeSpace {
        dwords: [u32; 64],
    }

    impl FakeSpace {
        fn new() -> Self {
            Self { dwords: [0; 64] }
        }

        /// Writes one virtio vendor capability at `at`.
        fn cap(&mut self, at: u8, next: u8, cfg_type: u8, bar: u8, offset: u32, length: u32) {
            // A notify capability is 20 bytes because it carries the
            // multiplier; the other three are 16. Getting this wrong in the
            // fixture is what found `NotifyTooShort`.
            let cap_len: u32 = if cfg_type == cfg::NOTIFY { 20 } else { 16 };
            let slot = (at / 4) as usize;
            self.dwords[slot] = u32::from(pci::CAP_VENDOR)
                | u32::from(next) << 8
                | cap_len << 16
                | u32::from(cfg_type) << 24;
            self.dwords[slot + 1] = u32::from(bar);
            self.dwords[slot + 2] = offset;
            self.dwords[slot + 3] = length;
        }

        fn set(&mut self, offset: u8, value: u32) {
            self.dwords[(offset / 4) as usize] = value;
        }
    }

    impl ConfigSpace for FakeSpace {
        unsafe fn read(&self, address: Address, offset: u8) -> u32 {
            if address != AT {
                return u32::MAX;
            }
            self.dwords[(offset / 4) as usize]
        }
        unsafe fn write(&mut self, _address: Address, _offset: u8, _value: u32) {}
    }

    /// The four capabilities a usable device has, laid out as QEMU lays them.
    fn complete_device() -> (FakeSpace, [Capability; 4]) {
        let mut space = FakeSpace::new();
        // Spaced as a real device spaces them: notify is 20 bytes, so the one
        // after it starts at 0x64 rather than 0x60.
        space.cap(0x40, 0x50, cfg::COMMON, 4, 0x0000, 0x38);
        space.cap(0x50, 0x64, cfg::NOTIFY, 4, 0x3000, 0x1000);
        space.set(0x50 + capoff::NOTIFY_MULTIPLIER, 4);
        space.cap(0x64, 0x74, cfg::ISR, 4, 0x1000, 0x1000);
        space.cap(0x74, 0x00, cfg::DEVICE, 4, 0x2000, 0x1000);

        let caps = [
            Capability {
                id: pci::CAP_VENDOR,
                offset: 0x40,
            },
            Capability {
                id: pci::CAP_VENDOR,
                offset: 0x50,
            },
            Capability {
                id: pci::CAP_VENDOR,
                offset: 0x64,
            },
            Capability {
                id: pci::CAP_VENDOR,
                offset: 0x74,
            },
        ];
        (space, caps)
    }

    /// A 16 KiB BAR 4, and nothing else implemented.
    fn only_bar_four(bar: u8) -> Option<u64> {
        if bar == 4 {
            Some(0x4000)
        } else {
            None
        }
    }

    #[test]
    fn a_complete_device_yields_every_region() {
        let (space, caps) = complete_device();
        // SAFETY: the fake touches no hardware.
        let layout = unsafe { layout(&space, AT, &caps, only_bar_four) }.unwrap();

        assert_eq!(
            layout.common,
            Region {
                bar: 4,
                offset: 0,
                length: 0x38
            }
        );
        assert_eq!(layout.notify.offset, 0x3000);
        assert_eq!(layout.notify_multiplier, 4);
        assert_eq!(layout.isr.offset, 0x1000);
        assert_eq!(layout.device.offset, 0x2000);
        assert!(layout.is_usable());
    }

    #[test]
    fn every_region_in_one_bar_produces_one_bit_in_the_mask() {
        let (space, caps) = complete_device();
        // SAFETY: the fake touches no hardware.
        let layout = unsafe { layout(&space, AT, &caps, only_bar_four) }.unwrap();
        assert_eq!(layout.bars_used(), 1 << 4);
    }

    #[test]
    fn a_device_missing_the_common_structure_is_not_usable() {
        // Without it there is no way to negotiate features or start a queue, so
        // reporting the device as present would hand a driver something it
        // cannot drive.
        let (mut space, caps) = complete_device();
        space.cap(0x40, 0x50, cfg::COMMON, 4, 0, 0);
        // SAFETY: the fake touches no hardware.
        assert_eq!(
            unsafe { layout(&space, AT, &caps, only_bar_four) },
            Err(LayoutError::Incomplete)
        );
    }

    #[test]
    fn a_structure_in_a_bar_that_does_not_exist_is_refused() {
        let (mut space, caps) = complete_device();
        space.cap(0x64, 0x74, cfg::ISR, 2, 0x1000, 0x1000);
        // SAFETY: the fake touches no hardware.
        assert_eq!(
            unsafe { layout(&space, AT, &caps, only_bar_four) },
            Err(LayoutError::BadBar {
                cfg_type: cfg::ISR,
                bar: 2
            })
        );
    }

    #[test]
    fn a_structure_running_past_the_end_of_its_bar_is_refused() {
        // The offset and length come from the device. Believing this one means
        // mapping whatever physical memory follows the device's window, which
        // is not the device's to give.
        let (mut space, caps) = complete_device();
        space.cap(0x74, 0x00, cfg::DEVICE, 4, 0x3F00, 0x1000);
        // SAFETY: the fake touches no hardware.
        assert_eq!(
            unsafe { layout(&space, AT, &caps, only_bar_four) },
            Err(LayoutError::PastEndOfBar {
                cfg_type: cfg::DEVICE,
                end: 0x4F00,
                bar_size: 0x4000,
            })
        );
    }

    #[test]
    fn an_offset_and_length_that_overflow_a_u32_do_not_wrap_into_looking_small() {
        // Each field fits in 32 bits; their sum does not. Computed in 32 bits
        // this pair looks like a tiny region at the start of the BAR.
        let region = Region {
            bar: 4,
            offset: 0xFFFF_F000,
            length: 0x2000,
        };
        assert_eq!(region.end(), 0x1_0000_1000);
        assert!(region.end() > 0x4000);
    }

    #[test]
    fn a_non_vendor_capability_is_skipped_rather_than_decoded() {
        // MSI-X sits in the same list. Decoding its bytes as a virtio
        // capability would produce a region from whatever they happen to be.
        let (mut space, mut caps) = complete_device();
        caps[3] = Capability {
            id: pci::CAP_MSIX,
            offset: 0x74,
        };
        space.cap(0x74, 0x00, cfg::DEVICE, 4, 0x2000, 0x1000);

        // SAFETY: the fake touches no hardware.
        let layout = unsafe { layout(&space, AT, &caps, only_bar_four) }.unwrap();
        assert!(layout.is_usable());
        assert!(
            !layout.device.is_present(),
            "an MSI-X capability was read as a virtio one"
        );
    }

    #[test]
    fn an_unknown_cfg_type_is_ignored_rather_than_being_an_error() {
        // Type 5 is the configuration access window, and a newer device may
        // report types this build has never heard of. Neither is a reason to
        // refuse a device whose required structures are all present.
        let (mut space, caps) = complete_device();
        space.cap(0x74, 0x00, 5, 4, 0x2000, 0x1000);
        // SAFETY: the fake touches no hardware.
        let layout = unsafe { layout(&space, AT, &caps, only_bar_four) }.unwrap();
        assert!(layout.is_usable());
    }

    #[test]
    fn a_virtio_block_device_is_recognised_and_a_network_one_is_not() {
        let block = pci::Header {
            vendor: VENDOR,
            device: DEVICE_ID_BASE + TYPE_BLOCK,
            class: 1,
            subclass: 0,
            prog_if: 0,
            revision: 1,
            header_type: 0,
            subsystem: 0,
            interrupt_line: 11,
            interrupt_pin: 1,
            has_capabilities: true,
        };
        assert!(is_virtio(&block, TYPE_BLOCK));

        let network = pci::Header {
            device: DEVICE_ID_BASE + 1,
            ..block
        };
        assert!(!is_virtio(&network, TYPE_BLOCK));

        let impostor = pci::Header {
            vendor: 0x8086,
            ..block
        };
        assert!(!is_virtio(&impostor, TYPE_BLOCK));
    }

    #[test]
    fn a_notify_capability_too_short_to_hold_its_multiplier_is_refused() {
        // The multiplier is at offset 16, so a 16-byte notify capability does
        // not contain it and reading there reads the next capability's header
        // — which is a plausible-looking stride, not an obvious failure. This
        // is the bug the fixture had before it was corrected.
        let (mut space, caps) = complete_device();
        let slot = 0x50usize / 4;
        space.dwords[slot] =
            u32::from(pci::CAP_VENDOR) | 0x64u32 << 8 | 16u32 << 16 | u32::from(cfg::NOTIFY) << 24;

        // SAFETY: the fake touches no hardware.
        assert_eq!(
            unsafe { layout(&space, AT, &caps, only_bar_four) },
            Err(LayoutError::NotifyTooShort { cap_len: 16 })
        );
    }

    #[test]
    fn a_region_of_no_length_is_not_present() {
        // A device reports an absent structure as a zero length, and treating
        // that as a region at offset zero would point a driver at the start of
        // the BAR — which is a different structure.
        assert!(!Region::default().is_present());
        let _ = offset::BAR0;
    }
}
