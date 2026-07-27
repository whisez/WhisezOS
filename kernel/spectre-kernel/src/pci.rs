//! PCI enumeration: finding out what is actually in the machine.
//!
//! `device.rs` has been listing two devices, one from the firmware handoff and
//! one hardcoded, with a comment saying discovery is what fills it in for real.
//! This is that. Everything past the framebuffer — a disk, a network card,
//! anything with a driver worth writing — is on the PCI bus and invisible until
//! somebody walks it.
//!
//! # Why the kernel walks it and a driver cannot
//!
//! Configuration space is reached through ports 0xCF8 and 0xCFC, and
//! `portauth.rs` puts those beyond the I/O bitmap deliberately: a process that
//! could write 0xCF8 could relocate every device in the machine, including into
//! the middle of another process's memory. So enumeration is kernel work by
//! construction, not by preference. What a driver gets is the result — one
//! device, its windows, its interrupt — through the same grant mechanism as the
//! framebuffer.
//!
//! That is also why this file is the last place the kernel needs to understand
//! hardware. It learns what exists and where; what any of it *does* is a
//! driver's problem.
//!
//! # The mechanism is a register pair, and it is a protocol
//!
//! Writing an address to 0xCF8 and then reading 0xCFC returns a dword of that
//! device's configuration space. Two accesses that must not be separated, like
//! the I/O APIC's selector and window — and for the same reason the accessor is
//! `unsafe` and every caller runs with interrupts off.
//!
//! # Almost none of this file touches a port
//!
//! Address encoding, header decoding, BAR sizing, capability walking: all of it
//! is arithmetic over dwords that came from somewhere. `ConfigSpace` is that
//! somewhere, and the real one is forty lines in `arch/pci.rs`. Everything else
//! is tested on the host against a synthetic device, which is how BAR sizing —
//! a write-then-read-then-restore sequence that is easy to get subtly wrong and
//! destructive when it is — gets covered without a machine.

#![allow(dead_code)]

/// A device's address on the bus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Address {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl Address {
    #[must_use]
    pub const fn new(bus: u8, device: u8, function: u8) -> Self {
        Self {
            bus,
            device,
            function,
        }
    }

    /// The dword written to 0xCF8 to select `offset` in this device's space.
    ///
    /// Bit 31 is the enable bit; without it the access is ignored and the read
    /// returns whatever the last one did. The low two bits of the offset are
    /// masked off because the mechanism is dword-granular — an offset of 2 and
    /// an offset of 0 select the same dword, and the caller extracts the half
    /// it wanted.
    #[must_use]
    pub const fn config_address(&self, offset: u8) -> u32 {
        1 << 31
            | (self.bus as u32) << 16
            | ((self.device as u32) & 0x1F) << 11
            | ((self.function as u32) & 0x07) << 8
            | (offset as u32) & 0xFC
    }
}

/// Configuration space, as something that can be read and written.
///
/// A trait so the walking above it can be tested against a device that does not
/// exist. The real implementation is two port accesses.
pub trait ConfigSpace {
    /// Reads the dword at `offset`. Must return `u32::MAX` for an absent
    /// device, which is what the bus does when nothing answers.
    ///
    /// # Safety
    /// The implementation touches ports; the caller must have interrupts off so
    /// the address/data pair cannot be interposed.
    unsafe fn read(&self, address: Address, offset: u8) -> u32;

    /// # Safety
    /// As `read`, and additionally: writing configuration space can move a
    /// device's windows. Only BAR sizing writes here, and it restores what it
    /// found.
    unsafe fn write(&mut self, address: Address, offset: u8, value: u32);
}

/// Nothing answered at this address.
pub const NO_DEVICE: u16 = 0xFFFF;

/// Offsets in the type 0 configuration header.
pub mod offset {
    pub const VENDOR_ID: u8 = 0x00;
    pub const DEVICE_ID: u8 = 0x02;
    pub const COMMAND: u8 = 0x04;
    pub const STATUS: u8 = 0x06;
    pub const REVISION: u8 = 0x08;
    pub const CLASS: u8 = 0x0B;
    pub const HEADER_TYPE: u8 = 0x0E;
    /// First of six base address registers.
    pub const BAR0: u8 = 0x10;
    pub const SUBSYSTEM_VENDOR: u8 = 0x2C;
    pub const SUBSYSTEM_ID: u8 = 0x2E;
    pub const CAPABILITIES: u8 = 0x34;
    pub const INTERRUPT_LINE: u8 = 0x3C;
    pub const INTERRUPT_PIN: u8 = 0x3D;
}

/// Command register bits worth naming.
pub mod command {
    /// Respond to memory accesses in this device's memory BARs.
    pub const MEMORY_SPACE: u16 = 1 << 1;
    /// Act as a bus master, which is what DMA needs.
    pub const BUS_MASTER: u16 = 1 << 2;
    /// Suppress the legacy INTx line. Set when using MSI-X, clear otherwise.
    pub const INTERRUPT_DISABLE: u16 = 1 << 10;
}

/// Status register bit 4: a capability list is present.
const STATUS_CAPABILITIES: u16 = 1 << 4;

/// Header type bit 7: this device has functions beyond function 0.
const HEADER_MULTIFUNCTION: u8 = 1 << 7;

/// The parts of a configuration header worth carrying around.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub vendor: u16,
    pub device: u16,
    pub class: u8,
    pub subclass: u8,
    pub prog_if: u8,
    pub revision: u8,
    /// Low seven bits: 0 is an ordinary device, 1 a bridge.
    pub header_type: u8,
    pub subsystem: u16,
    /// The ISA IRQ the firmware wired this device to, if any. `0xFF` means
    /// none, and is what a device using MSI reports.
    pub interrupt_line: u8,
    pub interrupt_pin: u8,
    pub has_capabilities: bool,
}

impl Header {
    #[must_use]
    pub const fn is_multifunction(&self) -> bool {
        self.header_type & HEADER_MULTIFUNCTION != 0
    }

    /// Type 0 is an ordinary device; type 1 is a bridge, whose header has a
    /// different layout and only two BARs.
    #[must_use]
    pub const fn is_bridge(&self) -> bool {
        self.header_type & 0x7F == 1
    }
}

/// Reads a device's header, or `None` if nothing is there.
///
/// # Safety
/// As `ConfigSpace::read`.
pub unsafe fn header(space: &impl ConfigSpace, address: Address) -> Option<Header> {
    // SAFETY: the caller guarantees the preconditions of `read`.
    let identity = unsafe { space.read(address, offset::VENDOR_ID) };
    let vendor = (identity & 0xFFFF) as u16;
    // An absent device leaves the bus floating, which reads as all-ones. Vendor
    // zero is not architecturally reserved but no real device uses it, and
    // treating it as absent costs nothing.
    if vendor == NO_DEVICE || vendor == 0 {
        return None;
    }

    // SAFETY: as above.
    let (status_command, class_revision, header_dword, interrupt, subsystem) = unsafe {
        (
            space.read(address, offset::COMMAND),
            space.read(address, offset::REVISION),
            space.read(address, offset::HEADER_TYPE),
            space.read(address, offset::INTERRUPT_LINE),
            space.read(address, offset::SUBSYSTEM_VENDOR),
        )
    };

    Some(Header {
        vendor,
        device: (identity >> 16) as u16,
        revision: (class_revision & 0xFF) as u8,
        prog_if: ((class_revision >> 8) & 0xFF) as u8,
        subclass: ((class_revision >> 16) & 0xFF) as u8,
        class: ((class_revision >> 24) & 0xFF) as u8,
        // `HEADER_TYPE` is 0x0E, which is the third byte of the dword at 0x0C.
        header_type: ((header_dword >> 16) & 0xFF) as u8,
        subsystem: (subsystem >> 16) as u16,
        interrupt_line: (interrupt & 0xFF) as u8,
        interrupt_pin: ((interrupt >> 8) & 0xFF) as u8,
        has_capabilities: ((status_command >> 16) as u16) & STATUS_CAPABILITIES != 0,
    })
}

/// One base address register, decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bar {
    /// A memory window. `base` is physical.
    Memory {
        base: u64,
        size: u64,
        prefetchable: bool,
        /// Whether this BAR consumed the next slot as its upper half.
        is_64: bool,
    },
    /// A port window. Reachable from ring 3 only if `portauth` permits it,
    /// which for anything a PCI device is assigned it does not — those live
    /// above the bitmap.
    Io { base: u16, size: u32 },
}

impl Bar {
    #[must_use]
    pub const fn slots_consumed(&self) -> usize {
        match self {
            Bar::Memory { is_64: true, .. } => 2,
            _ => 1,
        }
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        match self {
            Bar::Memory { size, .. } => *size == 0,
            Bar::Io { size, .. } => *size == 0,
        }
    }
}

/// Reads and sizes BAR `index`.
///
/// # How sizing works, and why it is briefly destructive
///
/// A BAR has no size field. The device implements only the address bits it
/// needs, so writing all-ones and reading back leaves zeros in the bits it does
/// not decode — the size is the low bit of what comes back. There is no way to
/// learn it without writing, which means the device's window is momentarily
/// pointed somewhere absurd, and the original value has to go back before
/// anything touches it.
///
/// This is why sizing happens during bring-up with interrupts off and before
/// any driver exists, and why the restore is not conditional on anything.
///
/// # Safety
/// As `ConfigSpace::write`. Must not run while any driver could access the
/// device, because for the duration of this call the device's window is not
/// where the driver thinks it is.
pub unsafe fn bar(space: &mut impl ConfigSpace, address: Address, index: usize) -> Option<Bar> {
    if index >= 6 {
        return None;
    }
    let slot = offset::BAR0 + (index as u8) * 4;

    // SAFETY: the caller guarantees the preconditions.
    let original = unsafe { space.read(address, slot) };
    // SAFETY: as above. The restore below is what makes this safe to do at all.
    let mask = unsafe {
        space.write(address, slot, u32::MAX);
        let probed = space.read(address, slot);
        space.write(address, slot, original);
        probed
    };

    if original & 1 != 0 {
        // Port window. Bit 0 set, address in bits 31:2.
        let base = (original & 0xFFFF_FFFC) as u16;
        let size = !(mask & 0xFFFF_FFFC) + 1;
        return Some(Bar::Io { base, size });
    }

    let kind = (original >> 1) & 0x3;
    let prefetchable = original & (1 << 3) != 0;
    let is_64 = kind == 0x2;

    // An unimplemented BAR decodes no address bits at all, so the probe reads
    // back as zeros. This has to be checked on the raw dword, before the
    // sign-extension below fills the upper half in — extending first makes an
    // absent BAR look like a 4 GiB window, which is then handed to the mapper.
    if mask & 0xFFFF_FFF0 == 0 && !is_64 {
        return Some(Bar::Memory {
            base: 0,
            size: 0,
            prefetchable,
            is_64: false,
        });
    }

    let (base, mask) = if is_64 {
        let upper_slot = slot + 4;
        // SAFETY: as above; a 64-bit BAR owns the next slot as its upper half.
        let upper = unsafe { space.read(address, upper_slot) };
        // SAFETY: as above — same probe-and-restore on the BAR's upper half.
        let upper_mask = unsafe {
            let previous = space.read(address, upper_slot);
            space.write(address, upper_slot, u32::MAX);
            let probed = space.read(address, upper_slot);
            space.write(address, upper_slot, previous);
            probed
        };
        (
            u64::from(original & 0xFFFF_FFF0) | u64::from(upper) << 32,
            u64::from(mask & 0xFFFF_FFF0) | u64::from(upper_mask) << 32,
        )
    } else {
        (
            u64::from(original & 0xFFFF_FFF0),
            u64::from(mask & 0xFFFF_FFF0) | 0xFFFF_FFFF_0000_0000,
        )
    };

    // An unimplemented BAR reads back as all zeros after the probe, and `!0 + 1`
    // would wrap to zero — which is the answer wanted, but by accident. Say it
    // deliberately instead.
    let size = if mask == 0 {
        0
    } else {
        (!mask).wrapping_add(1)
    };

    Some(Bar::Memory {
        base,
        size,
        prefetchable,
        is_64,
    })
}

/// One entry in a device's capability list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capability {
    pub id: u8,
    /// Where the capability structure starts in configuration space.
    pub offset: u8,
}

/// Vendor-specific capability. Virtio uses it for everything.
pub const CAP_VENDOR: u8 = 0x09;
/// MSI-X.
pub const CAP_MSIX: u8 = 0x11;

/// Capabilities a device can hold before the walk gives up.
///
/// The list is a chain of pointers in memory the device controls, so a
/// malfunctioning or hostile device can make it a cycle. A bound is the
/// difference between a bad device and a kernel that never finishes booting.
const MAX_CAPABILITIES: usize = 32;

/// Walks a device's capability list into `out`, returning how many were found.
///
/// # Safety
/// As `ConfigSpace::read`.
pub unsafe fn capabilities(
    space: &impl ConfigSpace,
    address: Address,
    header: &Header,
    out: &mut [Capability],
) -> usize {
    if !header.has_capabilities {
        return 0;
    }

    // SAFETY: the caller guarantees the preconditions.
    let mut pointer = (unsafe { space.read(address, offset::CAPABILITIES) } & 0xFC) as u8;
    let mut found = 0usize;
    let mut steps = 0usize;

    while pointer != 0 && found < out.len() && steps < MAX_CAPABILITIES {
        steps += 1;
        // A capability inside the header itself is malformed: the first 64
        // bytes are the standard header and cannot hold one.
        if pointer < 0x40 {
            break;
        }
        // SAFETY: as above.
        let entry = unsafe { space.read(address, pointer) };
        out[found] = Capability {
            id: (entry & 0xFF) as u8,
            offset: pointer,
        };
        found += 1;
        pointer = ((entry >> 8) & 0xFC) as u8;
    }

    found
}

/// Devices a scan will report before it stops.
pub const MAX_DEVICES_SCANNED: usize = 32;

/// Walks bus zero and calls `found` for every device that answers.
///
/// # What this does not do
///
/// It does not recurse through bridges. Everything QEMU's q35 puts a disk or a
/// network card on is on bus zero, and a recursive scan needs bridge secondary
/// bus numbers and a visited set to survive a loop. When there is a machine here
/// that needs it, it comes with the tests for it.
///
/// # Safety
/// As `ConfigSpace::read`.
pub unsafe fn scan_bus_zero(space: &impl ConfigSpace, mut found: impl FnMut(Address, Header)) {
    for device in 0..32u8 {
        let base = Address::new(0, device, 0);
        // SAFETY: the caller guarantees the preconditions.
        let Some(first) = (unsafe { header(space, base) }) else {
            continue;
        };
        let multifunction = first.is_multifunction();
        found(base, first);

        if !multifunction {
            continue;
        }
        for function in 1..8u8 {
            let address = Address::new(0, device, function);
            // SAFETY: as above.
            if let Some(other) = unsafe { header(space, address) } {
                found(address, other);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A configuration space with one device in it.
    ///
    /// Dwords are stored by offset, so a test can describe exactly the device it
    /// wants and nothing else answers. This is what makes BAR sizing testable:
    /// the fake implements the same write-all-ones-read-back behaviour a real
    /// device does, including only decoding the bits it claims.
    struct FakeSpace {
        address: Address,
        dwords: [u32; 64],
        /// Which bits of each BAR the device actually implements. Zero means
        /// the BAR is not implemented at all.
        bar_masks: [u32; 6],
        /// Set while a BAR holds the probe value rather than its address.
        probing: [bool; 6],
    }

    impl FakeSpace {
        fn new(address: Address) -> Self {
            Self {
                address,
                dwords: [0; 64],
                bar_masks: [0; 6],
                probing: [false; 6],
            }
        }

        fn set(&mut self, offset: u8, value: u32) {
            self.dwords[(offset / 4) as usize] = value;
        }

        fn bar_index(offset: u8) -> Option<usize> {
            if (offset::BAR0..offset::BAR0 + 24).contains(&offset) {
                Some(((offset - offset::BAR0) / 4) as usize)
            } else {
                None
            }
        }
    }

    impl ConfigSpace for FakeSpace {
        unsafe fn read(&self, address: Address, offset: u8) -> u32 {
            if address != self.address {
                return u32::MAX;
            }
            let slot = (offset / 4) as usize;
            if let Some(index) = Self::bar_index(offset) {
                if self.probing[index] {
                    // What a device returns after all-ones: only the bits it
                    // decodes, with the low type bits preserved.
                    let type_bits = self.dwords[slot] & 0xF;
                    return (self.bar_masks[index] & !0xF) | type_bits;
                }
            }
            self.dwords[slot]
        }

        unsafe fn write(&mut self, address: Address, offset: u8, value: u32) {
            if address != self.address {
                return;
            }
            if let Some(index) = Self::bar_index(offset) {
                self.probing[index] = value == u32::MAX;
                if !self.probing[index] {
                    self.dwords[(offset / 4) as usize] = value;
                }
                return;
            }
            self.dwords[(offset / 4) as usize] = value;
        }
    }

    const AT: Address = Address::new(0, 3, 0);

    /// A virtio block device as QEMU presents one.
    fn virtio_blk() -> FakeSpace {
        let mut space = FakeSpace::new(AT);
        space.set(offset::VENDOR_ID, 0x1042_1AF4);
        // Status with the capability bit, command clear.
        space.set(offset::COMMAND, u32::from(STATUS_CAPABILITIES) << 16);
        // class 0x01 (mass storage), subclass 0x00 (SCSI), prog_if 0, rev 1.
        space.set(offset::REVISION, 0x0100_0001);
        space.set(offset::HEADER_TYPE, 0);
        space.set(offset::CAPABILITIES, 0x84);
        // IRQ 11, pin A.
        space.set(offset::INTERRUPT_LINE, 0x0000_010B);
        space
    }

    #[test]
    fn the_config_address_has_the_enable_bit_and_the_right_fields() {
        let encoded = Address::new(0, 3, 0).config_address(offset::BAR0);
        assert_eq!(encoded & (1 << 31), 1 << 31, "enable bit missing");
        assert_eq!((encoded >> 11) & 0x1F, 3);
        assert_eq!(encoded & 0xFF, u32::from(offset::BAR0));
    }

    #[test]
    fn the_config_address_masks_the_low_two_bits_of_the_offset() {
        // The mechanism is dword-granular. An offset of 0x0E selects the dword
        // at 0x0C, and the caller extracts the half it wanted — which is
        // exactly what `header` does for the header-type byte.
        let a = Address::new(0, 3, 0);
        assert_eq!(a.config_address(0x0C), a.config_address(0x0E));
        assert_eq!(a.config_address(0x0E) & 0x3, 0);
    }

    #[test]
    fn an_address_cannot_encode_a_device_number_that_does_not_exist() {
        // Device numbers are five bits. A caller passing 33 must not have it
        // land on device 1 — the mask is what stops one enumeration bug from
        // becoming a report about the wrong device.
        let wide = Address::new(0, 33, 9);
        let narrow = Address::new(0, 33 & 0x1F, 9 & 0x07);
        assert_eq!(wide.config_address(0), narrow.config_address(0));
    }

    #[test]
    fn an_absent_device_reads_as_nothing_rather_than_as_a_device() {
        let space = FakeSpace::new(AT);
        // SAFETY: the fake touches no hardware.
        assert_eq!(unsafe { header(&space, Address::new(0, 4, 0)) }, None);
    }

    #[test]
    fn a_header_decodes_into_the_fields_it_is_made_of() {
        let space = virtio_blk();
        // SAFETY: the fake touches no hardware.
        let header = unsafe { header(&space, AT) }.unwrap();

        assert_eq!(header.vendor, 0x1AF4);
        assert_eq!(header.device, 0x1042);
        assert_eq!(header.class, 0x01);
        assert_eq!(header.subclass, 0x00);
        assert_eq!(header.revision, 0x01);
        assert_eq!(header.interrupt_line, 0x0B);
        assert_eq!(header.interrupt_pin, 0x01);
        assert!(header.has_capabilities);
        assert!(!header.is_bridge());
        assert!(!header.is_multifunction());
    }

    #[test]
    fn a_32_bit_memory_bar_is_sized_and_restored() {
        let mut space = virtio_blk();
        space.set(offset::BAR0, 0xFE00_0000);
        space.bar_masks[0] = 0xFFFF_F000; // 4 KiB window

        // SAFETY: the fake touches no hardware.
        let decoded = unsafe { bar(&mut space, AT, 0) }.unwrap();
        assert_eq!(
            decoded,
            Bar::Memory {
                base: 0xFE00_0000,
                size: 0x1000,
                prefetchable: false,
                is_64: false,
            }
        );

        // The BAR must be exactly where it was. Sizing points a device's window
        // somewhere absurd for the duration, and a probe that forgets to
        // restore leaves the device unreachable in a way that shows up much
        // later as a driver that reads zeros.
        // SAFETY: as above.
        assert_eq!(unsafe { space.read(AT, offset::BAR0) }, 0xFE00_0000);
    }

    #[test]
    fn a_64_bit_memory_bar_consumes_the_next_slot() {
        let mut space = virtio_blk();
        // Type bits 10: 64-bit. Prefetchable.
        space.set(offset::BAR0, 0xC000_0000 | 0b1100);
        space.set(offset::BAR0 + 4, 0x0000_0001);
        space.bar_masks[0] = 0xFFF0_0000;
        space.bar_masks[1] = 0xFFFF_FFFF;

        // SAFETY: the fake touches no hardware.
        let decoded = unsafe { bar(&mut space, AT, 0) }.unwrap();
        match decoded {
            Bar::Memory {
                base,
                prefetchable,
                is_64,
                ..
            } => {
                assert_eq!(base, 0x1_C000_0000);
                assert!(prefetchable);
                assert!(is_64);
                assert_eq!(decoded.slots_consumed(), 2);
            }
            other => panic!("expected a memory BAR, got {other:?}"),
        }
    }

    #[test]
    fn an_unimplemented_bar_has_no_size_rather_than_a_huge_one() {
        // Every bit reads back zero, and `!0 + 1` wraps. Getting this wrong
        // produces a BAR that appears to cover all of memory, which the mapper
        // would then be asked to map.
        let mut space = virtio_blk();
        space.set(offset::BAR0 + 8, 0);
        space.bar_masks[2] = 0;

        // SAFETY: the fake touches no hardware.
        let decoded = unsafe { bar(&mut space, AT, 2) }.unwrap();
        assert!(decoded.is_empty(), "{decoded:?} should be empty");
    }

    #[test]
    fn a_port_bar_is_recognised_by_its_low_bit() {
        let mut space = virtio_blk();
        space.set(offset::BAR0, 0xC041);
        space.bar_masks[0] = 0xFFFF_FFC0;

        // SAFETY: the fake touches no hardware.
        match unsafe { bar(&mut space, AT, 0) }.unwrap() {
            Bar::Io { base, size } => {
                assert_eq!(base, 0xC040);
                assert_eq!(size, 0x40);
            }
            other => panic!("expected a port BAR, got {other:?}"),
        }
    }

    #[test]
    fn there_is_no_seventh_bar() {
        let mut space = virtio_blk();
        // SAFETY: the fake touches no hardware.
        assert_eq!(unsafe { bar(&mut space, AT, 6) }, None);
    }

    #[test]
    fn the_capability_list_is_walked_in_order() {
        let mut space = virtio_blk();
        // 0x84 -> 0x90 -> 0xA0 -> end.
        space.set(0x84, 0x0000_9009);
        space.set(0x90, 0x0000_A011);
        space.set(0xA0, 0x0000_0009);

        let mut caps = [Capability { id: 0, offset: 0 }; 8];
        // SAFETY: the fake touches no hardware.
        let header = unsafe { header(&space, AT) }.unwrap();
        let found = unsafe { capabilities(&space, AT, &header, &mut caps) };

        assert_eq!(found, 3);
        assert_eq!(
            caps[0],
            Capability {
                id: 0x09,
                offset: 0x84
            }
        );
        assert_eq!(
            caps[1],
            Capability {
                id: 0x11,
                offset: 0x90
            }
        );
        assert_eq!(
            caps[2],
            Capability {
                id: 0x09,
                offset: 0xA0
            }
        );
    }

    #[test]
    fn a_capability_list_that_loops_does_not_hang_the_boot() {
        // The chain lives in memory the device controls. A device that points a
        // capability at itself is a device that stops the kernel from booting,
        // unless the walk is bounded.
        let mut space = virtio_blk();
        space.set(0x84, 0x0000_8409);

        let mut caps = [Capability { id: 0, offset: 0 }; MAX_CAPABILITIES + 8];
        // SAFETY: the fake touches no hardware.
        let header = unsafe { header(&space, AT) }.unwrap();
        let found = unsafe { capabilities(&space, AT, &header, &mut caps) };
        assert_eq!(found, MAX_CAPABILITIES);
    }

    #[test]
    fn a_capability_pointing_into_the_standard_header_is_rejected() {
        // The first 64 bytes are the header itself and cannot hold a
        // capability. Following such a pointer would read the header's own
        // fields as a capability id and a next pointer.
        let mut space = virtio_blk();
        space.set(offset::CAPABILITIES, 0x10);

        let mut caps = [Capability { id: 0, offset: 0 }; 8];
        // SAFETY: the fake touches no hardware.
        let header = unsafe { header(&space, AT) }.unwrap();
        assert_eq!(unsafe { capabilities(&space, AT, &header, &mut caps) }, 0);
    }

    #[test]
    fn a_device_without_the_capability_bit_is_not_walked() {
        let mut space = virtio_blk();
        space.set(offset::COMMAND, 0);
        space.set(offset::CAPABILITIES, 0x84);
        space.set(0x84, 0x0000_0009);

        let mut caps = [Capability { id: 0, offset: 0 }; 8];
        // SAFETY: the fake touches no hardware.
        let header = unsafe { header(&space, AT) }.unwrap();
        assert_eq!(unsafe { capabilities(&space, AT, &header, &mut caps) }, 0);
    }

    #[test]
    fn a_scan_reports_the_device_that_is_there_and_no_others() {
        let space = virtio_blk();
        let mut seen = std::vec::Vec::new();
        // SAFETY: the fake touches no hardware.
        unsafe {
            scan_bus_zero(&space, |address, header| {
                seen.push((address, header.device))
            })
        };
        assert_eq!(seen, [(AT, 0x1042)]);
    }

    #[test]
    fn a_single_function_device_is_not_probed_for_functions_it_does_not_have() {
        // Probing functions 1..8 of a device that did not claim to be
        // multifunction is how aliasing devices get reported eight times.
        let space = virtio_blk();
        let mut count = 0;
        // SAFETY: the fake touches no hardware.
        unsafe { scan_bus_zero(&space, |_, _| count += 1) };
        assert_eq!(count, 1);
    }
}
