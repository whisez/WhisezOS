//! Which ports a process may touch, and which the kernel never gives away.
//!
//! # This reverses a decision, deliberately
//!
//! `gdt.rs` used to say the I/O permission bitmap was set to deny everything
//! because "user-space drivers reach hardware through capability-mediated MMIO,
//! never through `in`/`out`". That is the right default and the wrong absolute.
//! Several devices a real system needs have no MMIO window at all: the RTC and
//! the CMOS behind it, the i8042 the keyboard and mouse hang off, the legacy
//! serial port. They are reached through port I/O or not at all.
//!
//! So the choice is not between port access and something cleaner. It is between
//! a driver in ring 3 with two permitted ports, and the same work done in ring 0
//! where a mistake is the kernel's mistake. `arch/rtc.rs` exists because of that
//! second option, and this file is what removes it.
//!
//! # The bitmap is the mechanism, and it is per-port
//!
//! x86 has had this since the 386: a bit per port in the TSS, clear meaning
//! permitted, consulted by the CPU on every `in` and `out` from ring 3. It is
//! the rare case where the hardware offers exactly the granularity wanted. A
//! process granted the RTC gets ports 0x70 and 0x71 and nothing else — not a
//! range, not a class of device, two ports.
//!
//! # What is never granted, and why each one
//!
//! Some ports are the kernel's own hands. Handing them out is not a narrow
//! privilege escalation, it is the end of the kernel's ability to do its job or
//! to report that it cannot. `FORBIDDEN` names them with the reason, because a
//! denylist whose entries have no stated cause is a denylist nobody will dare
//! change and everybody will eventually work around.
//!
//! # The honest limit: ports are not devices
//!
//! A grant is expressed in ports because that is what the hardware checks, and
//! ports do not always divide the way devices do. The RTC shares 0x70 and 0x71
//! with the whole CMOS, so a process granted the RTC can read and write every
//! CMOS byte and can mask NMI. That is a property of a machine designed in 1984,
//! not of this code, and the only fix is an emulated port space nobody wants.
//! It is written here so the grant is not mistaken for narrower than it is.

#![allow(dead_code)]

use crate::abi::SyscallError;

/// Ports the bitmap covers.
///
/// Everything from here up is denied by the TSS limit rather than by a bit,
/// which is a stronger statement than a bit that happens to be set: there is no
/// value that could be written to permit it. PCI configuration space at 0xCF8
/// is above this line, and that is not an accident — a process that could write
/// 0xCF8 could reprogram the address of every device in the machine.
pub const PORT_SPACE: usize = 1024;

/// Bytes of bitmap. One bit per port.
pub const BITMAP_BYTES: usize = PORT_SPACE / 8;

/// Port ranges one process may hold at once.
///
/// Four, because the session drives two devices and one of them needs two
/// ranges. The i8042's registers are 0x60 and 0x64, and the range between them
/// contains the PIT gate, which `FORBIDDEN` refuses — so the controller is two
/// one-port grants. With the RTC's pair that is three.
pub const MAX_PORT_GRANTS: usize = 4;

/// A contiguous run of ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    pub base: u16,
    pub len: u16,
}

impl PortRange {
    pub const EMPTY: Self = Self { base: 0, len: 0 };

    #[must_use]
    pub const fn new(base: u16, len: u16) -> Self {
        Self { base, len }
    }

    /// One past the last port. `u32` because a range ending at 0xFFFF would
    /// otherwise wrap to zero and compare as empty.
    #[must_use]
    pub const fn end(&self) -> u32 {
        self.base as u32 + self.len as u32
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[must_use]
    pub fn contains(&self, port: u16) -> bool {
        u32::from(port) >= u32::from(self.base) && u32::from(port) < self.end()
    }

    #[must_use]
    pub fn overlaps(&self, other: &PortRange) -> bool {
        !self.is_empty()
            && !other.is_empty()
            && u32::from(self.base) < other.end()
            && u32::from(other.base) < self.end()
    }
}

/// Ports the kernel keeps, with the reason it keeps them.
///
/// The reason is not decoration. Every entry here is a thing somebody will
/// eventually want to grant, and the answer has to be better than "it is on the
/// list".
pub const FORBIDDEN: &[(PortRange, &str)] = &[
    (
        PortRange::new(0x20, 2),
        "the master 8259, which can raise interrupts at any vector",
    ),
    (
        PortRange::new(0xA0, 2),
        "the slave 8259, for the same reason",
    ),
    (
        PortRange::new(0x40, 4),
        "the PIT, which the APIC timer is calibrated against",
    ),
    (
        PortRange::new(0x61, 1),
        "the PIT gate, which is half of that calibration",
    ),
    (
        PortRange::new(0x80, 1),
        "the POST port, used as an I/O delay by the 8259 sequence",
    ),
    (
        PortRange::new(0x3F8, 8),
        "the serial console, which is how the kernel reports anything at all",
    ),
];

/// Why a range cannot be granted, or `None` if it can.
#[must_use]
pub fn forbidden_reason(range: &PortRange) -> Option<&'static str> {
    FORBIDDEN
        .iter()
        .find(|(reserved, _)| range.overlaps(reserved))
        .map(|(_, why)| *why)
}

/// The port grants held by one process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Grants {
    ranges: [PortRange; MAX_PORT_GRANTS],
    count: usize,
}

impl Grants {
    pub const NONE: Self = Self {
        ranges: [PortRange::EMPTY; MAX_PORT_GRANTS],
        count: 0,
    };

    #[must_use]
    pub fn ranges(&self) -> &[PortRange] {
        &self.ranges[..self.count]
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Whether `port` is covered by any grant held here.
    #[must_use]
    pub fn permits(&self, port: u16) -> bool {
        self.ranges().iter().any(|r| r.contains(port))
    }

    /// Adds a range.
    ///
    /// Every refusal happens before anything is recorded, because the caller
    /// goes on to write hardware on the strength of the answer.
    pub fn add(&mut self, range: PortRange) -> Result<(), SyscallError> {
        if range.is_empty() {
            return Err(SyscallError::BadArgument);
        }
        // Past the bitmap is not a bit that is set, it is a port the TSS limit
        // denies outright — so a grant there would be recorded and then not
        // work, which is worse than being refused.
        if range.end() > PORT_SPACE as u32 {
            return Err(SyscallError::BadArgument);
        }
        if forbidden_reason(&range).is_some() {
            return Err(SyscallError::NotPermitted);
        }
        // Already held. Not an error — a driver may ask twice — but it must not
        // consume a second slot.
        if self.ranges().contains(&range) {
            return Ok(());
        }
        if self.count == MAX_PORT_GRANTS {
            return Err(SyscallError::TooLong);
        }
        self.ranges[self.count] = range;
        self.count += 1;
        Ok(())
    }
}

/// Renders a set of grants as the TSS bitmap the CPU consults.
///
/// A clear bit permits. The bitmap starts all-ones — everything denied — and
/// each granted port clears one bit, so a range that fails to be applied denies
/// rather than permits.
#[must_use]
pub fn bitmap(grants: &Grants) -> [u8; BITMAP_BYTES] {
    let mut map = [0xFFu8; BITMAP_BYTES];
    for range in grants.ranges() {
        for port in range.base..range.base.saturating_add(range.len) {
            let index = usize::from(port);
            if index < PORT_SPACE {
                map[index / 8] &= !(1u8 << (index % 8));
            }
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The RTC, which is the one device granted today.
    const RTC: PortRange = PortRange::new(0x70, 2);

    #[test]
    fn a_granted_range_is_permitted_and_nothing_either_side_of_it_is() {
        let mut grants = Grants::NONE;
        grants.add(RTC).unwrap();

        assert!(grants.permits(0x70));
        assert!(grants.permits(0x71));
        assert!(!grants.permits(0x6F));
        assert!(!grants.permits(0x72));
    }

    #[test]
    fn the_bitmap_clears_exactly_the_granted_bits() {
        let mut grants = Grants::NONE;
        grants.add(RTC).unwrap();
        let map = bitmap(&grants);

        for port in 0..PORT_SPACE {
            let permitted = map[port / 8] & (1 << (port % 8)) == 0;
            assert_eq!(
                permitted,
                grants.permits(port as u16),
                "port {port:#x} disagrees with the bitmap"
            );
        }
    }

    #[test]
    fn an_empty_grant_set_permits_nothing_at_all() {
        // The default a process starts with, and the state the bitmap must be
        // in for every process that was never given a device.
        let map = bitmap(&Grants::NONE);
        assert!(map.iter().all(|byte| *byte == 0xFF));
    }

    #[test]
    fn the_kernels_own_ports_cannot_be_granted() {
        let mut grants = Grants::NONE;
        for (reserved, why) in FORBIDDEN {
            assert_eq!(
                grants.add(*reserved),
                Err(SyscallError::NotPermitted),
                "granted {reserved:?}, which is {why}"
            );
        }
    }

    #[test]
    fn a_range_that_merely_touches_a_reserved_one_is_refused() {
        // Overlap, not containment. A range from 0x3F0 to 0x400 does not equal
        // the serial port's range and covers all of it.
        let mut grants = Grants::NONE;
        assert_eq!(
            grants.add(PortRange::new(0x3F0, 16)),
            Err(SyscallError::NotPermitted)
        );
        // And one that stops just short is fine.
        assert!(grants.add(PortRange::new(0x3F0, 8)).is_ok());
    }

    #[test]
    fn every_forbidden_reason_says_something() {
        // The list is only useful if each entry explains itself; an unexplained
        // entry is one nobody will dare change and everybody will work around.
        for (range, why) in FORBIDDEN {
            assert!(!why.is_empty(), "{range:?} has no stated reason");
            assert!(!range.is_empty());
        }
    }

    #[test]
    fn pci_configuration_space_is_outside_the_bitmap_entirely() {
        // Not a bit that happens to be set — a port the TSS limit denies, which
        // no value written anywhere could permit. A process that could write
        // 0xCF8 could move every device in the machine.
        assert!(0xCF8 >= PORT_SPACE);
        let mut grants = Grants::NONE;
        assert_eq!(
            grants.add(PortRange::new(0xCF8, 8)),
            Err(SyscallError::BadArgument)
        );
    }

    #[test]
    fn a_range_that_runs_off_the_end_of_the_bitmap_is_refused() {
        let mut grants = Grants::NONE;
        assert_eq!(
            grants.add(PortRange::new(PORT_SPACE as u16 - 1, 2)),
            Err(SyscallError::BadArgument)
        );
        // A range that ends exactly at the boundary is inside the bitmap, so if
        // it is refused it must be for the other reason. The last eight ports
        // of the space happen to be the serial console, which makes this the
        // one case where both rules could fire — and they must be told apart,
        // because one means "ask for less" and the other means "never".
        assert_eq!(
            grants.add(PortRange::new(PORT_SPACE as u16 - 8, 8)),
            Err(SyscallError::NotPermitted)
        );

        // An ordinary range inside the bitmap is accepted, which is what makes
        // the two refusals above statements about their own rules rather than
        // about `add` refusing everything.
        assert!(grants.add(PortRange::new(0x300, 4)).is_ok());
    }

    #[test]
    fn an_empty_range_is_refused_rather_than_recorded() {
        let mut grants = Grants::NONE;
        assert_eq!(
            grants.add(PortRange::new(0x70, 0)),
            Err(SyscallError::BadArgument)
        );
        assert!(grants.is_empty());
    }

    #[test]
    fn asking_twice_for_the_same_range_does_not_consume_a_second_slot() {
        let mut grants = Grants::NONE;
        for _ in 0..5 {
            grants.add(RTC).unwrap();
        }
        assert_eq!(grants.ranges().len(), 1);
    }

    #[test]
    fn a_process_cannot_hold_more_ranges_than_it_has_slots_for() {
        let mut grants = Grants::NONE;
        for slot in 0..MAX_PORT_GRANTS {
            grants
                .add(PortRange::new(0x100 + slot as u16 * 8, 4))
                .unwrap();
        }
        assert_eq!(
            grants.add(PortRange::new(0x200, 4)),
            Err(SyscallError::TooLong)
        );
    }

    #[test]
    fn a_refused_grant_leaves_the_bitmap_denying() {
        // The direction of failure matters. A bug that drops a grant costs a
        // driver its device; a bug that adds one costs the whole machine.
        let mut grants = Grants::NONE;
        let _ = grants.add(PortRange::new(0x20, 2));
        assert!(bitmap(&grants).iter().all(|byte| *byte == 0xFF));
    }

    #[test]
    fn ranges_that_do_not_meet_do_not_report_an_overlap() {
        let a = PortRange::new(0x70, 2);
        assert!(a.overlaps(&PortRange::new(0x71, 4)));
        assert!(a.overlaps(&PortRange::new(0x6E, 4)));
        assert!(!a.overlaps(&PortRange::new(0x72, 4)));
        assert!(!a.overlaps(&PortRange::new(0x6E, 2)));
        // An empty range covers nothing, so it meets nothing.
        assert!(!a.overlaps(&PortRange::EMPTY));
    }
}
