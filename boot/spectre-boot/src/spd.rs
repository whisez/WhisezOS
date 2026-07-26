//! Physical memory presence verification via SMBus SPD enumeration.
//!
//! # What this can and cannot do
//!
//! The spec calls for refusing to boot when *no physical RAM module is
//! detected*. That exact condition is unreachable from a bootloader: UEFI
//! firmware runs its memory reference code, trains the DIMMs, and tears down
//! cache-as-RAM long before `BOOTX64.EFI` is loaded. With zero populated
//! channels the platform never reaches a state where our code exists in
//! memory to execute. The firmware's own memory-error beep code is the only
//! thing that can report it.
//!
//! What *is* reachable, and what this module implements, is the useful
//! superset of that check:
//!
//!   1. Enumerate populated DIMM slots over SMBus by probing the SPD EEPROMs
//!      at 0x50..0x57 (JEDEC-reserved addresses). This tells us what the
//!      *hardware* claims is installed.
//!   2. Sum the geometry-derived capacity of every responding module.
//!   3. Cross-check that total against the UEFI memory map's conventional
//!      memory total.
//!   4. Halt on: zero responding modules, capacity below the 8 GiB floor, or a
//!      mismatch between (2) and (3) beyond firmware-reserved tolerance.
//!
//! Case (4)'s mismatch arm is the security-relevant one. A large negative
//! delta between SPD-declared and firmware-reported memory is the signature of
//! a hypervisor lying about the platform, or of firmware hiding a region from
//! the OS. Both are things a security-focused OS should refuse to boot on.
//!
//! On platforms where the SMBus controller is not reachable (locked by the
//! firmware, or a non-Intel/AMD host controller we do not have a driver for),
//! we degrade to memory-map-only enforcement rather than failing closed —
//! bricking a boot over an unreadable diagnostic bus is a worse outcome than
//! losing one of four checks.

#![allow(clippy::unusual_byte_groupings)]

use core::fmt;

/// JEDEC SPD EEPROM address range on the SMBus.
const SPD_ADDR_FIRST: u8 = 0x50;
const SPD_ADDR_LAST: u8 = 0x57;

/// Enforced minimum installed memory. Below this, WhisezOS refuses to boot:
/// Vault Allocation's per-process encrypted arenas plus Prism's triple-buffered
/// 4K framebuffers do not fit in less, and degrading either one silently would
/// break a security guarantee the user is relying on.
pub const MIN_RAM_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// Firmware legitimately reserves memory we will never see in the conventional
/// map: SMM ranges, ME/PSP carve-outs, integrated-GPU stolen memory, ACPI NVS.
/// 1 GiB covers the worst realistic case (large iGPU aperture) without being so
/// loose that a hypervisor can hide a meaningful amount behind it.
const MAP_TOLERANCE_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DramKind {
    Ddr4,
    Ddr5,
    Unknown(u8),
}

impl DramKind {
    fn from_byte(b: u8) -> Self {
        match b {
            0x0C => DramKind::Ddr4,
            0x12 => DramKind::Ddr5,
            other => DramKind::Unknown(other),
        }
    }
}

/// One populated slot, as described by its own SPD EEPROM.
#[derive(Debug, Clone, Copy)]
pub struct Module {
    pub slot: u8,
    pub kind: DramKind,
    pub capacity_bytes: u64,
}

#[derive(Debug, Clone, Copy)]
pub enum MemoryFault {
    /// No SPD EEPROM answered on any JEDEC address.
    NoModulesDetected,
    /// Modules present, but installed capacity is under the enforced floor.
    BelowMinimum { found: u64, required: u64 },
    /// SPD says one thing, the firmware memory map says another.
    MapMismatch { spd: u64, map: u64 },
}

impl fmt::Display for MemoryFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MemoryFault::NoModulesDetected => f.write_str("NO MEMORY DETECTED - SYSTEM HALTED"),
            MemoryFault::BelowMinimum { found, .. } => {
                write!(
                    f,
                    "INSUFFICIENT MEMORY: {} GiB < 8 GiB REQUIRED",
                    found >> 30
                )
            }
            MemoryFault::MapMismatch { spd, map } => write!(
                f,
                "MEMORY MAP INCONSISTENT: SPD {} GiB / FIRMWARE {} GiB",
                spd >> 30,
                map >> 30
            ),
        }
    }
}

/// Abstraction over the platform SMBus host controller.
///
/// Implemented for Intel ICH/PCH (`smbus::Ich`) and AMD FCH (`smbus::Fch`).
/// Kept as a trait so the audit logic below is testable on a host with a mock
/// bus — see `tests/spd_audit.rs`.
pub trait SmBus {
    /// Read one byte from `addr` at `offset`. `None` means the device did not
    /// acknowledge (slot empty) or the transaction timed out.
    fn read_byte(&mut self, addr: u8, offset: u8) -> Option<u8>;

    /// DDR5 SPDs are paged; DDR4 and earlier ignore this.
    fn set_page(&mut self, addr: u8, page: u8) -> Option<()>;
}

/// Probe every JEDEC SPD address and decode the modules that respond.
pub fn enumerate<B: SmBus>(bus: &mut B) -> heapless::Vec<Module, 8> {
    let mut found = heapless::Vec::new();

    for addr in SPD_ADDR_FIRST..=SPD_ADDR_LAST {
        // Byte 2 is the DRAM device type and is present on every SPD revision
        // since DDR1. If nothing acknowledges, the slot is empty.
        let Some(kind_byte) = bus.read_byte(addr, 0x02) else {
            continue;
        };
        let kind = DramKind::from_byte(kind_byte);

        let capacity_bytes = match kind {
            DramKind::Ddr4 => ddr4_capacity(bus, addr),
            DramKind::Ddr5 => ddr5_capacity(bus, addr),
            DramKind::Unknown(_) => None,
        };

        let Some(capacity_bytes) = capacity_bytes else {
            continue;
        };

        // Vec is sized to the address range, so push cannot overflow.
        let _ = found.push(Module {
            slot: addr - SPD_ADDR_FIRST,
            kind,
            capacity_bytes,
        });
    }

    found
}

/// DDR4 module capacity, per JESD79-4 SPD Annex L.
///
/// capacity = die_capacity / 8 * bus_width / sdram_width * ranks
fn ddr4_capacity<B: SmBus>(bus: &mut B, addr: u8) -> Option<u64> {
    let byte4 = bus.read_byte(addr, 0x04)?; // SDRAM density and banks
    let byte12 = bus.read_byte(addr, 0x0C)?; // module organization
    let byte13 = bus.read_byte(addr, 0x0D)?; // module memory bus width

    // Bits [3:0] encode die capacity in megabits: 0 => 256 Mb, then doubling.
    let die_mbits: u64 = match byte4 & 0x0F {
        0 => 256,
        1 => 512,
        n @ 2..=7 => 1024u64 << (n - 2), // 1 Gb .. 32 Gb
        8 => 16 * 1024,                  // 16 Gb (JEDEC ordering quirk)
        9 => 32 * 1024,
        _ => return None,
    };

    let sdram_width: u64 = 4u64 << ((byte12 & 0x07) as u32); // x4, x8, x16, x32
    let ranks: u64 = (((byte12 >> 3) & 0x07) as u64) + 1;
    let bus_width: u64 = 8u64 << ((byte13 & 0x07) as u32); // 8, 16, 32, 64 bits

    if sdram_width == 0 || bus_width == 0 {
        return None;
    }

    // die_mbits/8 converts megabits to megabytes; << 20 to bytes.
    Some((die_mbits / 8) * (bus_width / sdram_width) * ranks * (1 << 20))
}

/// DDR5 module capacity, per JESD400-5. Layout differs from DDR4 entirely and
/// the EEPROM is paged — capacity fields live in page 0, which we select
/// explicitly rather than trusting whatever page the firmware left selected.
fn ddr5_capacity<B: SmBus>(bus: &mut B, addr: u8) -> Option<u64> {
    bus.set_page(addr, 0)?;

    let byte4 = bus.read_byte(addr, 0x04)?; // first density/package
    let byte6 = bus.read_byte(addr, 0x06)?; // first SDRAM I/O width
    let byte234 = bus.read_byte(addr, 0xEA)?; // channels per DIMM / bus width

    // Bits [4:0]: density in gigabits, 1..=8 maps to 4,8,12,16,24,32,48,64 Gb.
    let die_gbits: u64 = match byte4 & 0x1F {
        1 => 4,
        2 => 8,
        3 => 12,
        4 => 16,
        5 => 24,
        6 => 32,
        7 => 48,
        8 => 64,
        _ => return None,
    };

    let sdram_width: u64 = 4u64 << (((byte6 >> 5) & 0x07) as u32);
    let channels: u64 = (((byte234 >> 5) & 0x03) as u64) + 1;
    let channel_width: u64 = 8u64 << ((byte234 & 0x07) as u32);

    if sdram_width == 0 {
        return None;
    }

    Some((die_gbits / 8) * (channel_width / sdram_width) * channels * (1 << 30))
}

/// The full memory audit. `map_conventional` is the sum of every
/// `EfiConventionalMemory`, `EfiBootServicesData`, and `EfiLoaderData`
/// descriptor from `GetMemoryMap` — i.e. what the OS will actually be able to
/// use, plus what the loader currently holds.
///
/// `modules` may legitimately be empty when the SMBus is inaccessible; in that
/// case we fall through to memory-map-only enforcement.
pub fn audit(
    modules: &[Module],
    map_conventional: u64,
    smbus_available: bool,
) -> Result<u64, MemoryFault> {
    let spd_total: u64 = modules.iter().map(|m| m.capacity_bytes).sum();

    if smbus_available {
        if modules.is_empty() {
            return Err(MemoryFault::NoModulesDetected);
        }

        // A hypervisor presenting a synthetic SPD, or firmware hiding a region,
        // shows up here as an out-of-tolerance shortfall.
        if spd_total > map_conventional.saturating_add(MAP_TOLERANCE_BYTES) {
            return Err(MemoryFault::MapMismatch {
                spd: spd_total,
                map: map_conventional,
            });
        }
    }

    // The floor is enforced against usable memory, not SPD-declared capacity:
    // a machine with 8 GiB installed but 2 GiB stolen by an iGPU genuinely
    // cannot run WhisezOS, regardless of what the sticker says.
    if map_conventional < MIN_RAM_BYTES {
        return Err(MemoryFault::BelowMinimum {
            found: map_conventional,
            required: MIN_RAM_BYTES,
        });
    }

    Ok(map_conventional)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module(gib: u64) -> Module {
        Module {
            slot: 0,
            kind: DramKind::Ddr5,
            capacity_bytes: gib << 30,
        }
    }

    #[test]
    fn empty_slots_with_working_smbus_is_fatal() {
        assert!(matches!(
            audit(&[], 16 << 30, true),
            Err(MemoryFault::NoModulesDetected)
        ));
    }

    #[test]
    fn unreadable_smbus_degrades_to_map_only() {
        assert_eq!(audit(&[], 16 << 30, false).unwrap(), 16 << 30);
    }

    #[test]
    fn under_floor_is_fatal_even_with_modules_present() {
        assert!(matches!(
            audit(&[module(4)], 4 << 30, true),
            Err(MemoryFault::BelowMinimum { .. })
        ));
    }

    #[test]
    fn igpu_stolen_memory_stays_within_tolerance() {
        // 16 GiB installed, 512 MiB stolen by the iGPU: legitimate, must pass.
        let map = (16 << 30) - (512 << 20);
        assert_eq!(audit(&[module(16)], map, true).unwrap(), map);
    }

    #[test]
    fn hypervisor_hiding_half_the_ram_is_caught() {
        assert!(matches!(
            audit(&[module(32)], 16 << 30, true),
            Err(MemoryFault::MapMismatch { .. })
        ));
    }
}
