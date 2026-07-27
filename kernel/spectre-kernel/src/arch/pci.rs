//! The two ports behind `pci::ConfigSpace`.
//!
//! Everything that decides anything is in `pci.rs`, tested on the host against a
//! synthetic device. This is the part that cannot be: an address written to one
//! port and a dword read from another.
//!
//! # Why this is not in `pci.rs`
//!
//! The same split as everywhere else in `arch` — but here it buys something
//! specific. BAR sizing writes all-ones into a device's base address register
//! and reads it back, which points the device's window somewhere absurd until
//! the original is restored. That sequence is easy to get subtly wrong and
//! expensive to get wrong on a real machine, and it is fully covered by host
//! tests precisely because the ports are behind this trait.

use super::cpu::{inl, outl};
use crate::pci::{Address, ConfigSpace};

/// Where the address goes.
const CONFIG_ADDRESS: u16 = 0xCF8;
/// Where the data comes back.
const CONFIG_DATA: u16 = 0xCFC;

/// The machine's configuration space.
///
/// A zero-sized handle rather than a set of free functions, so `pci.rs` can be
/// written against a trait and tested against something else. There is exactly
/// one of these and it refers to the whole bus.
pub struct PortConfigSpace;

impl ConfigSpace for PortConfigSpace {
    unsafe fn read(&self, address: Address, offset: u8) -> u32 {
        // SAFETY: the caller guarantees interrupts are off, which is what keeps
        // the address write and the data read from being separated. Both ports
        // are architectural and reading data has no side effect on the device.
        unsafe {
            outl(CONFIG_ADDRESS, address.config_address(offset));
            inl(CONFIG_DATA)
        }
    }

    unsafe fn write(&mut self, address: Address, offset: u8, value: u32) {
        // SAFETY: as `read`. What this writes is the caller's responsibility —
        // configuration space is where a device's windows live, and the only
        // caller that writes is BAR sizing, which restores what it found.
        unsafe {
            outl(CONFIG_ADDRESS, address.config_address(offset));
            outl(CONFIG_DATA, value);
        }
    }
}
