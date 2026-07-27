//! The I/O APIC — where a device interrupt enters the system.
//!
//! `pic.rs` put the two 8259s beyond the point where they can cause trouble, and
//! said the LAPIC is the interrupt controller from here on. That is true of
//! interrupts the processor raises for itself — the LAPIC timer — and not true
//! of anything else. A device's interrupt is a wire, and the thing that wire is
//! connected to on a modern PC is the I/O APIC. Until this file existed, every
//! device line in the machine was routed nowhere.
//!
//! # Register access is two steps, and the order is the whole protocol
//!
//! There are only two directly addressable registers: a selector at offset 0 and
//! a window at offset 0x10. Reading register *n* means writing *n* to the
//! selector and then reading the window. That is a read-modify sequence across
//! two MMIO accesses, and anything that reorders them, merges them, or satisfies
//! one from a cache reads a register nobody asked for.
//!
//! # The mapping is cacheable, and that is a compromise
//!
//! For exactly the reason above this wants an uncacheable mapping, and it does
//! not have one: the kernel's identity map covers the first four gigabytes in
//! 2 MiB pages, and 0xFEC0_0000 falls inside one of them. Changing the cache
//! type of this range means splitting that page.
//!
//! Why it is nevertheless correct on QEMU: an emulated device's registers are
//! not host memory, so the guest's cache attributes never enter into it — every
//! access traps to the emulator whatever the page tables say. On real hardware
//! that reasoning does not hold and this needs the split, which is the same
//! page-splitting work `arch/framebuffer.rs` defers and should be done once for
//! both. Named here rather than discovered later on a machine that behaves
//! differently.
//!
//! # Where the base address comes from
//!
//! 0xFEC0_0000, because that is what every PC-compatible machine uses and what
//! QEMU's q35 provides. The right answer is the ACPI MADT, which also carries
//! the interrupt source overrides that say which pin an ISA IRQ actually lands
//! on — there is no ACPI parser yet, so this file works with lines whose pin
//! number is not subject to an override, and `device.rs` picks accordingly.

use super::idt::vector;

/// The architectural I/O APIC address on a PC-compatible machine.
pub const DEFAULT_BASE: u64 = 0xFEC0_0000;

/// Register selector, at offset 0 from the base.
const IOREGSEL: u64 = 0x00;
/// Data window, at offset 0x10.
const IOWIN: u64 = 0x10;

/// Identification register.
const REG_ID: u32 = 0x00;
/// Version, and in bits 16..24 the highest redirection entry that exists.
const REG_VERSION: u32 = 0x01;
/// First redirection entry. Entry *n* occupies `0x10 + 2n` and `0x10 + 2n + 1`.
const REG_REDIRECT_BASE: u32 = 0x10;

/// Redirection entry bit 16: masked. Set at reset, and set again by `mask`.
const ENTRY_MASKED: u64 = 1 << 16;

/// Where a device line's vector starts.
///
/// Above the LAPIC timer at 32 and clear of the remapped 8259 range, which
/// starts at `FIRST_DEVICE + 0x20`. Line *n* is vector `DEVICE_VECTOR_BASE + n`.
pub const DEVICE_VECTOR_BASE: u8 = vector::FIRST_DEVICE + 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoApicError {
    /// The version register read back as all-ones or all-zeros, which is what a
    /// bus returns when nothing is there.
    NotPresent,
    /// The pin asked for is past the last one this I/O APIC has.
    NoSuchPin { pin: u8, highest: u8 },
}

/// One I/O APIC, once it has answered.
#[derive(Debug, Clone, Copy)]
pub struct IoApic {
    base: u64,
    /// Highest redirection entry, from the version register.
    pub highest_pin: u8,
    pub id: u8,
}

impl IoApic {
    /// Reads one 32-bit register.
    ///
    /// # Safety
    /// `base` must be the identity-mapped I/O APIC, and no other code may be
    /// between the selector write and the window access — which on one
    /// processor means interrupts must be off, and is why every caller is
    /// bring-up code or an interrupt handler.
    unsafe fn read(&self, register: u32) -> u32 {
        // SAFETY: both offsets are inside the I/O APIC's own page, which the
        // identity map covers. Volatile because the pair is a protocol, not two
        // independent accesses the compiler may reorder or elide.
        unsafe {
            ((self.base + IOREGSEL) as *mut u32).write_volatile(register);
            ((self.base + IOWIN) as *const u32).read_volatile()
        }
    }

    /// Writes one 32-bit register.
    ///
    /// # Safety
    /// As `read`.
    unsafe fn write(&self, register: u32, value: u32) {
        // SAFETY: as `read`.
        unsafe {
            ((self.base + IOREGSEL) as *mut u32).write_volatile(register);
            ((self.base + IOWIN) as *mut u32).write_volatile(value);
        }
    }

    /// Points a pin at a vector on the bootstrap processor, leaving it masked.
    ///
    /// Masked, because routing and permitting are different decisions. A line is
    /// routed once during bring-up, when the kernel knows the wiring; it is
    /// permitted to fire only when a process has claimed it, which happens much
    /// later or never. Unmasking here instead would deliver 64 interrupts a
    /// second into a kernel whose only possible response is to note that nobody
    /// wanted them.
    ///
    /// Fixed delivery, physical destination mode, active high, edge triggered —
    /// which is what an ISA line is. A level-triggered PCI line needs the
    /// polarity and trigger bits set the other way and an EOI written to the
    /// I/O APIC as well as the LAPIC; neither is here, because nothing routed
    /// through this yet is level triggered and guessing at hardware that does
    /// not exist is how the wrong thing gets written confidently.
    ///
    /// # Safety
    /// The vector must have a handler installed. Unmasking a pin whose gate
    /// reports and returns is survivable; unmasking one with no gate at all is a
    /// triple fault the moment the device fires.
    pub unsafe fn route(&self, pin: u8, vector: u8, apic_id: u8) -> Result<(), IoApicError> {
        if pin > self.highest_pin {
            return Err(IoApicError::NoSuchPin {
                pin,
                highest: self.highest_pin,
            });
        }
        let register = REG_REDIRECT_BASE + u32::from(pin) * 2;

        // SAFETY: the pin exists, and the caller guarantees the vector has a
        // handler. The high half — the destination — is written first, so the
        // entry is never briefly unmasked while pointing at processor zero by
        // accident rather than by choice.
        unsafe {
            self.write(register + 1, u32::from(apic_id) << 24);
            self.write(register, u32::from(vector) | ENTRY_MASKED as u32);
        }
        Ok(())
    }

    /// Lets a routed pin deliver.
    ///
    /// # Safety
    /// The pin must already have been routed to a vector that has a handler. An
    /// unmasked pin still holding its reset value points at vector zero, which
    /// is `#DE`.
    pub unsafe fn unmask(&self, pin: u8) -> Result<(), IoApicError> {
        if pin > self.highest_pin {
            return Err(IoApicError::NoSuchPin {
                pin,
                highest: self.highest_pin,
            });
        }
        let register = REG_REDIRECT_BASE + u32::from(pin) * 2;
        // SAFETY: as `route`.
        unsafe {
            let low = self.read(register);
            self.write(register, low & !(ENTRY_MASKED as u32));
        }
        Ok(())
    }

    /// Masks a pin, so the device's line is ignored.
    ///
    /// # Safety
    /// The I/O APIC must be present.
    pub unsafe fn mask(&self, pin: u8) -> Result<(), IoApicError> {
        if pin > self.highest_pin {
            return Err(IoApicError::NoSuchPin {
                pin,
                highest: self.highest_pin,
            });
        }
        let register = REG_REDIRECT_BASE + u32::from(pin) * 2;
        // SAFETY: as `route`.
        unsafe {
            let low = self.read(register);
            self.write(register, low | ENTRY_MASKED as u32);
        }
        Ok(())
    }
}

/// Finds the I/O APIC without changing anything.
///
/// Separate from `init` because `init` masks every pin, which is right exactly
/// once — at bring-up, before any line has an owner. Anything later that needs
/// to reach a redirection entry wants the chip, not a reset.
///
/// # Safety
/// The identity map must be active, and interrupts off for the duration of any
/// register access made through the result.
pub unsafe fn attach(base: u64) -> Result<IoApic, IoApicError> {
    let mut ioapic = IoApic {
        base,
        highest_pin: 0,
        id: 0,
    };
    // SAFETY: the caller guarantees the mapping and that IF is clear.
    let version = unsafe { ioapic.read(REG_VERSION) };
    if version == u32::MAX || version == 0 {
        return Err(IoApicError::NotPresent);
    }
    ioapic.highest_pin = ((version >> 16) & 0xFF) as u8;
    // SAFETY: as above.
    ioapic.id = ((unsafe { ioapic.read(REG_ID) } >> 24) & 0x0F) as u8;
    Ok(ioapic)
}

/// Finds the I/O APIC and masks every pin.
///
/// Masking all of them is the point of doing this during bring-up rather than
/// when the first driver appears. Reset leaves the entries masked, but firmware
/// runs before the kernel and is under no obligation to leave them that way, and
/// an unmasked pin whose device the firmware armed will fire into a vector this
/// kernel has other plans for.
///
/// # Safety
/// Called once during bring-up, with interrupts disabled, after the identity map
/// is active.
pub unsafe fn init(base: u64) -> Result<IoApic, IoApicError> {
    // SAFETY: bring-up, interrupts disabled, and the range is identity mapped.
    let ioapic = unsafe { attach(base) }?;

    for pin in 0..=ioapic.highest_pin {
        // SAFETY: every pin from zero to the highest exists by definition.
        unsafe { ioapic.mask(pin)? };
    }

    Ok(ioapic)
}
