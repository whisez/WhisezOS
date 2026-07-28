//! The hardware abstraction layer, and the bring-up sequence that uses it.
//!
//! The submodules split along one line: `addr`, `context`, `frame`, `gdt`,
//! `idt`, `paging`, and `serial` are pure data structures and algorithms with no
//! I/O, tested exhaustively on the host by `verify/`. `cpu`, `console`,
//! `segments`, `interrupts`, and `memory` are the parts that touch the machine
//! and can only be verified by booting.
//!
//! `early_init` is the ordering, and the order is not free:
//!
//!   1. **Console first.** Everything after this can fail, and a failure with no
//!      way to report it is a black screen.
//!   2. **Validate the handoff.** Every later step trusts the memory map. A
//!      malformed one caught here costs a serial line; caught later it is a
//!      frame allocator handing out the running kernel.
//!   3. **GDT, then IDT.** Gate descriptors name a code selector, so the GDT has
//!      to be live before the IDT can reference it.
//!   4. **Frame allocator, then page tables.** Building a page table requires
//!      somewhere to allocate the intermediate tables from.
//!   5. **Switch CR3 last.** It is the only step that cannot report its own
//!      failure: a page table that does not map the instruction after `mov cr3`
//!      triple-faults with nothing on the wire.

pub mod addr;
pub mod apic;
pub mod console;
pub mod context;
pub mod cpu;
pub mod frame;
pub mod framebuffer;
pub mod gdt;
pub mod idt;
pub mod interrupts;
pub mod ioapic;
pub mod memory;
pub mod paging;
pub mod pci;
pub mod pic;
pub mod rtc;
pub mod segments;
pub mod serial;
pub mod syscall;
pub mod trap;
pub mod user;

use crate::boot_info::BootInfo;
use crate::kprintln;

/// What went wrong during bring-up, in the order the steps run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitError {
    BootInfo(crate::boot_info::BootInfoError),
    Gdt(gdt::GdtError),
    Idt(idt::IdtError),
    Memory(memory::MemoryError),
}

/// What `early_init` produces and stage 2 needs.
#[derive(Debug, Clone, Copy)]
pub struct Platform {
    pub gdt: gdt::GdtLayout,
    pub kernel_root: addr::PhysAddr,
}

/// Brings the processor up to a known state.
///
/// # Safety
/// Called exactly once, on the bootstrap processor, with interrupts disabled and
/// the loader's identity mapping still active.
pub unsafe fn early_init(boot: &BootInfo) -> Result<Platform, InitError> {
    console::init();
    kprintln!("[kernel] WhisezOS microkernel, stage 1");

    boot.validate().map_err(InitError::BootInfo)?;

    // The screen comes up as early as the handoff allows, so everything after
    // this appears on it as well as on the wire. It cannot come first: the
    // geometry it needs is the thing `validate` has just checked.
    // SAFETY: the framebuffer is the one the firmware left running, described
    // by a handoff that has passed validation, and physical memory is identity
    // mapped by the loader's tables.
    if unsafe { framebuffer::init(&boot.framebuffer) } {
        kprintln!("[kernel] screen console up");
    }

    report_handoff(boot);

    // SAFETY: bring-up preconditions are the caller's; see the module comment
    // for why the order below cannot be rearranged.
    let layout = unsafe { segments::install() }.map_err(InitError::Gdt)?;
    kprintln!(
        "[kernel] gdt installed cs={:#06x} ds={:#06x} tss={:#06x}",
        layout.kernel_code.0,
        layout.kernel_data.0,
        layout.tss.0
    );

    // SAFETY: the GDT is live, so the gates' code selector is valid.
    unsafe { interrupts::install(&layout) }.map_err(InitError::Idt)?;
    kprintln!("[kernel] idt installed, 256 vectors present");

    report_protection_state();

    // SAFETY: the handoff has been validated, so the regions are sorted,
    // disjoint, and exclude the running kernel.
    let stats = unsafe { memory::init(boot) }.map_err(InitError::Memory)?;
    kprintln!(
        "[kernel] frames total={} free={} ({} MiB usable)",
        stats.total_frames,
        stats.free_frames,
        stats.usable_bytes >> 20
    );

    // SAFETY: `memory::init` built a table that maps all of physical memory,
    // which necessarily includes the running code, the current stack, and the
    // table itself.
    let root = unsafe { memory::activate_kernel_tables() }.map_err(InitError::Memory)?;
    kprintln!("[kernel] page tables active cr3={:#018x}", root.as_u64());

    // Last, because `SCE` makes `syscall` a valid instruction and the entry
    // path it points at needs a kernel stack and a live GDT to be worth
    // jumping to.
    // SAFETY: the GDT is installed and the selectors in `layout` are loaded.
    unsafe { syscall::init(&layout) };
    syscall::report();

    Ok(Platform {
        gdt: layout,
        kernel_root: root,
    })
}

fn report_handoff(boot: &BootInfo) {
    kprintln!(
        "[kernel] handoff v{} {} regions, {} MiB usable, {} cpu(s)",
        boot.version,
        boot.region_count,
        boot.usable_bytes >> 20,
        boot.cpu_count
    );
    kprintln!(
        "[kernel] image phys={:#018x} size={} KiB",
        boot.kernel_phys_base,
        boot.kernel_bytes >> 10
    );
    if boot.framebuffer.is_present() {
        kprintln!(
            "[kernel] framebuffer {}x{} stride={} at {:#018x}",
            boot.framebuffer.width,
            boot.framebuffer.height,
            boot.framebuffer.stride,
            boot.framebuffer.base
        );
    } else {
        kprintln!("[kernel] framebuffer absent, serial is the only console");
    }
    if boot.memory_map_truncated() {
        kprintln!("[kernel] WARNING memory map truncated, unknown ranges treated as reserved");
    }
    // Said out loud every boot, on purpose. The loader does not verify
    // signatures yet, and a chain that is not checked should not be silent
    // about it.
    if !boot.images_verified() {
        kprintln!("[kernel] WARNING images are NOT signature-verified in this build");
    }
}

/// Reports the protection features the page tables depend on.
///
/// `W^X` in `paging.rs` is enforced by the NX bit, which does nothing unless
/// `EFER.NXE` is set; read-only kernel mappings do nothing unless `CR0.WP` is
/// set. Printing the state each boot is how a firmware that left them off
/// becomes visible rather than becoming a silently unenforced policy.
fn report_protection_state() {
    let cr0 = cpu::read_cr0();
    let cr4 = cpu::read_cr4();
    let efer = cpu::read_efer();
    kprintln!(
        "[kernel] protection wp={} nx={} smep={} smap={}",
        yes_no(cr0 & cpu::CR0_WRITE_PROTECT != 0),
        yes_no(efer & cpu::EFER_NO_EXECUTE != 0),
        yes_no(cr4 & cpu::CR4_SMEP != 0),
        yes_no(cr4 & cpu::CR4_SMAP != 0),
    );
}

const fn yes_no(value: bool) -> &'static str {
    if value {
        "on"
    } else {
        "off"
    }
}

pub fn enable_interrupts() {
    cpu::enable_interrupts();
}

pub fn disable_interrupts() {
    cpu::disable_interrupts();
}

pub fn halt_forever() -> ! {
    cpu::halt_forever()
}

/// Waits for one interrupt, leaving the interrupt flag alone.
pub fn halt_once() {
    cpu::halt_once();
}

/// Top of the stack the CPU switches to when a fault arrives from ring 3.
#[must_use]
pub fn fault_stack_top() -> u64 {
    segments::ring3_kernel_stack_top()
}

/// Masks the legacy controllers and starts the LAPIC timer.
///
/// The two are one step because the order between them is not optional: the
/// 8259s power up delivering IRQs at vectors 8 through 15, which are exception
/// vectors, so anything that enables interrupts before they are masked reports
/// a double fault the first time the clock ticks.
///
/// # Safety
/// Called once, after the IDT is installed, with interrupts disabled.
pub unsafe fn start_timer() -> Result<apic::TimerInfo, apic::ApicError> {
    // SAFETY: bring-up, interrupts disabled, IDT live.
    unsafe {
        pic::disable();
        apic::init()
    }
}

/// Routes one device's interrupt to a vector, masked, and leaves it off.
///
/// Returns the rate the device will run at once somebody claims it.
///
/// # Why the device is not armed here
///
/// It was, and it did not work, for a reason worth keeping written down. The
/// RTC raises its interrupt and sets a flag in register C, and it raises no
/// further interrupt until that flag is read. Arming it at bring-up meant it
/// fired immediately, into a line that was masked because nobody owned it yet —
/// so the I/O APIC discarded the interrupt while the device went on holding the
/// flag. By the time a driver claimed the line and unmasked it, the device had
/// been waiting on an acknowledgement for several seconds and never asserted
/// again. The line was live, the handler was correct, and nothing arrived.
///
/// So bring-up decides the wiring and nothing else. Arming and unmasking both
/// happen when a process claims the line, in that order, in
/// `unmask_device_line`.
///
/// # Safety
/// Called once, after the IDT is installed and the LAPIC is up, with interrupts
/// disabled.
pub unsafe fn start_device_interrupt(line: usize) -> Result<u32, ioapic::IoApicError> {
    // SAFETY: bring-up, interrupts disabled, identity map active.
    let chip = unsafe { ioapic::init(ioapic::DEFAULT_BASE) }?;
    kprintln!(
        "[kernel] ioapic id={} pins={}",
        chip.id,
        u16::from(chip.highest_pin) + 1
    );

    let vector = ioapic::DEVICE_VECTOR_BASE + line as u8;
    // SAFETY: `interrupts::install` gave every device vector a gate, and this
    // one specifically the handler that delivers to user space.
    unsafe { chip.route(rtc::IRQ, vector, 0) }?;

    *ROUTED_PINS.lock() = Some((line, rtc::IRQ));
    kprintln!(
        "[kernel] rtc routed masked: irq {} -> vector {vector}, {} Hz when claimed",
        rtc::IRQ,
        rtc::HZ
    );
    Ok(rtc::HZ)
}

/// Stops a device and masks its line, after the process driving it has gone.
///
/// Releasing the line in `irq.rs` is bookkeeping: it says nobody owns this any
/// more. The device does not read that table. Left armed, the RTC goes on
/// raising its interrupt at 64 Hz into a kernel whose only response is to
/// notice nobody wanted it — which is exactly what the boot log showed after
/// the driver exited, one line of `interrupt on unclaimed line 0, masking`.
///
/// Harmless, because the storm defence caught it. Still wrong: a device outlives
/// its driver only because nothing told it not to.
///
/// # Safety
/// Called with interrupts disabled, from the exit path.
pub unsafe fn quiesce_device_line(line: usize) {
    let Some((routed, pin)) = *ROUTED_PINS.lock() else {
        return;
    };
    if routed != line {
        return;
    }

    // Device first, then the line. The other order leaves a window in which an
    // already-raised interrupt arrives at a line that is still unmasked and a
    // process that is already gone.
    // SAFETY: interrupts are off, as the caller guarantees.
    unsafe { rtc::stop_periodic() };

    // SAFETY: as above. `attach` rather than `init`: masking one pin should not
    // mask every other.
    if let Ok(chip) = unsafe { ioapic::attach(ioapic::DEFAULT_BASE) } {
        // SAFETY: the pin was routed by `start_device_interrupt`.
        let _ = unsafe { chip.mask(pin) };
    }
}

/// Which I/O APIC pin each claimable line was routed to.
///
/// One entry today. It exists because unmasking happens somewhere else and much
/// later — when a process claims the line — and that code has no business
/// knowing that line zero means IRQ 8. The wiring is decided once, here, and
/// remembered.
static ROUTED_PINS: spin::Mutex<Option<(usize, u8)>> = spin::Mutex::new(None);

/// Arms the device and lets its line deliver.
///
/// The separation from `start_device_interrupt` is the point, and it cost two
/// failed boots to get right. Routing is what the kernel knows — this pin, that
/// vector — and it is true from bring-up. Arming and unmasking are what a
/// process asked for, and they are true only once one has. Doing all three
/// together produces a device interrupting 64 times a second into a kernel whose
/// only possible response is to observe that nobody wanted it; doing the first
/// two together produces a device that latches an acknowledgement nobody will
/// read and then falls silent forever.
///
/// # Order
///
/// Arm, then unmask. An interrupt from an armed device whose line is masked is
/// discarded — recoverable, because the acknowledgement below clears the flag
/// that would otherwise wedge it. An unmasked line into an unarmed device is
/// merely quiet.
///
/// # Safety
/// The line must have been routed by `start_device_interrupt`, and the caller
/// must have established that a process owns it.
pub unsafe fn unmask_device_line(line: usize) -> Result<(), ioapic::IoApicError> {
    let Some((routed, pin)) = *ROUTED_PINS.lock() else {
        return Err(ioapic::IoApicError::NotPresent);
    };
    if routed != line {
        return Err(ioapic::IoApicError::NoSuchPin {
            pin: line as u8,
            highest: routed as u8,
        });
    }

    // SAFETY: the identity map is active and this runs with interrupts off — a
    // system call cleared IF through `SFMASK`. `attach` rather than `init`:
    // `init` masks every pin, which would undo this call as it made it.
    let chip = unsafe { ioapic::attach(ioapic::DEFAULT_BASE) }?;

    // SAFETY: interrupts are off, and `start_periodic` reads register C as its
    // last step — which clears any flag the firmware or a discarded interrupt
    // left set, and is what makes the device able to raise the next one.
    unsafe { rtc::start_periodic() };

    // SAFETY: the pin was routed to a vector with a handler by the call that
    // recorded it above.
    unsafe { chip.unmask(pin) }?;
    kprintln!(
        "[kernel] line {line} claimed and unmasked, rtc armed at {} Hz",
        rtc::HZ
    );
    Ok(())
}

/// Walks the PCI bus and reports what is on it.
///
/// Returns how many devices answered.
///
/// # Safety
/// Called once during bring-up, with interrupts disabled — the address and data
/// ports are one operation and must not be separated. Must run before any
/// driver exists, because BAR sizing briefly points a device's window
/// somewhere absurd.
pub unsafe fn scan_pci(
    mut found: impl FnMut(crate::pci::Address, &crate::pci::Header, &mut PortConfigSpace),
) -> usize {
    let mut space = PortConfigSpace;
    let mut count = 0usize;

    // The scan and the per-device work are separated because `scan_bus_zero`
    // holds a shared borrow of the space while a caller wanting to size BARs
    // needs a mutable one. Addresses first, then the work.
    let mut addresses = [crate::pci::Address::new(0, 0, 0); crate::pci::MAX_DEVICES_SCANNED];
    let mut headers = [None; crate::pci::MAX_DEVICES_SCANNED];
    // SAFETY: bring-up, interrupts disabled, as the caller guarantees.
    unsafe {
        crate::pci::scan_bus_zero(&space, |address, header| {
            if count < crate::pci::MAX_DEVICES_SCANNED {
                addresses[count] = address;
                headers[count] = Some(header);
                count += 1;
            }
        });
    }

    for index in 0..count {
        let header = headers[index].expect("filled above");
        kprintln!(
            "[kernel] pci {:02x}:{:02x}.{} {:04x}:{:04x} class {:02x}.{:02x}",
            addresses[index].bus,
            addresses[index].device,
            addresses[index].function,
            header.vendor,
            header.device,
            header.class,
            header.subclass
        );
        found(addresses[index], &header, &mut space);
    }

    count
}

pub use pci::PortConfigSpace;

/// Prints a panic message without taking the console lock.
pub fn emergency_serial(info: &core::panic::PanicInfo<'_>) {
    // SAFETY: the system is going down and the lock may be held by the code
    // that panicked; see `console::emergency_write`.
    unsafe {
        console::emergency_write(format_args!("\r\n[kernel] panic: {info}\r\n"));
    }
}
