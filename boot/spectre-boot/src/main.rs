//! WhisezOS stage-1 UEFI loader.
//!
//! Loads `\SPECTRE\KERNEL.ELF`, builds the handoff structure, leaves boot
//! services, and jumps. Boot order, and the reasoning for it:
//!
//!   1. **Serial first.** Everything after this can fail before there is a
//!      framebuffer, and a loader that cannot say why it stopped is a black
//!      screen with a blinking cursor. The kernel continues on the same port,
//!      so one capture covers the whole boot.
//!   2. **Memory audit.** `spd::audit` decides whether the platform clears the
//!      floor. Failing here, before anything is allocated or copied, is the
//!      cheapest place to fail.
//!   3. **Read and validate the kernel.** The image is parsed and every program
//!      header bounds-checked (`elf.rs`) before a single page is allocated for
//!      it.
//!   4. **Allocate, copy, zero.** At the address the image was linked for.
//!   5. **Collect what only boot services can provide** — framebuffer geometry
//!      and the ACPI pointer — while boot services still exist.
//!   6. **Exit boot services, then build the memory map.** In that order: the
//!      map is only final once nothing else can allocate.
//!   7. **Jump.** Interrupts masked, `rdi` carrying the handoff.
//!
//! # What this loader does not do yet
//!
//! It does not verify signatures. `attest.rs` implements the comparison and is
//! tested, but there is no signed manifest in the build and no key to check it
//! against, so wiring it up would produce a verification step that always
//! passes — worse than none, because it looks like a chain of trust. The
//! handoff carries `FLAG_IMAGES_VERIFIED` clear and the kernel says so on the
//! console every boot until that changes.

#![no_main]
#![no_std]

extern crate alloc;

mod elf;

/// The handoff layout, included from the kernel rather than copied.
///
/// Two binaries, two targets, one definition — see the module's own comment for
/// why a second copy is the failure mode worth designing against.
#[path = "../../../kernel/spectre-kernel/src/boot_info.rs"]
mod boot_info;

/// The same 16550 driver the kernel uses, so the loader's lines and the
/// kernel's lines are produced by identical code on the same port.
/// Only the transmit path is used here; the receive helpers exist for the
/// kernel's side of the same driver.
#[allow(dead_code)]
#[path = "../../../kernel/spectre-kernel/src/arch/serial.rs"]
mod serial;

/// The SMBus enumeration half has no caller until an SMBus driver exists; the
/// audit half is what stage 1 uses today.
#[allow(dead_code)]
mod spd;

use alloc::vec::Vec;
use core::fmt::Write;

use uefi::boot::{AllocateType, MemoryType};
use uefi::mem::memory_map::{MemoryMap, MemoryMapMut};
use uefi::prelude::*;
use uefi::proto::console::gop::GraphicsOutput;

use boot_info::{
    BootInfo, Framebuffer, MemoryKind, MemoryMapBuilder, MemoryRegion, FLAG_IMAGES_VERIFIED,
};
use elf::Elf64;
use serial::{Uart, X86Ports, COM1};

const KERNEL_PATH: &str = "\\SPECTRE\\KERNEL.ELF";
const PAGE_SIZE: u64 = 4096;

/// OS-defined memory type for the kernel image.
///
/// UEFI reserves everything at or above `0x8000_0000` for the loaded OS, so
/// tagging the image with its own type makes it a distinct descriptor in the
/// final memory map. Without it the image is indistinguishable from the
/// loader's other allocations, and the kernel cannot tell which range it must
/// never reclaim from the ranges it may.
const KERNEL_IMAGE_MEMORY_TYPE: u32 = 0x8000_0000;

macro_rules! log {
    ($uart:expr, $($arg:tt)*) => {{
        let _ = writeln!($uart, "\r[boot] {}\r", format_args!($($arg)*));
    }};
}

#[entry]
fn main() -> Status {
    if uefi::helpers::init().is_err() {
        return Status::ABORTED;
    }
    let mut uart = Uart::new(X86Ports, COM1);
    let _ = uart.init(115_200);
    log!(uart, "WhisezOS stage-1 loader");

    match load(&mut uart) {
        Ok(()) => Status::LOAD_ERROR, // `load` diverges on success.
        Err(status) => {
            log!(uart, "HALTED: {status:?}");
            halt_forever()
        }
    }
}

/// Everything that can fail, so the entry point stays a single decision.
fn load(uart: &mut Uart<X86Ports>) -> Result<(), Status> {
    // ---- 2. Memory audit -------------------------------------------------
    let conventional = conventional_memory_total();
    // No SMBus driver in this build, so the audit runs in map-only mode: it
    // checks the floor without cross-checking SPD against the firmware's map.
    let usable = match spd::audit(&[], conventional, false) {
        Ok(bytes) => bytes,
        Err(fault) => {
            log!(uart, "memory audit failed: {fault:?}");
            return Err(Status::OUT_OF_RESOURCES);
        }
    };
    log!(
        uart,
        "memory audit passed, {} MiB conventional",
        usable >> 20
    );

    // ---- 3. Read and validate the kernel ---------------------------------
    let image = read_kernel(uart)?;
    let kernel = Elf64::parse(&image).map_err(|e| {
        log!(uart, "kernel image rejected: {e:?}");
        Status::COMPROMISED_DATA
    })?;
    let (base, span) = kernel.physical_extent().ok_or(Status::COMPROMISED_DATA)?;
    log!(
        uart,
        "kernel {} KiB, entry {:#x}, load {:#x}..{:#x}",
        image.len() >> 10,
        kernel.entry(),
        base,
        base + span
    );

    // ---- 4. Allocate, copy, zero -----------------------------------------
    let pages = span.div_ceil(PAGE_SIZE) as usize;
    uefi::boot::allocate_pages(
        AllocateType::Address(base),
        MemoryType::custom(KERNEL_IMAGE_MEMORY_TYPE),
        pages,
    )
    .map_err(|e| {
        // The link address is fixed, so this is not recoverable by retrying
        // elsewhere: the image has no relocations to apply. What the operator
        // needs instead is the reason — which ranges the firmware left free —
        // because the fix is to relink, and that needs a target address.
        log!(uart, "cannot claim {pages} pages at {base:#x}: {e:?}");
        report_free_regions(uart, span);
        Status::OUT_OF_RESOURCES
    })?;

    for segment in kernel.segments() {
        let bytes = kernel.contents(&segment);
        // SAFETY: the destination is inside the allocation just made — every
        // segment lies within `physical_extent` by construction — and physical
        // memory is identity mapped under UEFI.
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), segment.phys as *mut u8, bytes.len());
            // Anything past the file-backed part is `.bss`. Leaving it as
            // whatever the firmware left behind gives the kernel statics that
            // differ between boots, which is the worst possible way to debug.
            core::ptr::write_bytes(
                (segment.phys + segment.file_size) as *mut u8,
                0,
                segment.zero_fill() as usize,
            );
        }
    }
    log!(uart, "{} segments loaded", kernel.segments().count());

    // ---- 5. Collect what needs boot services -----------------------------
    let framebuffer = probe_framebuffer();
    let rsdp = acpi_rsdp();

    let info = allocate_boot_info()?;
    // SAFETY: freshly allocated, page aligned, and large enough by
    // construction; nothing else holds a reference.
    let info = unsafe { &mut *info };
    *info = BootInfo::empty();
    info.kernel_phys_base = base;
    info.kernel_virt_base = base;
    info.kernel_bytes = span;
    info.framebuffer = framebuffer;
    info.acpi_rsdp = rsdp;
    // One processor. Counting the rest needs the ACPI MADT, which nothing
    // parses yet; reporting a guess would be worse than reporting the truth.
    info.cpu_count = 1;
    // Signature verification is not wired up. Stated once, in the one place
    // that decides it, rather than assumed anywhere.
    info.flags &= !FLAG_IMAGES_VERIFIED;

    log!(
        uart,
        "framebuffer {}x{} at {:#x}, rsdp {:#x}",
        framebuffer.width,
        framebuffer.height,
        framebuffer.base,
        rsdp
    );
    log!(uart, "exiting boot services");

    // ---- 6. Exit boot services, then build the map -----------------------
    // SAFETY: no further boot-services call is made after this point. The
    // allocations above are complete and the console is the serial port, which
    // is driven by direct port I/O rather than by any firmware protocol.
    let mut map = unsafe { uefi::boot::exit_boot_services(Some(MemoryType::LOADER_DATA)) };
    // UEFI does not promise an ordered map, and every consumer downstream —
    // the merge below, the validator, the frame allocator — assumes ascending
    // order.
    map.sort();

    let mut builder = MemoryMapBuilder::new();
    let kernel_end = base + span;
    for entry in map.entries() {
        let len = entry.page_count * PAGE_SIZE;
        if len == 0 {
            continue;
        }
        let kind = if entry.phys_start >= base && entry.phys_start < kernel_end {
            MemoryKind::Kernel
        } else {
            MemoryKind::from_uefi(entry.ty.0)
        };
        builder.push(MemoryRegion::new(entry.phys_start, len, kind));
    }
    builder.finish(info);

    log!(
        uart,
        "handoff: {} regions, {} MiB usable",
        info.region_count,
        info.usable_bytes >> 20
    );
    log!(uart, "jumping to kernel at {:#x}", kernel.entry());

    // ---- 7. Jump ---------------------------------------------------------
    // SAFETY: the entry point lies inside a loaded segment (checked by
    // `Elf64::parse`), the image is fully copied and zeroed, and the handoff
    // structure is live in `LOADER_DATA`. Interrupts are masked first because
    // the firmware left them enabled and the kernel's IDT does not exist yet —
    // one timer tick between here and `lidt` would be delivered through the
    // firmware's table, which we are about to stop keeping alive.
    unsafe {
        core::arch::asm!(
            "cli",
            "jmp {entry}",
            entry = in(reg) kernel.entry(),
            in("rdi") info as *mut BootInfo,
            options(noreturn),
        );
    }
}

fn read_kernel(uart: &mut Uart<X86Ports>) -> Result<Vec<u8>, Status> {
    let volume = uefi::boot::get_image_file_system(uefi::boot::image_handle()).map_err(|e| {
        log!(uart, "no filesystem on the boot device: {e:?}");
        Status::NOT_FOUND
    })?;
    let mut fs = uefi::fs::FileSystem::new(volume);

    let path = uefi::CString16::try_from(KERNEL_PATH).map_err(|_| Status::INVALID_PARAMETER)?;
    fs.read(uefi::fs::Path::new(&path)).map_err(|e| {
        log!(uart, "cannot read {KERNEL_PATH}: {e:?}");
        Status::NOT_FOUND
    })
}

/// Reserves a page-aligned home for the handoff structure.
///
/// `LOADER_DATA` on purpose: the kernel classifies it as `Loader`, which is not
/// allocatable, so the frame allocator cannot hand out the structure it is
/// reading its own configuration from.
fn allocate_boot_info() -> Result<*mut BootInfo, Status> {
    let pages = (core::mem::size_of::<BootInfo>() as u64).div_ceil(PAGE_SIZE) as usize;
    let ptr = uefi::boot::allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, pages)
        .map_err(|_| Status::OUT_OF_RESOURCES)?;
    Ok(ptr.as_ptr().cast())
}

/// Lists free conventional ranges big enough to hold the kernel.
///
/// Only reached when the fixed load address is unavailable. Printing the first
/// few candidates turns "allocation failed" into "relink at one of these",
/// which is the difference between a five-minute fix and an afternoon of
/// bisecting addresses by hand.
fn report_free_regions(uart: &mut Uart<X86Ports>, needed: u64) {
    let Ok(map) = uefi::boot::memory_map(MemoryType::LOADER_DATA) else {
        return;
    };
    log!(uart, "free conventional ranges that would fit {needed:#x}:");
    let mut shown = 0;
    for entry in map.entries() {
        if entry.ty != MemoryType::CONVENTIONAL {
            continue;
        }
        let len = entry.page_count * PAGE_SIZE;
        if len < needed {
            continue;
        }
        log!(
            uart,
            "  {:#012x}..{:#012x} ({} MiB)",
            entry.phys_start,
            entry.phys_start + len,
            len >> 20
        );
        shown += 1;
        if shown == 8 {
            break;
        }
    }
}

fn conventional_memory_total() -> u64 {
    let Ok(map) = uefi::boot::memory_map(MemoryType::LOADER_DATA) else {
        return 0;
    };
    map.entries()
        .filter(|d| MemoryKind::from_uefi(d.ty.0).is_allocatable())
        .map(|d| d.page_count * PAGE_SIZE)
        .sum()
}

/// Reads the framebuffer geometry the firmware already has running.
///
/// Deliberately no mode set: the loader takes what is there. Changing modes
/// here would mean the boot animation and the kernel disagree about the
/// framebuffer, and a mode set that fails halfway leaves no console at all.
fn probe_framebuffer() -> Framebuffer {
    let Ok(handle) = uefi::boot::get_handle_for_protocol::<GraphicsOutput>() else {
        return Framebuffer::default();
    };
    let Ok(mut gop) = uefi::boot::open_protocol_exclusive::<GraphicsOutput>(handle) else {
        return Framebuffer::default();
    };

    let mode = gop.current_mode_info();
    let (width, height) = mode.resolution();
    Framebuffer {
        base: gop.frame_buffer().as_mut_ptr() as u64,
        width: width as u32,
        height: height as u32,
        stride: mode.stride() as u32,
        // GOP reports BGR or RGB with a reserved byte; both are 4 bytes wide.
        bytes_per_pixel: 4,
    }
}

/// The ACPI 2.0 RSDP, preferred over the 1.0 one where both are present.
fn acpi_rsdp() -> u64 {
    use uefi::table::cfg::ConfigTableEntry;

    let mut fallback = 0u64;
    uefi::system::with_config_table(|entries| {
        for entry in entries {
            if entry.guid == ConfigTableEntry::ACPI2_GUID {
                return entry.address as u64;
            }
            if entry.guid == ConfigTableEntry::ACPI_GUID {
                fallback = entry.address as u64;
            }
        }
        fallback
    })
}

fn halt_forever() -> ! {
    loop {
        // SAFETY: halting has no memory effects and never returns.
        unsafe {
            core::arch::asm!("cli", "hlt", options(nomem, nostack));
        }
    }
}
