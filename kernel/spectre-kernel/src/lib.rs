//! WhisezOS microkernel.
//!
//! # What is in kernel space, and why nothing else is
//!
//! Four subsystems, roughly 11k lines of Rust plus 900 lines of assembly:
//!
//!   * `ipc`    — message passing. The kernel's reason for existing.
//!   * `sched`  — three-class scheduler with RT admission control.
//!   * `vault`  — address spaces and per-process encrypted arenas.
//!   * `arch`   — the hardware abstraction layer: paging, interrupts, context
//!                switch, APIC, IOMMU domain setup.
//!
//! Plus `cap`, which is not a subsystem so much as the type system the other
//! four are written in.
//!
//! Everything else is a user-space process: every driver except the GPU
//! (sandboxed, see ARCHITECTURE.md §8), every filesystem, the network stack,
//! the USB stack, the input stack, the compositor.
//!
//! The trade is real and worth naming. A monolithic kernel does a disk read in
//! one syscall; we do it in a syscall plus two IPC round trips. We buy that
//! back with direct handoff and timeslice donation (`ipc.rs`), which gets the
//! measured cost to ~1.4x a Linux read on the same hardware. In exchange, a bug
//! in the NVMe driver is a crashed process that restarts in 40 ms, not a
//! kernel panic — and an exploited USB stack yields one MMIO window rather than
//! ring 0.
//!
//! # Panic policy
//!
//! The kernel panics only on states that indicate the kernel's own invariants
//! are broken. Every failure that can be caused by user-space — bad pointer,
//! exhausted quota, malformed message, capability violation — is an `Err`, not
//! a panic. A microkernel that can be panicked by a user-space process has
//! given away the entire benefit of being a microkernel.

#![no_std]
#![feature(abi_x86_interrupt)]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(clippy::undocumented_unsafe_blocks)]

extern crate alloc;

pub mod cap;
pub mod gamemode;
pub mod ipc;
pub mod sched;
pub mod vault;

// Platform and support modules. These are thin by design — anything that grows
// past a few hundred lines is a candidate for eviction to user space.
pub mod arch;
pub mod compact;
pub mod debug;
pub mod entropy;
pub mod forensic;
pub mod gpu;
pub mod net;
pub mod notify;
pub mod percpu;
pub mod thread;
pub mod time;

/// Kernel entry, called from the stage-1 loader's handoff trampoline with the
/// verified memory map and the unlocked volume key.
///
/// # Safety
/// Called exactly once, on the bootstrap processor, with interrupts disabled
/// and the loader's page tables still active.
#[no_mangle]
pub unsafe extern "C" fn spectre_main(boot_info: *const BootInfo) -> ! {
    // SAFETY: the loader guarantees `boot_info` points to a live, verified
    // structure in LOADER_DATA memory that outlives this call.
    let boot = unsafe { &*boot_info };

    arch::early_init(boot);
    entropy::seed_from_boot(boot);
    vault::init(boot.usable_memory_bytes);
    sched::init(boot.cpu_count);
    ipc::init();

    // The first and only process the kernel starts. Everything else — drivers,
    // filesystems, Prism, the login screen — is init's problem, spawned with a
    // capability set carved out of init's own.
    let init = thread::spawn_init(boot);
    arch::enable_interrupts();
    sched::run(init)
}

#[repr(C)]
pub struct BootInfo {
    pub usable_memory_bytes: u64,
    pub cpu_count: u32,
    pub framebuffer: FramebufferInfo,
    pub volume_key_page: *mut u8,
    pub entropy_seed: [u8; 32],
    pub acpi_rsdp: u64,
}

#[repr(C)]
pub struct FramebufferInfo {
    pub base: u64,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
}

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    // A kernel panic is an invariant violation, so we assume nothing about the
    // system state: no allocation, no IPC, no scheduler. Write directly to the
    // framebuffer and the serial port, scrub key material, halt.
    arch::emergency_serial(info);
    vault::scrub_all_keys();
    arch::halt_forever()
}
