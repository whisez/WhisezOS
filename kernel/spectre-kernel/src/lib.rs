//! WhisezOS microkernel.
//!
//! # What is in kernel space, and why nothing else is
//!
//! Four subsystems:
//!
//! * `ipc`   — message passing. The kernel's reason for existing.
//! * `sched` — three-class scheduler with RT admission control.
//! * `vault` — address spaces and per-process encrypted arenas.
//! * `arch`  — the hardware abstraction layer: paging, interrupts, context
//!   switch, APIC, IOMMU domain setup.
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
//! # What this crate actually links today
//!
//! Only `arch` and `boot_info`. That is the honest state of the tree, and the
//! module list above describes the design rather than the build.
//!
//! `cap`, `sched`, `vault`, `ipc`, and `gamemode` are real, complete, and
//! covered by several hundred tests — but they are written against platform
//! modules (`thread`, `percpu`, `notify`, `compact`, `forensic`, `gpu`, `net`)
//! that do not exist yet. `verify/` compiles those five against host stand-ins
//! and runs their suites on every build, which is why they are tested but not
//! booted. Declaring them here as well would produce a crate that does not
//! compile, and a kernel that does not compile cannot be shown to boot.
//!
//! They come back one at a time, each with the platform module it needs, and
//! each proven by the QEMU boot test rather than by being listed here.
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

pub mod arch;
pub mod boot_info;

pub use boot_info::BootInfo;

/// Kernel entry, called from the loader's handoff trampoline with the verified
/// memory map and framebuffer.
///
/// # Safety
/// Called exactly once, on the bootstrap processor, with interrupts disabled and
/// the loader's identity mapping still active. `boot_info` must point to a live
/// `BootInfo` in memory the loader marked as its own, so nothing reclaims it
/// before `arch::early_init` has copied what it needs.
pub unsafe fn run(boot_info: *const BootInfo) -> ! {
    // SAFETY: the caller guarantees the pointer is live and correctly aligned.
    let boot = unsafe { &*boot_info };

    // SAFETY: first and only call, interrupts disabled, as required above.
    match unsafe { arch::early_init(boot) } {
        Ok(()) => {
            kprintln!("[kernel] stage 1 complete");
        }
        Err(error) => {
            kprintln!("[kernel] BRING-UP FAILED: {error:?}");
            arch::halt_forever();
        }
    }

    // Interrupts stay masked. Enabling them requires an interrupt controller
    // and a timer, and stage 1 has neither: `sti` here would let a stray legacy
    // PIC line arrive at a vector nothing is prepared to service.
    kprintln!("[kernel] no init process yet, halting");
    arch::halt_forever()
}
