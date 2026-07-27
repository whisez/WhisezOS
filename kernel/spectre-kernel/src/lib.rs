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
//! `arch`, `boot_info`, `abi`, `elf`, `usercopy`, `roundrobin`, `syscall`, and
//! `task`. That is the honest state of the tree, and the module list above
//! describes the design rather than the build.
//!
//! `task` in particular is not `sched`: it is a fixed table and a rotating
//! index, enough to preempt two processes with a timer. `sched.rs` is the
//! three-class scheduler the architecture calls for.
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

pub mod abi;
pub mod arch;
pub mod boot_info;
pub mod elf;
pub mod roundrobin;
pub mod syscall;
pub mod task;
pub mod usercopy;

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
    let platform = match unsafe { arch::early_init(boot) } {
        Ok(platform) => {
            kprintln!("[kernel] stage 1 complete");
            platform
        }
        Err(error) => {
            kprintln!("[kernel] BRING-UP FAILED: {error:?}");
            arch::halt_forever();
        }
    };

    // SAFETY: the handoff was validated by `early_init`, and the init image
    // lives in `Loader` memory, which the frame allocator does not hand out.
    let Some(image) = (unsafe { boot.init_image() }) else {
        kprintln!("[kernel] no init image in the handoff, halting");
        arch::halt_forever();
    };
    kprintln!("[kernel] init image {} KiB", image.len() >> 10);

    task::init(platform.gdt, arch::fault_stack_top());

    // Two processes from one image. They share no memory — each gets its own
    // address space built from the same bytes — and tell themselves apart only
    // by the argument the kernel puts in `rdi`. Two is the smallest number that
    // makes a scheduler observable: with one, "preempted and resumed" and
    // "never interrupted" produce the same output.
    for argument in 1..=2u64 {
        // SAFETY: the early allocator is up, physical memory is identity
        // mapped, and `platform.kernel_root` is the table currently in CR3.
        let process = match unsafe { arch::user::load(image, platform.kernel_root) } {
            Ok(process) => process,
            Err(error) => {
                kprintln!("[kernel] INIT REJECTED: {error:?}");
                arch::halt_forever();
            }
        };
        match task::admit(&process, argument) {
            Some(pid) => kprintln!(
                "[kernel] init mapped pid={pid} entry={:#018x} stack={:#018x} regions={}",
                process.entry,
                process.stack_top,
                process.regions().len()
            ),
            None => {
                kprintln!("[kernel] process table full");
                arch::halt_forever();
            }
        }
    }

    // The timer is started last. Once it is running, the next thing that
    // happens is a context switch, and there is no point being able to switch
    // before there is more than one thing to switch to.
    // SAFETY: the IDT is installed and the legacy PICs are about to be masked
    // by this call's own preamble; interrupts are still disabled.
    match unsafe { arch::start_timer() } {
        Ok(info) => arch::apic::report(&info),
        Err(error) => {
            // Not fatal. Without a timer there is no preemption, so the first
            // process runs until it makes a system call — which is a degraded
            // system, and is reported as one rather than looking like success.
            kprintln!("[kernel] WARNING no timer ({error:?}), running without preemption");
        }
    }

    kprintln!("[kernel] entering ring 3");
    // SAFETY: both processes were loaded against the active kernel table, the
    // syscall MSRs are installed, and interrupts are still masked — they come
    // on through the first frame's RFLAGS, in ring 3.
    unsafe { task::run() }
}
