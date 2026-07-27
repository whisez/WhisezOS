//! The kernel binary: entry point, stack, and panic handler.
//!
//! Everything else lives in the library so `verify/` can reach it. This file is
//! only the three things a freestanding image must own itself.

#![no_std]
#![no_main]

use spectre_kernel::{arch, BootInfo};

/// The kernel's initial stack.
///
/// The loader hands over on a stack it allocated, in memory it marked as its
/// own — which the frame allocator will reclaim. Switching to a stack inside the
/// kernel image, before anything else runs, is what stops the kernel from
/// executing on memory it is about to hand out.
///
/// 64 KiB. The bring-up path formats to serial and walks page tables; neither is
/// deep, but a stack that overflows before the IDT is loaded triple-faults with
/// nothing on the wire.
const STACK_BYTES: usize = 64 * 1024;

#[repr(C, align(16))]
struct Stack([u8; STACK_BYTES]);

static mut STACK: Stack = Stack([0; STACK_BYTES]);

/// ELF entry point.
///
/// `naked` because the first thing that must happen is the stack switch, and any
/// prologue the compiler emits would run on the loader's stack — the one being
/// abandoned. The System V argument register `rdi` already holds the `BootInfo`
/// pointer and is preserved across the switch.
#[unsafe(naked)]
#[no_mangle]
pub extern "sysv64" fn _start(_boot_info: *const BootInfo) -> ! {
    core::arch::naked_asm!(
        // Top of the static stack, 16-byte aligned as the ABI requires.
        "lea rsp, [rip + {stack}]",
        "add rsp, {size}",
        "and rsp, -16",
        // Terminate the frame-pointer chain so a backtrace stops here rather
        // than walking into whatever the loader left in rbp.
        "xor rbp, rbp",
        "call {entry}",
        // `entry` diverges; if it ever returns, stop rather than execute
        // whatever follows in memory.
        "2:",
        "cli",
        "hlt",
        "jmp 2b",
        stack = sym STACK,
        size = const STACK_BYTES,
        entry = sym kernel_entry,
    )
}

extern "sysv64" fn kernel_entry(boot_info: *const BootInfo) -> ! {
    // SAFETY: reached exactly once from `_start`, on the bootstrap processor,
    // with interrupts still masked by the loader and `rdi` carrying the pointer
    // the loader placed there.
    unsafe { spectre_kernel::run(boot_info) }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    // A kernel panic is an invariant violation, so we assume nothing about the
    // system state: no allocation, no IPC, no scheduler. Write directly to the
    // serial port and halt.
    arch::emergency_serial(info);
    arch::halt_forever()
}
