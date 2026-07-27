//! Installing the GDT and TSS on the running processor.
//!
//! `gdt.rs` builds the descriptors and proves their bit layout in host tests.
//! This file is the part that cannot be tested that way: putting the table
//! somewhere the CPU can reach it, pointing GDTR at it, and reloading every
//! segment register before the firmware's table stops being kept alive.
//!
//! # Why the interrupt stacks are static arrays
//!
//! The IST stacks have to exist before the first fault can happen, which is
//! before any allocator exists. A static array in `.bss` is memory the loader
//! already accounted for as part of the kernel image, so it is guaranteed
//! present and guaranteed not to be handed out by the frame allocator later.

use super::addr::{PagingMode, VirtAddr};
use super::cpu::{self, DescriptorTablePointer};
use super::gdt::{ist, GdtBuilder, GdtError, GdtLayout, Tss};

/// Size of each dedicated fault stack.
///
/// 16 KiB rather than 4: the double-fault handler prints a register dump and a
/// backtrace, and a handler that overflows its own emergency stack produces the
/// exact silent triple fault the stack exists to prevent.
const FAULT_STACK_BYTES: usize = 16 * 1024;

#[repr(C, align(16))]
struct FaultStack([u8; FAULT_STACK_BYTES]);

/// One stack per IST slot in use. They must not be shared: an NMI delivered
/// while the double-fault handler is running would otherwise land on the stack
/// that handler is already using.
static mut DOUBLE_FAULT_STACK: FaultStack = FaultStack([0; FAULT_STACK_BYTES]);
static mut NMI_STACK: FaultStack = FaultStack([0; FAULT_STACK_BYTES]);
static mut MACHINE_CHECK_STACK: FaultStack = FaultStack([0; FAULT_STACK_BYTES]);
static mut DEBUG_STACK: FaultStack = FaultStack([0; FAULT_STACK_BYTES]);

#[repr(C, align(16))]
struct GdtStorage([u64; GdtBuilder::CAPACITY]);

static mut GDT: GdtStorage = GdtStorage([0; GdtBuilder::CAPACITY]);
static mut TSS: Tss = Tss::new();

/// Top of a static stack. Stacks grow downwards, so the CPU wants the address
/// one past the end.
fn stack_top(stack: *mut FaultStack) -> VirtAddr {
    let end = stack as u64 + FAULT_STACK_BYTES as u64;
    VirtAddr::from_indices_sign_extended(end, PagingMode::Level4)
}

/// Builds the GDT and TSS, loads them, and reloads every segment register.
///
/// # Safety
/// Called once, on the bootstrap processor, with interrupts disabled. The
/// returned layout must outlive every later use of its selectors, which it does
/// because the table behind it is static.
pub unsafe fn install() -> Result<GdtLayout, GdtError> {
    // SAFETY: single-threaded bring-up before any other processor is started,
    // so these statics have no concurrent access.
    let tss = unsafe { &mut *core::ptr::addr_of_mut!(TSS) };

    tss.set_ist(
        ist::DOUBLE_FAULT,
        stack_top(core::ptr::addr_of_mut!(DOUBLE_FAULT_STACK)),
    )?;
    tss.set_ist(ist::NMI, stack_top(core::ptr::addr_of_mut!(NMI_STACK)))?;
    tss.set_ist(
        ist::MACHINE_CHECK,
        stack_top(core::ptr::addr_of_mut!(MACHINE_CHECK_STACK)),
    )?;
    tss.set_ist(ist::DEBUG, stack_top(core::ptr::addr_of_mut!(DEBUG_STACK)))?;

    let tss_base =
        VirtAddr::from_indices_sign_extended(core::ptr::addr_of!(TSS) as u64, PagingMode::Level4);
    let (builder, layout) = GdtBuilder::build(tss_base)?;

    // SAFETY: as above — exclusive during bring-up.
    let gdt = unsafe { &mut *core::ptr::addr_of_mut!(GDT) };
    for (slot, descriptor) in builder.entries().iter().enumerate() {
        gdt.0[slot] = descriptor.0;
    }

    let pointer = DescriptorTablePointer {
        limit: builder.limit(),
        base: core::ptr::addr_of!(GDT) as u64,
    };

    // SAFETY: `pointer` describes the static table just filled in, which lives
    // for the rest of the kernel's life. The segment reload immediately after
    // is what makes the new descriptors take effect, and `ltr` needs the GDT
    // already loaded to find the TSS descriptor.
    unsafe {
        cpu::lgdt(&pointer);
        cpu::reload_segments(layout.kernel_code, layout.kernel_data);
        cpu::load_tss(layout.tss);
    }

    Ok(layout)
}

/// Sets the stack the CPU switches to on a ring 3 → 0 transition.
///
/// Not used yet — nothing runs in ring 3 — but it is the one TSS field that has
/// to change on every context switch, so it lives next to the rest of the TSS
/// handling rather than being rediscovered later.
///
/// # Safety
/// `stack_top` must be the top of a stack that stays mapped and is not in use
/// by any other thread.
pub unsafe fn set_kernel_stack(stack_top: VirtAddr) {
    // SAFETY: the caller guarantees exclusivity of the TSS update.
    let tss = unsafe { &mut *core::ptr::addr_of_mut!(TSS) };
    tss.privilege_stack_table[0] = stack_top.as_u64();
}
