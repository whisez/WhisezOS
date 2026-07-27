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
use crate::portauth::{self, Grants, BITMAP_BYTES};

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

/// The TSS, with the I/O permission bitmap the CPU consults on `in` and `out`.
///
/// One allocation, because the bitmap is not a separate structure — the CPU
/// finds it at `iomap_base` bytes past the TSS and reads it as part of the same
/// segment, so the descriptor's limit has to cover both. Splitting them into
/// two statics would work only if the linker happened to place them adjacently,
/// which is not a thing to rely on.
#[repr(C, packed(4))]
struct TssWithBitmap {
    tss: Tss,
    /// A clear bit permits the port. Starts all-ones: everything denied.
    bitmap: [u8; BITMAP_BYTES],
    /// The terminator the SDM requires past the end of the bitmap.
    ///
    /// The CPU may read the byte after the bit it wants when a port access
    /// straddles a byte boundary — a 16-bit `out` to the last port covered
    /// touches this. All-ones means "denied", which is the answer that keeps
    /// the edge case from permitting something by reading off the end.
    terminator: u8,
}

static mut TSS_STORAGE: TssWithBitmap = TssWithBitmap {
    tss: Tss::new(),
    bitmap: [0xFF; BITMAP_BYTES],
    terminator: 0xFF,
};

/// Which ranges the bitmap currently permits.
///
/// The switch needs it: making the bitmap match the incoming process means
/// knowing what the outgoing one had, and re-denying only that is a handful of
/// bit operations rather than rewriting a bitmap on every context switch.
static ACTIVE_GRANTS: spin::Mutex<Grants> = spin::Mutex::new(Grants::NONE);

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
    let storage = unsafe { &mut *core::ptr::addr_of_mut!(TSS_STORAGE) };
    let tss = &mut storage.tss;

    // Where the CPU looks for the bitmap, measured from the base of the TSS.
    // Until this is set the field holds the TSS size, which is past the old
    // limit and denies every port — the previous behaviour, and still the
    // behaviour for every process that is granted nothing.
    tss.iomap_base = core::mem::size_of::<Tss>() as u16;

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

    let tss_base = VirtAddr::from_indices_sign_extended(
        core::ptr::addr_of!(TSS_STORAGE) as u64,
        PagingMode::Level4,
    );
    // The limit covers the bitmap and its terminator. A limit that stopped at
    // the TSS would leave `iomap_base` pointing past the segment, which the CPU
    // reads as "no bitmap, deny everything" — the grants would be written and
    // silently have no effect.
    let (builder, layout) = GdtBuilder::build_with_tss_limit(
        tss_base,
        core::mem::size_of::<TssWithBitmap>() as u32 - 1,
    )?;

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

/// A kernel stack for exceptions arriving from ring 3.
///
/// Reuses the debug IST stack's sibling rather than adding a fifth: this is the
/// `RSP0` the CPU loads on a privilege transition, and it must not be the user
/// stack or the syscall stack. It becomes per-thread the moment there is more
/// than one thread.
#[must_use]
pub fn ring3_kernel_stack_top() -> u64 {
    stack_top(core::ptr::addr_of_mut!(RING3_STACK)).as_u64()
}

static mut RING3_STACK: FaultStack = FaultStack([0; FAULT_STACK_BYTES]);

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
    let storage = unsafe { &mut *core::ptr::addr_of_mut!(TSS_STORAGE) };
    storage.tss.privilege_stack_table[0] = stack_top.as_u64();
}

/// Makes the I/O bitmap say what `grants` says, and nothing more.
///
/// Called on every context switch, next to the `RSP0` update and for the same
/// reason: there is one TSS on one processor, and it describes whichever process
/// is running. A bitmap left holding the last process's grants is that process's
/// device handed to the next one to be scheduled.
///
/// # Why this is not a memcpy
///
/// Rewriting all 128 bytes every switch would be simpler and is what a first
/// version would do. It is also 128 bytes of write traffic per switch to change
/// two bits. Denying what the last process had and permitting what this one has
/// touches only the ports actually involved, which is a handful — and the cost
/// scales with grants held rather than with the size of the port space.
///
/// # Safety
/// Called with interrupts disabled, on the processor whose TSS this is.
pub unsafe fn apply_io_permissions(grants: &Grants) {
    let mut active = ACTIVE_GRANTS.lock();
    if *active == *grants {
        return;
    }

    // SAFETY: the caller guarantees exclusivity.
    let storage = unsafe { &mut *core::ptr::addr_of_mut!(TSS_STORAGE) };

    // Deny first, then permit. The other order would briefly permit the union
    // of both processes' ports, which on one processor with interrupts off
    // nothing could observe — but "nothing could observe it" is a weaker
    // property than "it never happens", and this costs nothing.
    for range in active.ranges() {
        for port in range.base..range.base.saturating_add(range.len) {
            let index = usize::from(port);
            if index < portauth::PORT_SPACE {
                storage.bitmap[index / 8] |= 1u8 << (index % 8);
            }
        }
    }
    for range in grants.ranges() {
        for port in range.base..range.base.saturating_add(range.len) {
            let index = usize::from(port);
            if index < portauth::PORT_SPACE {
                storage.bitmap[index / 8] &= !(1u8 << (index % 8));
            }
        }
    }

    *active = *grants;
}
