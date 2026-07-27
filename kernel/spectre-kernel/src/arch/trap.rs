//! The interrupt entry that can change which process is running.
//!
//! # Why this is separate from the exception handlers
//!
//! `interrupts.rs` uses the `x86-interrupt` ABI, which is exactly right for a
//! fault: the compiler saves what it clobbers, hands you the CPU's frame, and
//! returns where you came from. It cannot preempt, because it has no access to
//! the registers it did not happen to touch and no way to return somewhere
//! else.
//!
//! Preemption needs the whole architectural state — all fifteen general
//! registers plus the frame the CPU pushed — laid out somewhere a scheduler can
//! read and rewrite. That is what the stub below builds, and why it is hand
//! written.
//!
//! # Switching by rewriting the frame
//!
//! The obvious design gives every process its own kernel stack and switches
//! `RSP` between them. This one copies the frame into the process's control
//! block instead and copies the next process's frame back over it, leaving
//! `RSP` alone.
//!
//! It is simpler, and the reason it is *sound* is that no kernel path here ever
//! blocks: interrupt gates clear `IF`, `SFMASK` clears it for system calls, and
//! neither handler waits on anything. A process therefore has no kernel state
//! that outlives a single entry, so there is nothing for a per-process kernel
//! stack to hold. The day a syscall can block, that stops being true and the
//! stacks come back.
//!
//! # `swapgs` on the right edges
//!
//! `GS` holds the per-CPU pointer while the kernel runs and the process's own
//! base while user space runs. Entry swaps it when the interrupt came from ring
//! 3; exit swaps it when the frame we are returning through targets ring 3.
//!
//! Those two conditions are not the same condition, and the difference is load
//! bearing. An interrupt arriving during a system call comes from ring 0 — the
//! syscall stub already swapped — and may leave through a frame the scheduler
//! replaced with a different process's, bound for ring 3. Entry does nothing,
//! exit swaps once, and `GS` is correct at both ends.

use core::arch::naked_asm;

/// The full architectural state at the point of interruption.
///
/// Field order is the push order in the stub, reversed: the last register
/// pushed sits at the lowest address. Reordering either without the other hands
/// the scheduler `RIP` where it expects `RAX`.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct TrapFrame {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rbp: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rbx: u64,
    pub rax: u64,
    // Pushed by the CPU itself.
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

impl TrapFrame {
    /// An all-zero frame, for a process slot that holds nothing yet.
    pub const ZERO: TrapFrame = TrapFrame {
        r15: 0,
        r14: 0,
        r13: 0,
        r12: 0,
        r11: 0,
        r10: 0,
        r9: 0,
        r8: 0,
        rbp: 0,
        rdi: 0,
        rsi: 0,
        rdx: 0,
        rcx: 0,
        rbx: 0,
        rax: 0,
        rip: 0,
        cs: 0,
        rflags: 0,
        rsp: 0,
        ss: 0,
    };

    /// Was the interrupted code running in ring 3?
    #[must_use]
    pub const fn from_user(&self) -> bool {
        self.cs & 3 == 3
    }
}

const _: () = assert!(core::mem::size_of::<TrapFrame>() == 20 * 8);

/// Byte offset of `cs` from the start of the frame, which the stub tests to
/// decide whether to `swapgs`.
const CS_OFFSET: usize = 16 * 8;

const _: () = assert!(CS_OFFSET == core::mem::offset_of!(TrapFrame, cs));

/// The LAPIC timer vector's handler.
///
/// Naked because the register saves have to be the first thing that happens and
/// have to be in an order the `TrapFrame` layout matches exactly.
///
/// # Safety
/// Never called. Its address goes into an IDT gate, and the CPU is the only
/// thing that transfers control here — calling it as a function would run
/// `iretq` on a stack holding a return address rather than an interrupt frame.
#[unsafe(naked)]
pub unsafe extern "C" fn timer_entry() {
    naked_asm!(
        // Came from ring 3? Then GS currently holds the process's base.
        "test byte ptr [rsp + 8], 3",
        "jz 2f",
        "swapgs",
        "2:",

        "push rax",
        "push rbx",
        "push rcx",
        "push rdx",
        "push rsi",
        "push rdi",
        "push rbp",
        "push r8",
        "push r9",
        "push r10",
        "push r11",
        "push r12",
        "push r13",
        "push r14",
        "push r15",

        "mov rdi, rsp",
        "call {tick}",

        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rbp",
        "pop rdi",
        "pop rsi",
        "pop rdx",
        "pop rcx",
        "pop rbx",
        "pop rax",

        // Returning to ring 3? Decided from the frame as it stands *now*, which
        // the scheduler may have replaced with another process's.
        "test byte ptr [rsp + 8], 3",
        "jz 3f",
        "swapgs",
        "3:",
        "iretq",
        tick = sym tick,
    )
}

/// Resumes `frame`, which need not be the frame this processor was using.
///
/// The mirror image of the stub's exit path, reached without a matching entry:
/// it is how the very first process starts. `RSP` is pointed at the frame and
/// the same pops run, so there is one description of what a frame is rather
/// than two that have to be kept in step.
///
/// # Safety
/// `frame` must describe a complete, valid state to resume, and the address
/// space it belongs to must already be active. Nothing on the current stack is
/// reachable afterwards.
pub unsafe fn enter_frame(frame: &TrapFrame) -> ! {
    // SAFETY: the caller guarantees the frame. `rsp` is pointed at it and only
    // read from; execution never returns to the stack being abandoned.
    unsafe {
        core::arch::asm!(
            "mov rsp, {frame}",
            "pop r15",
            "pop r14",
            "pop r13",
            "pop r12",
            "pop r11",
            "pop r10",
            "pop r9",
            "pop r8",
            "pop rbp",
            "pop rdi",
            "pop rsi",
            "pop rdx",
            "pop rcx",
            "pop rbx",
            "pop rax",
            "test byte ptr [rsp + 8], 3",
            "jz 4f",
            "swapgs",
            "4:",
            "iretq",
            frame = in(reg) frame,
            options(noreturn),
        )
    }
}

/// Called with the saved state. May rewrite it to resume a different process.
extern "sysv64" fn tick(frame: &mut TrapFrame) {
    // The acknowledgement comes first. Everything below can take a while and
    // can switch address spaces; leaving the APIC unacknowledged across that
    // means the next tick is never delivered, and the symptom is a system that
    // simply stops being preempted.
    super::apic::end_of_interrupt();
    crate::task::on_tick(frame);
}
