//! The `SYSCALL`/`SYSRET` entry path.
//!
//! # Why `syscall` and not an interrupt gate
//!
//! An interrupt gate would be less code: the CPU switches to `TSS.RSP0` for us,
//! pushes a frame, and `iretq` undoes all of it. `syscall` does none of that. It
//! leaves `RSP` pointing at the *user* stack, so the first thing this entry does
//! is find a kernel stack by hand.
//!
//! It is still the right instruction. It is several times faster, it is what
//! every 64-bit ABI expects, and — the reason it is worth the care — the GDT was
//! already laid out for it. `gdt.rs` orders user data before user code
//! specifically because `SYSRET` computes both selectors from `STAR[63:48]`, and
//! that constraint is only paid for if something actually issues a `SYSRET`.
//!
//! # `swapgs`, and the window that must not exist
//!
//! Between `syscall` arriving and the stack switch completing, the kernel is
//! running on a stack the user chose. Everything in that window is in the entry
//! stub below and touches nothing but `GS`-relative memory. There is no call, no
//! push to the user stack, and no memory access the user could have arranged.
//!
//! `swapgs` is what makes `gs:` point at per-CPU data instead of whatever base
//! user space left in `GS`. It is its own instruction with no state of its own,
//! so calling it twice — or forgetting it on one exit path — leaves the kernel
//! reading per-CPU fields through a user-controlled base. There is exactly one
//! entry and one exit here for that reason.

use core::arch::naked_asm;

use super::gdt::GdtLayout;
use crate::abi::{self, SyscallError};
use crate::kprintln;

/// Per-processor scratch reachable through `gs:` in the entry stub.
///
/// The field offsets are load bearing: the assembly below addresses them by
/// number, so reordering these fields silently swaps the kernel stack with the
/// saved user stack.
#[repr(C)]
struct PerCpu {
    /// Offset 0: where the entry stub puts `RSP`.
    kernel_stack_top: u64,
    /// Offset 8: where it saves the user's `RSP` until `sysret`.
    user_stack: u64,
}

const SYSCALL_STACK_BYTES: usize = 32 * 1024;

#[repr(C, align(16))]
struct SyscallStack([u8; SYSCALL_STACK_BYTES]);

/// A stack of its own rather than the boot stack.
///
/// The code that entered ring 3 is still parked on the boot stack, and a
/// syscall reusing it would overwrite the frames that will run again when the
/// process stops.
static mut SYSCALL_STACK: SyscallStack = SyscallStack([0; SYSCALL_STACK_BYTES]);

static mut PER_CPU: PerCpu = PerCpu {
    kernel_stack_top: 0,
    user_stack: 0,
};

/// What the entry stub pushes, in push order, so `rdi` points at field zero.
///
/// Field order must match the pushes exactly; a mismatch hands the dispatcher
/// the user's `RIP` as a syscall number.
#[repr(C)]
pub struct SyscallFrame {
    pub number: u64,
    pub a0: u64,
    pub a1: u64,
    pub a2: u64,
    pub a3: u64,
    /// `syscall` leaves the return address here, not on the stack.
    pub rip: u64,
    /// And `RFLAGS` here.
    pub rflags: u64,
}

/// Installs the MSRs that make `syscall` work.
///
/// # Safety
/// Called once, on the bootstrap processor, after the GDT is installed. The
/// selectors in `layout` must be the ones currently loaded.
pub unsafe fn init(layout: &GdtLayout) {
    use super::cpu;

    // SAFETY: single-threaded bring-up.
    let per_cpu = unsafe { &mut *core::ptr::addr_of_mut!(PER_CPU) };
    per_cpu.kernel_stack_top =
        core::ptr::addr_of!(SYSCALL_STACK) as u64 + SYSCALL_STACK_BYTES as u64;
    per_cpu.user_stack = 0;

    // STAR[47:32] is the base `syscall` uses: CS = base, SS = base + 8.
    // STAR[63:48] is the base `sysret` uses: SS = base + 8, CS = base + 16.
    // `GdtBuilder` produced a layout that satisfies both; `GdtLayout::validate`
    // already refused it otherwise.
    let star = (u64::from(layout.sysret_base) << 48) | (u64::from(layout.kernel_code.0) << 32);

    // Cleared from RFLAGS on entry:
    //   IF (9)  — the kernel runs the syscall with interrupts masked. There is
    //             no preemption to enable yet, and an interrupt arriving before
    //             the stack switch would be delivered on the user stack.
    //   DF (10) — the string instructions must start forwards regardless of
    //             what user space left set.
    //   TF (8)  — otherwise a user process single-steps the kernel.
    //   AC (18) — with SMAP, AC set in ring 0 is an open door to user memory.
    let sfmask = (1 << 9) | (1 << 10) | (1 << 8) | (1 << 18);

    // SAFETY: architecturally defined MSRs with values assembled above. `SCE`
    // is set last, so `syscall` only becomes a valid instruction once the
    // entry point and stack are already installed — otherwise a syscall
    // arriving in between would jump to whatever LSTAR happened to contain.
    unsafe {
        cpu::write_msr(cpu::MSR_STAR, star);
        cpu::write_msr(cpu::MSR_LSTAR, syscall_entry as *const () as u64);
        cpu::write_msr(cpu::MSR_SFMASK, sfmask);
        // The invariant every `swapgs` in the kernel maintains:
        //
        //   executing kernel code — GS = per-CPU, KERNEL_GS = the process's
        //   executing user code   — GS = the process's, KERNEL_GS = per-CPU
        //
        // This runs in the kernel, so it establishes the first of the two. The
        // mirror image looks equally plausible and is wrong: the path into ring
        // 3 swaps on the way out, so starting from the user configuration
        // leaves ring 3 running with the per-CPU pointer in `GS`, and the first
        // `syscall` swaps it away to zero — turning `gs:[8]` into a write to
        // absolute address 8.
        cpu::write_msr(cpu::MSR_GS_BASE, core::ptr::addr_of!(PER_CPU) as u64);
        cpu::write_msr(cpu::MSR_KERNEL_GS_BASE, 0);
        cpu::write_msr(
            cpu::MSR_EFER,
            cpu::read_msr(cpu::MSR_EFER) | cpu::EFER_SYSCALL_ENABLE,
        );
    }
}

/// The `LSTAR` target.
///
/// Naked because every instruction before the stack switch is part of the
/// contract — a compiler-generated prologue would push to the user's stack.
///
/// Registers: `syscall` destroys `rcx` and `r11`, so those are the only two the
/// caller expects to lose. Everything else the dispatcher might touch is saved
/// and restored here, including `r8` and `r9`, which the System V convention
/// treats as caller-saved but the user-space stub does not declare clobbered.
#[unsafe(naked)]
unsafe extern "C" fn syscall_entry() {
    naked_asm!(
        "swapgs",
        "mov qword ptr gs:[8], rsp",
        "mov rsp, qword ptr gs:[0]",

        // Caller-saved registers the dispatcher may use but user space still
        // expects to find intact.
        "push r8",
        "push r9",

        // SyscallFrame, pushed so the last push lands on field zero.
        "push r11",  // rflags
        "push rcx",  // rip
        "push r10",  // a3
        "push rdx",  // a2
        "push rsi",  // a1
        "push rdi",  // a0
        "push rax",  // number

        "mov rdi, rsp",
        "call {dispatch}",
        // rax now holds the encoded result and must survive the pops below.

        "add rsp, 8", // the number slot; rax replaces it
        "pop rdi",
        "pop rsi",
        "pop rdx",
        "pop r10",
        "pop rcx",   // return rip for sysret
        "pop r11",   // return rflags for sysret

        "pop r9",
        "pop r8",

        "mov rsp, qword ptr gs:[8]",
        "swapgs",
        // `sysretq` faults in ring 0 if RCX is non-canonical, which is a known
        // escalation primitive. RCX here came from the CPU on entry and was
        // never exposed to the dispatcher, so it is the address that issued the
        // syscall and is canonical by construction.
        "sysretq",
        dispatch = sym dispatch,
    )
}

extern "sysv64" fn dispatch(frame: &mut SyscallFrame) -> u64 {
    abi::encode(crate::syscall::handle(
        frame.number,
        frame.a0,
        frame.a1,
        frame.a2,
        frame.a3,
    ))
}

/// Reports the state of the syscall MSRs, so a boot where `SCE` failed to take
/// is visible before the first `#UD` rather than after it.
pub fn report() {
    use super::cpu;
    let efer = cpu::read_msr(cpu::MSR_EFER);
    kprintln!(
        "[kernel] syscall enabled={} star={:#018x} lstar={:#018x}",
        efer & cpu::EFER_SYSCALL_ENABLE != 0,
        cpu::read_msr(cpu::MSR_STAR),
        cpu::read_msr(cpu::MSR_LSTAR),
    );
}

/// Never returned by a handler; present so the dispatcher's error type is the
/// same one user space decodes.
pub type SyscallResult = Result<u64, SyscallError>;
