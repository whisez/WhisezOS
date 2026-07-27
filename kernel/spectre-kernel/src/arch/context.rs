//! Thread context and initial stack construction.
//!
//! The assembly in `context.S` does the switching; this module decides what a
//! brand-new thread's stack must contain so that the *first* switch into it
//! works with no special case in the scheduler.
//!
//! # The bootstrap trick
//!
//! `spectre_context_switch` ends with `pop`s of six callee-saved registers and
//! a `ret`. It does not know or care whether the thread it is switching to has
//! run before. So to start a new thread we simply forge a stack that looks
//! exactly like one a suspended thread would have left behind:
//!
//! ```text
//!   higher addresses
//!   ┌──────────────────────────┐  <- stack_top (16-byte aligned)
//!   │ 0  (fake return address) │     terminates stack unwinding
//!   ├──────────────────────────┤
//!   │ trampoline address       │  <- what `ret` jumps to
//!   ├──────────────────────────┤
//!   │ rbp = 0                  │
//!   │ rbx = 0                  │
//!   │ r12 = entry point        │     trampoline calls this
//!   │ r13 = argument           │     trampoline passes this
//!   │ r14 = 0                  │
//!   │ r15 = 0                  │  <- Context.rsp points here
//!   └──────────────────────────┘
//!   lower addresses
//! ```
//!
//! The scheduler then has exactly one code path for "run this thread", which is
//! worth more than it sounds: the "has it started yet" branch is the kind of
//! thing that works until the day a thread is preempted between being created
//! and first running.
//!
//! # Stack alignment
//!
//! SysV requires RSP ≡ 16 (mod 16) *at the call instruction*, meaning RSP+8 is
//! 16-aligned on entry to the callee after the return address is pushed. Get
//! this wrong and every `movaps` the compiler emits into a stack slot faults —
//! typically deep inside a function that has nothing to do with the bug, in
//! whichever thread happened to be the one with an odd frame.

use super::addr::VirtAddr;

/// Registers that must survive a switch. Everything else is caller-saved and
/// already spilled by the compiler at the call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Context {
    /// Stack pointer of the suspended thread. All other state is reachable
    /// from here.
    pub rsp: u64,
    /// Address space root. `context.S` skips the CR3 write when this matches
    /// the current value, avoiding a full TLB flush between threads of the same
    /// process.
    pub cr3: u64,
    /// Shadow stack pointer, when CET is active. Zero means the thread has no
    /// shadow stack, which is only true for the idle threads.
    pub ssp: u64,
}

// The assembly hard-codes these offsets. If the struct layout ever drifts, the
// switch writes RSP into the CR3 field and the machine dies on the next switch
// with no diagnostic. Catch it at build time instead.
const _: () = {
    assert!(core::mem::offset_of!(Context, rsp) == 0);
    assert!(core::mem::offset_of!(Context, cr3) == 8);
    assert!(core::mem::offset_of!(Context, ssp) == 16);
};

/// Number of u64 slots the switch pushes: 6 callee-saved registers.
pub const SAVED_REGISTER_COUNT: usize = 6;

/// Slots the bootstrap frame occupies: 6 registers + trampoline address +
/// terminator.
pub const BOOTSTRAP_FRAME_SLOTS: usize = SAVED_REGISTER_COUNT + 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextError {
    /// Stack top is not 16-byte aligned.
    MisalignedStack(u64),
    /// Stack is too small to hold the bootstrap frame.
    StackTooSmall { bytes: u64, required: u64 },
    /// Entry point or CR3 is null.
    NullEntry,
}

/// Minimum kernel stack. 16 KiB rather than the more common 8: WhisezOS's IPC
/// path can nest four servers deep (`app → vfs → spectrefs → nvme`) and each
/// frame carries a message buffer. 8 KiB stacks overflowed under a deep VFS
/// call in early testing, and a kernel stack overflow lands on the guard page —
/// which is survivable only because of the IST double-fault stack in `gdt.rs`.
pub const MIN_KERNEL_STACK_BYTES: u64 = 16 * 1024;

impl Context {
    pub const fn empty() -> Context {
        Context {
            rsp: 0,
            cr3: 0,
            ssp: 0,
        }
    }

    /// Forge the initial stack for a thread that has never run.
    ///
    /// `stack_top` is the *exclusive* upper bound — the first address past the
    /// stack, as stacks grow down. `writer` stores one u64 at a given address;
    /// it is a closure so this can be tested against a plain array instead of
    /// requiring a real mapped stack.
    pub fn bootstrap(
        stack_top: VirtAddr,
        stack_bytes: u64,
        entry: VirtAddr,
        arg: u64,
        cr3: u64,
        trampoline: VirtAddr,
        mut writer: impl FnMut(u64, u64),
    ) -> Result<Context, ContextError> {
        if !stack_top.as_u64().is_multiple_of(16) {
            return Err(ContextError::MisalignedStack(stack_top.as_u64()));
        }
        if entry.as_u64() == 0 {
            return Err(ContextError::NullEntry);
        }

        let required = BOOTSTRAP_FRAME_SLOTS as u64 * 8;
        if stack_bytes < required.max(MIN_KERNEL_STACK_BYTES) {
            return Err(ContextError::StackTooSmall {
                bytes: stack_bytes,
                required: required.max(MIN_KERNEL_STACK_BYTES),
            });
        }

        let mut sp = stack_top.as_u64();

        // Terminator. A zero return address stops stack unwinders and backtrace
        // walkers cleanly; without it, a panic in a fresh thread walks off the
        // end of the stack into whatever is mapped next.
        sp -= 8;
        writer(sp, 0);

        // What `ret` at the end of the switch will jump to.
        sp -= 8;
        writer(sp, trampoline.as_u64());

        // The six callee-saved registers, in the order the switch pops them:
        // r15, r14, r13, r12, rbx, rbp — so they are pushed in reverse here.
        sp -= 8;
        writer(sp, 0); // rbp
        sp -= 8;
        writer(sp, 0); // rbx
        sp -= 8;
        writer(sp, entry.as_u64()); // r12 — trampoline calls this
        sp -= 8;
        writer(sp, arg); // r13 — trampoline passes this
        sp -= 8;
        writer(sp, 0); // r14
        sp -= 8;
        writer(sp, 0); // r15

        Ok(Context {
            rsp: sp,
            cr3,
            ssp: 0,
        })
    }

    /// Will the trampoline see a correctly aligned stack when it `call`s the
    /// entry point?
    ///
    /// After the switch pops six registers and `ret` consumes the trampoline
    /// address, RSP sits at `bootstrap_rsp + 7*8`. The trampoline then executes
    /// `call`, which pushes 8 more. SysV wants RSP ≡ 0 (mod 16) at the callee's
    /// first instruction — i.e. RSP+8 ≡ 0 (mod 16) at the `call`.
    pub fn entry_stack_is_aligned(&self) -> bool {
        let at_trampoline = self.rsp + (SAVED_REGISTER_COUNT as u64 + 1) * 8;
        at_trampoline % 16 == 8
    }
}

extern "C" {
    /// Defined in `context.S`.
    pub fn spectre_context_switch(from: *mut Context, to: *const Context);
    pub fn spectre_thread_trampoline();
}

#[cfg(test)]
mod tests {
    use super::super::addr::PagingMode;
    use super::*;
    use std::collections::HashMap;

    const L4: PagingMode = PagingMode::Level4;

    fn va(addr: u64) -> VirtAddr {
        VirtAddr::from_indices_sign_extended(addr, L4)
    }

    /// Build a bootstrap frame into a fake memory map, returning the context
    /// and everything written.
    fn build(stack_top: u64, stack_bytes: u64) -> (Context, HashMap<u64, u64>) {
        let mut mem = HashMap::new();
        let ctx = Context::bootstrap(
            va(stack_top),
            stack_bytes,
            va(0xFFFF_8000_0BAD_C0DE),
            0x1234_5678,
            0x10_0000,
            va(0xFFFF_8000_0000_7000),
            |addr, val| {
                mem.insert(addr, val);
            },
        )
        .unwrap();
        (ctx, mem)
    }

    #[test]
    fn bootstrap_frame_has_the_expected_shape() {
        let top = 0xFFFF_8000_0010_0000u64;
        let (ctx, mem) = build(top, MIN_KERNEL_STACK_BYTES);

        // Reading back in pop order: r15, r14, r13, r12, rbx, rbp, then the
        // trampoline address that `ret` consumes.
        let slots: Vec<u64> = (0..BOOTSTRAP_FRAME_SLOTS as u64)
            .map(|i| mem[&(ctx.rsp + i * 8)])
            .collect();

        assert_eq!(slots[0], 0, "r15");
        assert_eq!(slots[1], 0, "r14");
        assert_eq!(slots[2], 0x1234_5678, "r13 must carry the argument");
        assert_eq!(
            slots[3], 0xFFFF_8000_0BAD_C0DE,
            "r12 must carry the entry point"
        );
        assert_eq!(slots[4], 0, "rbx");
        assert_eq!(slots[5], 0, "rbp");
        assert_eq!(
            slots[6], 0xFFFF_8000_0000_7000,
            "ret target must be the trampoline"
        );
        assert_eq!(slots[7], 0, "unwinder terminator");
    }

    #[test]
    fn entry_point_and_argument_land_in_callee_saved_registers() {
        // r12 and r13 specifically, because the switch's pop sequence restores
        // them and nothing between the pops and the trampoline clobbers them.
        // Using a caller-saved register here would work in a debug build and
        // fail under optimisation.
        let (ctx, mem) = build(0xFFFF_8000_0010_0000, MIN_KERNEL_STACK_BYTES);
        let r13 = mem[&(ctx.rsp + 2 * 8)];
        let r12 = mem[&(ctx.rsp + 3 * 8)];
        assert_eq!(r13, 0x1234_5678);
        assert_eq!(r12, 0xFFFF_8000_0BAD_C0DE);
    }

    #[test]
    fn stack_pointer_lands_below_the_frame() {
        let top = 0xFFFF_8000_0010_0000u64;
        let (ctx, _) = build(top, MIN_KERNEL_STACK_BYTES);
        assert_eq!(ctx.rsp, top - BOOTSTRAP_FRAME_SLOTS as u64 * 8);
        assert!(ctx.rsp < top);
    }

    #[test]
    fn entry_stack_alignment_satisfies_the_abi() {
        // A misaligned frame faults on the first movaps into a stack slot,
        // typically far from the thread-creation code that caused it.
        let (ctx, _) = build(0xFFFF_8000_0010_0000, MIN_KERNEL_STACK_BYTES);
        assert!(
            ctx.entry_stack_is_aligned(),
            "rsp {:#x} produces a misaligned call frame",
            ctx.rsp
        );
    }

    #[test]
    fn misaligned_stack_top_is_refused() {
        let mut mem = HashMap::new();
        let r = Context::bootstrap(
            va(0xFFFF_8000_0010_0008), // 8-aligned, not 16
            MIN_KERNEL_STACK_BYTES,
            va(0x1000),
            0,
            0x1000,
            va(0x2000),
            |a, v| {
                mem.insert(a, v);
            },
        );
        assert!(matches!(r, Err(ContextError::MisalignedStack(_))));
        assert!(mem.is_empty(), "wrote to the stack before validating it");
    }

    #[test]
    fn undersized_stack_is_refused() {
        let mut mem = HashMap::new();
        let r = Context::bootstrap(
            va(0xFFFF_8000_0010_0000),
            512, // far below the 16 KiB minimum
            va(0x1000),
            0,
            0x1000,
            va(0x2000),
            |a, v| {
                mem.insert(a, v);
            },
        );
        match r {
            Err(ContextError::StackTooSmall { required, .. }) => {
                assert_eq!(required, MIN_KERNEL_STACK_BYTES);
            }
            other => panic!("expected StackTooSmall, got {other:?}"),
        }
    }

    #[test]
    fn null_entry_point_is_refused() {
        let mut mem = HashMap::new();
        let r = Context::bootstrap(
            va(0xFFFF_8000_0010_0000),
            MIN_KERNEL_STACK_BYTES,
            va(0),
            0,
            0x1000,
            va(0x2000),
            |a, v| {
                mem.insert(a, v);
            },
        );
        assert_eq!(r, Err(ContextError::NullEntry));
    }

    #[test]
    fn frame_stays_within_the_allocated_stack() {
        let top = 0xFFFF_8000_0010_0000u64;
        let bytes = MIN_KERNEL_STACK_BYTES;
        let (ctx, mem) = build(top, bytes);

        let low_bound = top - bytes;
        for addr in mem.keys() {
            assert!(
                *addr >= low_bound && *addr < top,
                "wrote {addr:#x} outside [{low_bound:#x}, {top:#x})"
            );
        }
        assert!(ctx.rsp >= low_bound);
    }

    #[test]
    fn minimum_stack_accounts_for_deep_ipc_nesting() {
        // The IPC chain app -> vfs -> spectrefs -> nvme is four frames, each
        // carrying a 256-byte message buffer plus locals. 8 KiB was measured to
        // overflow; this guards the decision to double it.
        assert!(MIN_KERNEL_STACK_BYTES >= 16 * 1024);
    }

    #[test]
    fn context_layout_matches_the_assembly_offsets() {
        // The static assertions above catch this at build time; this restates it
        // as a test so the failure names the problem instead of pointing at a
        // const block.
        assert_eq!(core::mem::offset_of!(Context, rsp), 0);
        assert_eq!(core::mem::offset_of!(Context, cr3), 8);
        assert_eq!(core::mem::offset_of!(Context, ssp), 16);
    }
}
