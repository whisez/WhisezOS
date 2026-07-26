/* WhisezOS context switch.
 *
 * void spectre_context_switch(Context *from, Context *to);
 *
 * SysV AMD64 ABI: from = RDI, to = RSI.
 *
 * The ABI does the heavy lifting here and it is worth being explicit about why
 * this function is so short. A context switch only has to preserve what the
 * compiler expects to survive a call. Caller-saved registers (RAX, RCX, RDX,
 * RSI, RDI, R8-R11) are already spilled by the compiler at the call site, so
 * saving them here would be duplicated work on the hottest path in the kernel.
 * Only the six callee-saved registers plus RSP need to move.
 *
 * This is what makes `switch_to_donating` in sched.rs cheap enough to put on
 * the IPC fast path: roughly 20 instructions plus a possible CR3 write.
 *
 * NOT handled here, deliberately:
 *   - FPU/SSE/AVX state. Saved lazily via the #NM (device-not-available) trap;
 *     eagerly saving 2.5 KiB of AVX-512 state on every switch would cost more
 *     than everything else in this file combined, and most switches are between
 *     threads that never touch a vector register.
 *   - Segment registers. Flat in long mode; FS/GS base are handled by the
 *     per-CPU code via MSR writes when the address space changes.
 *   - RSP0 in the TSS. Updated by the Rust caller, which knows the new thread's
 *     kernel stack. Doing it here would need a second pointer argument for a
 *     write that only matters on the ring 3 return path.
 */

    .intel_syntax noprefix
    .section .text

/* Offsets into `struct Context`. Must match arch/context.rs — the static
 * assertions there fail the build if these drift. */
    .set CTX_RSP,  0
    .set CTX_CR3,  8
    .set CTX_SSP, 16

    .globl spectre_context_switch
    .type  spectre_context_switch, @function
spectre_context_switch:
    /* Save callee-saved registers onto the outgoing thread's stack. Order here
     * must mirror the pop sequence below exactly; a mismatch produces a thread
     * that resumes with RBX in RBP and is essentially undebuggable. */
    push    rbp
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15

    /* Park the outgoing stack pointer. Everything above is now recoverable
     * from this one value, which is the entire trick. */
    mov     [rdi + CTX_RSP], rsp

    /* Address space switch, but only when it actually changes.
     *
     * Writing CR3 unconditionally flushes the entire non-global TLB. Between
     * two threads of the same process — the common case for a multithreaded
     * game or compositor — that flush is pure loss, and it measured as ~8% of
     * total switch cost before this check was added. PCID would avoid the flush
     * entirely; it is not used yet because correct PCID handling interacts with
     * the KPTI trampoline and is deferred until that is in place. */
    mov     rax, [rsi + CTX_CR3]
    mov     rcx, cr3
    cmp     rax, rcx
    je      .Lsame_address_space
    mov     cr3, rax
.Lsame_address_space:

    /* Switch to the incoming thread's stack. Past this instruction we are
     * executing on the new thread; RIP is still in this function only because
     * the return address on that stack points back here. */
    mov     rsp, [rsi + CTX_RSP]

    /* Restore in exact reverse order. */
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp

    /* Returns onto whatever the incoming thread pushed as its return address.
     * For a thread that has run before, that is the call site inside this same
     * function. For a brand-new thread, it is the trampoline installed by
     * `Context::bootstrap` — which is why a new thread needs no special case
     * anywhere in the scheduler. */
    ret
    .size spectre_context_switch, . - spectre_context_switch

/* ------------------------------------------------------------------------ *
 * spectre_thread_trampoline
 *
 * Entry point for a thread that has never run. `Context::bootstrap` lays out
 * the initial stack so the `ret` above lands here with the thread's entry point
 * in R12 and its argument in R13 — both callee-saved, so they survive the
 * restore sequence untouched.
 *
 * This exists so that starting a thread and resuming a thread are the same
 * operation. The alternative is a branch in the scheduler for "has this thread
 * run before", which is a test on the hot path to handle a case that occurs
 * once per thread lifetime.
 * ------------------------------------------------------------------------ */
    .globl spectre_thread_trampoline
    .type  spectre_thread_trampoline, @function
spectre_thread_trampoline:
    /* The scheduler released its runqueue lock before switching, but the
     * incoming thread has not yet re-enabled interrupts — a new thread starts
     * with IF clear because it inherited RFLAGS from nobody. Enable them here,
     * at a point where the stack is valid and a timer tick is safe. */
    sti

    mov     rdi, r13            /* argument */
    call    r12                 /* entry point */

    /* A thread function that returns has exited. Hand off to the reaper, which
     * never returns. Falling through to `ret` here would pop garbage from a
     * stack that has nothing left on it. */
    call    spectre_thread_exit
    ud2                         /* unreachable; trap loudly if it is not */
    .size spectre_thread_trampoline, . - spectre_thread_trampoline

    .section .note.GNU-stack, "", @progbits
