/* WhisezOS stage-1 terminal halt routines.
 *
 * These run in the worst conditions the loader can be in: boot services may be
 * exited, the allocator is gone, and on the tamper path we have just wiped TPM
 * state. No Rust, no stack assumptions beyond 16-byte alignment, no returns.
 *
 * SysV AMD64 ABI is NOT in effect here for UEFI callers — the UEFI ABI is
 * Microsoft x64 (RCX, RDX, R8, R9). Both are handled: the only argument used
 * is a byte pattern for the POST-code port, taken from RCX (MS x64 arg0).
 */

    .intel_syntax noprefix
    .section .text

/* ------------------------------------------------------------------------ *
 * spectre_halt_forever(u8 post_code) -> !
 *
 * Masks every interrupt source we can reach, emits a POST code to port 0x80 so
 * a hardware POST card shows the halt reason, then parks the core in the
 * canonical low-power halt loop. `cli; hlt` is re-issued rather than a single
 * `hlt` because an NMI or SMI can resume execution past one `hlt`.
 * ------------------------------------------------------------------------ */
    .globl spectre_halt_forever
    .type  spectre_halt_forever, @function
spectre_halt_forever:
    cli

    /* POST code to 0x80 — visible on a diagnostic card with no working video. */
    mov     al, cl
    out     0x80, al

    /* Mask both 8259 PICs. Legacy, but present on every x86 platform and
     * cheap insurance if the firmware left them unmasked. */
    mov     al, 0xFF
    out     0xA1, al                /* slave  PIC OCW1 */
    out     0x21, al                /* master PIC OCW1 */

    /* Disable NMI via the CMOS index register high bit. */
    in      al, 0x70
    or      al, 0x80
    out     0x70, al

.Lhalt_loop:
    cli
    hlt
    jmp     .Lhalt_loop
    .size spectre_halt_forever, . - spectre_halt_forever

/* ------------------------------------------------------------------------ *
 * spectre_scrub_and_halt(void *base, u64 len, u8 post_code) -> !
 *
 * Overwrites a region (the key-material scratch page) before halting, so a
 * cold-boot attacker recovering DRAM contents finds zeroes where the derived
 * disk key was. Written with non-temporal stores to bypass cache and reach
 * DRAM even though we never get a chance to flush.
 * ------------------------------------------------------------------------ */
    .globl spectre_scrub_and_halt
    .type  spectre_scrub_and_halt, @function
spectre_scrub_and_halt:
    cli
    mov     rdi, rcx                /* base  (MS x64 arg0) */
    mov     rsi, rdx                /* len   (MS x64 arg1) */
    mov     r10, r8                 /* post  (MS x64 arg2) */

    xor     eax, eax
    test    rsi, rsi
    jz      .Lscrub_done

.Lscrub_loop:
    movnti  qword ptr [rdi], rax
    add     rdi, 8
    sub     rsi, 8
    ja      .Lscrub_loop

.Lscrub_done:
    sfence                          /* retire the non-temporal stores */
    mov     rcx, r10
    jmp     spectre_halt_forever
    .size spectre_scrub_and_halt, . - spectre_scrub_and_halt

/* Mark the stack non-executable so the linker does not emit an executable
 * PT_GNU_STACK for the whole image. */
    .section .note.GNU-stack, "", @progbits
