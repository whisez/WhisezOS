//! Raw x86-64 instructions the bring-up path needs.
//!
//! Everything here is a one-to-one wrapper over a single instruction, kept in
//! one file so the rest of `arch` reads as sequencing rather than assembly. None
//! of it can be tested on the host — it is the boundary where testing stops and
//! the serial log takes over.

use super::gdt::SegmentSelector;

/// # Safety
/// Reading an I/O port can have side effects on the device behind it. `port`
/// must be one the caller understands.
pub unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: the caller guarantees the port.
    unsafe {
        core::arch::asm!("in al, dx", out("al") value, in("dx") port, options(nomem, nostack, preserves_flags));
    }
    value
}

/// # Safety
/// As `inb`, and a write is rather more likely to have an effect.
pub unsafe fn outb(port: u16, value: u8) {
    // SAFETY: the caller guarantees the port and the value.
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags));
    }
}

/// # Safety
/// As `inb`. The 32-bit width matters: PCI configuration space is dword
/// granular, and a byte read of 0xCFC returns one byte of the selected dword
/// rather than the dword the caller wanted.
pub unsafe fn inl(port: u16) -> u32 {
    let value: u32;
    // SAFETY: the caller guarantees the port.
    unsafe {
        core::arch::asm!("in eax, dx", out("eax") value, in("dx") port, options(nomem, nostack, preserves_flags));
    }
    value
}

/// # Safety
/// As `outb`.
pub unsafe fn outl(port: u16, value: u32) {
    // SAFETY: the caller guarantees the port and the value.
    unsafe {
        core::arch::asm!("out dx, eax", in("dx") port, in("eax") value, options(nomem, nostack, preserves_flags));
    }
}

/// One leaf of `cpuid`.
#[derive(Debug, Clone, Copy)]
pub struct CpuidResult {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

/// Executes `cpuid` for `leaf` with `ECX` zero.
#[must_use]
pub fn cpuid(leaf: u32) -> CpuidResult {
    let (eax, ebx, ecx, edx);
    // SAFETY: `cpuid` has no side effects. `rbx` is LLVM's reserved register,
    // so it is exchanged around the instruction rather than named directly.
    unsafe {
        core::arch::asm!(
            "mov {tmp:r}, rbx",
            "cpuid",
            "xchg {tmp:r}, rbx",
            tmp = out(reg) ebx,
            inout("eax") leaf => eax,
            inlateout("ecx") 0 => ecx,
            out("edx") edx,
            options(nomem, nostack, preserves_flags),
        );
    }
    CpuidResult { eax, ebx, ecx, edx }
}

/// Operand for `lgdt` and `lidt`.
///
/// `packed(2)` is not cosmetic: the CPU reads a 2-byte limit immediately
/// followed by an 8-byte base. Natural alignment would insert six bytes of
/// padding between them and the CPU would load a garbage base — a fault at the
/// first interrupt, pointing nowhere useful.
#[derive(Debug, Clone, Copy)]
#[repr(C, packed(2))]
pub struct DescriptorTablePointer {
    pub limit: u16,
    pub base: u64,
}

const _: () = assert!(core::mem::size_of::<DescriptorTablePointer>() == 10);

/// # Safety
/// `pointer` must describe a well-formed GDT that remains live for as long as it
/// is loaded, and the caller must reload the segment registers afterwards.
pub unsafe fn lgdt(pointer: &DescriptorTablePointer) {
    // SAFETY: the caller guarantees the table is valid and live.
    unsafe {
        core::arch::asm!("lgdt [{0}]", in(reg) pointer, options(readonly, nostack, preserves_flags));
    }
}

/// # Safety
/// `pointer` must describe a well-formed IDT that remains live for as long as it
/// is loaded, with every deliverable vector present.
pub unsafe fn lidt(pointer: &DescriptorTablePointer) {
    // SAFETY: the caller guarantees the table is valid and live.
    unsafe {
        core::arch::asm!("lidt [{0}]", in(reg) pointer, options(readonly, nostack, preserves_flags));
    }
}

/// # Safety
/// `selector` must index an available 64-bit TSS descriptor in the current GDT.
pub unsafe fn load_tss(selector: SegmentSelector) {
    // SAFETY: the caller guarantees the selector names a valid TSS descriptor.
    unsafe {
        core::arch::asm!("ltr {0:x}", in(reg) selector.0, options(nostack, preserves_flags));
    }
}

/// Reloads `CS` with `code`, and every data segment register with `data`.
///
/// `CS` cannot be written with `mov`; the only ways to change it are a far jump,
/// a far call, a far return, or an interrupt return. The sequence below pushes a
/// selector and a return address and executes a far return into the very next
/// instruction, which is the least disruptive of the four.
///
/// This must run immediately after `lgdt`. Between the two, the segment
/// registers still cache descriptors from the firmware's GDT, which we are about
/// to stop keeping alive.
///
/// # Safety
/// A GDT with `code` as a 64-bit code descriptor and `data` as a writable data
/// descriptor must already be loaded.
pub unsafe fn reload_segments(code: SegmentSelector, data: SegmentSelector) {
    // SAFETY: the caller guarantees both selectors are valid in the loaded GDT.
    // The far return targets the label immediately below, so execution
    // continues in order with only CS changed.
    unsafe {
        core::arch::asm!(
            "push {code}",
            "lea {tmp}, [rip + 2f]",
            "push {tmp}",
            "retfq",
            "2:",
            code = in(reg) u64::from(code.0),
            tmp = lateout(reg) _,
            options(preserves_flags),
        );

        core::arch::asm!(
            "mov ss, {0:x}",
            "mov ds, {0:x}",
            "mov es, {0:x}",
            // FS and GS bases are set through MSRs in long mode, but the
            // selectors still have to name a valid descriptor or a later
            // `swapgs` path faults.
            "mov fs, {0:x}",
            "mov gs, {0:x}",
            in(reg) data.0,
            options(nostack, preserves_flags),
        );
    }
}

/// The faulting linear address, valid only inside a page-fault handler.
#[must_use]
pub fn read_cr2() -> u64 {
    let value: u64;
    // SAFETY: reading a control register has no side effects.
    unsafe {
        core::arch::asm!("mov {}, cr2", out(reg) value, options(nomem, nostack, preserves_flags));
    }
    value
}

/// Physical address of the active top-level page table, with its low flag bits.
#[must_use]
pub fn read_cr3() -> u64 {
    let value: u64;
    // SAFETY: reading a control register has no side effects.
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) value, options(nomem, nostack, preserves_flags));
    }
    value
}

/// Switches the active page table.
///
/// # Safety
/// `frame` must be the physical address of a complete, correctly formed PML4
/// that maps at least the currently executing code, the current stack, and
/// itself. Anything less triple-faults on the instruction after this one, with
/// no diagnostic — the CPU cannot fetch the fault handler either.
pub unsafe fn write_cr3(frame: u64) {
    // SAFETY: the caller guarantees the table maps the running code and stack.
    unsafe {
        core::arch::asm!("mov cr3, {}", in(reg) frame, options(nostack, preserves_flags));
    }
}

#[must_use]
pub fn read_cr0() -> u64 {
    let value: u64;
    // SAFETY: reading a control register has no side effects.
    unsafe {
        core::arch::asm!("mov {}, cr0", out(reg) value, options(nomem, nostack, preserves_flags));
    }
    value
}

#[must_use]
pub fn read_cr4() -> u64 {
    let value: u64;
    // SAFETY: reading a control register has no side effects.
    unsafe {
        core::arch::asm!("mov {}, cr4", out(reg) value, options(nomem, nostack, preserves_flags));
    }
    value
}

/// `EFER`, which holds the long-mode and no-execute enables.
#[must_use]
pub fn read_efer() -> u64 {
    read_msr(MSR_EFER)
}

/// `IA32_EFER`. Bit 0 is `SCE`, which is what makes `syscall` an instruction
/// rather than `#UD`.
pub const MSR_EFER: u32 = 0xC000_0080;
/// `IA32_STAR`: the segment selectors `syscall` and `sysret` derive.
pub const MSR_STAR: u32 = 0xC000_0081;
/// `IA32_LSTAR`: where `syscall` jumps in 64-bit mode.
pub const MSR_LSTAR: u32 = 0xC000_0082;
/// `IA32_FMASK`: RFLAGS bits cleared on `syscall` entry.
pub const MSR_SFMASK: u32 = 0xC000_0084;
/// `IA32_GS_BASE`: the base `gs:` adds while this code is running.
pub const MSR_GS_BASE: u32 = 0xC000_0101;
/// `IA32_KERNEL_GS_BASE`: what `swapgs` exchanges `IA32_GS_BASE` with.
pub const MSR_KERNEL_GS_BASE: u32 = 0xC000_0102;

/// `EFER.SCE` — system call extensions.
pub const EFER_SYSCALL_ENABLE: u64 = 1 << 0;

/// # Safety
/// Writing an MSR can change how the processor executes every instruction after
/// it. `msr` must be an MSR the caller understands and `value` a bit pattern it
/// accepts; a reserved bit set here is a #GP with no useful diagnostic.
pub unsafe fn write_msr(msr: u32, value: u64) {
    let low = value as u32;
    let high = (value >> 32) as u32;
    // SAFETY: the caller guarantees the MSR and the value.
    unsafe {
        core::arch::asm!("wrmsr", in("ecx") msr, in("eax") low, in("edx") high, options(nostack, preserves_flags));
    }
}

#[must_use]
pub fn read_msr(msr: u32) -> u64 {
    let (high, low): (u32, u32);
    // SAFETY: `rdmsr` on an architecturally defined MSR. Reading an
    // unimplemented MSR raises #GP, which is why callers pass constants.
    unsafe {
        core::arch::asm!("rdmsr", in("ecx") msr, out("eax") low, out("edx") high, options(nomem, nostack, preserves_flags));
    }
    (u64::from(high) << 32) | u64::from(low)
}

/// CR0 bit 16. When clear, ring 0 may write through read-only page mappings,
/// which quietly defeats every `W^X` guarantee the page tables express.
pub const CR0_WRITE_PROTECT: u64 = 1 << 16;
/// CR4 bit 20: ring 0 cannot execute user pages.
pub const CR4_SMEP: u64 = 1 << 20;
/// CR4 bit 21: ring 0 cannot read or write user pages outside an explicit
/// `stac`/`clac` window.
pub const CR4_SMAP: u64 = 1 << 21;
/// EFER bit 11: the NX bit in page-table entries is honoured.
pub const EFER_NO_EXECUTE: u64 = 1 << 11;

pub fn enable_interrupts() {
    // SAFETY: `sti` is safe once a complete IDT is loaded; `early_init` does
    // that before anything calls this.
    unsafe {
        core::arch::asm!("sti", options(nomem, nostack));
    }
}

pub fn disable_interrupts() {
    // SAFETY: masking interrupts has no memory effects.
    unsafe {
        core::arch::asm!("cli", options(nomem, nostack));
    }
}

#[must_use]
pub fn interrupts_enabled() -> bool {
    let rflags: u64;
    // SAFETY: reading RFLAGS via the stack has no side effects.
    unsafe {
        core::arch::asm!("pushfq", "pop {}", out(reg) rflags, options(nomem, preserves_flags));
    }
    rflags & (1 << 9) != 0
}

/// Waits for the next interrupt.
///
/// Unlike `halt_forever`, this leaves interrupts as it found them: the caller
/// wants to be woken.
pub fn halt_once() {
    // SAFETY: halting has no memory effects.
    unsafe {
        core::arch::asm!("hlt", options(nomem, nostack));
    }
}

/// Stops this processor for good.
///
/// `cli` before `hlt` and the loop around both: an NMI or a machine check can
/// wake a halted processor even with interrupts masked, and a `hlt` that falls
/// through starts executing whatever follows it in memory.
pub fn halt_forever() -> ! {
    loop {
        // SAFETY: halting has no memory effects and we never return.
        unsafe {
            core::arch::asm!("cli", "hlt", options(nomem, nostack));
        }
    }
}
