//! Installing the IDT and the CPU exception handlers.
//!
//! `idt.rs` builds and validates gate descriptors; this file supplies the
//! handlers behind them and loads the table.
//!
//! # Every deliverable vector gets a handler, even the ones that "cannot happen"
//!
//! A vector with no present gate does not do nothing — it raises #GP, and a #GP
//! raised while delivering an exception escalates to #DF, and a fault during #DF
//! delivery is a triple fault: the machine resets with no message at all. So an
//! unhandled #DE is not a missing feature, it is a silent reboot with a cause
//! that no longer exists by the time you look.
//!
//! `Idt::missing_exception_vectors` exists for exactly this, and `install`
//! refuses to load a table it reports on rather than discovering the gap the
//! first time a divide by zero happens in a driver.

use super::addr::{PagingMode, VirtAddr};
use super::cpu::{self, DescriptorTablePointer};
use super::gdt::{ist, GdtLayout};
use super::idt::{vector, GateKind, Idt, IdtError, InterruptFrame, PageFaultError};
use crate::kprintln;

/// `Idt` is already `repr(C, align(16))`, which is what the IDTR needs.
static mut IDT: Idt = Idt::new();

fn handler_addr(f: usize) -> VirtAddr {
    VirtAddr::from_indices_sign_extended(f as u64, PagingMode::Level4)
}

/// Fills every architecturally deliverable vector and loads the table.
///
/// # Safety
/// Called once, on the bootstrap processor, after the GDT is installed —
/// the gates name `layout.kernel_code`, which must already be valid.
pub unsafe fn install(layout: &GdtLayout) -> Result<(), IdtError> {
    // SAFETY: single-threaded bring-up; nothing else touches the table.
    let idt = unsafe { &mut *core::ptr::addr_of_mut!(IDT) };
    let cs = layout.kernel_code;

    // Faults and traps without an error code.
    let plain: [(u8, usize, u8); 10] = [
        (vector::DIVIDE_ERROR, divide_error as *const () as usize, 0),
        (vector::DEBUG, debug as *const () as usize, ist::DEBUG),
        (vector::NMI, nmi as *const () as usize, ist::NMI),
        (vector::OVERFLOW, overflow as *const () as usize, 0),
        (vector::BOUND_RANGE, bound_range as *const () as usize, 0),
        (
            vector::INVALID_OPCODE,
            invalid_opcode as *const () as usize,
            0,
        ),
        (
            vector::DEVICE_NOT_AVAILABLE,
            device_not_available as *const () as usize,
            0,
        ),
        (
            vector::X87_FLOATING_POINT,
            x87_floating_point as *const () as usize,
            0,
        ),
        (
            vector::SIMD_FLOATING_POINT,
            simd_floating_point as *const () as usize,
            0,
        ),
        (
            vector::HYPERVISOR_INJECTION,
            hypervisor_injection as *const () as usize,
            0,
        ),
    ];
    for (v, f, ist_index) in plain {
        idt.set_handler(v, handler_addr(f), cs, GateKind::Interrupt, ist_index)?;
    }

    // Faults that push an error code.
    let with_error: [(u8, usize, u8); 7] = [
        (vector::INVALID_TSS, invalid_tss as *const () as usize, 0),
        (
            vector::SEGMENT_NOT_PRESENT,
            segment_not_present as *const () as usize,
            0,
        ),
        (
            vector::STACK_SEGMENT_FAULT,
            stack_segment_fault as *const () as usize,
            0,
        ),
        (
            vector::GENERAL_PROTECTION,
            general_protection as *const () as usize,
            0,
        ),
        (
            vector::ALIGNMENT_CHECK,
            alignment_check as *const () as usize,
            0,
        ),
        (
            vector::CONTROL_PROTECTION,
            control_protection as *const () as usize,
            0,
        ),
        (
            vector::VIRTUALISATION,
            virtualisation as *const () as usize,
            0,
        ),
    ];
    for (v, f, ist_index) in with_error {
        idt.set_handler(v, handler_addr(f), cs, GateKind::Interrupt, ist_index)?;
    }

    idt.set_handler(
        vector::PAGE_FAULT,
        handler_addr(page_fault as *const () as usize),
        cs,
        GateKind::Interrupt,
        0,
    )?;
    // #DF and #MC each run on their own stack: by the time they fire, the
    // current one may be exhausted or the hardware untrustworthy.
    idt.set_handler(
        vector::DOUBLE_FAULT,
        handler_addr(double_fault as *const () as usize),
        cs,
        GateKind::Interrupt,
        ist::DOUBLE_FAULT,
    )?;
    idt.set_handler(
        vector::MACHINE_CHECK,
        handler_addr(machine_check as *const () as usize),
        cs,
        GateKind::Interrupt,
        ist::MACHINE_CHECK,
    )?;

    // #BP is the one vector ring 3 is allowed to raise with `int3`; a debugger
    // that cannot breakpoint is not a debugger. `set_user_invokable_handler`
    // refuses any other vector, so this cannot become a general escape hatch.
    idt.set_user_invokable_handler(
        vector::BREAKPOINT,
        handler_addr(breakpoint as *const () as usize),
        cs,
        GateKind::Trap,
    )?;

    // Device vectors. Nothing is wired to an interrupt controller yet, so all
    // of them land on one handler that reports and continues rather than
    // leaving 224 gates absent.
    for v in vector::FIRST_DEVICE..=u8::MAX {
        idt.set_device_handler(v, handler_addr(unexpected_device as *const () as usize), cs)?;
    }

    if let Some(missing) = idt.missing_exception_vectors().next() {
        return Err(IdtError::MissingHandler(missing));
    }

    let pointer = DescriptorTablePointer {
        limit: Idt::limit(),
        base: core::ptr::addr_of!(IDT) as u64,
    };
    // SAFETY: the table is static, complete, and its gates name a code selector
    // that is already loaded.
    unsafe { cpu::lidt(&pointer) };
    Ok(())
}

/// Reports a fatal exception and stops.
///
/// Deliberately not a `panic!`: the panic machinery formats through the same
/// console lock the faulting code may have been holding. This path takes no
/// locks at all.
fn fatal(name: &str, frame: &InterruptFrame, error: Option<u64>) -> ! {
    // SAFETY: the system is going down; interleaved output beats no output.
    unsafe {
        crate::arch::console::emergency_write(format_args!(
            "\r\n[kernel] fatal exception: {name}\r\n\
             [kernel]   rip={:#018x} cs={:#06x} rflags={:#018x}\r\n\
             [kernel]   rsp={:#018x} ss={:#06x} cr2={:#018x}\r\n",
            frame.rip,
            frame.cs,
            frame.rflags,
            frame.rsp,
            frame.ss,
            cpu::read_cr2(),
        ));
        if let Some(code) = error {
            crate::arch::console::emergency_write(format_args!(
                "[kernel]   error_code={code:#018x}\r\n"
            ));
        }
    }
    cpu::halt_forever()
}

// --- handlers ---------------------------------------------------------------
//
// The signatures are dictated by the `x86-interrupt` ABI: the first argument is
// the frame the CPU pushed, and a second `u64` appears exactly for the vectors
// that push an error code. Getting that second argument wrong on either side
// shifts every field of the frame by eight bytes, so the split above mirrors
// `idt::pushes_error_code`, which is tested against the architecture tables.

extern "x86-interrupt" fn divide_error(frame: InterruptFrame) -> ! {
    fatal("#DE divide error", &frame, None)
}

extern "x86-interrupt" fn debug(frame: InterruptFrame) {
    kprintln!("[kernel] #DB debug trap at {:#018x}", frame.rip);
}

extern "x86-interrupt" fn nmi(frame: InterruptFrame) {
    // An NMI during bring-up is almost always a hardware or hypervisor
    // condition rather than anything the kernel did. Report and continue: an
    // NMI is not by itself a reason to stop.
    kprintln!("[kernel] NMI at {:#018x}", frame.rip);
}

extern "x86-interrupt" fn breakpoint(frame: InterruptFrame) {
    kprintln!("[kernel] #BP breakpoint at {:#018x}", frame.rip);
}

extern "x86-interrupt" fn overflow(frame: InterruptFrame) -> ! {
    fatal("#OF overflow", &frame, None)
}

extern "x86-interrupt" fn bound_range(frame: InterruptFrame) -> ! {
    fatal("#BR bound range exceeded", &frame, None)
}

extern "x86-interrupt" fn invalid_opcode(frame: InterruptFrame) -> ! {
    fatal("#UD invalid opcode", &frame, None)
}

extern "x86-interrupt" fn device_not_available(frame: InterruptFrame) -> ! {
    fatal("#NM device not available", &frame, None)
}

extern "x86-interrupt" fn x87_floating_point(frame: InterruptFrame) -> ! {
    fatal("#MF x87 floating point", &frame, None)
}

extern "x86-interrupt" fn simd_floating_point(frame: InterruptFrame) -> ! {
    fatal("#XM SIMD floating point", &frame, None)
}

extern "x86-interrupt" fn invalid_tss(frame: InterruptFrame, error: u64) -> ! {
    fatal("#TS invalid TSS", &frame, Some(error))
}

extern "x86-interrupt" fn segment_not_present(frame: InterruptFrame, error: u64) -> ! {
    fatal("#NP segment not present", &frame, Some(error))
}

extern "x86-interrupt" fn stack_segment_fault(frame: InterruptFrame, error: u64) -> ! {
    fatal("#SS stack segment fault", &frame, Some(error))
}

extern "x86-interrupt" fn general_protection(frame: InterruptFrame, error: u64) -> ! {
    fatal("#GP general protection", &frame, Some(error))
}

extern "x86-interrupt" fn alignment_check(frame: InterruptFrame, error: u64) -> ! {
    fatal("#AC alignment check", &frame, Some(error))
}

extern "x86-interrupt" fn control_protection(frame: InterruptFrame, error: u64) -> ! {
    // Shadow-stack mismatch or a missing ENDBR. Always fatal by policy — a
    // control-flow violation that is recovered from is a control-flow violation
    // that succeeded.
    fatal("#CP control protection", &frame, Some(error))
}

extern "x86-interrupt" fn virtualisation(frame: InterruptFrame, error: u64) -> ! {
    fatal("#VE virtualisation", &frame, Some(error))
}

extern "x86-interrupt" fn page_fault(frame: InterruptFrame, error: u64) -> ! {
    let decoded = PageFaultError(error);
    // SAFETY: fatal path, no locks.
    unsafe {
        crate::arch::console::emergency_write(format_args!(
            "\r\n[kernel] #PF at {:#018x} accessing {:#018x}\r\n\
             [kernel]   {} {} {}{}\r\n",
            frame.rip,
            cpu::read_cr2(),
            if decoded.protection_violation() {
                "protection-violation"
            } else {
                "not-present"
            },
            if decoded.caused_by_write() {
                "write"
            } else {
                "read"
            },
            if decoded.from_user_mode() {
                "user"
            } else {
                "kernel"
            },
            if decoded.instruction_fetch() {
                " instruction-fetch"
            } else {
                ""
            },
        ));
    }
    fatal("#PF page fault", &frame, Some(error))
}

extern "x86-interrupt" fn double_fault(frame: InterruptFrame, error: u64) -> ! {
    // Reached only because a fault happened while delivering another fault. The
    // dedicated IST stack is why this handler can run at all.
    fatal("#DF double fault", &frame, Some(error))
}

extern "x86-interrupt" fn machine_check(frame: InterruptFrame) -> ! {
    fatal("#MC machine check", &frame, None)
}

extern "x86-interrupt" fn hypervisor_injection(frame: InterruptFrame) -> ! {
    // Only a hypervisor can deliver this. Nothing in stage 1 knows how to
    // service it, and continuing would mean ignoring a message from the layer
    // that owns the machine.
    fatal("#HV hypervisor injection", &frame, None)
}

extern "x86-interrupt" fn unexpected_device(frame: InterruptFrame) {
    // No interrupt controller is programmed yet, so nothing should arrive here.
    // Reporting and returning rather than halting keeps a stray interrupt from
    // a legacy PIC — which QEMU leaves in a default state — from killing a boot
    // that is otherwise fine.
    kprintln!(
        "[kernel] unexpected device interrupt at {:#018x}",
        frame.rip
    );
}
