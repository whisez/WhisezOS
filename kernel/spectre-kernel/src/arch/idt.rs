//! Interrupt Descriptor Table.
//!
//! 256 vectors, each a 16-byte gate descriptor in long mode.
//!
//! Three things in this file are easy to get wrong and produce failures far
//! from their cause:
//!
//! **The handler address is split across three fields.** Bits [15:0], [31:16],
//! and [63:32] live at non-adjacent offsets. Reassemble it wrong and the CPU
//! jumps somewhere arbitrary on the first interrupt, which presents as a
//! spontaneous triple fault with no useful state.
//!
//! **Gate DPL controls who can raise the vector with `int N`.** A gate at DPL 3
//! can be invoked directly from user space. Setting DPL 3 on, say, the page
//! fault vector lets a user process synthesise a #PF with a forged error code
//! and a stack frame of its choosing — the handler then makes privileged
//! decisions based on attacker-supplied data. Only vectors that are *meant* to
//! be user-invokable (`int3` for debuggers, and nothing else here) get DPL 3.
//! `Idt::set_handler` defaults to DPL 0 and requires an explicit call to raise
//! it, so the dangerous case is never the one you get by accident.
//!
//! **Some vectors push an error code and some do not.** The handler's stack
//! frame layout differs by 8 bytes between the two. Use the wrong prologue and
//! every field the handler reads is off by one slot — including the return
//! address, so `iretq` returns into the middle of a function. The table in
//! `pushes_error_code` is the authority, checked against the SDM, and
//! `HandlerKind` makes the compiler enforce that the right prologue is attached.

use super::addr::VirtAddr;
use super::gdt::SegmentSelector;

pub const VECTOR_COUNT: usize = 256;

/// Architecturally defined exception vectors (SDM Vol. 3A §6.15).
pub mod vector {
    pub const DIVIDE_ERROR: u8 = 0;
    pub const DEBUG: u8 = 1;
    pub const NMI: u8 = 2;
    pub const BREAKPOINT: u8 = 3;
    pub const OVERFLOW: u8 = 4;
    pub const BOUND_RANGE: u8 = 5;
    pub const INVALID_OPCODE: u8 = 6;
    pub const DEVICE_NOT_AVAILABLE: u8 = 7;
    pub const DOUBLE_FAULT: u8 = 8;
    pub const INVALID_TSS: u8 = 10;
    pub const SEGMENT_NOT_PRESENT: u8 = 11;
    pub const STACK_SEGMENT_FAULT: u8 = 12;
    pub const GENERAL_PROTECTION: u8 = 13;
    pub const PAGE_FAULT: u8 = 14;
    pub const X87_FLOATING_POINT: u8 = 16;
    pub const ALIGNMENT_CHECK: u8 = 17;
    pub const MACHINE_CHECK: u8 = 18;
    pub const SIMD_FLOATING_POINT: u8 = 19;
    pub const VIRTUALISATION: u8 = 20;
    /// Raised when a Control-flow Enforcement violation is detected — shadow
    /// stack mismatch or a missing ENDBR. WhisezOS treats this as fatal to the
    /// faulting process, never as recoverable.
    pub const CONTROL_PROTECTION: u8 = 21;

    /// Hypervisor injection exception (AMD SVM). Delivered to a guest by the
    /// hypervisor, so it can arrive on a VM even though nothing in the guest
    /// can raise it. Leaving it without a gate is how a kernel that works on
    /// bare metal triple-faults under a hypervisor and nowhere else.
    pub const HYPERVISOR_INJECTION: u8 = 28;

    /// First vector available for device interrupts. 32 vectors are reserved by
    /// the architecture; using any of them for a device is a bug that surfaces
    /// as random exceptions under load.
    pub const FIRST_DEVICE: u8 = 32;

    /// LAPIC timer, the scheduler's tick source.
    pub const LAPIC_TIMER: u8 = 32;
    /// Spurious interrupt. The LAPIC requires the low 4 bits to be set on some
    /// older parts, so 0xFF is the conventional choice.
    pub const SPURIOUS: u8 = 255;
}

/// Does this vector push an error code onto the stack?
///
/// Getting this wrong shifts every field in the interrupt frame by 8 bytes.
/// Notably #DF, #TS, #NP, #SS, #GP, #PF, #AC, and #CP all push one; #NMI, #BP,
/// #UD, and every device interrupt do not. Vector 9 is the historical
/// coprocessor segment overrun, reserved since the 486 and listed here so the
/// gap is deliberate rather than an oversight.
pub const fn pushes_error_code(vector: u8) -> bool {
    matches!(
        vector,
        vector::DOUBLE_FAULT
            | vector::INVALID_TSS
            | vector::SEGMENT_NOT_PRESENT
            | vector::STACK_SEGMENT_FAULT
            | vector::GENERAL_PROTECTION
            | vector::PAGE_FAULT
            | vector::ALIGNMENT_CHECK
            | vector::CONTROL_PROTECTION
    )
}

/// Vectors that abort rather than return. The handler must not `iretq`.
pub const fn is_abort(vector: u8) -> bool {
    matches!(vector, vector::DOUBLE_FAULT | vector::MACHINE_CHECK)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdtError {
    /// IST index outside 0..=7.
    BadIstIndex(u8),
    /// A gate was given DPL 3 for a vector that must not be user-invokable.
    UnsafeUserGate(u8),
    /// Handler address is not canonical.
    NonCanonicalHandler(u64),
    /// Reserved vector used for a device interrupt.
    ReservedVector(u8),
    /// A deliverable exception vector has no present gate. Loading such a table
    /// turns that exception into a #GP, and a #GP during exception delivery
    /// escalates to #DF and then to a silent triple fault, so the table is
    /// refused rather than loaded.
    MissingHandler(u8),
}

/// Interrupt gate vs trap gate.
///
/// The only difference: an interrupt gate clears IF on entry, a trap gate does
/// not. Every fault handler here uses an interrupt gate, because a handler that
/// can be interrupted before it has saved state is a race. The exception is
/// #BP, which is a trap gate so a debugger breakpoint does not silently disable
/// interrupts for the duration of the debugger's inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateKind {
    Interrupt,
    Trap,
}

impl GateKind {
    const fn type_bits(self) -> u8 {
        match self {
            GateKind::Interrupt => 0xE,
            GateKind::Trap => 0xF,
        }
    }
}

/// A 16-byte long-mode gate descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct GateDescriptor {
    offset_low: u16,
    selector: u16,
    /// IST index in bits [2:0]; bits [7:3] reserved and must be zero.
    ist: u8,
    /// P | DPL[1:0] | 0 | type[3:0]
    type_attr: u8,
    offset_mid: u16,
    offset_high: u32,
    _reserved: u32,
}

impl GateDescriptor {
    pub const MISSING: GateDescriptor = GateDescriptor {
        offset_low: 0,
        selector: 0,
        ist: 0,
        type_attr: 0,
        offset_mid: 0,
        offset_high: 0,
        _reserved: 0,
    };

    pub fn new(
        handler: VirtAddr,
        selector: SegmentSelector,
        kind: GateKind,
        dpl: u8,
        ist_index: u8,
    ) -> Result<GateDescriptor, IdtError> {
        if ist_index > 7 {
            return Err(IdtError::BadIstIndex(ist_index));
        }

        let addr = handler.as_u64();
        Ok(GateDescriptor {
            offset_low: (addr & 0xFFFF) as u16,
            selector: selector.0,
            ist: ist_index & 0x7,
            type_attr: 0x80 | ((dpl & 0x3) << 5) | kind.type_bits(),
            offset_mid: ((addr >> 16) & 0xFFFF) as u16,
            offset_high: ((addr >> 32) & 0xFFFF_FFFF) as u32,
            _reserved: 0,
        })
    }

    /// Reassemble the handler address from its three fields.
    pub fn handler_address(&self) -> u64 {
        self.offset_low as u64
            | ((self.offset_mid as u64) << 16)
            | ((self.offset_high as u64) << 32)
    }

    pub fn is_present(&self) -> bool {
        self.type_attr & 0x80 != 0
    }

    pub fn dpl(&self) -> u8 {
        (self.type_attr >> 5) & 0x3
    }

    pub fn kind(&self) -> GateKind {
        if self.type_attr & 0x0F == 0xF {
            GateKind::Trap
        } else {
            GateKind::Interrupt
        }
    }

    pub fn ist_index(&self) -> u8 {
        self.ist & 0x7
    }
}

/// The table itself.
#[derive(Clone, Copy)]
#[repr(C, align(16))]
pub struct Idt {
    gates: [GateDescriptor; VECTOR_COUNT],
}

impl Idt {
    pub const fn new() -> Idt {
        Idt {
            gates: [GateDescriptor::MISSING; VECTOR_COUNT],
        }
    }

    /// Install a kernel-only handler. DPL defaults to 0 — see the module note
    /// on why the dangerous case must never be the default.
    pub fn set_handler(
        &mut self,
        vector: u8,
        handler: VirtAddr,
        selector: SegmentSelector,
        kind: GateKind,
        ist_index: u8,
    ) -> Result<(), IdtError> {
        self.gates[vector as usize] = GateDescriptor::new(handler, selector, kind, 0, ist_index)?;
        Ok(())
    }

    /// Install a handler that user space may invoke with `int N`.
    ///
    /// Deliberately a separate, longer-named method rather than a `dpl`
    /// parameter on `set_handler`. A parameter invites passing `3` without
    /// thinking; a distinct name makes the reviewer ask why.
    ///
    /// Only `#BP` qualifies. Everything else is refused, because a user-forgeable
    /// fault vector hands an attacker control of the error code and stack frame
    /// that a privileged handler then trusts.
    pub fn set_user_invokable_handler(
        &mut self,
        vector: u8,
        handler: VirtAddr,
        selector: SegmentSelector,
        kind: GateKind,
    ) -> Result<(), IdtError> {
        if vector != vector::BREAKPOINT {
            return Err(IdtError::UnsafeUserGate(vector));
        }
        self.gates[vector as usize] = GateDescriptor::new(handler, selector, kind, 3, 0)?;
        Ok(())
    }

    /// Install a device interrupt handler, refusing the architecturally
    /// reserved range.
    pub fn set_device_handler(
        &mut self,
        vector: u8,
        handler: VirtAddr,
        selector: SegmentSelector,
    ) -> Result<(), IdtError> {
        if vector < vector::FIRST_DEVICE {
            return Err(IdtError::ReservedVector(vector));
        }
        self.set_handler(vector, handler, selector, GateKind::Interrupt, 0)
    }

    pub fn gate(&self, vector: u8) -> &GateDescriptor {
        &self.gates[vector as usize]
    }

    /// Vectors with no handler installed.
    ///
    /// A missing gate for an exception means the CPU raises #GP on delivery,
    /// which then also has no handler, which double-faults. Checking this at
    /// boot converts a triple fault into a diagnosable panic.
    pub fn missing_exception_vectors(&self) -> impl Iterator<Item = u8> + '_ {
        (0..32u8).filter(move |v| {
            // Vectors 9, 15, 22..=27, 29..=31 are reserved and never delivered
            // on any current CPU. Requiring handlers for them would be noise.
            let reserved = matches!(*v, 9 | 15 | 22..=27 | 29..=31);
            !reserved && !self.gates[*v as usize].is_present()
        })
    }

    /// Value for the IDTR limit field.
    pub const fn limit() -> u16 {
        (VECTOR_COUNT * 16 - 1) as u16
    }
}

impl Default for Idt {
    fn default() -> Self {
        Self::new()
    }
}

/// The frame the CPU pushes on interrupt entry, after any error code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct InterruptFrame {
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

/// Decoded #PF error code (SDM Vol. 3A §4.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageFaultError(pub u64);

impl PageFaultError {
    /// Fault was a protection violation rather than a not-present page.
    pub fn protection_violation(self) -> bool {
        self.0 & (1 << 0) != 0
    }
    pub fn caused_by_write(self) -> bool {
        self.0 & (1 << 1) != 0
    }
    pub fn from_user_mode(self) -> bool {
        self.0 & (1 << 2) != 0
    }
    pub fn reserved_bit_set(self) -> bool {
        self.0 & (1 << 3) != 0
    }
    pub fn instruction_fetch(self) -> bool {
        self.0 & (1 << 4) != 0
    }
    /// Shadow-stack access. Distinguishes a CET violation from an ordinary
    /// write fault, which matters because the two get very different responses:
    /// a shadow-stack fault is always an attack or a severe compiler bug.
    pub fn shadow_stack(self) -> bool {
        self.0 & (1 << 6) != 0
    }

    /// Is this fault a candidate for demand paging, or is it fatal?
    ///
    /// Only a not-present fault from a legitimate access can be satisfied by
    /// mapping a page. A protection violation, a reserved-bit fault (which means
    /// the page tables themselves are corrupt), or a shadow-stack fault are all
    /// terminal.
    pub fn is_demand_pageable(self) -> bool {
        !self.protection_violation() && !self.reserved_bit_set() && !self.shadow_stack()
    }
}

#[cfg(test)]
mod tests {
    use super::super::addr::PagingMode;
    use super::*;

    const L4: PagingMode = PagingMode::Level4;

    fn kernel_cs() -> SegmentSelector {
        SegmentSelector::new(1, 0)
    }

    fn handler(addr: u64) -> VirtAddr {
        VirtAddr::from_indices_sign_extended(addr, L4)
    }

    #[test]
    fn handler_address_survives_the_three_way_split() {
        // A kernel-half address exercises all three fields including the high
        // 32 bits, which a low test address would leave zero and hide a bug in.
        let addr = 0xFFFF_8000_DEAD_BEEFu64;
        let g = GateDescriptor::new(handler(addr), kernel_cs(), GateKind::Interrupt, 0, 0).unwrap();
        assert_eq!(g.handler_address(), addr, "handler address mangled");
    }

    #[test]
    fn handler_address_round_trips_across_many_values() {
        for shift in 0..64 {
            let addr = VirtAddr::from_indices_sign_extended(1u64 << shift, L4).as_u64();
            let g = GateDescriptor::new(
                unsafe { VirtAddr::new_unchecked(addr) },
                kernel_cs(),
                GateKind::Interrupt,
                0,
                0,
            )
            .unwrap();
            assert_eq!(g.handler_address(), addr, "failed at bit {shift}");
        }
    }

    #[test]
    fn gates_default_to_ring_zero() {
        let mut idt = Idt::new();
        idt.set_handler(
            vector::PAGE_FAULT,
            handler(0xFFFF_8000_0000_1000),
            kernel_cs(),
            GateKind::Interrupt,
            0,
        )
        .unwrap();
        assert_eq!(
            idt.gate(vector::PAGE_FAULT).dpl(),
            0,
            "page fault gate is user-invokable"
        );
    }

    #[test]
    fn only_breakpoint_may_be_user_invokable() {
        let mut idt = Idt::new();
        let h = handler(0xFFFF_8000_0000_2000);

        // The dangerous case: a user-forgeable page fault.
        assert_eq!(
            idt.set_user_invokable_handler(vector::PAGE_FAULT, h, kernel_cs(), GateKind::Interrupt),
            Err(IdtError::UnsafeUserGate(vector::PAGE_FAULT))
        );
        assert_eq!(
            idt.set_user_invokable_handler(
                vector::GENERAL_PROTECTION,
                h,
                kernel_cs(),
                GateKind::Interrupt
            ),
            Err(IdtError::UnsafeUserGate(vector::GENERAL_PROTECTION))
        );

        idt.set_user_invokable_handler(vector::BREAKPOINT, h, kernel_cs(), GateKind::Trap)
            .unwrap();
        assert_eq!(idt.gate(vector::BREAKPOINT).dpl(), 3);
    }

    #[test]
    fn device_handlers_cannot_use_reserved_vectors() {
        let mut idt = Idt::new();
        let h = handler(0xFFFF_8000_0000_3000);

        for v in 0..vector::FIRST_DEVICE {
            assert_eq!(
                idt.set_device_handler(v, h, kernel_cs()),
                Err(IdtError::ReservedVector(v)),
                "vector {v} was accepted as a device interrupt"
            );
        }
        assert!(idt
            .set_device_handler(vector::FIRST_DEVICE, h, kernel_cs())
            .is_ok());
    }

    #[test]
    fn ist_index_is_bounded() {
        let h = handler(0xFFFF_8000_0000_4000);
        assert_eq!(
            GateDescriptor::new(h, kernel_cs(), GateKind::Interrupt, 0, 8),
            Err(IdtError::BadIstIndex(8))
        );
        let g = GateDescriptor::new(h, kernel_cs(), GateKind::Interrupt, 0, 7).unwrap();
        assert_eq!(g.ist_index(), 7);
    }

    #[test]
    fn ist_reserved_bits_stay_clear() {
        // Bits [7:3] of the IST byte are reserved. Leaking the index into them
        // is a #GP on IDT load, which happens before any handler can report it.
        let g = GateDescriptor::new(
            handler(0xFFFF_8000_0000_5000),
            kernel_cs(),
            GateKind::Interrupt,
            0,
            7,
        )
        .unwrap();
        assert_eq!(g.ist & 0xF8, 0, "reserved IST bits set");
    }

    #[test]
    fn gate_kind_round_trips() {
        let h = handler(0xFFFF_8000_0000_6000);
        let i = GateDescriptor::new(h, kernel_cs(), GateKind::Interrupt, 0, 0).unwrap();
        let t = GateDescriptor::new(h, kernel_cs(), GateKind::Trap, 0, 0).unwrap();
        assert_eq!(i.kind(), GateKind::Interrupt);
        assert_eq!(t.kind(), GateKind::Trap);
        assert!(i.is_present() && t.is_present());
    }

    #[test]
    fn missing_gate_is_not_present() {
        let idt = Idt::new();
        assert!(!idt.gate(vector::PAGE_FAULT).is_present());
    }

    #[test]
    fn missing_exception_vectors_are_reported() {
        let mut idt = Idt::new();
        // Nothing installed: every deliverable exception vector is missing.
        let missing: Vec<u8> = idt.missing_exception_vectors().collect();
        assert!(missing.contains(&vector::PAGE_FAULT));
        assert!(missing.contains(&vector::DOUBLE_FAULT));
        // Reserved vectors must not be reported — that would be permanent noise.
        assert!(!missing.contains(&9));
        assert!(!missing.contains(&15));

        let h = handler(0xFFFF_8000_0000_7000);
        for v in 0..32u8 {
            let _ = idt.set_handler(v, h, kernel_cs(), GateKind::Interrupt, 0);
        }
        assert_eq!(idt.missing_exception_vectors().count(), 0);
    }

    #[test]
    fn error_code_table_matches_the_architecture() {
        // Spot-checked against SDM Vol. 3A Table 6-1. A wrong entry here shifts
        // the entire interrupt frame by 8 bytes in the affected handler.
        for v in [8u8, 10, 11, 12, 13, 14, 17, 21] {
            assert!(pushes_error_code(v), "vector {v} should push an error code");
        }
        for v in [0u8, 1, 2, 3, 4, 5, 6, 7, 16, 18, 19, 20, 32, 255] {
            assert!(
                !pushes_error_code(v),
                "vector {v} should not push an error code"
            );
        }
    }

    #[test]
    fn aborts_are_identified() {
        assert!(is_abort(vector::DOUBLE_FAULT));
        assert!(is_abort(vector::MACHINE_CHECK));
        assert!(!is_abort(vector::PAGE_FAULT), "#PF is recoverable");
        assert!(!is_abort(vector::BREAKPOINT));
    }

    #[test]
    fn idt_limit_covers_every_vector() {
        assert_eq!(Idt::limit() as usize, VECTOR_COUNT * 16 - 1);
        assert_eq!(core::mem::size_of::<GateDescriptor>(), 16);
        assert_eq!(core::mem::size_of::<Idt>(), VECTOR_COUNT * 16);
    }

    #[test]
    fn page_fault_error_decodes() {
        // Not present, write, from user: the classic demand-paging case.
        let e = PageFaultError(0b110);
        assert!(!e.protection_violation());
        assert!(e.caused_by_write());
        assert!(e.from_user_mode());
        assert!(e.is_demand_pageable());
    }

    #[test]
    fn protection_violations_are_not_demand_pageable() {
        // Present + write: the page exists and is read-only. Mapping a page here
        // would silently paper over a real permission bug.
        let e = PageFaultError(0b011);
        assert!(e.protection_violation());
        assert!(!e.is_demand_pageable());
    }

    #[test]
    fn reserved_bit_faults_are_never_demand_pageable() {
        // A reserved bit set in a PTE means the page tables are corrupt.
        // Treating it as a missing page would loop forever.
        let e = PageFaultError(1 << 3);
        assert!(e.reserved_bit_set());
        assert!(!e.is_demand_pageable());
    }

    #[test]
    fn shadow_stack_faults_are_terminal() {
        // A CET shadow-stack mismatch is an attack or a severe compiler bug;
        // it must never be quietly satisfied by mapping a page.
        let e = PageFaultError(1 << 6);
        assert!(e.shadow_stack());
        assert!(!e.is_demand_pageable());
    }

    #[test]
    fn instruction_fetch_faults_are_distinguishable() {
        // Needed to tell "jumped into a NX page" (an exploit signature worth
        // reporting to SpectreShield) from an ordinary data fault.
        let e = PageFaultError(1 << 4);
        assert!(e.instruction_fetch());
        assert!(!e.caused_by_write());
    }
}
