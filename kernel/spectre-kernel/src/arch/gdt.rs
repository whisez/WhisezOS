//! Global Descriptor Table and Task State Segment.
//!
//! In long mode the GDT does almost nothing it used to — segmentation is
//! flattened and base/limit are ignored for code and data. What remains is
//! still load-bearing:
//!
//!   * The **L bit** distinguishes 64-bit code from compatibility mode. Getting
//!     it wrong drops the CPU into 32-bit mode on the next far jump.
//!   * **DPL** is what actually separates ring 0 from ring 3.
//!   * The **TSS** holds `RSP0` (the stack the CPU switches to on a ring 3 → 0
//!     transition) and the **IST** table.
//!   * The **descriptor order** is constrained by SYSCALL/SYSRET in a way that
//!     is not obvious and fails at runtime rather than at build time.
//!
//! # The SYSRET ordering constraint
//!
//! `SYSRET` does not read a selector from anywhere. It computes them:
//!
//! ```text
//! CS = STAR[63:48] + 16
//! SS = STAR[63:48] + 8
//! ```
//!
//! So the GDT *must* place user data immediately after the SYSRET base and user
//! code immediately after that. Order them the intuitive way — code before data,
//! matching the kernel entries — and every `SYSRET` loads a data descriptor into
//! CS. The CPU faults on the first instruction back in user space, with a
//! diagnostic that points at user code rather than at the GDT.
//!
//! `GdtLayout::validate` enforces this at construction so it is caught in a unit
//! test rather than on the first syscall return.
//!
//! # Why the double-fault handler needs its own stack
//!
//! A kernel stack overflow pushes the guard page, raising #PF. The #PF handler
//! tries to push its frame onto the same exhausted stack, which faults again —
//! now a #DF. The #DF handler pushes onto the same stack, faults a third time,
//! and a fault during double-fault delivery is a **triple fault**: the CPU
//! resets with no diagnostic at all.
//!
//! The IST breaks the chain by giving #DF a known-good stack the CPU switches to
//! unconditionally, ignoring whatever RSP contained. That turns an unrecoverable
//! silent reboot into a panic message naming the overflowing thread.

use super::addr::VirtAddr;

/// A GDT entry. Code/data descriptors are 8 bytes; the TSS descriptor is 16 and
/// occupies two consecutive slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(transparent)]
pub struct Descriptor(pub u64);

/// Access byte bits (SDM Vol. 3A §3.4.5).
pub mod access {
    pub const ACCESSED: u8 = 1 << 0;
    /// Readable for code segments, writable for data segments.
    pub const RW: u8 = 1 << 1;
    /// Direction/conforming.
    pub const CONFORMING: u8 = 1 << 2;
    pub const EXECUTABLE: u8 = 1 << 3;
    /// Set for code/data, clear for system descriptors (TSS, LDT, gates).
    pub const USER_SEGMENT: u8 = 1 << 4;
    pub const DPL_RING3: u8 = 3 << 5;
    pub const PRESENT: u8 = 1 << 7;

    /// Available 64-bit TSS. Type 0x9 in the low nibble, S bit clear.
    pub const TSS_AVAILABLE: u8 = 0x9;
}

/// Flags nibble in the upper half of the descriptor.
pub mod flags {
    /// Long mode: this is a 64-bit code segment.
    pub const LONG_MODE: u8 = 1 << 1;
    /// Default operand size 32-bit. Must be **clear** when LONG_MODE is set —
    /// the combination is architecturally reserved.
    pub const DB_32BIT: u8 = 1 << 2;
    /// Limit is in 4 KiB units.
    pub const GRANULARITY: u8 = 1 << 3;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GdtError {
    /// LONG_MODE and DB_32BIT both set: architecturally reserved.
    LongModeWith32BitDefault,
    /// SYSRET requires user data at base+8 and user code at base+16.
    SysretOrdering {
        expected_data: u16,
        expected_code: u16,
    },
    /// More entries than the table holds.
    TableFull,
    /// IST index outside 1..=7. Index 0 means "no IST", so a handler asking for
    /// IST 0 has silently opted out of its dedicated stack.
    BadIstIndex(u8),
}

impl Descriptor {
    pub const NULL: Descriptor = Descriptor(0);

    /// Build a code or data descriptor.
    ///
    /// Base and limit are accepted but ignored by the hardware in long mode for
    /// these types. They are still written correctly rather than zeroed, because
    /// the values are architecturally defined and a debugger reading the GDT
    /// should see something coherent.
    pub fn segment(access_byte: u8, flags_nibble: u8) -> Result<Descriptor, GdtError> {
        if flags_nibble & flags::LONG_MODE != 0 && flags_nibble & flags::DB_32BIT != 0 {
            return Err(GdtError::LongModeWith32BitDefault);
        }

        let mut d: u64 = 0;
        d |= (access_byte as u64) << 40;
        d |= ((flags_nibble & 0x0F) as u64) << 52;
        // Limit 0xFFFFF with 4 KiB granularity spans the full 32-bit space.
        d |= 0xFFFF; // limit[15:0]
        d |= 0xF << 48; // limit[19:16]
        Ok(Descriptor(d))
    }

    pub fn kernel_code() -> Descriptor {
        Descriptor::segment(
            access::PRESENT | access::USER_SEGMENT | access::EXECUTABLE | access::RW,
            flags::LONG_MODE | flags::GRANULARITY,
        )
        .expect("kernel code descriptor is well-formed by construction")
    }

    pub fn kernel_data() -> Descriptor {
        Descriptor::segment(
            access::PRESENT | access::USER_SEGMENT | access::RW,
            flags::GRANULARITY,
        )
        .expect("kernel data descriptor is well-formed by construction")
    }

    pub fn user_code() -> Descriptor {
        Descriptor::segment(
            access::PRESENT
                | access::USER_SEGMENT
                | access::EXECUTABLE
                | access::RW
                | access::DPL_RING3,
            flags::LONG_MODE | flags::GRANULARITY,
        )
        .expect("user code descriptor is well-formed by construction")
    }

    pub fn user_data() -> Descriptor {
        Descriptor::segment(
            access::PRESENT | access::USER_SEGMENT | access::RW | access::DPL_RING3,
            flags::GRANULARITY,
        )
        .expect("user data descriptor is well-formed by construction")
    }

    pub fn dpl(self) -> u8 {
        ((self.0 >> 45) & 0x3) as u8
    }

    pub fn is_present(self) -> bool {
        self.0 & (1 << 47) != 0
    }

    pub fn is_long_mode_code(self) -> bool {
        let executable = self.0 & (1u64 << 43) != 0;
        let long = self.0 & (1u64 << 53) != 0;
        executable && long
    }

    /// The two halves of a 16-byte TSS descriptor.
    ///
    /// The base address is split across three non-adjacent fields in the low
    /// half plus a fourth in the high half — a layout inherited from the 286 and
    /// preserved for compatibility. Assembling it by hand is exactly the kind of
    /// bit-shuffling that is easy to get subtly wrong and impossible to notice
    /// until the CPU faults on a privilege transition.
    pub fn tss(base: VirtAddr, limit: u32) -> (Descriptor, Descriptor) {
        let base = base.as_u64();

        let mut low: u64 = 0;
        low |= (limit as u64) & 0xFFFF; // limit[15:0]
        low |= (base & 0xFF_FFFF) << 16; // base[23:0]
        low |= (access::PRESENT as u64 | access::TSS_AVAILABLE as u64) << 40;
        low |= ((limit as u64 >> 16) & 0xF) << 48; // limit[19:16]
        low |= ((base >> 24) & 0xFF) << 56; // base[31:24]

        let high: u64 = (base >> 32) & 0xFFFF_FFFF; // base[63:32]

        (Descriptor(low), Descriptor(high))
    }
}

/// A segment selector: index into the GDT plus RPL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct SegmentSelector(pub u16);

impl SegmentSelector {
    pub const fn new(index: u16, rpl: u8) -> SegmentSelector {
        SegmentSelector((index << 3) | (rpl as u16 & 0x3))
    }

    pub const fn index(self) -> u16 {
        self.0 >> 3
    }

    pub const fn rpl(self) -> u8 {
        (self.0 & 0x3) as u8
    }

    /// Byte offset of this selector's descriptor within the GDT.
    pub const fn offset(self) -> u16 {
        self.0 & !0x7
    }
}

/// Selectors produced by a built GDT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GdtLayout {
    pub kernel_code: SegmentSelector,
    pub kernel_data: SegmentSelector,
    pub user_data: SegmentSelector,
    pub user_code: SegmentSelector,
    pub tss: SegmentSelector,
    /// Value for STAR[63:48]. SYSRET derives user CS and SS from it.
    pub sysret_base: u16,
}

impl GdtLayout {
    /// Check the SYSCALL/SYSRET selector arithmetic.
    ///
    /// This is the whole reason `GdtLayout` exists as a separate type rather
    /// than a handful of constants: the constraint is invisible in the
    /// descriptor bits and only manifests on the first return to user space.
    pub fn validate(&self) -> Result<(), GdtError> {
        let expected_data = self.sysret_base + 8;
        let expected_code = self.sysret_base + 16;

        if self.user_data.offset() != expected_data || self.user_code.offset() != expected_code {
            return Err(GdtError::SysretOrdering {
                expected_data,
                expected_code,
            });
        }
        Ok(())
    }
}

/// The Task State Segment.
///
/// In long mode the TSS no longer holds a task context — hardware task
/// switching is gone. It holds two things that matter: `privilege_stack_table`
/// (RSP0..RSP2, the stacks the CPU switches to on a privilege escalation) and
/// `interrupt_stack_table` (IST1..IST7, unconditional stacks for chosen
/// vectors).
#[derive(Debug, Clone, Copy)]
#[repr(C, packed(4))]
pub struct Tss {
    _reserved0: u32,
    /// RSP0..RSP2. RSP0 is the kernel stack for ring 3 → 0 transitions and must
    /// be updated on every context switch, or a syscall from thread B lands on
    /// thread A's stack.
    pub privilege_stack_table: [u64; 3],
    _reserved1: u64,
    /// IST1..IST7. Index 0 in this array is IST1; the IST index in a gate
    /// descriptor is 1-based, with 0 meaning "no IST".
    pub interrupt_stack_table: [u64; 7],
    _reserved2: u64,
    _reserved3: u16,
    /// Offset of the I/O permission bitmap, measured from the base of the TSS.
    ///
    /// This used to be pinned past the segment limit, denying every port, on the
    /// grounds that user-space drivers reach hardware through MMIO rather than
    /// `in`/`out`. That is the right default and was the wrong absolute: the
    /// RTC, the i8042, and the legacy serial port have no MMIO window, so the
    /// choice was never between port access and something cleaner — it was
    /// between a driver in ring 3 holding two ports and the same work done in
    /// ring 0. See `portauth.rs`.
    ///
    /// It still denies everything by default. A bitmap of all-ones permits no
    /// port, and a process is granted bits only through `SYS_GRANT_PORTS`.
    pub iomap_base: u16,
}

impl Tss {
    pub const fn new() -> Tss {
        Tss {
            _reserved0: 0,
            privilege_stack_table: [0; 3],
            _reserved1: 0,
            interrupt_stack_table: [0; 7],
            _reserved2: 0,
            _reserved3: 0,
            // Equal to the TSS size: no I/O bitmap present, all ports denied.
            iomap_base: core::mem::size_of::<Tss>() as u16,
        }
    }

    /// Install a stack for IST slot `index` (1-based, per the gate encoding).
    pub fn set_ist(&mut self, index: u8, stack_top: VirtAddr) -> Result<(), GdtError> {
        if index == 0 || index > 7 {
            return Err(GdtError::BadIstIndex(index));
        }
        self.interrupt_stack_table[(index - 1) as usize] = stack_top.as_u64();
        Ok(())
    }

    pub fn ist(&self, index: u8) -> Result<u64, GdtError> {
        if index == 0 || index > 7 {
            return Err(GdtError::BadIstIndex(index));
        }
        Ok(self.interrupt_stack_table[(index - 1) as usize])
    }
}

impl Default for Tss {
    fn default() -> Self {
        Self::new()
    }
}

/// IST slot assignments. Each of these can fire while the current kernel stack
/// is unusable, which is precisely when a dedicated stack is the difference
/// between a panic message and a silent triple fault.
pub mod ist {
    /// Stack overflow's terminal case.
    pub const DOUBLE_FAULT: u8 = 1;
    /// NMI can arrive at any instruction boundary, including mid-stack-switch.
    pub const NMI: u8 = 2;
    /// Machine check: hardware is already failing; do not trust RSP.
    pub const MACHINE_CHECK: u8 = 3;
    /// Debug exceptions can fire inside the #DF handler during postmortem.
    pub const DEBUG: u8 = 4;
}

/// Builder for the GDT, laying entries out in SYSRET-compatible order.
pub struct GdtBuilder {
    entries: [Descriptor; Self::CAPACITY],
    len: usize,
}

impl GdtBuilder {
    /// Null + kernel code + kernel data + user data + user code + TSS (2 slots).
    pub const CAPACITY: usize = 8;

    pub const fn new() -> Self {
        GdtBuilder {
            entries: [Descriptor::NULL; Self::CAPACITY],
            len: 1, // slot 0 is the mandatory null descriptor
        }
    }

    fn push(&mut self, d: Descriptor) -> Result<SegmentSelector, GdtError> {
        if self.len >= Self::CAPACITY {
            return Err(GdtError::TableFull);
        }
        let index = self.len;
        self.entries[index] = d;
        self.len += 1;
        Ok(SegmentSelector::new(index as u16, 0))
    }

    /// Build the standard layout.
    ///
    /// The order is not stylistic. `user_data` must precede `user_code` — see
    /// the SYSRET note at the top of this file.
    pub fn build(tss_base: VirtAddr) -> Result<(Self, GdtLayout), GdtError> {
        Self::build_with_tss_limit(tss_base, core::mem::size_of::<Tss>() as u32 - 1)
    }

    /// Build the standard layout, with a TSS longer than the structure itself.
    ///
    /// The limit is a parameter because the I/O permission bitmap lives past the
    /// end of the `Tss` struct and is part of the same segment. A limit that
    /// stops at the struct leaves `iomap_base` pointing outside the segment,
    /// which the CPU reads as "no bitmap" and denies every port — so a grant
    /// would be written and silently do nothing.
    pub fn build_with_tss_limit(
        tss_base: VirtAddr,
        tss_limit: u32,
    ) -> Result<(Self, GdtLayout), GdtError> {
        let mut b = GdtBuilder::new();

        let kernel_code = b.push(Descriptor::kernel_code())?;
        let kernel_data = b.push(Descriptor::kernel_data())?;

        // SYSRET computes user selectors from this point.
        let sysret_base = (b.len as u16) * 8 - 8;

        let user_data = b.push(Descriptor::user_data())?;
        let user_code = b.push(Descriptor::user_code())?;

        let (tss_low, tss_high) = Descriptor::tss(tss_base, tss_limit);
        let tss = b.push(tss_low)?;
        b.push(tss_high)?;

        let layout = GdtLayout {
            kernel_code,
            kernel_data,
            // Ring 3 selectors carry RPL 3; loading a DPL-3 descriptor with
            // RPL 0 raises #GP.
            user_data: SegmentSelector::new(user_data.index(), 3),
            user_code: SegmentSelector::new(user_code.index(), 3),
            tss,
            sysret_base,
        };

        layout.validate()?;
        Ok((b, layout))
    }

    pub fn entries(&self) -> &[Descriptor] {
        &self.entries[..self.len]
    }

    /// Value for the GDTR limit field: table size in bytes, minus one.
    pub fn limit(&self) -> u16 {
        (self.len * 8 - 1) as u16
    }
}

impl Default for GdtBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tss_base() -> VirtAddr {
        VirtAddr::from_indices_sign_extended(
            0xFFFF_8000_0012_3456,
            super::super::addr::PagingMode::Level4,
        )
    }

    #[test]
    fn long_mode_code_cannot_also_be_32_bit() {
        // Architecturally reserved. A CPU encountering it faults, and the fault
        // points at the far jump rather than at the descriptor.
        assert_eq!(
            Descriptor::segment(
                access::PRESENT | access::USER_SEGMENT | access::EXECUTABLE,
                flags::LONG_MODE | flags::DB_32BIT,
            ),
            Err(GdtError::LongModeWith32BitDefault)
        );
    }

    #[test]
    fn kernel_code_is_long_mode_ring_zero() {
        let d = Descriptor::kernel_code();
        assert!(d.is_present());
        assert!(d.is_long_mode_code());
        assert_eq!(d.dpl(), 0);
    }

    #[test]
    fn user_code_is_long_mode_ring_three() {
        let d = Descriptor::user_code();
        assert!(d.is_present());
        assert!(d.is_long_mode_code());
        assert_eq!(d.dpl(), 3);
    }

    #[test]
    fn data_descriptors_are_not_long_mode_code() {
        // The L bit is meaningless on data descriptors; asserting this keeps a
        // copy-paste of the code descriptor from silently becoming a data one.
        assert!(!Descriptor::kernel_data().is_long_mode_code());
        assert!(!Descriptor::user_data().is_long_mode_code());
        assert_eq!(Descriptor::user_data().dpl(), 3);
        assert_eq!(Descriptor::kernel_data().dpl(), 0);
    }

    #[test]
    fn sysret_ordering_is_enforced() {
        let (_, layout) = GdtBuilder::build(tss_base()).unwrap();
        layout.validate().unwrap();

        assert_eq!(layout.user_data.offset(), layout.sysret_base + 8);
        assert_eq!(layout.user_code.offset(), layout.sysret_base + 16);
    }

    #[test]
    fn swapped_user_selectors_are_rejected() {
        // The intuitive ordering — code before data, matching the kernel
        // entries — is exactly what SYSRET cannot use.
        let (_, good) = GdtBuilder::build(tss_base()).unwrap();
        let swapped = GdtLayout {
            user_data: good.user_code,
            user_code: good.user_data,
            ..good
        };
        assert!(matches!(
            swapped.validate(),
            Err(GdtError::SysretOrdering { .. })
        ));
    }

    #[test]
    fn user_selectors_carry_rpl_three() {
        let (_, layout) = GdtBuilder::build(tss_base()).unwrap();
        assert_eq!(
            layout.user_code.rpl(),
            3,
            "loading DPL3 with RPL0 raises #GP"
        );
        assert_eq!(layout.user_data.rpl(), 3);
        assert_eq!(layout.kernel_code.rpl(), 0);
    }

    #[test]
    fn selector_index_and_rpl_round_trip() {
        for index in 0..8u16 {
            for rpl in 0..4u8 {
                let s = SegmentSelector::new(index, rpl);
                assert_eq!(s.index(), index);
                assert_eq!(s.rpl(), rpl);
                assert_eq!(s.offset(), index * 8);
            }
        }
    }

    #[test]
    fn tss_descriptor_reassembles_the_base_address() {
        // The base is scattered across four fields; this reverses the split and
        // checks nothing was lost, which is the one thing that matters here.
        let base = tss_base();
        let (low, high) = Descriptor::tss(base, 0x67);

        let b0 = (low.0 >> 16) & 0xFF_FFFF; // base[23:0]
        let b1 = (low.0 >> 56) & 0xFF; // base[31:24]
        let b2 = high.0 & 0xFFFF_FFFF; // base[63:32]
        let reassembled = b0 | (b1 << 24) | (b2 << 32);

        assert_eq!(reassembled, base.as_u64(), "TSS base mangled by the split");
    }

    #[test]
    fn tss_descriptor_reassembles_the_limit() {
        let (low, _) = Descriptor::tss(tss_base(), 0x1_2345);
        let l0 = low.0 & 0xFFFF;
        let l1 = (low.0 >> 48) & 0xF;
        assert_eq!(l0 | (l1 << 16), 0x1_2345);
    }

    #[test]
    fn tss_descriptor_is_a_system_descriptor() {
        let (low, _) = Descriptor::tss(tss_base(), 0x67);
        // S bit (bit 44) must be clear for a system descriptor. Setting it
        // would make the CPU read it as a data segment.
        assert_eq!(low.0 & (1 << 44), 0, "S bit set on a TSS descriptor");
        assert!(low.is_present());
    }

    #[test]
    fn a_tss_limit_can_reach_past_the_struct_to_cover_an_io_bitmap() {
        // The bitmap lives after the `Tss` struct and is part of the same
        // segment. A limit that stopped at the struct would leave `iomap_base`
        // pointing outside the segment, which the CPU reads as "no bitmap" and
        // denies every port — so a grant would be written and silently do
        // nothing, which is the failure that looks like a driver bug.
        let extended = core::mem::size_of::<Tss>() as u32 + 128;
        let (low, _) = Descriptor::tss(tss_base(), extended - 1);

        let encoded = (low.0 & 0xFFFF) | ((low.0 >> 32) & 0xF_0000);
        assert_eq!(encoded, u64::from(extended - 1));
        assert!(encoded > core::mem::size_of::<Tss>() as u64);
    }

    #[test]
    fn the_default_build_denies_every_port() {
        // No bitmap means `iomap_base` sits at the segment limit, and the CPU
        // treats a port whose bit is outside the segment as denied. This is
        // what every process that was granted nothing runs with.
        let tss = Tss::new();
        let iomap = tss.iomap_base;
        assert_eq!(u32::from(iomap), core::mem::size_of::<Tss>() as u32);
    }

    #[test]
    fn ist_slots_are_one_based() {
        let mut tss = Tss::new();
        let stack = VirtAddr::from_indices_sign_extended(
            0xFFFF_8000_0000_9000,
            super::super::addr::PagingMode::Level4,
        );

        // IST index 0 means "no IST" in a gate descriptor, so accepting it here
        // would silently give a handler no dedicated stack at all.
        assert_eq!(tss.set_ist(0, stack), Err(GdtError::BadIstIndex(0)));
        assert_eq!(tss.set_ist(8, stack), Err(GdtError::BadIstIndex(8)));

        tss.set_ist(1, stack).unwrap();
        // Copy out before comparing: `Tss` is `packed(4)` because the hardware
        // layout is, so a reference to a u64 field would be unaligned. Reading
        // through the accessor is the supported path and is what callers use.
        let slot0 = tss.interrupt_stack_table[0];
        assert_eq!(slot0, stack.as_u64());
        assert_eq!(tss.ist(1).unwrap(), stack.as_u64());
    }

    #[test]
    fn double_fault_and_nmi_get_distinct_stacks() {
        // Sharing a stack between #DF and NMI reintroduces the triple-fault
        // path: an NMI during double-fault handling would reuse the same stack.
        assert_ne!(ist::DOUBLE_FAULT, ist::NMI);
        assert_ne!(ist::DOUBLE_FAULT, ist::MACHINE_CHECK);
        assert_ne!(ist::NMI, ist::MACHINE_CHECK);
        for slot in [ist::DOUBLE_FAULT, ist::NMI, ist::MACHINE_CHECK, ist::DEBUG] {
            assert!((1..=7).contains(&slot), "IST slot {slot} out of range");
        }
    }

    #[test]
    fn iomap_base_denies_all_port_access() {
        let tss = Tss::new();
        // An iomap_base at or past the TSS limit means no bitmap, which the CPU
        // reads as "every port denied". Pointing it inside the TSS would expose
        // whatever bytes happen to be there as an I/O permission map.
        let base = tss.iomap_base;
        assert!(
            base as usize >= core::mem::size_of::<Tss>(),
            "iomap_base {base} points inside the TSS"
        );
    }

    #[test]
    fn gdt_limit_is_size_minus_one() {
        let (gdt, _) = GdtBuilder::build(tss_base()).unwrap();
        assert_eq!(gdt.limit() as usize, gdt.entries().len() * 8 - 1);
    }

    #[test]
    fn slot_zero_is_the_null_descriptor() {
        let (gdt, _) = GdtBuilder::build(tss_base()).unwrap();
        assert_eq!(gdt.entries()[0], Descriptor::NULL);
        assert!(!gdt.entries()[0].is_present());
    }

    #[test]
    fn tss_occupies_two_consecutive_slots() {
        let (gdt, layout) = GdtBuilder::build(tss_base()).unwrap();
        let idx = layout.tss.index() as usize;
        assert_eq!(gdt.entries().len(), idx + 2, "TSS high half missing");
    }
}
