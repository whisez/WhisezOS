//! The Local APIC and its timer — the scheduler's clock.
//!
//! # x2APIC, not memory-mapped xAPIC
//!
//! The older interface is a 4 KiB MMIO window at 0xFEE0_0000. Using it means
//! that page has to be mapped strongly uncacheable, and the kernel's identity
//! map covers the first 4 GiB in 2 MiB pages — so honouring that would mean
//! splitting a large page into 512 small ones to change the cache type of one
//! of them. Writing APIC registers through a write-back cacheable mapping is
//! not a shortcut: reads can be satisfied from cache and writes can be
//! reordered or combined, which for a device whose registers have side effects
//! on write is undefined in practice as well as on paper.
//!
//! x2APIC exposes the same registers as MSRs. No mapping, no cache type, no
//! ordering question — `wrmsr` is serialising with respect to the APIC. It is
//! present on every 64-bit CPU worth supporting and on QEMU's default model.
//!
//! Where it is genuinely absent, this reports so and the system runs without a
//! timer. That means no preemption, which is a real degradation and is stated
//! as one rather than papered over.
//!
//! # Calibrating against the PIT
//!
//! The LAPIC timer counts at some rate derived from the bus clock, and nothing
//! tells you what that rate is. So it is measured: run the PIT, a channel of
//! the 8254 whose input clock is fixed at 1.193182 MHz by thirty years of
//! compatibility, for a known interval and see how far the APIC timer got.
//! Channel 2 is used because it is the one not wired to an interrupt controller
//! — gating it on and off is a local operation that cannot deliver an IRQ to a
//! system that is not ready for one.
//!
//! What comes out is the counting rate at the divisor that is configured, and
//! that is deliberately as far as the inference goes. Multiplying by the
//! divisor to name a bus frequency would be asserting that the hardware applied
//! it, which QEMU does not appear to in this mode. The period is correct either
//! way, because calibration and operation run at the same setting and the error
//! cancels — but only if nothing in between pretends to know more than was
//! measured.

use super::cpu::{self, inb, outb};
use super::idt::vector;
use crate::kprintln;

/// `IA32_APIC_BASE`.
const MSR_APIC_BASE: u32 = 0x1B;
/// Bit 10: x2APIC mode. Bit 11: the APIC is enabled at all.
const APIC_BASE_X2APIC: u64 = 1 << 10;
const APIC_BASE_ENABLE: u64 = 1 << 11;

/// x2APIC MSRs. The xAPIC register offset divided by 16, plus 0x800.
const MSR_X2APIC_APICID: u32 = 0x802;
const MSR_X2APIC_EOI: u32 = 0x80B;
const MSR_X2APIC_SIVR: u32 = 0x80F;
const MSR_X2APIC_LVT_TIMER: u32 = 0x832;
const MSR_X2APIC_LVT_LINT0: u32 = 0x835;
const MSR_X2APIC_LVT_LINT1: u32 = 0x836;
const MSR_X2APIC_TIMER_ICR: u32 = 0x838;
const MSR_X2APIC_TIMER_CCR: u32 = 0x839;
const MSR_X2APIC_TIMER_DCR: u32 = 0x83E;

/// Spurious Interrupt Vector Register bit 8: software enable.
const SIVR_ENABLE: u32 = 1 << 8;
/// LVT bit 16: masked.
const LVT_MASKED: u32 = 1 << 16;
/// LVT timer bit 17: periodic mode.
const LVT_TIMER_PERIODIC: u32 = 1 << 17;
/// Divide configuration for divide-by-16. The encoding is not sequential: bit 2
/// is skipped, so 0b1011 is 16 and 0b0011 would be 8.
const DCR_DIVIDE_BY_16: u32 = 0b1011;

/// PIT channel 2, and the port that gates it.
const PIT_CHANNEL2_DATA: u16 = 0x42;
const PIT_COMMAND: u16 = 0x43;
const PIT_GATE_PORT: u16 = 0x61;
/// The 8254's input clock, fixed by compatibility.
const PIT_HZ: u32 = 1_193_182;

/// How often the timer fires. 100 Hz — a 10 ms slice.
///
/// Fast enough that preemption is visible in a boot that lasts a second, slow
/// enough that the cost of taking the interrupt is irrelevant. It becomes a
/// tickless deadline once there is a scheduler with something to say about when
/// it next needs to run.
pub const TIMER_HZ: u32 = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApicError {
    /// No local APIC at all.
    NotPresent,
    /// The CPU has no x2APIC, and the memory-mapped fallback is not implemented.
    NoX2Apic,
    /// Calibration measured no ticks: the PIT did not run, or the APIC timer
    /// did not count.
    CalibrationFailed,
}

/// What `init` measured, for reporting.
#[derive(Debug, Clone, Copy)]
pub struct TimerInfo {
    pub apic_id: u32,
    /// The counter value programmed for one period.
    pub initial_count: u32,
    /// How fast the counter was observed to run, in ticks per second, at the
    /// divisor configured below.
    ///
    /// Not a bus frequency. Deriving one would mean multiplying by the divisor
    /// and asserting that the hardware applied it — which QEMU, at least, does
    /// not appear to in x2APIC mode. That error cancels out for the period,
    /// because calibration and operation run at the same setting, but it does
    /// not cancel out for a number printed on the console. So the measurement
    /// is reported and the inference is not.
    pub ticks_per_second: u64,
}

/// Brings up the local APIC and starts the periodic timer.
///
/// # Safety
/// Called once, on the bootstrap processor, with interrupts disabled, after the
/// IDT is installed and the legacy PICs are masked.
pub unsafe fn init() -> Result<TimerInfo, ApicError> {
    let features = cpu::cpuid(1);
    // CPUID.1:EDX bit 9 — a local APIC exists. Bit 21 of ECX — it can be put
    // into x2APIC mode.
    if features.edx & (1 << 9) == 0 {
        return Err(ApicError::NotPresent);
    }
    if features.ecx & (1 << 21) == 0 {
        return Err(ApicError::NoX2Apic);
    }

    // SAFETY: architecturally defined MSRs. Setting both bits of APIC_BASE
    // enables the APIC and puts it in x2APIC mode; the transition is one-way
    // per the SDM, which is fine because nothing wants it back.
    let apic_id = unsafe {
        let base = cpu::read_msr(MSR_APIC_BASE);
        cpu::write_msr(MSR_APIC_BASE, base | APIC_BASE_ENABLE | APIC_BASE_X2APIC);

        // The spurious vector register's enable bit is what actually turns the
        // APIC on. Until it is set, every LVT entry is ignored.
        cpu::write_msr(
            MSR_X2APIC_SIVR,
            u64::from(SIVR_ENABLE | u32::from(vector::SPURIOUS)),
        );

        // LINT0 and LINT1 are the legacy 8259 and NMI pins. The firmware may
        // have left them delivering; masking them means the only thing that can
        // arrive is what this kernel asked for.
        cpu::write_msr(MSR_X2APIC_LVT_LINT0, u64::from(LVT_MASKED));
        cpu::write_msr(MSR_X2APIC_LVT_LINT1, u64::from(LVT_MASKED));

        cpu::read_msr(MSR_X2APIC_APICID) as u32
    };

    // SAFETY: the APIC is enabled and its timer is masked, so calibration can
    // run the counter without anything being delivered.
    let ticks_per_second = unsafe { calibrate()? };
    let initial_count = (ticks_per_second / u64::from(TIMER_HZ)) as u32;
    if initial_count == 0 {
        return Err(ApicError::CalibrationFailed);
    }

    // SAFETY: as above. The mode and vector are written before the count,
    // because writing the initial count is what starts the timer.
    unsafe {
        cpu::write_msr(MSR_X2APIC_TIMER_DCR, u64::from(DCR_DIVIDE_BY_16));
        cpu::write_msr(
            MSR_X2APIC_LVT_TIMER,
            u64::from(LVT_TIMER_PERIODIC | u32::from(vector::LAPIC_TIMER)),
        );
        cpu::write_msr(MSR_X2APIC_TIMER_ICR, u64::from(initial_count));
    }

    Ok(TimerInfo {
        apic_id,
        initial_count,
        ticks_per_second,
    })
}

/// Measures how fast the APIC timer counts, in ticks per second.
///
/// # Safety
/// The APIC must be enabled and its timer LVT masked.
unsafe fn calibrate() -> Result<u64, ApicError> {
    // 50 ms. Long enough that the one-tick granularity of the PIT read is
    // noise, short enough not to be noticeable in a boot.
    const MILLIS: u32 = 50;
    let pit_ticks = PIT_HZ / 1000 * MILLIS;

    // SAFETY: the PIT and the port-0x61 gate are architectural, and channel 2
    // is the one channel not connected to an interrupt controller.
    unsafe {
        // Gate channel 2 off, and disconnect its output from the speaker so
        // calibration is silent.
        let gate = inb(PIT_GATE_PORT) & 0xFC;
        outb(PIT_GATE_PORT, gate);

        // Channel 2, access lo/hi, mode 0 (interrupt on terminal count), binary.
        outb(PIT_COMMAND, 0b1011_0000);
        outb(PIT_CHANNEL2_DATA, (pit_ticks & 0xFF) as u8);
        outb(PIT_CHANNEL2_DATA, (pit_ticks >> 8) as u8);

        // Start the APIC timer counting down from the maximum, then gate the
        // PIT on. The order matters only in that both must be running before
        // either is read.
        cpu::write_msr(MSR_X2APIC_TIMER_DCR, u64::from(DCR_DIVIDE_BY_16));
        cpu::write_msr(MSR_X2APIC_LVT_TIMER, u64::from(LVT_MASKED));
        cpu::write_msr(MSR_X2APIC_TIMER_ICR, u64::from(u32::MAX));

        outb(PIT_GATE_PORT, gate | 1);

        // Bit 5 of port 0x61 mirrors channel 2's output, which goes high when
        // the count reaches zero.
        let mut guard = 0u64;
        while inb(PIT_GATE_PORT) & 0x20 == 0 {
            guard += 1;
            // A PIT that never fires would otherwise hang the boot here with no
            // message. 50 ms is a few hundred million spins at worst.
            if guard > 2_000_000_000 {
                return Err(ApicError::CalibrationFailed);
            }
        }

        let remaining = cpu::read_msr(MSR_X2APIC_TIMER_CCR) as u32;
        cpu::write_msr(MSR_X2APIC_TIMER_ICR, 0);
        outb(PIT_GATE_PORT, gate);

        let elapsed = u64::from(u32::MAX - remaining);
        if elapsed == 0 {
            return Err(ApicError::CalibrationFailed);
        }
        // Ticks in 50 ms, scaled to a second. Whatever the divisor actually
        // does is already folded into this, which is exactly why the period is
        // computed from it directly.
        Ok(elapsed * 1000 / u64::from(MILLIS))
    }
}

/// Acknowledges the interrupt currently being serviced.
///
/// Every handler must call this exactly once before returning. Miss it and the
/// APIC never delivers another interrupt of equal or lower priority — the
/// system does not crash, it simply stops being preempted, which is a great
/// deal harder to notice.
pub fn end_of_interrupt() {
    // SAFETY: writing zero to the EOI MSR is the architectural acknowledgement
    // and has no other effect.
    unsafe { cpu::write_msr(MSR_X2APIC_EOI, 0) };
}

pub fn report(info: &TimerInfo) {
    kprintln!(
        "[kernel] lapic id={} timer {} Hz (count {}, measured {} kticks/s)",
        info.apic_id,
        TIMER_HZ,
        info.initial_count,
        info.ticks_per_second / 1000
    );
}
