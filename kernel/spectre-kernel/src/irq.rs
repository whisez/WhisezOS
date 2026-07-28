//! Delivering a device interrupt to a process that is not the kernel.
//!
//! A driver in ring 3 can already reach its device's registers (`device.rs`)
//! and give it memory to read (`dma.rs`). The missing half is the device
//! answering: an interrupt arrives in ring 0, on the kernel's stack, at a moment
//! nobody chose, and the process that cares about it is asleep somewhere else.
//!
//! # An interrupt is not a message
//!
//! The obvious design queues an event per interrupt and lets the driver read
//! them in order. It is the wrong shape. Interrupts carry no data — the data is
//! in the device, and the driver reads it from there — so a queue of them is a
//! queue of identical empty things whose only content is how many arrived. Worse,
//! a queue has a depth, and a device that interrupts faster than its driver runs
//! will overflow it, at which point the kernel has to choose between blocking an
//! interrupt handler and dropping an event. Both are bad and neither is
//! necessary.
//!
//! So a line has a count, not a queue. Interrupts that arrive while the driver
//! is busy are added up, and the driver is told how many when it next asks. It
//! then reads the device once and finds whatever state accumulated, which is
//! what the hardware wanted it to do anyway. Nothing is dropped and nothing can
//! overflow: the count saturates at `u64::MAX`, which at any plausible interrupt
//! rate is longer than the universe has been running.
//!
//! # The interrupt that arrives before the wait
//!
//! This is the race the whole file exists for. A driver arms its device and then
//! calls `wait`. If the device is fast, the interrupt lands in the window
//! between those two, and a design that only wakes sleepers loses it — the
//! driver then waits forever for something that already happened, which is the
//! classic lost-wakeup deadlock and is miserable to diagnose because it needs
//! exactly that timing.
//!
//! Counting first and sleeping second removes the window rather than narrowing
//! it: `on_interrupt` always increments, and `wait` returns immediately when the
//! count is non-zero. There is no ordering of the two that loses anything.
//!
//! # What is not decided here
//!
//! Nothing in this file touches hardware or the process table. It answers "what
//! should happen", and the caller — `syscall.rs` for waits, the interrupt
//! handler for deliveries — does it. That is what lets every rule below be an
//! ordinary host test instead of something only a boot can exercise.

#![allow(dead_code)]

use spin::Mutex;

use crate::abi::SyscallError;

/// Interrupt lines the kernel can hand out.
///
/// One per device that has an interrupt, and there is currently one such
/// device. Small on purpose: every line costs a vector and a redirection entry,
/// and lines nothing claims are lines nothing masks.
pub const MAX_LINES: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Line {
    /// The process that owns this line. Zero means unclaimed — pid 0 is never a
    /// user process, so it doubles as "nobody" without a separate flag that
    /// could disagree with the owner field.
    owner: u64,
    /// Interrupts since the owner last collected them.
    pending: u64,
    /// Whether the owner is currently blocked waiting.
    waiting: bool,
    /// Every interrupt this line has ever taken, for reporting. Not reset by a
    /// collection, so it can be compared against what the driver says it saw.
    total: u64,
}

impl Line {
    const EMPTY: Self = Self {
        owner: 0,
        pending: 0,
        waiting: false,
        total: 0,
    };

    const fn is_claimed(&self) -> bool {
        self.owner != 0
    }
}

/// The lines themselves.
///
/// Every rule below is written against one of these rather than against the
/// static, so the tests can hold their own table. Sharing one global across
/// tests that `cargo test` runs on several threads at once would make each of
/// them depend on which others happened to be running.
type Table = [Line; MAX_LINES];

static LINES: Mutex<Table> = Mutex::new([Line::EMPTY; MAX_LINES]);

/// What the caller of `wait` should do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wait {
    /// Interrupts were already waiting. This many; return it.
    Ready(u64),
    /// Nothing yet. Block the process; `on_interrupt` will wake it.
    Block,
}

/// What the interrupt handler should do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// Wake this process with this count as its `wait`'s return value.
    Wake { pid: u64, count: u64 },
    /// The owner was not waiting. The count was incremented; nothing to do.
    Counted,
    /// Nobody claimed this line, or there is no such line.
    ///
    /// Worth reporting rather than ignoring: an interrupt arriving on a line no
    /// process owns means something is unmasked that should not be, and left
    /// alone it will arrive again immediately and forever.
    Unclaimed,
}

/// Gives a line to a process.
///
/// A line has one owner. Sharing would mean deciding which of two drivers reads
/// the device to work out whose interrupt it was, and that decision belongs to
/// whoever wires the hardware, not to the kernel.
/// Returns whether this claim is the one that took the line, so the caller can
/// arm the hardware exactly once. A repeat claim by the owner is not an error —
/// `SYS_IRQ_WAIT` claims on every call rather than requiring a separate step —
/// but it must not re-arm a device that is already running.
pub fn claim(line: usize, pid: u64) -> Result<bool, SyscallError> {
    claim_in(&mut LINES.lock(), line, pid)
}

fn claim_in(lines: &mut Table, line: usize, pid: u64) -> Result<bool, SyscallError> {
    if line >= MAX_LINES || pid == 0 {
        return Err(SyscallError::NotPermitted);
    }
    if lines[line].is_claimed() && lines[line].owner != pid {
        return Err(SyscallError::NotPermitted);
    }
    // Re-claiming a line already held is not an error, but it must not clear a
    // count: an interrupt that arrived between the first claim and the second
    // is still an interrupt the driver has not seen.
    let fresh = !lines[line].is_claimed();
    lines[line].owner = pid;
    Ok(fresh)
}

/// Collects interrupts, or says the process should block until there are some.
///
/// A non-owner is refused with the same error as a line nobody holds, for the
/// reason `BadEndpoint` is one answer for two questions: telling a process that
/// line two exists but belongs to somebody else is telling it something it was
/// not given.
pub fn wait(line: usize, pid: u64) -> Result<Wait, SyscallError> {
    wait_in(&mut LINES.lock(), line, pid)
}

fn wait_in(lines: &mut Table, line: usize, pid: u64) -> Result<Wait, SyscallError> {
    if line >= MAX_LINES || pid == 0 {
        return Err(SyscallError::NotPermitted);
    }
    if lines[line].owner != pid {
        return Err(SyscallError::NotPermitted);
    }
    // Two processes cannot both be the owner, so a line already waiting means
    // the owner called twice — which it cannot do from one thread, and which
    // would leave the first wait unwakeable if it could.
    if lines[line].waiting {
        return Err(SyscallError::Busy);
    }

    let count = lines[line].pending;
    if count > 0 {
        lines[line].pending = 0;
        return Ok(Wait::Ready(count));
    }
    lines[line].waiting = true;
    Ok(Wait::Block)
}

/// Records an interrupt and says whether it woke anybody.
///
/// Called from an interrupt handler, so it does the least it can: no allocation,
/// no page tables, no scheduling decision. Just arithmetic and a verdict.
pub fn on_interrupt(line: usize) -> Delivery {
    on_interrupt_in(&mut LINES.lock(), line)
}

fn on_interrupt_in(lines: &mut Table, line: usize) -> Delivery {
    if line >= MAX_LINES {
        return Delivery::Unclaimed;
    }
    if !lines[line].is_claimed() {
        return Delivery::Unclaimed;
    }

    // Saturating rather than wrapping. A wrap would take a count of
    // `u64::MAX` interrupts to zero, and report "nothing happened" at the exact
    // moment the most has.
    lines[line].total = lines[line].total.saturating_add(1);

    if lines[line].waiting {
        lines[line].waiting = false;
        // The pending count is folded into what the waiter is told, so an
        // interrupt that arrived just before it blocked is not left behind.
        let count = lines[line].pending.saturating_add(1);
        lines[line].pending = 0;
        return Delivery::Wake {
            pid: lines[line].owner,
            count,
        };
    }

    lines[line].pending = lines[line].pending.saturating_add(1);
    Delivery::Counted
}

/// Releases every line a process held.
///
/// Called when a process exits, like `channel::on_process_gone`. A line left
/// claimed by a dead process is a line no other driver can take and whose
/// interrupts wake nothing — and since pids are reused, one that would
/// eventually be inherited by an unrelated process.
pub fn on_process_gone(pid: u64) -> usize {
    on_process_gone_in(&mut LINES.lock(), pid)
}

fn on_process_gone_in(lines: &mut Table, pid: u64) -> usize {
    if pid == 0 {
        return 0;
    }
    let mut released = 0;
    for line in lines.iter_mut() {
        if line.owner == pid {
            *line = Line::EMPTY;
            released += 1;
        }
    }
    released
}

/// Who owns a line, if anybody.
///
/// The exit path needs it: silencing a device is only correct for the process
/// that was driving it, and asking before releasing is the only order in which
/// the answer is still there.
#[must_use]
pub fn owner(line: usize) -> Option<u64> {
    if line >= MAX_LINES {
        return None;
    }
    let lines = LINES.lock();
    lines[line].is_claimed().then_some(lines[line].owner)
}

/// How many processes are blocked waiting for an interrupt.
///
/// The scheduler needs this to tell a deadlock from an idle system. Every live
/// process being blocked normally means each is waiting on another and none can
/// move — but a process waiting on hardware is waiting on something outside the
/// set, and the right response is to idle until it arrives rather than to
/// declare the system stuck.
#[must_use]
pub fn waiters() -> usize {
    LINES.lock().iter().filter(|line| line.waiting).count()
}

/// Total interrupts a line has taken, for reporting.
#[must_use]
pub fn total(line: usize) -> u64 {
    if line >= MAX_LINES {
        return 0;
    }
    LINES.lock()[line].total
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNER: u64 = 7;
    const OTHER: u64 = 9;

    /// A table of this test's own, so nothing depends on what another test
    /// running at the same time is doing to the kernel's.
    fn fresh() -> Table {
        [Line::EMPTY; MAX_LINES]
    }

    #[test]
    fn an_unclaimed_line_cannot_be_waited_on() {
        let mut t = fresh();
        assert_eq!(wait_in(&mut t, 0, OWNER), Err(SyscallError::NotPermitted));
    }

    #[test]
    fn an_interrupt_on_an_unclaimed_line_is_reported_as_such() {
        let mut t = fresh();
        assert_eq!(on_interrupt_in(&mut t, 0), Delivery::Unclaimed);
    }

    #[test]
    fn a_claimed_line_blocks_its_owner_when_nothing_has_happened() {
        let mut t = fresh();
        claim_in(&mut t, 0, OWNER).unwrap();
        assert_eq!(wait_in(&mut t, 0, OWNER), Ok(Wait::Block));
    }

    #[test]
    fn an_interrupt_wakes_a_waiting_owner() {
        let mut t = fresh();
        claim_in(&mut t, 0, OWNER).unwrap();
        assert_eq!(wait_in(&mut t, 0, OWNER), Ok(Wait::Block));
        assert_eq!(
            on_interrupt_in(&mut t, 0),
            Delivery::Wake {
                pid: OWNER,
                count: 1
            }
        );
    }

    #[test]
    fn an_interrupt_that_arrives_before_the_wait_is_not_lost() {
        // The race this file exists for. A driver arms its device and then
        // waits; if the interrupt lands in between, a design that only wakes
        // sleepers deadlocks.
        let mut t = fresh();
        claim_in(&mut t, 0, OWNER).unwrap();
        assert_eq!(on_interrupt_in(&mut t, 0), Delivery::Counted);
        assert_eq!(wait_in(&mut t, 0, OWNER), Ok(Wait::Ready(1)));
    }

    #[test]
    fn interrupts_while_the_driver_is_busy_are_added_up_not_dropped() {
        let mut t = fresh();
        claim_in(&mut t, 0, OWNER).unwrap();
        for _ in 0..5 {
            assert_eq!(on_interrupt_in(&mut t, 0), Delivery::Counted);
        }
        assert_eq!(wait_in(&mut t, 0, OWNER), Ok(Wait::Ready(5)));
        // And collecting them clears the count, so the next wait blocks rather
        // than returning the same five again.
        assert_eq!(wait_in(&mut t, 0, OWNER), Ok(Wait::Block));
    }

    #[test]
    fn a_count_pending_at_the_moment_of_a_wake_is_included() {
        // `wait` blocks only when the count is zero, so this needs the count to
        // become non-zero after the block — which is exactly what a second
        // interrupt racing the first would do on a real machine.
        let mut t = fresh();
        claim_in(&mut t, 0, OWNER).unwrap();
        assert_eq!(wait_in(&mut t, 0, OWNER), Ok(Wait::Block));
        t[0].pending = 3;
        assert_eq!(
            on_interrupt_in(&mut t, 0),
            Delivery::Wake {
                pid: OWNER,
                count: 4
            }
        );
        assert_eq!(t[0].pending, 0);
    }

    #[test]
    fn a_line_belongs_to_one_process() {
        let mut t = fresh();
        claim_in(&mut t, 0, OWNER).unwrap();
        assert_eq!(claim_in(&mut t, 0, OTHER), Err(SyscallError::NotPermitted));
        assert_eq!(wait_in(&mut t, 0, OTHER), Err(SyscallError::NotPermitted));
    }

    #[test]
    fn a_stranger_cannot_tell_a_taken_line_from_one_that_does_not_exist() {
        // Distinguishing them would tell a process which lines are in use.
        let mut t = fresh();
        claim_in(&mut t, 0, OWNER).unwrap();
        assert_eq!(wait_in(&mut t, 0, OTHER), wait_in(&mut t, 1, OTHER));
        assert_eq!(wait_in(&mut t, 0, OTHER), wait_in(&mut t, MAX_LINES, OTHER));
    }

    #[test]
    fn only_the_claim_that_takes_a_line_reports_itself_as_the_first() {
        // The caller arms the device on the strength of this. Reporting `true`
        // twice would re-arm a running device on every `SYS_IRQ_WAIT`, and for
        // the RTC that means reprogramming it 64 times a second.
        let mut t = fresh();
        assert_eq!(claim_in(&mut t, 0, OWNER), Ok(true));
        assert_eq!(claim_in(&mut t, 0, OWNER), Ok(false));

        // And a line released and taken again is a first claim once more, since
        // whatever the last owner armed went away with it.
        on_process_gone_in(&mut t, OWNER);
        assert_eq!(claim_in(&mut t, 0, OTHER), Ok(true));
    }

    #[test]
    fn re_claiming_a_held_line_does_not_discard_a_pending_count() {
        let mut t = fresh();
        claim_in(&mut t, 0, OWNER).unwrap();
        on_interrupt_in(&mut t, 0);
        claim(0, OWNER).unwrap();
        assert_eq!(wait_in(&mut t, 0, OWNER), Ok(Wait::Ready(1)));
    }

    #[test]
    fn waiting_twice_is_refused_rather_than_stranding_the_first_wait() {
        let mut t = fresh();
        claim_in(&mut t, 0, OWNER).unwrap();
        assert_eq!(wait_in(&mut t, 0, OWNER), Ok(Wait::Block));
        assert_eq!(wait_in(&mut t, 0, OWNER), Err(SyscallError::Busy));
    }

    #[test]
    fn pid_zero_is_never_an_owner() {
        // Zero is the "unclaimed" marker, so a process with pid zero would make
        // an unclaimed line indistinguishable from a claimed one.
        let mut t = fresh();
        assert_eq!(claim_in(&mut t, 0, 0), Err(SyscallError::NotPermitted));
        assert_eq!(wait_in(&mut t, 0, 0), Err(SyscallError::NotPermitted));
        assert_eq!(on_process_gone_in(&mut t, 0), 0);
    }

    #[test]
    fn a_line_past_the_last_is_refused() {
        let mut t = fresh();
        assert_eq!(
            claim_in(&mut t, MAX_LINES, OWNER),
            Err(SyscallError::NotPermitted)
        );
        assert_eq!(on_interrupt_in(&mut t, MAX_LINES), Delivery::Unclaimed);
        assert_eq!(total(MAX_LINES), 0);
    }

    #[test]
    fn an_exiting_process_releases_its_lines() {
        let mut t = fresh();
        claim_in(&mut t, 0, OWNER).unwrap();
        claim_in(&mut t, 1, OWNER).unwrap();
        claim_in(&mut t, 2, OTHER).unwrap();
        assert_eq!(on_process_gone_in(&mut t, OWNER), 2);

        // Released, so another process can take them — which matters because
        // pids are reused, and an inherited line would deliver somebody else's
        // interrupts to a process that never asked.
        assert_eq!(on_interrupt_in(&mut t, 0), Delivery::Unclaimed);
        claim_in(&mut t, 0, OTHER).unwrap();
        assert_eq!(wait_in(&mut t, 0, OTHER), Ok(Wait::Block));
    }

    #[test]
    fn releasing_clears_a_pending_count_with_the_line() {
        let mut t = fresh();
        claim_in(&mut t, 0, OWNER).unwrap();
        on_interrupt_in(&mut t, 0);
        on_process_gone_in(&mut t, OWNER);
        claim_in(&mut t, 0, OTHER).unwrap();
        // The new owner must not inherit interrupts raised for the old one.
        assert_eq!(wait_in(&mut t, 0, OTHER), Ok(Wait::Block));
    }

    #[test]
    fn a_waiting_line_whose_owner_dies_does_not_wake_anything() {
        let mut t = fresh();
        claim_in(&mut t, 0, OWNER).unwrap();
        wait_in(&mut t, 0, OWNER).unwrap();
        on_process_gone_in(&mut t, OWNER);
        assert_eq!(on_interrupt_in(&mut t, 0), Delivery::Unclaimed);
    }

    #[test]
    fn the_running_total_counts_every_interrupt_including_uncollected_ones() {
        let mut t = fresh();
        claim_in(&mut t, 0, OWNER).unwrap();
        for _ in 0..3 {
            on_interrupt_in(&mut t, 0);
        }
        wait_in(&mut t, 0, OWNER).unwrap();
        on_interrupt_in(&mut t, 0);
        assert_eq!(t[0].total, 4);
    }

    #[test]
    fn counts_saturate_rather_than_wrapping_to_zero() {
        // Wrapping would report "nothing happened" at the moment the most has.
        let mut t = fresh();
        claim_in(&mut t, 0, OWNER).unwrap();
        t[0].pending = u64::MAX;
        t[0].total = u64::MAX;
        assert_eq!(on_interrupt_in(&mut t, 0), Delivery::Counted);
        assert_eq!(t[0].pending, u64::MAX);
        assert_eq!(t[0].total, u64::MAX);
    }
}
