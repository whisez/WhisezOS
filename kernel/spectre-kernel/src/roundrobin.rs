//! The scheduling policy, separated from everything that makes it happen.
//!
//! Choosing the next process is three lines and one easy mistake, and the
//! mistake is invisible in a boot log: search from slot zero instead of from
//! after the current slot and the rotation still *works*, in the sense that
//! processes run and finish. What it stops doing is rotating — the lowest-
//! numbered runnable process is found first every time, so it gets every slice
//! until it exits and everything behind it starves.
//!
//! Two processes cannot show the difference. Three can, and a host test can
//! have as many as it likes, which is why this is a free function over a slice
//! of states rather than a few lines inside the timer handler.

#![allow(dead_code)]

/// What a process-table slot holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    /// Unused.
    Empty,
    /// Runnable, not currently on a processor.
    Ready,
    Running,
    /// Waiting on IPC. Not runnable, and not gone either — only another process
    /// can make it ready again, which is why a table with nothing `Ready` and
    /// something `Blocked` is a deadlock rather than an idle system.
    Blocked,
    /// Finished, waiting to be reaped.
    Exited,
}

impl Slot {
    #[must_use]
    pub const fn is_schedulable(self) -> bool {
        matches!(self, Self::Ready | Self::Running)
    }

    /// Still alive, whether or not it can run right now.
    #[must_use]
    pub const fn is_live(self) -> bool {
        matches!(self, Self::Ready | Self::Running | Self::Blocked)
    }
}

/// The next slot to run after `current`, or `None` if nothing is runnable.
///
/// Searching starts at `current + 1` and wraps, so a process that has just run
/// is the *last* candidate rather than the first. That is the whole of the
/// fairness guarantee: every runnable slot is reached within one full turn of
/// the table, regardless of which one is running now.
///
/// `current` may be out of range — a table that has never been scheduled has no
/// meaningful current slot — and is taken modulo the length rather than
/// refused, because there is always an answer.
#[must_use]
pub fn next_ready(slots: &[Slot], current: usize) -> Option<usize> {
    if slots.is_empty() {
        return None;
    }
    let current = current % slots.len();
    (1..=slots.len())
        .map(|step| (current + step) % slots.len())
        .find(|&candidate| slots[candidate] == Slot::Ready)
}

/// How many slots could be scheduled: ready or already running.
#[must_use]
pub fn schedulable(slots: &[Slot]) -> usize {
    slots.iter().filter(|s| s.is_schedulable()).count()
}

#[cfg(test)]
mod tests {
    use super::Slot::{Blocked, Empty, Exited, Ready, Running};
    use super::*;

    #[test]
    fn the_next_ready_slot_is_after_the_current_one() {
        let slots = [Running, Ready, Ready, Empty];
        assert_eq!(next_ready(&slots, 0), Some(1));
        assert_eq!(next_ready(&slots, 1), Some(2));
    }

    #[test]
    fn the_search_wraps_past_the_end() {
        let slots = [Ready, Empty, Running, Empty];
        assert_eq!(next_ready(&slots, 2), Some(0));
    }

    #[test]
    fn three_processes_rotate_rather_than_alternate() {
        // The failure this exists for. Searching from zero would return slot 0
        // forever and slot 2 would never run, which two processes cannot
        // distinguish from a working rotation.
        let mut slots = [Ready, Ready, Ready];
        let mut current = 0usize;
        let mut order = Vec::new();
        for _ in 0..6 {
            slots[current] = Ready;
            current = next_ready(&slots, current).unwrap();
            slots[current] = Running;
            order.push(current);
        }
        assert_eq!(order, vec![1, 2, 0, 1, 2, 0]);
    }

    #[test]
    fn every_runnable_slot_is_reached_within_one_turn() {
        let slots = [Ready; 4];
        let mut seen = [false; 4];
        let mut current = 3usize;
        for _ in 0..slots.len() {
            current = next_ready(&slots, current).unwrap();
            seen[current] = true;
        }
        assert!(seen.iter().all(|&s| s), "a runnable slot was never chosen");
    }

    #[test]
    fn exited_empty_and_blocked_slots_are_skipped() {
        let slots = [Running, Exited, Blocked, Ready];
        assert_eq!(next_ready(&slots, 0), Some(3));
    }

    #[test]
    fn a_table_with_only_blocked_processes_has_nothing_to_run() {
        // Not the same as an empty table: these processes are alive and waiting
        // on each other, which is a deadlock rather than a finished system.
        let slots = [Blocked, Blocked];
        assert_eq!(next_ready(&slots, 0), None);
        assert_eq!(schedulable(&slots), 0);
        assert!(slots.iter().all(|s| s.is_live()));
    }

    #[test]
    fn liveness_and_schedulability_are_different_questions() {
        assert!(Blocked.is_live() && !Blocked.is_schedulable());
        assert!(!Exited.is_live() && !Exited.is_schedulable());
        assert!(!Empty.is_live());
    }

    #[test]
    fn a_running_slot_is_not_chosen_again_while_marked_running() {
        // The caller marks the outgoing process `Ready` before asking. A slot
        // still marked `Running` is one the caller did not release, and picking
        // it would resume a frame that has not been saved.
        let slots = [Running, Empty, Empty];
        assert_eq!(next_ready(&slots, 0), None);
    }

    #[test]
    fn a_single_ready_process_is_rescheduled() {
        let slots = [Ready, Empty];
        assert_eq!(next_ready(&slots, 0), Some(0));
    }

    #[test]
    fn nothing_runnable_reports_nothing() {
        assert_eq!(next_ready(&[Exited, Exited, Empty], 1), None);
        assert_eq!(next_ready(&[], 0), None);
    }

    #[test]
    fn an_out_of_range_current_slot_still_yields_an_answer() {
        // A table that has never been scheduled has no meaningful current slot.
        let slots = [Ready, Ready];
        assert!(next_ready(&slots, 99).is_some());
    }

    #[test]
    fn schedulable_counts_ready_and_running_only() {
        assert_eq!(schedulable(&[Ready, Running, Exited, Empty]), 2);
        assert_eq!(schedulable(&[Exited, Exited]), 0);
        assert!(Ready.is_schedulable() && Running.is_schedulable());
        assert!(!Exited.is_schedulable() && !Empty.is_schedulable());
    }
}
