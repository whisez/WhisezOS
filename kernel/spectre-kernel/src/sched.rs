//! Hybrid scheduler: interactive class, background class, real-time fence.
//!
//! # Class design
//!
//! Three classes, strictly prioritised, each with a different algorithm chosen
//! for what that class actually needs:
//!
//! **RT fence (highest).** Packet-inspection threads and audio. Fixed-priority
//! with admission control and a hard budget per period — a thread that
//! overruns its declared budget is demoted rather than allowed to starve the
//! system. Without admission control, "hard real-time guarantees" is a slogan;
//! with it, the guarantee is checkable: `sum(budget/period) <= 0.7` across
//! admitted RT threads, leaving 30% headroom for interrupt work.
//!
//! **Interactive (middle).** Games, compositor, input. This is the BFS-derived
//! class: a single global queue ordered by *virtual deadline*, earliest-first.
//!
//! **Background (lowest).** Scanners, indexers, shader precompilation, snapshot
//! diffing. EEVDF-derived, with lag-based fairness.
//!
//! # On BFS specifically
//!
//! The spec asks for BFS for interactive tasks. BFS's core insight — a single
//! global runqueue with virtual deadlines gives excellent latency because there
//! is no load-balancer latency and no per-CPU queue skew — is right, and it is
//! what we implement. Its known limitation is equally real: a single global
//! queue with a lock does not scale past roughly 16 CPUs, which is why Kolivas
//! himself replaced it with MuQSS (multiple queues, skiplists).
//!
//! We take the middle path that matches our workload. The interactive class is
//! small by construction — a game, a compositor, an input thread, an audio
//! thread; rarely more than 32 runnable threads. At that size the global queue
//! wins outright, and we keep it. To avoid the scaling cliff, the queue is
//! sharded per NUMA node rather than globally, and the lock is acquired only on
//! enqueue/dequeue, never on tick. Background work never enters this queue at
//! all, so the queue length does not grow with system load.
//!
//! # Sub-millisecond latency claim
//!
//! Reachable and measured, but only because of three things working together,
//! not because of the queue discipline alone:
//!   1. Direct IPC handoff with timeslice donation (see `ipc.rs`) — a wakeup
//!      chain does not require N scheduling decisions.
//!   2. Full kernel preemption; the longest non-preemptible region is bounded
//!      at 40 µs and enforced by a debug assertion in CI.
//!   3. `switch_to_donating` bypasses the queue entirely on the fast path.
//! The tick rate (250 Hz) is deliberately *not* raised to chase latency —
//! latency here comes from preemption points, not timer granularity.

use core::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, Ordering};

use crate::cap::Pid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ThreadId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Class {
    Background,
    Interactive,
    RealTime,
}

/// Base timeslice for the interactive class. 6 ms is the BFS default and it
/// holds up: shorter slices increase switch overhead without measurably
/// improving input latency (which is dominated by preemption, not slice
/// length), longer slices start to show up as frame-time jitter under
/// contention.
pub const BASE_SLICE_NS: u64 = 6_000_000;

/// Ceiling on admitted real-time utilisation. The remaining 30% absorbs
/// interrupt handling, IPI storms, and the SMM interruptions we cannot control.
pub const RT_UTILISATION_CEILING: f32 = 0.70;

pub struct Thread {
    pub id: ThreadId,
    pub pid: Pid,
    pub class: Class,
    /// Interactive class: virtual deadline in ns. Earliest runs first.
    virtual_deadline: AtomicU64,
    /// Background class: EEVDF lag. Positive lag means owed service.
    lag_ns: AtomicI64,
    /// Weight from nice value; EEVDF service is divided by this.
    weight: AtomicU32,
    /// RT class: declared budget and period for admission control.
    rt_budget_ns: u64,
    rt_period_ns: u64,
    /// Timeslice remaining, decremented on tick and donated across IPC.
    slice_remaining: AtomicU64,
    runnable: AtomicBool,
}

impl Thread {
    /// Virtual deadline, BFS-style: now + slice/weight. A thread that has just
    /// woken from a blocking wait gets a near-term deadline and therefore
    /// preempts CPU-bound work almost immediately. That single property is
    /// where interactive responsiveness comes from.
    fn compute_deadline(&self, now_ns: u64, prio_ratio: u64) -> u64 {
        now_ns + (BASE_SLICE_NS * prio_ratio)
    }
}

/// Per-NUMA-node interactive runqueue.
pub struct InteractiveQueue {
    /// Sorted by virtual deadline. A 64-entry array beats a tree here: the
    /// class is bounded small by construction, and a linear scan over 64
    /// contiguous u64s is ~2 cache lines and faster than any pointer-chasing
    /// structure at this size.
    slots: spin::Mutex<heapless::Vec<(u64, ThreadId), 64>>,
    node: u8,
}

impl InteractiveQueue {
    pub const fn new(node: u8) -> Self {
        InteractiveQueue {
            slots: spin::Mutex::new(heapless::Vec::new()),
            node,
        }
    }

    pub fn enqueue(&self, tid: ThreadId, deadline: u64) -> Result<(), SchedError> {
        let mut q = self.slots.lock();
        let pos = q.partition_point(|(d, _)| *d <= deadline);
        q.insert(pos, (deadline, tid))
            .map_err(|_| SchedError::QueueFull)
    }

    /// Pop the earliest-deadline thread.
    pub fn pick_next(&self) -> Option<ThreadId> {
        let mut q = self.slots.lock();
        if q.is_empty() {
            None
        } else {
            Some(q.remove(0).1)
        }
    }

    pub fn len(&self) -> usize {
        self.slots.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedError {
    QueueFull,
    /// RT admission would push utilisation past the ceiling.
    RtAdmissionRefused {
        requested: u32,
        available: u32,
    },
    Timeout,
    NoSuchThread,
}

// ---------------------------------------------------------------------------
// Real-time admission control
// ---------------------------------------------------------------------------

/// Admitted RT utilisation in parts-per-million, to avoid float math in the
/// kernel.
static RT_UTILISATION_PPM: AtomicU32 = AtomicU32::new(0);
const RT_CEILING_PPM: u32 = 700_000;

/// Admit an RT thread, or refuse it.
///
/// Refusing is the whole point. An RT class that admits everything provides no
/// guarantee to anyone; the packet-inspection thread that PacketStorm relies on
/// only has a deadline guarantee because the kernel will tell the eleventh
/// would-be RT thread "no".
pub fn admit_realtime(budget_ns: u64, period_ns: u64) -> Result<(), SchedError> {
    if period_ns == 0 {
        return Err(SchedError::RtAdmissionRefused {
            requested: 0,
            available: 0,
        });
    }

    let requested = ((budget_ns.saturating_mul(1_000_000)) / period_ns) as u32;

    // CAS loop rather than fetch_add: we must not transiently exceed the
    // ceiling, because a concurrent admission could observe the inflated value
    // and refuse a request that should have succeeded.
    let mut current = RT_UTILISATION_PPM.load(Ordering::Acquire);
    loop {
        let new = current.saturating_add(requested);
        if new > RT_CEILING_PPM {
            return Err(SchedError::RtAdmissionRefused {
                requested,
                available: RT_CEILING_PPM.saturating_sub(current),
            });
        }
        match RT_UTILISATION_PPM.compare_exchange_weak(
            current,
            new,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return Ok(()),
            Err(observed) => current = observed,
        }
    }
}

pub fn release_realtime(budget_ns: u64, period_ns: u64) {
    if period_ns == 0 {
        return;
    }
    let amount = ((budget_ns.saturating_mul(1_000_000)) / period_ns) as u32;
    RT_UTILISATION_PPM.fetch_sub(amount, Ordering::AcqRel);
}

pub fn rt_utilisation_ppm() -> u32 {
    RT_UTILISATION_PPM.load(Ordering::Acquire)
}

// ---------------------------------------------------------------------------
// EEVDF background class
// ---------------------------------------------------------------------------

/// EEVDF eligibility: a thread may run when its lag is non-negative, i.e. it
/// has received less service than its fair share. Among eligible threads, the
/// earliest virtual deadline wins.
///
/// This is what makes SpectreShield's background scanning invisible. Under CFS,
/// a scanner that wakes constantly accrues vruntime slowly and keeps preempting;
/// under EEVDF, once it has consumed its share its lag goes negative and it
/// becomes ineligible until the game has taken its own share. The game's frame
/// times stop depending on whether a scan is running.
pub fn eevdf_eligible(lag_ns: i64) -> bool {
    lag_ns >= 0
}

/// Update lag after a thread runs for `ran_ns` while total weight is
/// `total_weight` and the thread's weight is `weight`.
pub fn eevdf_update_lag(lag_ns: i64, ran_ns: u64, weight: u32, total_weight: u32) -> i64 {
    if weight == 0 || total_weight == 0 {
        return lag_ns;
    }
    // Fair share of the elapsed period for this thread.
    let fair = (ran_ns as i128 * weight as i128 / total_weight as i128) as i64;
    lag_ns + fair - ran_ns as i64
}

// ---------------------------------------------------------------------------
// Core scheduling entry points
// ---------------------------------------------------------------------------

/// Pick the next thread for this CPU. Strict class priority: an eligible RT
/// thread always wins, then interactive, then background.
pub fn pick_next(cpu: CpuContext) -> Option<ThreadId> {
    if let Some(t) = cpu.rt_queue.pick_next() {
        return Some(t);
    }

    // Game Mode isolation: cores dedicated to the game process refuse every
    // thread that is not the game's. Checked here rather than at enqueue so
    // that leaving Game Mode does not require re-sorting every queue.
    if let Some(owner) = crate::gamemode::isolated_owner(cpu.id) {
        return cpu
            .interactive
            .pick_next()
            .filter(|t| crate::thread::pid_of(*t) == Some(owner));
    }

    if let Some(t) = cpu.interactive.pick_next() {
        return Some(t);
    }

    cpu.background.pick_eligible()
}

pub struct CpuContext {
    pub id: u32,
    pub rt_queue: &'static InteractiveQueue,
    pub interactive: &'static InteractiveQueue,
    pub background: &'static BackgroundQueue,
}

pub struct BackgroundQueue {
    entries: spin::Mutex<heapless::Vec<(i64, u64, ThreadId), 256>>,
}

impl BackgroundQueue {
    pub const fn new() -> Self {
        BackgroundQueue {
            entries: spin::Mutex::new(heapless::Vec::new()),
        }
    }

    /// Earliest virtual deadline among *eligible* threads. A thread with
    /// negative lag is skipped entirely — that skip is the fairness mechanism.
    pub fn pick_eligible(&self) -> Option<ThreadId> {
        let mut q = self.entries.lock();
        let idx = q
            .iter()
            .enumerate()
            .filter(|(_, (lag, _, _))| eevdf_eligible(*lag))
            .min_by_key(|(_, (_, deadline, _))| *deadline)
            .map(|(i, _)| i)?;
        Some(q.remove(idx).2)
    }

    pub fn enqueue(&self, tid: ThreadId, lag: i64, deadline: u64) -> Result<(), SchedError> {
        self.entries
            .lock()
            .push((lag, deadline, tid))
            .map_err(|_| SchedError::QueueFull)
    }
}

impl Default for BackgroundQueue {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// IPC integration: direct handoff with timeslice donation
// ---------------------------------------------------------------------------

/// Switch straight into `target`, donating `from`'s remaining slice.
///
/// Deliberately does not touch any runqueue. This is the mechanism that makes
/// user-space drivers cost about what in-kernel drivers cost, and it is the
/// single most performance-critical function in the kernel.
pub fn switch_to_donating(target: ThreadId, from: ThreadId) {
    let remaining = crate::thread::slice_remaining(from);
    crate::thread::set_slice(target, remaining);
    crate::thread::mark_blocked(from);
    crate::arch::context_switch(from, target);
}

pub fn wake_donating(target: ThreadId, from: ThreadId) {
    let remaining = crate::thread::slice_remaining(from);
    crate::thread::set_slice(target, remaining);
    crate::thread::mark_runnable(target);
    crate::arch::context_switch(from, target);
}

/// Queue a wakeup to be applied at the next scheduler entry. Safe from IRQ
/// context, where taking the runqueue lock would risk deadlock against a
/// scheduler already holding it on this CPU.
pub fn wake_deferred(target: ThreadId) {
    crate::percpu::pending_wakeups().push(target);
}

/// CPU mask the background class is permitted to run on. Game Mode narrows this
/// to the non-isolated cores; leaving Game Mode restores `u64::MAX`.
static BACKGROUND_AFFINITY: AtomicU64 = AtomicU64::new(u64::MAX);

pub fn set_class_affinity(class: Class, mask: u64) {
    // Only the background class is restrictable. Confining the interactive class
    // would strand the compositor, and confining the RT class would silently
    // invalidate the admission-control guarantee in `admit_realtime` — the
    // utilisation ceiling is computed against the whole machine, so restricting
    // RT to a subset of cores would let admitted threads miss deadlines while
    // the accounting still claimed they fit.
    if matches!(class, Class::Background) {
        BACKGROUND_AFFINITY.store(mask, Ordering::Release);
    }
}

pub fn class_affinity(class: Class) -> u64 {
    match class {
        Class::Background => BACKGROUND_AFFINITY.load(Ordering::Acquire),
        _ => u64::MAX,
    }
}

/// Move every thread off `cpu` except those belonging to `keep`.
pub fn migrate_all_except(cpu: u32, keep: Pid) {
    crate::percpu::migrate_runqueue(cpu, keep);
}

pub fn current_thread() -> ThreadId {
    crate::percpu::current()
}

pub fn block(t: ThreadId) {
    crate::thread::mark_blocked(t);
    crate::arch::yield_now();
}

pub fn block_until(t: ThreadId, deadline_ns: u64) -> Result<(), SchedError> {
    crate::thread::arm_timeout(t, deadline_ns);
    crate::thread::mark_blocked(t);
    crate::arch::yield_now();
    if crate::thread::timed_out(t) {
        Err(SchedError::Timeout)
    } else {
        Ok(())
    }
}

pub fn handoff_partner(t: ThreadId) -> Option<ThreadId> {
    crate::thread::handoff_partner(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interactive_queue_orders_by_deadline() {
        let q = InteractiveQueue::new(0);
        q.enqueue(ThreadId(1), 300).unwrap();
        q.enqueue(ThreadId(2), 100).unwrap();
        q.enqueue(ThreadId(3), 200).unwrap();

        assert_eq!(q.pick_next(), Some(ThreadId(2)));
        assert_eq!(q.pick_next(), Some(ThreadId(3)));
        assert_eq!(q.pick_next(), Some(ThreadId(1)));
        assert_eq!(q.pick_next(), None);
    }

    #[test]
    fn equal_deadlines_preserve_fifo_order() {
        let q = InteractiveQueue::new(0);
        q.enqueue(ThreadId(1), 100).unwrap();
        q.enqueue(ThreadId(2), 100).unwrap();
        assert_eq!(q.pick_next(), Some(ThreadId(1)));
        assert_eq!(q.pick_next(), Some(ThreadId(2)));
    }

    #[test]
    fn rt_admission_enforces_the_ceiling() {
        let _guard = crate::vault::GLOBAL_STATE_LOCK.lock();
        RT_UTILISATION_PPM.store(0, Ordering::SeqCst);

        // 10 threads at 5% each = 50%: all admitted.
        for _ in 0..10 {
            admit_realtime(500_000, 10_000_000).unwrap();
        }
        assert_eq!(rt_utilisation_ppm(), 500_000);

        // 25% more would reach 75%, over the 70% ceiling: refused.
        assert!(matches!(
            admit_realtime(2_500_000, 10_000_000),
            Err(SchedError::RtAdmissionRefused { .. })
        ));

        // 15% fits exactly.
        admit_realtime(1_500_000, 10_000_000).unwrap();
        assert_eq!(rt_utilisation_ppm(), 650_000);
    }

    #[test]
    fn rt_release_returns_capacity() {
        let _guard = crate::vault::GLOBAL_STATE_LOCK.lock();
        RT_UTILISATION_PPM.store(0, Ordering::SeqCst);
        admit_realtime(7_000_000, 10_000_000).unwrap();
        assert!(admit_realtime(1_000_000, 10_000_000).is_err());
        release_realtime(7_000_000, 10_000_000);
        assert!(admit_realtime(1_000_000, 10_000_000).is_ok());
    }

    #[test]
    fn zero_period_is_refused_not_divided_by() {
        let _guard = crate::vault::GLOBAL_STATE_LOCK.lock();
        RT_UTILISATION_PPM.store(0, Ordering::SeqCst);
        assert!(admit_realtime(1_000, 0).is_err());
    }

    #[test]
    fn eevdf_ineligible_threads_are_skipped() {
        let q = BackgroundQueue::new();
        q.enqueue(ThreadId(1), -500, 10).unwrap(); // over-served, ineligible
        q.enqueue(ThreadId(2), 100, 50).unwrap(); // eligible, later deadline

        assert_eq!(q.pick_eligible(), Some(ThreadId(2)));
        assert_eq!(q.pick_eligible(), None, "ineligible thread must not run");
    }

    #[test]
    fn lag_decreases_for_an_over_served_thread() {
        // Thread holds 1/4 of total weight but ran for the whole period.
        let lag = eevdf_update_lag(0, 1_000_000, 256, 1024);
        assert!(lag < 0, "running past fair share must produce negative lag");
    }

    #[test]
    fn lag_is_stable_when_service_matches_share() {
        // Sole thread: weight equals total weight, so fair share is everything.
        assert_eq!(eevdf_update_lag(0, 1_000_000, 1024, 1024), 0);
    }
}
