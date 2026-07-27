//! Round-robin scheduling over the loaded processes.
//!
//! This is not `sched.rs`. That one is the three-class scheduler with real-time
//! admission control the architecture calls for; it is written and tested, and
//! it needs `thread`, `percpu`, and a blocking primitive before it can be
//! linked. This is the smallest thing that makes preemption real: a fixed
//! table, a rotating index, and a timer.
//!
//! What it demonstrates is not the policy, which is trivial, but the mechanism:
//! two processes in separate address spaces, each unaware of the other, taking
//! turns because a clock says so rather than because either yielded.
//!
//! # No locking discipline beyond "interrupts are off"
//!
//! The table is reached from two places: the timer interrupt and the system
//! call path. Interrupt gates clear `IF` and `SFMASK` clears it for `syscall`,
//! so on one processor neither can interrupt the other and the mutex below is
//! never contended. It is a mutex rather than a bare static because that
//! assumption stops holding the moment a second processor starts, and a lock
//! that was never there is harder to add than one that was.

use spin::Mutex;

use crate::arch::addr::{PagingMode, PhysAddr, VirtAddr};
use crate::arch::gdt::GdtLayout;
use crate::arch::trap::TrapFrame;
use crate::arch::user::{UserProcess, MAX_USER_REGIONS};
use crate::arch::{cpu, segments};
use crate::kprintln;
use crate::roundrobin::{self, Slot};
use crate::usercopy::UserRegion;

/// Processes the table holds. Four is enough to show a rotation and small
/// enough that the table is a plain array in `.bss`.
pub const MAX_PROCESSES: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Slot unused.
    Empty,
    /// Runnable, not currently on a processor.
    Ready,
    Running,
    /// Called `SYS_EXIT`. Never scheduled again, and the slot is not reused:
    /// there is no process teardown yet, so reusing it would leak its frames.
    Exited,
}

#[derive(Debug, Clone, Copy)]
struct Process {
    pid: u64,
    state: State,
    /// Top-level page table.
    root: PhysAddr,
    /// Where this process was interrupted. Meaningful in every state but
    /// `Empty`; for a process that has not run yet, it is the frame that starts
    /// it.
    frame: TrapFrame,
    regions: [UserRegion; MAX_USER_REGIONS],
    region_count: usize,
    exit_code: u64,
}

impl Process {
    const EMPTY: Self = Self {
        pid: 0,
        state: State::Empty,
        root: PhysAddr::ZERO,
        frame: TrapFrame::ZERO,
        regions: [UserRegion::new(0, 0); MAX_USER_REGIONS],
        region_count: 0,
        exit_code: 0,
    };

    fn regions(&self) -> &[UserRegion] {
        &self.regions[..self.region_count]
    }
}

struct Table {
    slots: [Process; MAX_PROCESSES],
    current: usize,
    ticks: u64,
    switches: u64,
}

impl Table {
    /// The slot states, in the shape the policy takes.
    ///
    /// A copy rather than a borrow because `next_ready` is a free function over
    /// a slice and the table is behind a lock; four bytes is not worth an API
    /// that lets the policy reach into the table it is choosing from.
    fn states(&self) -> [Slot; MAX_PROCESSES] {
        let mut out = [Slot::Empty; MAX_PROCESSES];
        for (slot, process) in out.iter_mut().zip(self.slots.iter()) {
            *slot = match process.state {
                State::Empty => Slot::Empty,
                State::Ready => Slot::Ready,
                State::Running => Slot::Running,
                State::Exited => Slot::Exited,
            };
        }
        out
    }
}

static TABLE: Mutex<Table> = Mutex::new(Table {
    slots: [Process::EMPTY; MAX_PROCESSES],
    current: 0,
    ticks: 0,
    switches: 0,
});

/// Selectors for the initial frames, and the stack the CPU switches to on a
/// ring 3 → 0 transition.
static PLATFORM: Mutex<Option<(GdtLayout, u64)>> = Mutex::new(None);

pub fn init(layout: GdtLayout, ring0_stack_top: u64) {
    *PLATFORM.lock() = Some((layout, ring0_stack_top));
}

/// Adds a loaded image to the table and builds the frame that will start it.
///
/// `argument` arrives in `rdi`, the first System V argument register, so a
/// process entered this way sees it as the first parameter of `_start`. It is
/// the whole of a process's initial environment right now, and it is how two
/// instances of the same image tell themselves apart.
pub fn admit(image: &UserProcess, argument: u64) -> Option<u64> {
    let (layout, _) = (*PLATFORM.lock())?;
    let mut table = TABLE.lock();
    let slot = table.slots.iter().position(|p| p.state == State::Empty)?;

    let pid = slot as u64 + 1;
    let mut frame = TrapFrame::ZERO;
    frame.rip = image.entry;
    frame.cs = u64::from(layout.user_code.0);
    frame.ss = u64::from(layout.user_data.0);
    frame.rsp = image.stack_top;
    // Bit 1 is reserved and always set; bit 9 is IF. Interrupts must be *on* in
    // ring 3, or the timer never arrives and a process that does not call the
    // kernel runs forever.
    frame.rflags = 0x202;
    frame.rdi = argument;

    let mut regions = [UserRegion::new(0, 0); MAX_USER_REGIONS];
    let supplied = image.regions();
    regions[..supplied.len()].copy_from_slice(supplied);

    table.slots[slot] = Process {
        pid,
        state: State::Ready,
        root: image.root(),
        frame,
        regions,
        region_count: supplied.len(),
        exit_code: 0,
    };
    Some(pid)
}

/// The current process's permitted address ranges, for pointer validation.
pub fn with_current_regions<R>(f: impl FnOnce(&[UserRegion]) -> R) -> R {
    let table = TABLE.lock();
    let process = &table.slots[table.current];
    if process.state == State::Running {
        f(process.regions())
    } else {
        // No running process means no permitted ranges — the right answer for a
        // call that cannot have come from anywhere legitimate.
        f(&[])
    }
}

#[must_use]
pub fn current_pid() -> u64 {
    let table = TABLE.lock();
    table.slots[table.current].pid
}

/// Marks the running process as finished, returning its pid.
///
/// Does not switch away. The caller returns to a halt loop with interrupts
/// enabled and the next tick picks something else, which keeps the only path
/// that changes what is running in one place.
pub fn exit_current(code: u64) -> u64 {
    let mut table = TABLE.lock();
    let current = table.current;
    let process = &mut table.slots[current];
    process.state = State::Exited;
    process.exit_code = code;
    process.pid
}

/// Chooses the next process and rewrites `frame` to resume it.
///
/// Called from the timer interrupt, with interrupts disabled.
pub fn on_tick(frame: &mut TrapFrame) {
    let mut table = TABLE.lock();
    table.ticks += 1;

    let current = table.current;
    if table.slots[current].state == State::Running {
        table.slots[current].frame = *frame;
        table.slots[current].state = State::Ready;
    }

    let states = table.states();
    let Some(next) = roundrobin::next_ready(&states, current) else {
        let (ticks, switches) = (table.ticks, table.switches);
        drop(table);
        kprintln!("[kernel] all processes exited after {ticks} ticks, {switches} switches");
        kprintln!("[kernel] stage 2 complete");
        kprintln!("[kernel] nothing left to schedule, halting");
        crate::arch::halt_forever();
    };

    if next != current {
        table.switches += 1;
    }
    table.current = next;
    table.slots[next].state = State::Running;
    *frame = table.slots[next].frame;
    let root = table.slots[next].root;
    drop(table);

    let stack = PLATFORM.lock().map_or(0, |(_, stack)| stack);
    // SAFETY: single processor, interrupts disabled. The kernel stack is
    // static, and switching address spaces is safe because every one of them
    // maps the kernel's identity range at the same top-level entry — so the
    // instruction after the CR3 load is still mapped.
    unsafe {
        segments::set_kernel_stack(VirtAddr::from_indices_sign_extended(
            stack,
            PagingMode::Level4,
        ));
        cpu::write_cr3(root.as_u64());
    }
}

/// Starts the first process. Does not return.
///
/// # Safety
/// At least one process must be admitted, `init` must have run, and interrupts
/// must be disabled — they come on through the `RFLAGS` in the frame, at the
/// moment control reaches ring 3 and not before.
pub unsafe fn run() -> ! {
    let mut table = TABLE.lock();
    let Some(first) = table.slots.iter().position(|p| p.state == State::Ready) else {
        drop(table);
        kprintln!("[kernel] nothing to schedule");
        crate::arch::halt_forever();
    };
    table.current = first;
    table.slots[first].state = State::Running;
    let frame = table.slots[first].frame;
    let root = table.slots[first].root;
    drop(table);

    let stack = PLATFORM.lock().map_or(0, |(_, stack)| stack);
    // SAFETY: as documented above.
    unsafe {
        segments::set_kernel_stack(VirtAddr::from_indices_sign_extended(
            stack,
            PagingMode::Level4,
        ));
        cpu::write_cr3(root.as_u64());
        crate::arch::trap::enter_frame(&frame)
    }
}
