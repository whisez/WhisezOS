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
use crate::arch::{cpu, memory, segments};
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
    /// Waiting on IPC. Its saved frame is the system call that blocked; waking
    /// it means writing the result into that frame's `rax` and marking it
    /// `Ready`, so it returns from the call as if it had never stopped.
    Blocked,
    /// Called `SYS_EXIT`, and waiting to be reaped. The next tick frees its
    /// address space and returns the slot to `Empty`; until then it must not be
    /// scheduled, because its frame describes a process that has finished.
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
    /// DMA buffers this process holds, which is both its next slot number and
    /// the limit it is checked against.
    dma_regions: u64,
    /// Device mappings this process has taken, so a second request for the same
    /// device does not map it twice.
    devices_mapped: u64,
}

impl State {
    /// Still a process, whether or not it can run right now.
    #[must_use]
    pub const fn is_live(self) -> bool {
        matches!(self, Self::Ready | Self::Running | Self::Blocked)
    }
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
        dma_regions: 0,
        devices_mapped: 0,
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
                State::Blocked => Slot::Blocked,
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

/// Selectors for the initial frames, the stack the CPU switches to on a ring 3
/// → 0 transition, and the kernel's own top-level table.
static PLATFORM: Mutex<Option<(GdtLayout, u64, PhysAddr)>> = Mutex::new(None);

pub fn init(layout: GdtLayout, ring0_stack_top: u64, kernel_root: PhysAddr) {
    *PLATFORM.lock() = Some((layout, ring0_stack_top, kernel_root));
}

/// What the kernel needs to build another process after one has been reaped.
///
/// Keeping the image address rather than a slice because this is read from an
/// interrupt handler, where a borrow of something owned by `run` would have no
/// lifetime to speak of. The bytes live in `Loader` memory, which the frame
/// allocator never hands out.
#[derive(Debug, Clone, Copy)]
struct Spawner {
    image_phys: u64,
    image_len: usize,
    kernel_root: PhysAddr,
    /// Processes still to be created. Bounded so the demonstration terminates;
    /// a real system would spawn on request rather than on a budget.
    remaining: u32,
    next_argument: u64,
    /// The endpoint every process is introduced to.
    endpoint: u64,
}

static SPAWNER: Mutex<Option<Spawner>> = Mutex::new(None);

/// Free frames before any process existed, for the leak check at the end.
static BASELINE_FREE_FRAMES: Mutex<u64> = Mutex::new(0);

/// Arms the respawn path.
///
/// # Safety
/// `image` must remain valid and mapped for the life of the system, which holds
/// because it is in loader memory the allocator does not issue.
pub unsafe fn arm_respawn(
    image: &'static [u8],
    kernel_root: PhysAddr,
    count: u32,
    first_argument: u64,
    endpoint: u64,
) {
    *SPAWNER.lock() = Some(Spawner {
        image_phys: image.as_ptr() as u64,
        image_len: image.len(),
        kernel_root,
        remaining: count,
        next_argument: first_argument,
        endpoint,
    });
}

/// Records how much memory was free before any process was built.
pub fn set_baseline_free_frames(frames: u64) {
    *BASELINE_FREE_FRAMES.lock() = frames;
}

/// Builds one more process, if the budget allows and a slot is free.
///
/// Called after a reap, which is the only time a slot becomes free — so this is
/// also the proof that a reclaimed slot and reclaimed frames are usable again,
/// rather than merely accounted for.
fn try_spawn() {
    let plan = {
        let mut guard = SPAWNER.lock();
        let Some(spawner) = guard.as_mut() else {
            return;
        };
        if spawner.remaining == 0 {
            return;
        }
        spawner.remaining -= 1;
        let argument = spawner.next_argument;
        spawner.next_argument += 1;
        (
            spawner.image_phys,
            spawner.image_len,
            spawner.kernel_root,
            argument,
            spawner.endpoint,
        )
    };
    let (phys, len, kernel_root, argument, endpoint) = plan;

    // SAFETY: the image is in loader memory, identity mapped and never
    // reclaimed; `arm_respawn` recorded a slice that was live then and cannot
    // have been freed since.
    let image = unsafe { core::slice::from_raw_parts(phys as *const u8, len) };

    // SAFETY: the frame allocator is up, physical memory is identity mapped,
    // and `on_tick` put the kernel's own table in CR3 before calling here.
    let process = match unsafe { crate::arch::user::load(image, kernel_root) } {
        Ok(process) => process,
        Err(error) => {
            kprintln!("[kernel] respawn failed: {error:?}");
            return;
        }
    };
    // A respawned process is an ordinary client: it gets the endpoint and no
    // device grant. Authority is not inherited by occupying a slot.
    match admit(&process, argument, endpoint, 0) {
        Some(pid) => kprintln!("[kernel] respawned pid={pid} into a reclaimed slot"),
        None => kprintln!("[kernel] respawn found no free slot"),
    }
}

/// Adds a loaded image to the table and builds the frame that will start it.
///
/// `argument` arrives in `rdi`, the first System V argument register, so a
/// process entered this way sees it as the first parameter of `_start`. It is
/// the whole of a process's initial environment right now, and it is how two
/// instances of the same image tell themselves apart.
pub fn admit(image: &UserProcess, argument: u64, second: u64, third: u64) -> Option<u64> {
    let (layout, _, _) = (*PLATFORM.lock())?;
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
    // The second System V argument register. Two values are the whole of a
    // process's initial environment: who it is, and the one endpoint it was
    // introduced to. A process cannot name any other.
    frame.rsi = second;
    // Third argument register. Zero for every process that was not given a
    // device grant, which is what makes "holds nothing" the default.
    frame.rdx = third;

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
        dma_regions: 0,
        devices_mapped: 0,
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

/// Records a device mapping the running process has just been given.
///
/// The range joins its permitted regions, because a driver passing a pointer
/// into its framebuffer to another system call is doing something ordinary, and
/// the pointer validator has no other way to know the range is his.
///
/// Returns the slot the mapping used, or `None` when the process has taken as
/// many as its region table holds.
pub fn record_device_mapping(base: u64, length: u64) -> Option<u64> {
    let mut table = TABLE.lock();
    let current = table.current;
    let process = &mut table.slots[current];
    if process.region_count == MAX_USER_REGIONS {
        return None;
    }
    let slot = process.devices_mapped;
    process.regions[process.region_count] = UserRegion::new(base, length);
    process.region_count += 1;
    process.devices_mapped += 1;
    Some(slot)
}

/// How many devices the running process has already mapped.
#[must_use]
pub fn devices_mapped() -> u64 {
    let table = TABLE.lock();
    table.slots[table.current].devices_mapped
}

/// Records a DMA buffer the running process has just been given.
///
/// The same bookkeeping as `record_device_mapping` and for the same reason —
/// the range has to become a permitted region or the process cannot pass a
/// pointer into its own buffer to any other call — but counted separately,
/// because the two windows have separate slot numbering and sharing a counter
/// would place the second buffer in the slot the first device took.
///
/// Returns the slot the buffer used, or `None` when the process has taken as
/// many as it may.
pub fn record_dma_mapping(base: u64, length: u64) -> Option<u64> {
    let mut table = TABLE.lock();
    let current = table.current;
    let process = &mut table.slots[current];
    if process.region_count == MAX_USER_REGIONS
        || process.dma_regions >= crate::dma::MAX_DMA_REGIONS
    {
        return None;
    }
    let slot = process.dma_regions;
    process.regions[process.region_count] = UserRegion::new(base, length);
    process.region_count += 1;
    process.dma_regions += 1;
    Some(slot)
}

/// How many DMA buffers the running process already holds.
#[must_use]
pub fn dma_regions() -> u64 {
    let table = TABLE.lock();
    table.slots[table.current].dma_regions
}

/// The running process's top-level page table.
///
/// Needed by IPC: a message delivered later has to be written through the
/// recipient's tables, so the sender's identity and address space are recorded
/// while it is still the one running.
#[must_use]
pub fn current_root() -> PhysAddr {
    let table = TABLE.lock();
    table.slots[table.current].root
}

#[must_use]
pub fn current_pid() -> u64 {
    let table = TABLE.lock();
    table.slots[table.current].pid
}

/// Parks the running process and resumes something else. Does not return.
///
/// `frame` is the system call that is blocking, saved exactly as it stands, so
/// waking the process later is a matter of writing a result into its `rax` and
/// marking it runnable — it then returns from the call having noticed only that
/// time passed.
///
/// # Safety
/// Called from a system call, with interrupts disabled, on the syscall stack.
/// Nothing on that stack is reachable afterwards.
pub unsafe fn block_current(frame: &TrapFrame) -> ! {
    {
        let mut table = TABLE.lock();
        let current = table.current;
        table.slots[current].frame = *frame;
        table.slots[current].state = State::Blocked;
    }
    // SAFETY: the caller's state is saved, so resuming somebody else loses
    // nothing.
    unsafe { resume_next() }
}

/// Makes a blocked process runnable again, with `result` as its call's return.
///
/// Returns false if the pid names nothing blocked, which is a bug in the caller
/// rather than something to recover from — but reporting it beats corrupting a
/// frame that belongs to a different process in a reused slot.
pub fn wake(pid: u64, result: u64) -> bool {
    let mut table = TABLE.lock();
    let Some(slot) = table
        .slots
        .iter()
        .position(|p| p.pid == pid && p.state == State::Blocked)
    else {
        return false;
    };
    table.slots[slot].frame.rax = result;
    table.slots[slot].state = State::Ready;
    true
}

/// Whether a pid names a live process.
#[must_use]
pub fn is_live(pid: u64) -> bool {
    TABLE
        .lock()
        .slots
        .iter()
        .any(|p| p.pid == pid && p.state.is_live())
}

/// Picks the next runnable process and resumes it. Does not return.
///
/// Shared by every path that gives the processor away outside the timer: the
/// caller has already recorded whatever state it needed to.
///
/// # Safety
/// The current process must not be left marked `Running` — it has no valid
/// frame to come back to.
unsafe fn resume_next() -> ! {
    let mut table = TABLE.lock();
    let states = table.states();

    let Some(next) = roundrobin::next_ready(&states, table.current) else {
        drop(table);
        no_runnable_process(&states);
    };

    table.current = next;
    table.slots[next].state = State::Running;
    let frame = table.slots[next].frame;
    let root = table.slots[next].root;
    drop(table);

    let stack = PLATFORM.lock().map_or(0, |(_, stack, _)| stack);
    // SAFETY: single processor, interrupts disabled, static stack, and every
    // address space maps the kernel identically, so the instruction after the
    // CR3 load is still mapped.
    unsafe {
        segments::set_kernel_stack(VirtAddr::from_indices_sign_extended(
            stack,
            PagingMode::Level4,
        ));
        cpu::write_cr3(root.as_u64());
        crate::arch::trap::enter_frame(&frame)
    }
}

/// Reports why there is nothing to run, and stops.
///
/// The two reasons are not the same and must not print the same thing. Nothing
/// alive is a system that finished. Something alive but nothing runnable is a
/// deadlock — every live process waiting on another — and a deadlock that halts
/// quietly is indistinguishable from success in a boot log.
fn no_runnable_process(states: &[Slot]) -> ! {
    let live = states.iter().filter(|s| s.is_live()).count();
    if live == 0 {
        report_shutdown();
    }
    kprintln!("[kernel] DEADLOCK: {live} process(es) blocked, none runnable");
    crate::arch::halt_forever();
}

fn report_shutdown() -> ! {
    let (ticks, switches) = {
        let table = TABLE.lock();
        (table.ticks, table.switches)
    };
    kprintln!("[kernel] all processes exited after {ticks} ticks, {switches} switches");
    kprintln!(
        "[kernel] {} ipc exchanges completed",
        crate::channel::exchanges()
    );
    report_frame_balance();
    kprintln!("[kernel] stage 2 complete");
    kprintln!("[kernel] nothing left to schedule, halting");
    crate::arch::halt_forever();
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

/// Frees the address space of every exited process and empties its slot.
///
/// Must not run while any of those spaces is in `CR3`, which is why `on_tick`
/// switches to the kernel's own table before calling it. Returns the number of
/// frames recovered.
///
/// The table lock is dropped before each teardown. Destroying an address space
/// takes the frame allocator's lock, and holding the process table across that
/// is the one nesting order that could deadlock once a second processor exists.
fn reap() -> u64 {
    let mut recovered = 0u64;
    loop {
        let victim = {
            let mut table = TABLE.lock();
            match table.slots.iter().position(|p| p.state == State::Exited) {
                Some(slot) => {
                    let root = table.slots[slot].root;
                    let pid = table.slots[slot].pid;
                    // Emptied before the walk, not after: if the teardown
                    // faults, the slot must not still name memory that is
                    // half freed.
                    table.slots[slot] = Process::EMPTY;
                    Some((pid, root))
                }
                None => None,
            }
        };
        let Some((pid, root)) = victim else {
            return recovered;
        };

        // SAFETY: `on_tick` switched to the kernel's table before calling this,
        // and this is a single processor, so nothing is running on `root`.
        match unsafe { memory::destroy_address_space(root) } {
            Ok(reclaimed) => {
                recovered += reclaimed.total();
                kprintln!(
                    "[kernel] reaped pid={pid}, freed {} frames ({} data, {} tables)",
                    reclaimed.total(),
                    reclaimed.leaf_frames,
                    reclaimed.table_frames
                );
            }
            Err(error) => {
                // Not recoverable and not survivable: the walk has already
                // freed an unknown amount, so the allocator's idea of what is
                // in use no longer matches reality.
                kprintln!("[kernel] TEARDOWN FAILED for pid={pid}: {error:?}");
                crate::arch::halt_forever();
            }
        }
    }
}

/// Chooses the next process and rewrites `frame` to resume it.
///
/// Called from the timer interrupt, with interrupts disabled.
pub fn on_tick(frame: &mut TrapFrame) {
    // Move off whatever address space was interrupted, first thing. The process
    // that just exited may be the one whose tables are about to be freed, and
    // `CR3` pointing at a freed table is a fault with no connection to the code
    // that caused it. Every address space maps the kernel identically, so this
    // changes nothing about the instructions that follow.
    if let Some((_, _, kernel_root)) = *PLATFORM.lock() {
        // SAFETY: the kernel's own table maps the running code and stack, and
        // is never freed.
        unsafe { cpu::write_cr3(kernel_root.as_u64()) };
    }

    let exited = {
        let table = TABLE.lock();
        table.slots.iter().any(|p| p.state == State::Exited)
    };
    if exited {
        reap();
        try_spawn();
    }

    let mut table = TABLE.lock();
    table.ticks += 1;

    let current = table.current;
    if table.slots[current].state == State::Running {
        table.slots[current].frame = *frame;
        table.slots[current].state = State::Ready;
    }

    let states = table.states();
    let Some(next) = roundrobin::next_ready(&states, current) else {
        drop(table);
        no_runnable_process(&states);
    };

    if next != current {
        table.switches += 1;
    }
    table.current = next;
    table.slots[next].state = State::Running;
    *frame = table.slots[next].frame;
    let root = table.slots[next].root;
    drop(table);

    let stack = PLATFORM.lock().map_or(0, |(_, stack, _)| stack);
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

/// Compares free memory now against what was free before any process existed.
///
/// The whole point of teardown, stated as a number. Every frame a process was
/// given came from the allocator and every one should have gone back, so the
/// two counts must be identical — not close. A difference in either direction
/// is a bug: fewer frames means a leak, more means the walk freed something
/// that was never the process's.
fn report_frame_balance() {
    let baseline = *BASELINE_FREE_FRAMES.lock();
    let now = memory::free_frames();
    if baseline == 0 {
        return;
    }
    if now == baseline {
        kprintln!("[kernel] frames balanced: {now} free, no leak across process teardown");
    } else if now < baseline {
        kprintln!(
            "[kernel] FRAME LEAK: {} frames never returned ({baseline} before, {now} after)",
            baseline - now
        );
    } else {
        kprintln!(
            "[kernel] FRAME OVER-RELEASE: {} more frames than there were ({baseline} before, {now} after)",
            now - baseline
        );
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

    let stack = PLATFORM.lock().map_or(0, |(_, stack, _)| stack);
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
