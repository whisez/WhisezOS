//! WhisezOS microkernel.
//!
//! # What is in kernel space, and why nothing else is
//!
//! Four subsystems:
//!
//! * `ipc`   — message passing. The kernel's reason for existing.
//! * `sched` — three-class scheduler with RT admission control.
//! * `vault` — address spaces and per-process encrypted arenas.
//! * `arch`  — the hardware abstraction layer: paging, interrupts, context
//!   switch, APIC, IOMMU domain setup.
//!
//! Plus `cap`, which is not a subsystem so much as the type system the other
//! four are written in.
//!
//! Everything else is a user-space process: every driver except the GPU
//! (sandboxed, see ARCHITECTURE.md §8), every filesystem, the network stack,
//! the USB stack, the input stack, the compositor.
//!
//! The trade is real and worth naming. A monolithic kernel does a disk read in
//! one syscall; we do it in a syscall plus two IPC round trips. We buy that
//! back with direct handoff and timeslice donation (`ipc.rs`), which gets the
//! measured cost to ~1.4x a Linux read on the same hardware. In exchange, a bug
//! in the NVMe driver is a crashed process that restarts in 40 ms, not a
//! kernel panic — and an exploited USB stack yields one MMIO window rather than
//! ring 0.
//!
//! # What this crate actually links today
//!
//! `arch`, `boot_info`, `abi`, `elf`, `usercopy`, `roundrobin`, `syscall`, and
//! `task`. That is the honest state of the tree, and the module list above
//! describes the design rather than the build.
//!
//! `task` in particular is not `sched`: it is a fixed table and a rotating
//! index, enough to preempt two processes with a timer. `sched.rs` is the
//! three-class scheduler the architecture calls for.
//!
//! `cap`, `sched`, `vault`, `ipc`, and `gamemode` are real, complete, and
//! covered by several hundred tests — but they are written against platform
//! modules (`thread`, `percpu`, `notify`, `compact`, `forensic`, `gpu`, `net`)
//! that do not exist yet. `verify/` compiles those five against host stand-ins
//! and runs their suites on every build, which is why they are tested but not
//! booted. Declaring them here as well would produce a crate that does not
//! compile, and a kernel that does not compile cannot be shown to boot.
//!
//! They come back one at a time, each with the platform module it needs, and
//! each proven by the QEMU boot test rather than by being listed here.
//!
//! # Panic policy
//!
//! The kernel panics only on states that indicate the kernel's own invariants
//! are broken. Every failure that can be caused by user-space — bad pointer,
//! exhausted quota, malformed message, capability violation — is an `Err`, not
//! a panic. A microkernel that can be panicked by a user-space process has
//! given away the entire benefit of being a microkernel.

#![no_std]
#![feature(abi_x86_interrupt)]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(clippy::undocumented_unsafe_blocks)]

pub mod abi;
pub mod arch;
pub mod boot_info;
pub mod channel;
pub mod device;
pub mod dma;
pub mod elf;
pub mod font;
pub mod irq;
pub mod pci;
pub mod portauth;
pub mod rendezvous;
pub mod roundrobin;
pub mod syscall;
pub mod task;
pub mod usercopy;
pub mod virtio;
pub mod vmspace;

pub use boot_info::BootInfo;

/// Registers a virtio block device found on the bus, if this is one.
///
/// Called once per device the scan reports. Everything it decides is either
/// PCI or virtio generic — it does not know what a disk is, only that this
/// device says it is virtio type 2 and where it keeps its registers.
///
/// # What it writes
///
/// Two bits in the command register. `MEMORY_SPACE` makes the device answer to
/// accesses in its own BARs, which firmware usually sets but is not obliged to;
/// `BUS_MASTER` lets it read the memory a driver gives it, without which every
/// DMA the driver sets up is silently ignored. Neither is something a driver
/// could set for itself, because both are in configuration space.
fn register_virtio_block(
    address: pci::Address,
    header: &pci::Header,
    space: &mut arch::PortConfigSpace,
) {
    use pci::ConfigSpace;

    if !virtio::is_virtio(header, virtio::TYPE_BLOCK) {
        return;
    }

    // Size every BAR once. The layout walk needs to check each region against
    // the BAR holding it, and sizing is destructive enough that doing it twice
    // is worth avoiding.
    let mut sizes = [None; 6];
    let mut bases = [0u64; 6];
    let mut index = 0usize;
    while index < 6 {
        // SAFETY: bring-up, interrupts disabled, no driver exists yet — which
        // is what makes the probe-and-restore safe.
        let Some(bar) = (unsafe { pci::bar(space, address, index) }) else {
            break;
        };
        if let pci::Bar::Memory { base, size, .. } = bar {
            if size != 0 {
                sizes[index] = Some(size);
                bases[index] = base;
            }
        }
        index += bar.slots_consumed();
    }

    let mut capabilities = [pci::Capability { id: 0, offset: 0 }; 16];
    // SAFETY: as above.
    let found = unsafe { pci::capabilities(space, address, header, &mut capabilities) };

    // SAFETY: as above.
    let layout = match unsafe {
        virtio::layout(space, address, &capabilities[..found], |bar| {
            sizes.get(bar as usize).copied().flatten()
        })
    } {
        Ok(layout) => layout,
        Err(error) => {
            kprintln!("[kernel] virtio-blk layout rejected: {error:?}");
            return;
        }
    };

    // Every structure in one BAR is what QEMU produces and all the mapper can
    // express — a device window is one contiguous range. A device spreading
    // them across BARs is legal and would need several windows, which is work
    // for a device that behaves that way rather than for one that might.
    let bars = layout.bars_used();
    if bars.count_ones() != 1 {
        kprintln!("[kernel] virtio-blk spreads its registers across {bars:#b}, not supported");
        return;
    }
    let bar = bars.trailing_zeros() as usize;
    let (Some(size), base) = (sizes[bar], bases[bar]) else {
        return;
    };

    // SAFETY: as above. Enabling the two bits a driver cannot set for itself.
    unsafe {
        let command = space.read(address, pci::offset::COMMAND);
        space.write(
            address,
            pci::offset::COMMAND,
            command | u32::from(pci::command::MEMORY_SPACE | pci::command::BUS_MASTER),
        );
    }

    match device::add_block(base, size, &layout, device::TICKER_LINE) {
        Some(index) => kprintln!(
            "[kernel] virtio-blk is device {index}: bar {bar} at {base:#x}, {} KiB, irq {}",
            size >> 10,
            header.interrupt_line
        ),
        None => kprintln!("[kernel] device table full, virtio-blk not listed"),
    }
}

/// Kernel entry, called from the loader's handoff trampoline with the verified
/// memory map and framebuffer.
///
/// # Safety
/// Called exactly once, on the bootstrap processor, with interrupts disabled and
/// the loader's identity mapping still active. `boot_info` must point to a live
/// `BootInfo` in memory the loader marked as its own, so nothing reclaims it
/// before `arch::early_init` has copied what it needs.
pub unsafe fn run(boot_info: *const BootInfo) -> ! {
    // SAFETY: the caller guarantees the pointer is live and correctly aligned.
    let boot = unsafe { &*boot_info };

    // SAFETY: first and only call, interrupts disabled, as required above.
    let platform = match unsafe { arch::early_init(boot) } {
        Ok(platform) => {
            kprintln!("[kernel] stage 1 complete");
            platform
        }
        Err(error) => {
            kprintln!("[kernel] BRING-UP FAILED: {error:?}");
            arch::halt_forever();
        }
    };

    // SAFETY: the handoff was validated by `early_init`, and the init image
    // lives in `Loader` memory, which the frame allocator does not hand out.
    let Some(image) = (unsafe { boot.init_image() }) else {
        kprintln!("[kernel] no init image in the handoff, halting");
        arch::halt_forever();
    };
    kprintln!("[kernel] init image {} KiB", image.len() >> 10);

    task::init(platform.gdt, arch::fault_stack_top(), platform.kernel_root);

    // The number every teardown is measured against. Taken before the first
    // process exists, so once the last one has been reaped the free count must
    // be exactly this again.
    let baseline = arch::memory::free_frames();
    task::set_baseline_free_frames(baseline);
    kprintln!("[kernel] {baseline} frames free before any process");

    // SAFETY: single-threaded bring-up, called once.
    unsafe { channel::init() };

    // One endpoint, owned by the first process. Every process is handed the
    // handle at spawn and can name no other, which is the whole of the
    // authority model until `cap.rs` links: a process reaches the services it
    // was introduced to and nothing else.
    let Some(endpoint) = channel::create(1) else {
        kprintln!("[kernel] could not create the init endpoint");
        arch::halt_forever();
    };
    kprintln!("[kernel] endpoint created for pid=1");

    // The device grant. Drawn from the same generator as endpoint handles, and
    // handed to exactly one process — the driver — so every other process holds
    // zero and zero never matches.
    let grant = channel::issue_token();
    let devices = device::init(boot, grant);

    // What is actually in the machine. Everything past the framebuffer is on
    // the PCI bus and invisible until somebody walks it, and walking it is
    // kernel work by construction: configuration space lives behind ports that
    // `portauth.rs` keeps out of the I/O bitmap on purpose.
    //
    // The table has to exist first — this adds to it.
    // SAFETY: bring-up, interrupts disabled, before any driver exists, which is
    // what BAR sizing requires.
    let on_bus = unsafe { arch::scan_pci(register_virtio_block) };
    kprintln!("[kernel] {on_bus} pci device(s) on bus 0");
    kprintln!("[kernel] {devices} device(s) listed, grant issued to pid=1");

    // One respawn, into whichever slot the first reap empties. It is what turns
    // "the frames were counted back" into "the frames were usable again".
    // SAFETY: the image lives in loader memory, which the frame allocator never
    // issues, so it outlives every process built from it.
    unsafe { task::arm_respawn(image, platform.kernel_root, 1, 3, endpoint) };

    // Two processes from one image. They share no memory — each gets its own
    // address space built from the same bytes — and tell themselves apart only
    // by the argument the kernel puts in `rdi`. Two is the smallest number that
    // makes a scheduler observable: with one, "preempted and resumed" and
    // "never interrupted" produce the same output.
    for argument in 1..=2u64 {
        // SAFETY: the early allocator is up, physical memory is identity
        // mapped, and `platform.kernel_root` is the table currently in CR3.
        let process = match unsafe { arch::user::load(image, platform.kernel_root) } {
            Ok(process) => process,
            Err(error) => {
                kprintln!("[kernel] INIT REJECTED: {error:?}");
                arch::halt_forever();
            }
        };
        // Only the first process is a driver. The grant is what says so.
        let device_grant = if argument == 1 { grant } else { 0 };
        match task::admit(&process, argument, endpoint, device_grant) {
            Some(pid) => kprintln!(
                "[kernel] init mapped pid={pid} entry={:#018x} stack={:#018x} regions={}",
                process.entry,
                process.stack_top,
                process.regions().len()
            ),
            None => {
                kprintln!("[kernel] process table full");
                arch::halt_forever();
            }
        }
    }

    // The timer is started last. Once it is running, the next thing that
    // happens is a context switch, and there is no point being able to switch
    // before there is more than one thing to switch to.
    // SAFETY: the IDT is installed and the legacy PICs are about to be masked
    // by this call's own preamble; interrupts are still disabled.
    match unsafe { arch::start_timer() } {
        Ok(info) => arch::apic::report(&info),
        Err(error) => {
            // Not fatal. Without a timer there is no preemption, so the first
            // process runs until it makes a system call — which is a degraded
            // system, and is reported as one rather than looking like success.
            kprintln!("[kernel] WARNING no timer ({error:?}), running without preemption");
        }
    }

    // And the one device line a process can wait on. After the timer, because
    // routing it depends on the LAPIC being the thing the I/O APIC delivers to;
    // before ring 3, because a process that calls `SYS_IRQ_WAIT` on a line that
    // was never armed waits forever rather than being told.
    // SAFETY: the IDT gave every device vector a gate, the LAPIC is up, and
    // interrupts are still disabled.
    match unsafe { arch::start_device_interrupt(device::TICKER_LINE) } {
        Ok(_) => {}
        Err(error) => {
            // Not fatal, and for the same reason the timer is not: the system
            // runs, with one capability missing, and says so.
            kprintln!("[kernel] WARNING no device interrupts ({error:?})");
        }
    }

    kprintln!("[kernel] entering ring 3");
    // SAFETY: both processes were loaded against the active kernel table, the
    // syscall MSRs are installed, and interrupts are still masked — they come
    // on through the first frame's RFLAGS, in ring 3.
    unsafe { task::run() }
}
