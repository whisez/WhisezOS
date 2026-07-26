//! The `arch` module as the host harness sees it.
//!
//! Real, testable submodules (`addr`, `paging`) are included from the kernel
//! tree. The genuinely hardware-bound entry points below are stand-ins — they
//! panic rather than no-op, so a test that starts depending on real context
//! switching or MSR access fails loudly instead of passing against a fiction.

#[path = "../../kernel/spectre-kernel/src/arch/addr.rs"]
pub mod addr;

#[path = "../../kernel/spectre-kernel/src/arch/paging.rs"]
pub mod paging;

#[path = "../../kernel/spectre-kernel/src/arch/frame.rs"]
pub mod frame;

#[path = "../../kernel/spectre-kernel/src/arch/gdt.rs"]
pub mod gdt;

#[path = "../../kernel/spectre-kernel/src/arch/idt.rs"]
pub mod idt;

#[path = "../../kernel/spectre-kernel/src/arch/serial.rs"]
pub mod serial;

// Only the stack-construction logic is host-testable; the `extern "C"` switch
// itself is declared but never called here.
#[path = "../../kernel/spectre-kernel/src/arch/context.rs"]
pub mod context;

use crate::cap::Pid;
use crate::sched::ThreadId;

pub fn context_switch(_from: ThreadId, _to: ThreadId) {
    unimplemented!("context switch is not modelled on the host harness")
}

pub fn yield_now() {
    unimplemented!("yield is not modelled on the host harness")
}

pub mod mktme {
    pub fn alloc_keyid() -> u16 {
        1
    }
}

pub struct Topology;

impl Topology {
    /// Reference layout: 8 logical CPUs, SMT pairs (0,1) (2,3) (4,5) (6,7).
    pub fn smt_sibling(&self, cpu: u32) -> Option<u32> {
        if cpu >= 8 {
            return None;
        }
        Some(cpu ^ 1)
    }
}

pub fn topology() -> Topology {
    Topology
}

#[allow(dead_code)]
pub fn migrate_hint(_cpu: u32, _keep: Pid) {}
