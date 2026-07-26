//! Platform-service stand-ins for the host harness.
//!
//! Each shim is the minimum needed to let the logic under test execute. None of
//! them models the real hardware. Where a shim would silently change the
//! meaning of a test, it panics instead — a test that depends on real context
//! switching should fail loudly here, not quietly pass against a no-op.

use crate::cap::Pid;
use crate::sched::ThreadId;

pub mod thread {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SLICE: AtomicU64 = AtomicU64::new(0);

    pub fn slice_remaining(_t: ThreadId) -> u64 {
        SLICE.load(Ordering::Relaxed)
    }
    pub fn set_slice(_t: ThreadId, ns: u64) {
        SLICE.store(ns, Ordering::Relaxed);
    }
    pub fn mark_blocked(_t: ThreadId) {}
    pub fn mark_runnable(_t: ThreadId) {}
    pub fn arm_timeout(_t: ThreadId, _deadline_ns: u64) {}
    pub fn timed_out(_t: ThreadId) -> bool {
        false
    }
    pub fn handoff_partner(_t: ThreadId) -> Option<ThreadId> {
        None
    }
    pub fn set_handoff_partner(_to: ThreadId, _from: ThreadId) {}
    pub fn deliver_caps(_from: ThreadId, _to: ThreadId, _count: usize) {}

    /// Whichever process the test last declared alive. Defaults to alive so the
    /// Game Mode watchdog does not tear down state mid-test.
    pub fn process_alive(_p: Pid) -> bool {
        true
    }

    pub fn pid_of(_t: ThreadId) -> Option<Pid> {
        None
    }

    pub struct MessageBuffer {
        pub label: u32,
        pub len: usize,
        pub bytes: [u8; crate::ipc::INLINE_MAX],
        pub pages: Option<crate::ipc::PageGrant>,
        pub cap_count: usize,
        pub caps: [crate::cap::Capability; 8],
    }

    pub fn with_message_buffer<R>(_t: ThreadId, _f: impl FnOnce(&mut MessageBuffer) -> R) -> R {
        unimplemented!("message buffers require per-thread kernel state")
    }

    pub enum ReplyStatus {
        Ready(usize),
        PeerGone,
        TimedOut,
    }

    pub fn reply_status(_t: ThreadId) -> ReplyStatus {
        ReplyStatus::PeerGone
    }
}

pub mod percpu {
    use super::*;

    pub fn current() -> ThreadId {
        ThreadId(1)
    }

    pub struct WakeQueue;

    impl WakeQueue {
        pub fn push(&self, _t: ThreadId) {}
    }

    pub fn pending_wakeups() -> WakeQueue {
        WakeQueue
    }

    pub fn migrate_runqueue(_cpu: u32, _keep: Pid) {}
}

pub mod debug {
    use super::*;

    pub fn is_consented_introspection(_offender: Pid, _victim: Pid) -> bool {
        false
    }
}

pub mod forensic {
    use super::*;
    use crate::vault::Intrusion;

    pub fn log_intrusion(_i: &Intrusion) {}

    #[allow(dead_code)]
    pub fn dump_process(_p: Pid, _i: &Intrusion) {}
}

pub mod notify {
    use super::*;
    use crate::vault::Intrusion;

    pub fn intrusion_detected(_i: &Intrusion) {}
    pub fn game_mode_recovered(_p: Pid) {}
}

pub mod net {
    use super::*;

    pub fn apply_low_latency_profile(_p: Pid) {}
    pub fn restore_default_profile() {}
}

pub mod gpu {
    use super::*;

    pub fn request_direct_scanout(_p: Pid) {}
    pub fn release_direct_scanout() {}
}

pub mod compact {
    use super::*;

    pub fn request_contiguous(_p: Pid) {}
}
