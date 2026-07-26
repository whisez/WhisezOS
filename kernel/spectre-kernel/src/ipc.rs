//! Inter-process communication.
//!
//! IPC is the microkernel's hot path and its reason for existing. Every
//! filesystem read, every packet, every frame Prism composites crosses it.
//! seL4's lesson applies: a microkernel lives or dies on IPC cost, and the way
//! to make it cheap is to make the common case involve zero copies and zero
//! scheduler work.
//!
//! Two mechanisms, chosen deliberately:
//!
//! **Synchronous rendezvous** (`call`/`reply`) for request/response. The
//! sender blocks, and the kernel performs a *direct context switch* into the
//! receiver without going through the scheduler — the sender donates its
//! remaining timeslice. A `read()` on SpectreFS is therefore about as
//! expensive as a Linux syscall plus one address-space switch, not a full
//! reschedule. This is the path that makes user-space drivers viable.
//!
//! **Asynchronous ports** (`post`) for notifications: IRQs, input events,
//! frame-ready signals. Non-blocking, bounded ring, drops oldest on overflow
//! with a counter the receiver can read. Notifications are edge-ish signals
//! where the newest is the most valuable; blocking an IRQ handler because a
//! sleepy consumer has not drained its queue is how you deadlock a driver.
//!
//! # Message payloads
//!
//! Small messages (≤ 256 bytes) travel in registers and a per-thread message
//! buffer — no mapping, no TLB work. Large transfers move by *page donation*:
//! the sender's pages are unmapped from its address space and mapped into the
//! receiver's. This is why a 4 MiB texture upload to Prism costs the same as a
//! 4 KiB one. Donation is destructive by design; a sender that wants to keep
//! its copy must ask for `Grant::Share`, which maps read-only into both and
//! is refused for pages under Vault encryption with an active rotation.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::cap::{Capability, EndpointId, Pid, Rights};
use crate::sched::{self, ThreadId};

/// Inline payload limit. 256 bytes covers ~95% of observed traffic (syscall
/// arguments, file offsets, event structs) and fits in the per-thread buffer
/// that is already hot in L1 after the context switch.
pub const INLINE_MAX: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcError {
    /// Caller does not hold a token with the required right.
    Denied,
    /// Endpoint has no receiver and the call was non-blocking.
    WouldBlock,
    /// Receiver died while the sender was blocked.
    PeerGone,
    /// Payload exceeded INLINE_MAX and no pages were donated.
    TooLarge,
    /// Async ring is full and the message was dropped.
    Overflow,
    /// Blocking call exceeded its deadline.
    TimedOut,
}

/// How a large payload crosses the address-space boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Grant {
    /// Pages are unmapped from sender, mapped into receiver. Sender loses them.
    Move,
    /// Pages are mapped read-only into both. Refused for Vault-encrypted pages
    /// mid-rotation, because the receiver would hold a mapping whose key is
    /// about to change underneath it.
    Share,
}

/// A message in flight.
pub struct Message<'a> {
    pub label: u32,
    pub inline: &'a [u8],
    pub pages: Option<PageGrant>,
    /// Capabilities being delegated alongside the message. This is how a
    /// process hands a driver access to a buffer it just allocated.
    pub caps: &'a [Capability],
}

#[derive(Debug, Clone, Copy)]
pub struct PageGrant {
    pub base: u64,
    pub page_count: u32,
    pub mode: Grant,
}

/// State of a synchronous endpoint.
enum EndpointState {
    Idle,
    /// A receiver is parked waiting for a sender.
    ReceiverWaiting(ThreadId),
    /// Senders are queued because no receiver is available.
    SendersQueued,
}

pub struct Endpoint {
    id: EndpointId,
    owner: Pid,
    state: spin::Mutex<EndpointState>,
    send_queue: spin::Mutex<heapless::Deque<ThreadId, 64>>,
    /// Incremented on every completed call; exposed to the scheduler so an
    /// endpoint under heavy load can have its server thread boosted.
    traffic: AtomicU64,
}

impl Endpoint {
    pub fn new(id: EndpointId, owner: Pid) -> Self {
        Endpoint {
            id,
            owner,
            state: spin::Mutex::new(EndpointState::Idle),
            send_queue: spin::Mutex::new(heapless::Deque::new()),
            traffic: AtomicU64::new(0),
        }
    }

    /// Synchronous call: send and block for the reply.
    ///
    /// The fast path — a receiver is already parked — performs a direct handoff
    /// with **no scheduler involvement**. `sched::switch_to_donating` moves us
    /// straight into the receiver on the current CPU, carrying our remaining
    /// timeslice with us. That donation is what keeps a chain of
    /// `app -> vfs -> spectrefs -> nvme driver` from burning four full
    /// scheduling quanta and blowing the latency budget.
    pub fn call(
        &self,
        caller: &Capability,
        msg: Message<'_>,
        deadline_ns: Option<u64>,
    ) -> Result<usize, IpcError> {
        if !caller.permits(Rights::SEND) {
            return Err(IpcError::Denied);
        }
        if msg.inline.len() > INLINE_MAX && msg.pages.is_none() {
            return Err(IpcError::TooLarge);
        }

        let me = sched::current_thread();
        let mut state = self.state.lock();

        match core::mem::replace(&mut *state, EndpointState::Idle) {
            EndpointState::ReceiverWaiting(receiver) => {
                // Fast path. Stage the payload, then hand off directly.
                stage_payload(me, receiver, &msg)?;
                self.traffic.fetch_add(1, Ordering::Relaxed);
                drop(state);

                // Donating switch: we block, receiver runs on our quantum.
                sched::switch_to_donating(receiver, me);
                collect_reply(me)
            }
            EndpointState::Idle | EndpointState::SendersQueued => {
                // Slow path: park until a receiver shows up.
                *state = EndpointState::SendersQueued;
                let mut q = self.send_queue.lock();
                if q.push_back(me).is_err() {
                    return Err(IpcError::Overflow);
                }
                drop(q);
                drop(state);

                match deadline_ns {
                    Some(d) => sched::block_until(me, d).map_err(|_| IpcError::TimedOut)?,
                    None => sched::block(me),
                }
                collect_reply(me)
            }
        }
    }

    /// Block waiting for an incoming call. Returns the sender so the server can
    /// reply.
    pub fn receive(&self, holder: &Capability) -> Result<(ThreadId, usize), IpcError> {
        if !holder.permits(Rights::RECEIVE) {
            return Err(IpcError::Denied);
        }

        let me = sched::current_thread();
        let mut q = self.send_queue.lock();

        if let Some(sender) = q.pop_front() {
            // A sender was already waiting; take its message and keep running.
            drop(q);
            let len = commit_payload(sender, me)?;
            self.traffic.fetch_add(1, Ordering::Relaxed);
            return Ok((sender, len));
        }
        drop(q);

        *self.state.lock() = EndpointState::ReceiverWaiting(me);
        sched::block(me);

        let sender = sched::handoff_partner(me).ok_or(IpcError::PeerGone)?;
        let len = commit_payload(sender, me)?;
        Ok((sender, len))
    }

    /// Reply to a completed call and wake the caller.
    ///
    /// Symmetric donation: the server gives its remaining quantum back to the
    /// caller, so a request/reply round trip costs one quantum total rather
    /// than two. Without this, a Prism frame that touches three servers would
    /// miss its 144 Hz deadline under load.
    pub fn reply(&self, to: ThreadId, msg: Message<'_>) -> Result<(), IpcError> {
        let me = sched::current_thread();
        stage_payload(me, to, &msg)?;
        sched::wake_donating(to, me);
        Ok(())
    }

    pub fn traffic(&self) -> u64 {
        self.traffic.load(Ordering::Relaxed)
    }
}

// ---------------------------------------------------------------------------
// Asynchronous notification ports
// ---------------------------------------------------------------------------

/// Bounded, lock-free-on-the-producer-side notification ring.
///
/// Sized at 256 slots: large enough that a Prism vsync burst or an NVMe
/// completion storm does not drop under normal load, small enough that the
/// whole ring stays in two cache lines' worth of index state plus 4 KiB of
/// payload.
pub struct Port {
    ring: [spin::Mutex<Option<Notification>>; Self::SLOTS],
    head: AtomicU32,
    tail: AtomicU32,
    /// Count of messages dropped due to a full ring. The receiver reads and
    /// clears this; a nonzero value means "you missed events, resynchronise
    /// from authoritative state" — which is exactly the contract a driver
    /// needs, and is why dropping is safe here but would not be for `call`.
    dropped: AtomicU32,
    waiter: spin::Mutex<Option<ThreadId>>,
}

#[derive(Debug, Clone, Copy)]
pub struct Notification {
    pub label: u32,
    pub payload: [u8; 24],
    pub from: Pid,
}

impl Port {
    const SLOTS: usize = 256;

    pub const fn new() -> Self {
        #[allow(clippy::declare_interior_mutable_const)]
        const EMPTY: spin::Mutex<Option<Notification>> = spin::Mutex::new(None);
        Port {
            ring: [EMPTY; Self::SLOTS],
            head: AtomicU32::new(0),
            tail: AtomicU32::new(0),
            dropped: AtomicU32::new(0),
            waiter: spin::Mutex::new(None),
        }
    }

    /// Non-blocking send. Safe to call from an interrupt context — this is the
    /// only IPC primitive that is.
    pub fn post(&self, cap: &Capability, note: Notification) -> Result<(), IpcError> {
        if !cap.permits(Rights::SEND) {
            return Err(IpcError::Denied);
        }

        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);

        if head.wrapping_sub(tail) as usize >= Self::SLOTS {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return Err(IpcError::Overflow);
        }

        let slot = (head as usize) % Self::SLOTS;
        *self.ring[slot].lock() = Some(note);
        self.head.store(head.wrapping_add(1), Ordering::Release);

        // Wake a parked receiver without taking the scheduler lock in IRQ
        // context: `wake_deferred` queues the wakeup for the next scheduler
        // entry, which is at worst one tick away.
        if let Some(t) = *self.waiter.lock() {
            sched::wake_deferred(t);
        }

        Ok(())
    }

    pub fn try_recv(&self, cap: &Capability) -> Result<Option<Notification>, IpcError> {
        if !cap.permits(Rights::RECEIVE) {
            return Err(IpcError::Denied);
        }

        let tail = self.tail.load(Ordering::Relaxed);
        if tail == self.head.load(Ordering::Acquire) {
            return Ok(None);
        }

        let slot = (tail as usize) % Self::SLOTS;
        let note = self.ring[slot].lock().take();
        self.tail.store(tail.wrapping_add(1), Ordering::Release);
        Ok(note)
    }

    /// Read and reset the drop counter.
    pub fn take_drop_count(&self) -> u32 {
        self.dropped.swap(0, Ordering::Relaxed)
    }
}

impl Default for Port {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Payload staging. These touch per-thread state and the page tables; they are
// separated from the endpoint logic so the concurrency reasoning above stays
// legible.
// ---------------------------------------------------------------------------

fn stage_payload(from: ThreadId, to: ThreadId, msg: &Message<'_>) -> Result<(), IpcError> {
    crate::thread::with_message_buffer(from, |buf| {
        buf.label = msg.label;
        buf.len = msg.inline.len();
        buf.bytes[..msg.inline.len()].copy_from_slice(msg.inline);
        buf.pages = msg.pages;
        buf.cap_count = msg.caps.len().min(buf.caps.len());
        buf.caps[..buf.cap_count].copy_from_slice(&msg.caps[..buf.cap_count]);
    });
    crate::thread::set_handoff_partner(to, from);
    Ok(())
}

fn commit_payload(from: ThreadId, to: ThreadId) -> Result<usize, IpcError> {
    // Page donation happens here, not in `stage_payload`, so that a sender that
    // times out before a receiver arrives never loses its pages.
    crate::thread::with_message_buffer(from, |buf| -> Result<usize, IpcError> {
        if let Some(grant) = buf.pages {
            crate::vault::transfer_pages(from, to, grant).map_err(|_| IpcError::Denied)?;
        }
        crate::thread::deliver_caps(from, to, buf.cap_count);
        Ok(buf.len)
    })
}

fn collect_reply(me: ThreadId) -> Result<usize, IpcError> {
    match crate::thread::reply_status(me) {
        crate::thread::ReplyStatus::Ready(len) => Ok(len),
        crate::thread::ReplyStatus::PeerGone => Err(IpcError::PeerGone),
        crate::thread::ReplyStatus::TimedOut => Err(IpcError::TimedOut),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cap::Object;

    fn send_cap() -> Capability {
        Capability::mint(Object::Endpoint(7), Rights::SEND)
    }
    fn recv_cap() -> Capability {
        Capability::mint(Object::Endpoint(7), Rights::RECEIVE)
    }

    #[test]
    fn post_requires_send_right() {
        let port = Port::new();
        let note = Notification {
            label: 1,
            payload: [0; 24],
            from: Pid(2),
        };
        assert_eq!(port.post(&recv_cap(), note), Err(IpcError::Denied));
        assert!(port.post(&send_cap(), note).is_ok());
    }

    #[test]
    fn ring_drops_and_counts_rather_than_blocking() {
        let port = Port::new();
        let cap = send_cap();
        let note = Notification {
            label: 1,
            payload: [0; 24],
            from: Pid(2),
        };

        for _ in 0..Port::SLOTS {
            assert!(port.post(&cap, note).is_ok());
        }
        assert_eq!(port.post(&cap, note), Err(IpcError::Overflow));
        assert_eq!(port.take_drop_count(), 1);
        assert_eq!(port.take_drop_count(), 0, "counter must reset on read");
    }

    #[test]
    fn ring_wraps_correctly_over_many_cycles() {
        let port = Port::new();
        let s = send_cap();
        let r = recv_cap();
        let note = Notification {
            label: 9,
            payload: [0; 24],
            from: Pid(3),
        };

        for _ in 0..(Port::SLOTS * 4) {
            port.post(&s, note).unwrap();
            let got = port.try_recv(&r).unwrap();
            assert_eq!(got.map(|n| n.label), Some(9));
        }
        assert_eq!(port.take_drop_count(), 0);
    }

    #[test]
    fn oversized_inline_without_pages_is_rejected() {
        let ep = Endpoint::new(7, Pid(1));
        let big = [0u8; INLINE_MAX + 1];
        let msg = Message {
            label: 0,
            inline: &big,
            pages: None,
            caps: &[],
        };
        assert_eq!(ep.call(&send_cap(), msg, None), Err(IpcError::TooLarge));
    }
}
