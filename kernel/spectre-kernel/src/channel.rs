//! Endpoints: the kernel side of synchronous IPC.
//!
//! `rendezvous.rs` decides what a call, a receive, or a reply does to an
//! exchange. This is what makes those decisions real — the buffer the message
//! sits in, the pointer validation at both ends, and the blocking and waking of
//! the processes involved.
//!
//! # The handle is the capability
//!
//! An endpoint is named by a 64-bit value a process cannot compute. Nothing
//! else gates access: hold the number and you may send to it; own it and you
//! may receive. That is the whole authority model here, and it is deliberately
//! a placeholder — `cap.rs` specifies 128-bit tokens with rights and
//! revocation, and it is written and tested but reaches subsystems that do not
//! link yet.
//!
//! What matters is that it is not *ambient*. A process is handed the handles it
//! may use; it cannot enumerate them and it cannot construct one, so it reaches
//! exactly the services it was introduced to and no others.
//!
//! # The copy happens twice, on purpose
//!
//! A message goes sender → kernel buffer → receiver rather than straight
//! across. A direct copy needs both address spaces reachable at the same
//! moment, which means either a window into the other space or a switch
//! mid-copy — more machinery than a 256-byte memcpy is worth, and both put two
//! processes' pointers live simultaneously, which is precisely the arrangement
//! where one process's mistake becomes another's.
//!
//! The second copy is the interesting one: it lands in a process that is not
//! running, so it goes through that process's page tables and the identity map
//! (`arch::user::copy_into_space`), and it re-checks that the destination is
//! actually writable by its owner.

#![allow(dead_code)]

use spin::Mutex;

use crate::abi::{self, SyscallError, MAX_MESSAGE_BYTES};
use crate::arch::addr::PhysAddr;
use crate::rendezvous::{Action, Rendezvous};
use crate::usercopy::validate_user_range;

/// Endpoints the kernel can hold.
pub const MAX_ENDPOINTS: usize = 8;

/// Where a blocked process wants bytes written, and in whose address space.
#[derive(Debug, Clone, Copy)]
struct Target {
    pid: u64,
    root: PhysAddr,
    ptr: u64,
    capacity: u64,
}

#[derive(Clone, Copy)]
struct Endpoint {
    /// Zero when the slot is unused. Also the handle user space holds.
    handle: u64,
    exchange: Rendezvous,
    /// The message in flight, in whichever direction it is travelling.
    buffer: [u8; MAX_MESSAGE_BYTES],
    len: usize,
    /// Where the blocked sender wants its reply. Recorded when the call is
    /// made, while the sender's address space is still active, because that is
    /// the only moment its pointer can be validated against its own regions.
    reply_to: Option<Target>,
    /// Where a blocked receiver wants the message.
    receive_into: Option<Target>,
}

impl Endpoint {
    const EMPTY: Self = Self {
        handle: 0,
        exchange: Rendezvous::new(0),
        buffer: [0; MAX_MESSAGE_BYTES],
        len: 0,
        reply_to: None,
        receive_into: None,
    };
}

struct Table {
    slots: [Endpoint; MAX_ENDPOINTS],
    /// Xorshift state for handle generation.
    entropy: u64,
    /// Completed exchanges, reported at shutdown.
    exchanges: u64,
}

static TABLE: Mutex<Table> = Mutex::new(Table {
    slots: [Endpoint::EMPTY; MAX_ENDPOINTS],
    entropy: 0,
    exchanges: 0,
});

/// What the caller must do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Finished; return this value to user space.
    Return(u64),
    /// The caller has to block. Its frame is saved and something else runs.
    Block,
}

/// Seeds handle generation.
///
/// # Safety
/// Called once during bring-up.
pub unsafe fn init() {
    let mut table = TABLE.lock();
    // SAFETY: `rdtsc` exists on every 64-bit x86 and has no side effects. It is
    // not an entropy source in any serious sense, and is not claimed to be —
    // `cap.rs` specifies the real one.
    let seed = unsafe {
        let (low, high): (u32, u32);
        core::arch::asm!("rdtsc", out("eax") low, out("edx") high, options(nomem, nostack));
        (u64::from(high) << 32) | u64::from(low)
    };
    // A zero state makes the xorshift produce zeros forever, and zero is the
    // value that means "no endpoint".
    table.entropy = seed | 1;
}

fn next_handle(table: &mut Table) -> u64 {
    let mut x = table.entropy;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    table.entropy = x;
    let handle = x.wrapping_mul(0x2545_F491_4F6C_DD1D);
    if handle == 0 {
        1
    } else {
        handle
    }
}

/// Creates an endpoint owned by `owner`, returning its handle.
pub fn create(owner: u64) -> Option<u64> {
    let mut table = TABLE.lock();
    let slot = table.slots.iter().position(|e| e.handle == 0)?;
    let handle = next_handle(&mut table);
    table.slots[slot] = Endpoint {
        handle,
        exchange: Rendezvous::new(owner),
        ..Endpoint::EMPTY
    };
    Some(handle)
}

/// Completed exchanges, for the shutdown report.
#[must_use]
pub fn exchanges() -> u64 {
    TABLE.lock().exchanges
}

fn slot_of(table: &Table, handle: u64) -> Option<usize> {
    if handle == 0 {
        return None;
    }
    table.slots.iter().position(|e| e.handle == handle)
}

/// Reads `len` bytes from the *running* process into `dst`.
fn read_from_current(
    ptr: u64,
    len: u64,
    dst: &mut [u8; MAX_MESSAGE_BYTES],
) -> Result<usize, SyscallError> {
    crate::task::with_current_regions(|regions| {
        validate_user_range(regions, ptr, len, MAX_MESSAGE_BYTES as u64)
    })?;
    let len = len as usize;
    // SAFETY: the range lies inside a region the running process was given, and
    // that process's address space is the one in CR3 — a system call does not
    // switch away before this point.
    unsafe {
        core::ptr::copy_nonoverlapping(ptr as *const u8, dst.as_mut_ptr(), len);
    }
    Ok(len)
}

/// Writes `body` into the *running* process's buffer.
fn write_to_current(ptr: u64, capacity: u64, body: &[u8]) -> Result<usize, SyscallError> {
    if body.len() as u64 > capacity {
        return Err(SyscallError::TooLong);
    }
    crate::task::with_current_regions(|regions| {
        validate_user_range(regions, ptr, capacity, MAX_MESSAGE_BYTES as u64)
    })?;
    // SAFETY: as above, and `body` fits inside the validated capacity.
    unsafe {
        core::ptr::copy_nonoverlapping(body.as_ptr(), ptr as *mut u8, body.len());
    }
    Ok(body.len())
}

/// Writes `body` into a blocked process and wakes it with the length.
///
/// A failure here is the *target's* fault — it named a buffer it cannot write —
/// so it is delivered to the target as the return value of its own blocked
/// call, not to whoever happened to be sending.
fn deliver_and_wake(target: Target, body: &[u8]) {
    let result = if body.len() as u64 > target.capacity {
        Err(SyscallError::TooLong)
    } else {
        // SAFETY: `target.root` belongs to a process that is blocked, so it is
        // not running on any processor, and physical memory is identity mapped.
        // `copy_into_space` re-checks that the destination is writable by its
        // owner before touching it.
        let copied = unsafe { crate::arch::user::copy_into_space(target.root, target.ptr, body) };
        match copied {
            Ok(()) => Ok(body.len() as u64),
            Err(_) => Err(SyscallError::BadPointer),
        }
    };
    crate::task::wake(target.pid, abi::encode(result));
}

/// `SYS_CALL(handle, send_ptr, send_len, reply_ptr, reply_cap) -> reply_len`.
pub fn call(
    caller: u64,
    caller_root: PhysAddr,
    handle: u64,
    send_ptr: u64,
    send_len: u64,
    reply_ptr: u64,
    reply_cap: u64,
) -> Result<Outcome, SyscallError> {
    // The reply buffer is checked now, while the caller's space is active. When
    // the reply actually arrives the kernel will be in somebody else's address
    // space, where this pointer means nothing.
    crate::task::with_current_regions(|regions| {
        validate_user_range(regions, reply_ptr, reply_cap, MAX_MESSAGE_BYTES as u64)
    })?;

    let mut staged = [0u8; MAX_MESSAGE_BYTES];
    let len = read_from_current(send_ptr, send_len, &mut staged)?;

    let mut table = TABLE.lock();
    let slot = slot_of(&table, handle).ok_or(SyscallError::BadEndpoint)?;
    let action = table.slots[slot].exchange.call(caller, len)?;

    table.slots[slot].buffer = staged;
    table.slots[slot].len = len;
    table.slots[slot].reply_to = Some(Target {
        pid: caller,
        root: caller_root,
        ptr: reply_ptr,
        capacity: reply_cap,
    });

    match action {
        Action::BlockSender => Ok(Outcome::Block),
        Action::DeliverToWaitingReceiver { .. } => {
            let target = table.slots[slot].receive_into.take();
            let body = table.slots[slot].buffer;
            drop(table);
            if let Some(target) = target {
                deliver_and_wake(target, &body[..len]);
            }
            // The sender blocks either way: it is waiting for the reply, not
            // for the message to be taken.
            Ok(Outcome::Block)
        }
        _ => Err(SyscallError::Busy),
    }
}

/// `SYS_RECEIVE(handle, buf_ptr, buf_cap) -> len`.
pub fn receive(
    receiver: u64,
    receiver_root: PhysAddr,
    handle: u64,
    buf_ptr: u64,
    buf_cap: u64,
) -> Result<Outcome, SyscallError> {
    crate::task::with_current_regions(|regions| {
        validate_user_range(regions, buf_ptr, buf_cap, MAX_MESSAGE_BYTES as u64)
    })?;

    let mut table = TABLE.lock();
    let slot = slot_of(&table, handle).ok_or(SyscallError::BadEndpoint)?;
    let action = table.slots[slot].exchange.receive(receiver)?;

    match action {
        Action::BlockReceiver => {
            table.slots[slot].receive_into = Some(Target {
                pid: receiver,
                root: receiver_root,
                ptr: buf_ptr,
                capacity: buf_cap,
            });
            Ok(Outcome::Block)
        }
        Action::TakeWaitingMessage { len, .. } => {
            let body = table.slots[slot].buffer;
            drop(table);
            // The receiver is the running process, so this is an ordinary copy
            // into the active address space.
            let written = write_to_current(buf_ptr, buf_cap, &body[..len])?;
            Ok(Outcome::Return(written as u64))
        }
        _ => Err(SyscallError::Busy),
    }
}

/// `SYS_REPLY(handle, ptr, len) -> bytes sent`.
pub fn reply(replier: u64, handle: u64, ptr: u64, len: u64) -> Result<Outcome, SyscallError> {
    let mut staged = [0u8; MAX_MESSAGE_BYTES];
    let len = read_from_current(ptr, len, &mut staged)?;

    let mut table = TABLE.lock();
    let slot = slot_of(&table, handle).ok_or(SyscallError::BadEndpoint)?;
    let action = table.slots[slot].exchange.reply(replier, len)?;

    match action {
        Action::WakeSender { .. } => {
            let target = table.slots[slot].reply_to.take();
            table.slots[slot].len = 0;
            table.exchanges += 1;
            drop(table);
            match target {
                Some(target) => {
                    deliver_and_wake(target, &staged[..len]);
                    Ok(Outcome::Return(len as u64))
                }
                // The exchange said a sender was waiting and the bookkeeping
                // says otherwise. Refusing beats waking a slot that may now
                // hold a different process.
                None => Err(SyscallError::NoReplyPending),
            }
        }
        _ => Err(SyscallError::NoReplyPending),
    }
}

/// Releases whatever a departing process was holding.
///
/// Called when a process exits. Without it, a client blocked on a server that
/// died waits forever — and an endpoint owned by a dead process stays busy for
/// the life of the system.
pub fn on_process_gone(pid: u64) {
    let mut woken = None;
    {
        let mut table = TABLE.lock();
        for slot in table.slots.iter_mut() {
            if slot.handle == 0 {
                continue;
            }
            if let Some(stranded) = slot.exchange.on_process_gone(pid) {
                woken = slot.reply_to.take().filter(|t| t.pid == stranded);
            }
            if slot.exchange.owner == pid {
                // The service is gone; the endpoint goes with it.
                *slot = Endpoint::EMPTY;
            } else {
                if slot.reply_to.is_some_and(|t| t.pid == pid) {
                    slot.reply_to = None;
                }
                if slot.receive_into.is_some_and(|t| t.pid == pid) {
                    slot.receive_into = None;
                }
            }
        }
    }
    if let Some(target) = woken {
        crate::task::wake(target.pid, abi::encode(Err(SyscallError::BadEndpoint)));
    }
}
