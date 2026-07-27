//! The synchronous IPC state machine.
//!
//! This is not `ipc.rs`. That one is the full design — badged endpoints, page
//! grants, capability transfer, timeslice donation on handoff — and it is
//! written and tested, but it reaches `cap`, `sched`, `vault`, and `thread`,
//! which between them pull in ten platform modules that do not exist and a
//! crypto dependency that does not compile for this target. This is the part of
//! it that can run today: one endpoint, one message in flight, call and reply.
//!
//! # Why the transitions are a separate, testable thing
//!
//! Rendezvous IPC is four states and three operations, and almost every bug in
//! it is a state that should have been unreachable. A sender that blocks when a
//! receiver was already waiting deadlocks both. A reply accepted from a process
//! that is not the one that received deadlocks the sender for good. A second
//! sender admitted while one is in flight overwrites the message buffer under
//! the first.
//!
//! None of those show up as a crash. They show up as two processes that stop,
//! with no output and nothing to look at. So the transitions are a pure
//! function of the state, returning what the caller must *do* rather than doing
//! it, and the host tests drive every ordering — including the ones that should
//! be refused.

#![allow(dead_code)]

use crate::abi::SyscallError;

/// Which process. Zero is never a live process, so it doubles as "nobody".
pub type Pid = u64;

/// Where an exchange has got to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Nobody is waiting.
    Idle,
    /// A sender is blocked, its message already in the endpoint's buffer.
    SenderWaiting { sender: Pid, len: usize },
    /// The owner is blocked waiting for a message.
    ReceiverWaiting { receiver: Pid },
    /// A message has been delivered and its sender is blocked for the reply.
    AwaitingReply { sender: Pid, receiver: Pid },
}

/// What the caller must do to make a transition real.
///
/// Returned rather than performed because everything here is a decision and
/// nothing here can copy a buffer, block a process, or touch a page table —
/// which is what makes it testable without any of those existing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Copy the message in, then block this process.
    BlockSender,
    /// Block this process; no message to copy yet.
    BlockReceiver,
    /// Copy the message in, hand it straight to the waiting receiver, and wake
    /// it with this length. The sender still blocks, for the reply.
    DeliverToWaitingReceiver { receiver: Pid, len: usize },
    /// A sender was already waiting: take its message and carry on without
    /// blocking.
    TakeWaitingMessage { sender: Pid, len: usize },
    /// Copy the reply in and wake the sender with this length.
    WakeSender { sender: Pid, len: usize },
}

/// One endpoint's exchange state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rendezvous {
    /// The only process allowed to receive and reply.
    pub owner: Pid,
    pub state: State,
}

impl Rendezvous {
    #[must_use]
    pub const fn new(owner: Pid) -> Self {
        Self {
            owner,
            state: State::Idle,
        }
    }

    /// A process sends a message and will block until replied to.
    ///
    /// The owner calling its own endpoint is refused rather than allowed to
    /// deadlock itself against a receive it can no longer reach.
    pub fn call(&mut self, sender: Pid, len: usize) -> Result<Action, SyscallError> {
        if sender == self.owner {
            return Err(SyscallError::BadEndpoint);
        }
        match self.state {
            State::ReceiverWaiting { receiver } => {
                self.state = State::AwaitingReply { sender, receiver };
                Ok(Action::DeliverToWaitingReceiver { receiver, len })
            }
            State::Idle => {
                self.state = State::SenderWaiting { sender, len };
                Ok(Action::BlockSender)
            }
            // One message in flight. A second sender would overwrite the buffer
            // the first one's message is sitting in.
            State::SenderWaiting { .. } | State::AwaitingReply { .. } => Err(SyscallError::Busy),
        }
    }

    /// The owner waits for a message.
    pub fn receive(&mut self, receiver: Pid) -> Result<Action, SyscallError> {
        if receiver != self.owner {
            return Err(SyscallError::BadEndpoint);
        }
        match self.state {
            State::SenderWaiting { sender, len } => {
                self.state = State::AwaitingReply { sender, receiver };
                Ok(Action::TakeWaitingMessage { sender, len })
            }
            State::Idle => {
                self.state = State::ReceiverWaiting { receiver };
                Ok(Action::BlockReceiver)
            }
            State::ReceiverWaiting { .. } | State::AwaitingReply { .. } => Err(SyscallError::Busy),
        }
    }

    /// The owner replies, unblocking the sender.
    pub fn reply(&mut self, replier: Pid, len: usize) -> Result<Action, SyscallError> {
        if replier != self.owner {
            return Err(SyscallError::BadEndpoint);
        }
        match self.state {
            State::AwaitingReply { sender, receiver } if receiver == replier => {
                self.state = State::Idle;
                Ok(Action::WakeSender { sender, len })
            }
            _ => Err(SyscallError::NoReplyPending),
        }
    }

    /// Rewrites the state so a process that has died is no longer waited on.
    ///
    /// Returns the process that must be woken with an error, if the death left
    /// one blocked forever. Without this, a server that exits mid-exchange
    /// leaves its client blocked with nothing that will ever reply.
    pub fn on_process_gone(&mut self, gone: Pid) -> Option<Pid> {
        match self.state {
            State::SenderWaiting { sender, .. } if sender == gone => {
                self.state = State::Idle;
                None
            }
            State::ReceiverWaiting { receiver } if receiver == gone => {
                self.state = State::Idle;
                None
            }
            State::AwaitingReply { sender, receiver } if receiver == gone => {
                self.state = State::Idle;
                Some(sender)
            }
            State::AwaitingReply { sender, .. } if sender == gone => {
                // The receiver is running and will reply into nothing. Leave the
                // exchange open so its reply is refused rather than delivered to
                // whatever occupies the sender's slot next.
                self.state = State::Idle;
                None
            }
            _ => None,
        }
    }

    #[must_use]
    pub const fn is_idle(&self) -> bool {
        matches!(self.state, State::Idle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVER: Pid = 1;
    const CLIENT: Pid = 2;
    const OTHER: Pid = 3;

    fn endpoint() -> Rendezvous {
        Rendezvous::new(SERVER)
    }

    #[test]
    fn a_sender_arriving_first_blocks_and_a_later_receive_takes_the_message() {
        let mut ep = endpoint();
        assert_eq!(ep.call(CLIENT, 16), Ok(Action::BlockSender));
        assert_eq!(
            ep.receive(SERVER),
            Ok(Action::TakeWaitingMessage {
                sender: CLIENT,
                len: 16
            })
        );
        assert_eq!(
            ep.state,
            State::AwaitingReply {
                sender: CLIENT,
                receiver: SERVER
            }
        );
    }

    #[test]
    fn a_receiver_arriving_first_blocks_and_a_later_call_delivers_straight_to_it() {
        let mut ep = endpoint();
        assert_eq!(ep.receive(SERVER), Ok(Action::BlockReceiver));
        assert_eq!(
            ep.call(CLIENT, 8),
            Ok(Action::DeliverToWaitingReceiver {
                receiver: SERVER,
                len: 8
            })
        );
    }

    #[test]
    fn both_orderings_reach_the_same_state() {
        // The two races that exist, and the whole reason this is a state
        // machine: whichever side gets there first, the exchange must end up
        // identical.
        let mut sender_first = endpoint();
        sender_first.call(CLIENT, 4).unwrap();
        sender_first.receive(SERVER).unwrap();

        let mut receiver_first = endpoint();
        receiver_first.receive(SERVER).unwrap();
        receiver_first.call(CLIENT, 4).unwrap();

        assert_eq!(sender_first.state, receiver_first.state);
    }

    #[test]
    fn a_reply_wakes_the_sender_and_returns_the_endpoint_to_idle() {
        let mut ep = endpoint();
        ep.call(CLIENT, 4).unwrap();
        ep.receive(SERVER).unwrap();
        assert_eq!(
            ep.reply(SERVER, 32),
            Ok(Action::WakeSender {
                sender: CLIENT,
                len: 32
            })
        );
        assert!(ep.is_idle());
    }

    #[test]
    fn the_endpoint_is_reusable_after_a_complete_exchange() {
        let mut ep = endpoint();
        for round in 0..4 {
            ep.call(CLIENT, round).unwrap();
            ep.receive(SERVER).unwrap();
            ep.reply(SERVER, round).unwrap();
            assert!(ep.is_idle(), "round {round} left the endpoint stuck");
        }
    }

    #[test]
    fn only_the_owner_may_receive_or_reply() {
        // Otherwise any process that learns a handle can steal messages
        // addressed to the service that owns it.
        let mut ep = endpoint();
        assert_eq!(ep.receive(CLIENT), Err(SyscallError::BadEndpoint));
        assert_eq!(ep.receive(OTHER), Err(SyscallError::BadEndpoint));

        ep.call(CLIENT, 4).unwrap();
        ep.receive(SERVER).unwrap();
        assert_eq!(ep.reply(OTHER, 4), Err(SyscallError::BadEndpoint));
        assert_eq!(ep.reply(CLIENT, 4), Err(SyscallError::BadEndpoint));
        // And the exchange is untouched by the refusals.
        assert_eq!(
            ep.reply(SERVER, 4),
            Ok(Action::WakeSender {
                sender: CLIENT,
                len: 4
            })
        );
    }

    #[test]
    fn the_owner_cannot_call_its_own_endpoint() {
        // It would block waiting for a reply from itself, and the only process
        // that could send one is the process that is now blocked.
        let mut ep = endpoint();
        assert_eq!(ep.call(SERVER, 4), Err(SyscallError::BadEndpoint));
        assert!(ep.is_idle());
    }

    #[test]
    fn a_second_sender_is_refused_rather_than_overwriting_the_first() {
        let mut ep = endpoint();
        ep.call(CLIENT, 4).unwrap();
        assert_eq!(ep.call(OTHER, 4), Err(SyscallError::Busy));
        // And the first sender is still the one waiting.
        assert_eq!(
            ep.state,
            State::SenderWaiting {
                sender: CLIENT,
                len: 4
            }
        );
    }

    #[test]
    fn a_sender_is_refused_while_a_reply_is_outstanding() {
        let mut ep = endpoint();
        ep.call(CLIENT, 4).unwrap();
        ep.receive(SERVER).unwrap();
        assert_eq!(ep.call(OTHER, 4), Err(SyscallError::Busy));
    }

    #[test]
    fn a_second_receive_is_refused() {
        let mut ep = endpoint();
        ep.receive(SERVER).unwrap();
        assert_eq!(ep.receive(SERVER), Err(SyscallError::Busy));
    }

    #[test]
    fn replying_with_nothing_outstanding_is_refused() {
        let mut ep = endpoint();
        assert_eq!(ep.reply(SERVER, 4), Err(SyscallError::NoReplyPending));

        // Waiting for a message is not the same as holding one.
        ep.receive(SERVER).unwrap();
        assert_eq!(ep.reply(SERVER, 4), Err(SyscallError::NoReplyPending));

        // A call delivered straight to the waiting receiver does not need a
        // second `receive` — the receiver is woken holding the message.
        ep.call(CLIENT, 4).unwrap();
        ep.reply(SERVER, 4).unwrap();
        // A second reply to the same message.
        assert_eq!(ep.reply(SERVER, 4), Err(SyscallError::NoReplyPending));
    }

    #[test]
    fn a_dying_server_wakes_the_client_it_would_have_replied_to() {
        // The failure this prevents: a service crashes mid-request and its
        // client waits forever with no output and nothing to look at.
        let mut ep = endpoint();
        ep.call(CLIENT, 4).unwrap();
        ep.receive(SERVER).unwrap();
        assert_eq!(ep.on_process_gone(SERVER), Some(CLIENT));
        assert!(ep.is_idle());
    }

    #[test]
    fn a_dying_blocked_sender_leaves_the_endpoint_usable() {
        let mut ep = endpoint();
        ep.call(CLIENT, 4).unwrap();
        assert_eq!(ep.on_process_gone(CLIENT), None);
        assert!(ep.is_idle());
        // Another client can use it immediately.
        assert_eq!(ep.call(OTHER, 4), Ok(Action::BlockSender));
    }

    #[test]
    fn a_dying_blocked_receiver_leaves_the_endpoint_usable() {
        let mut ep = endpoint();
        ep.receive(SERVER).unwrap();
        assert_eq!(ep.on_process_gone(SERVER), None);
        assert!(ep.is_idle());
    }

    #[test]
    fn a_sender_dying_mid_exchange_does_not_get_a_reply_delivered_to_its_slot() {
        // The slot may be reused by a new process; a reply landing there would
        // wake a process that never sent anything.
        let mut ep = endpoint();
        ep.call(CLIENT, 4).unwrap();
        ep.receive(SERVER).unwrap();
        assert_eq!(ep.on_process_gone(CLIENT), None);
        assert_eq!(ep.reply(SERVER, 4), Err(SyscallError::NoReplyPending));
    }

    #[test]
    fn the_death_of_an_uninvolved_process_changes_nothing() {
        let mut ep = endpoint();
        ep.call(CLIENT, 4).unwrap();
        let before = ep.state;
        assert_eq!(ep.on_process_gone(OTHER), None);
        assert_eq!(ep.state, before);
    }
}
