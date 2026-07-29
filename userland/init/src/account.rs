//! One local WhisezOS account, its on-disk verifier, and the sign-in workflow.
//!
//! Passwords never leave this module as stored text. The disk record contains
//! a public salt and an iterated BLAKE3 verifier; the live form buffers are
//! cleared whenever a step completes, fails, locks, or leaves Settings.

#![allow(dead_code)]

use crate::blake3;
use crate::keymap::Key;

pub const FILE_NAME: &[u8] = b".WHISEZ-ACCOUNT";
pub const RECORD_BYTES: usize = 128;
pub const USERNAME_MAX: usize = 24;
pub const PASSWORD_MAX: usize = 48;
pub const PASSWORD_MIN: usize = 6;

const MAGIC: [u8; 8] = *b"WHZACCT1";
const VERSION: u32 = 1;
const KDF_ROUNDS: u32 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record {
    username: [u8; USERNAME_MAX],
    username_len: u8,
    salt: [u8; 16],
    verifier: [u8; 32],
}

impl Record {
    #[must_use]
    pub fn create(username: &[u8], password: &[u8], tick: u64, previous: Option<&Self>) -> Self {
        let mut held_name = [0u8; USERNAME_MAX];
        let name_len = username.len().min(USERNAME_MAX);
        held_name[..name_len].copy_from_slice(&username[..name_len]);
        let salt = make_salt(&held_name[..name_len], tick, previous);
        let verifier = password_verifier(&held_name[..name_len], password, &salt);
        Self {
            username: held_name,
            username_len: name_len as u8,
            salt,
            verifier,
        }
    }

    #[must_use]
    pub fn username(&self) -> &[u8] {
        &self.username[..self.username_len as usize]
    }

    #[must_use]
    pub fn verify(&self, password: &[u8]) -> bool {
        let candidate = password_verifier(self.username(), password, &self.salt);
        constant_time_equal(&candidate, &self.verifier)
    }

    #[must_use]
    pub fn encode(&self) -> [u8; RECORD_BYTES] {
        let mut out = [0u8; RECORD_BYTES];
        out[..8].copy_from_slice(&MAGIC);
        out[8..12].copy_from_slice(&VERSION.to_le_bytes());
        out[12] = self.username_len;
        out[16..32].copy_from_slice(&self.salt);
        out[32..64].copy_from_slice(&self.verifier);
        out[64..64 + USERNAME_MAX].copy_from_slice(&self.username);
        let checksum = blake3::blake3(&out[..96]);
        out[96..128].copy_from_slice(&checksum);
        out
    }

    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != RECORD_BYTES || bytes[..8] != MAGIC {
            return None;
        }
        let version = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        if version != VERSION
            || bytes[13..16].iter().any(|byte| *byte != 0)
            || bytes[88..96].iter().any(|byte| *byte != 0)
        {
            return None;
        }
        let expected = blake3::blake3(&bytes[..96]);
        if !constant_time_equal(&expected, &bytes[96..128]) {
            return None;
        }
        let username_len = bytes[12] as usize;
        if username_len == 0 || username_len > USERNAME_MAX {
            return None;
        }
        let username = &bytes[64..64 + username_len];
        if !valid_username(username)
            || bytes[64 + username_len..64 + USERNAME_MAX]
                .iter()
                .any(|b| *b != 0)
        {
            return None;
        }
        let mut record = Self {
            username: [0; USERNAME_MAX],
            username_len: username_len as u8,
            salt: [0; 16],
            verifier: [0; 32],
        };
        record
            .username
            .copy_from_slice(&bytes[64..64 + USERNAME_MAX]);
        record.salt.copy_from_slice(&bytes[16..32]);
        record.verifier.copy_from_slice(&bytes[32..64]);
        Some(record)
    }
}

fn make_salt(username: &[u8], tick: u64, previous: Option<&Record>) -> [u8; 16] {
    let mut seed = [0u8; 96];
    let domain = b"WhisezOS local account salt v1";
    seed[..domain.len()].copy_from_slice(domain);
    let mut at = domain.len();
    seed[at..at + 8].copy_from_slice(&tick.to_le_bytes());
    at += 8;
    seed[at..at + username.len()].copy_from_slice(username);
    at += username.len();
    if let Some(old) = previous {
        seed[at..at + old.salt.len()].copy_from_slice(&old.salt);
        at += old.salt.len();
        seed[at..at + old.verifier.len()].copy_from_slice(&old.verifier);
        at += old.verifier.len();
    }
    let digest = blake3::blake3(&seed[..at]);
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&digest[..16]);
    salt
}

fn password_verifier(username: &[u8], password: &[u8], salt: &[u8; 16]) -> [u8; 32] {
    let mut material = [0u8; 128];
    let domain = b"WhisezOS password verifier v1";
    material[..domain.len()].copy_from_slice(domain);
    let mut at = domain.len();
    material[at..at + salt.len()].copy_from_slice(salt);
    at += salt.len();
    material[at..at + username.len()].copy_from_slice(username);
    at += username.len();
    material[at..at + password.len()].copy_from_slice(password);
    at += password.len();
    let mut state = blake3::blake3(&material[..at]);

    for round in 0..KDF_ROUNDS {
        material.fill(0);
        material[..state.len()].copy_from_slice(&state);
        let mut next = state.len();
        material[next..next + salt.len()].copy_from_slice(salt);
        next += salt.len();
        material[next..next + password.len()].copy_from_slice(password);
        next += password.len();
        material[next..next + username.len()].copy_from_slice(username);
        next += username.len();
        material[next..next + 4].copy_from_slice(&round.to_le_bytes());
        next += 4;
        state = blake3::blake3(&material[..next]);
    }
    material.fill(0);
    state
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right) {
        difference |= a ^ b;
    }
    difference == 0
}

#[must_use]
pub fn valid_username(name: &[u8]) -> bool {
    !name.is_empty()
        && name.len() <= USERNAME_MAX
        && name
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-' | b'.'))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    SetupName,
    SetupPassword,
    SetupConfirm,
    LoginPassword,
    Desktop,
    SettingsHome,
    ChangeCurrent,
    ChangeNew,
    ChangeConfirm,
    SavingSetup,
    SavingChange,
    Damaged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    None,
    NameInvalid,
    PasswordShort,
    PasswordMismatch,
    WrongPassword,
    SignedIn,
    PasswordChanged,
    SaveFailed,
    Locked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    None,
    Redraw,
    Persist(Record),
}

pub struct State {
    record: Option<Record>,
    pending_record: Option<Record>,
    stage: Stage,
    status: Status,
    unlocked: bool,
    input: [u8; PASSWORD_MAX],
    input_len: usize,
    setup_name: [u8; USERNAME_MAX],
    setup_name_len: usize,
    first_password: [u8; PASSWORD_MAX],
    first_password_len: usize,
}

impl State {
    #[must_use]
    pub const fn new(record: Option<Record>) -> Self {
        Self {
            record,
            pending_record: None,
            stage: if record.is_some() {
                Stage::LoginPassword
            } else {
                Stage::SetupName
            },
            status: Status::None,
            unlocked: false,
            input: [0; PASSWORD_MAX],
            input_len: 0,
            setup_name: [0; USERNAME_MAX],
            setup_name_len: 0,
            first_password: [0; PASSWORD_MAX],
            first_password_len: 0,
        }
    }

    #[must_use]
    pub const fn damaged() -> Self {
        let mut state = Self::new(None);
        state.stage = Stage::Damaged;
        state
    }

    #[must_use]
    pub const fn stage(&self) -> Stage {
        self.stage
    }

    #[must_use]
    pub const fn status(&self) -> Status {
        self.status
    }

    #[must_use]
    pub const fn unlocked(&self) -> bool {
        self.unlocked
    }

    #[must_use]
    pub fn username(&self) -> &[u8] {
        if let Some(record) = &self.record {
            record.username()
        } else {
            &self.setup_name[..self.setup_name_len]
        }
    }

    #[must_use]
    pub fn input(&self) -> &[u8] {
        &self.input[..self.input_len]
    }

    #[must_use]
    pub const fn input_is_secret(&self) -> bool {
        !matches!(self.stage, Stage::SetupName)
    }

    pub fn apply(&mut self, key: Key, tick: u64) -> Action {
        match key {
            Key::Char(byte) => {
                if self.accepts(byte) && self.input_len < self.input.len() {
                    self.input[self.input_len] = byte;
                    self.input_len += 1;
                    self.status = Status::None;
                    Action::Redraw
                } else {
                    Action::None
                }
            }
            Key::Backspace => {
                if self.input_len != 0 {
                    self.input_len -= 1;
                    self.input[self.input_len] = 0;
                    self.status = Status::None;
                    Action::Redraw
                } else {
                    Action::None
                }
            }
            Key::Enter => self.submit(tick),
            Key::None
            | Key::Left
            | Key::Right
            | Key::Up
            | Key::Down
            | Key::Home
            | Key::End
            | Key::Delete
            | Key::Save => Action::None,
        }
    }

    fn accepts(&self, byte: u8) -> bool {
        match self.stage {
            Stage::SetupName => byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'),
            Stage::SetupPassword
            | Stage::SetupConfirm
            | Stage::LoginPassword
            | Stage::ChangeCurrent
            | Stage::ChangeNew
            | Stage::ChangeConfirm => (0x20..=0x7E).contains(&byte),
            _ => false,
        }
    }

    pub fn submit(&mut self, tick: u64) -> Action {
        match self.stage {
            Stage::SetupName => {
                if !valid_username(self.input()) {
                    self.status = Status::NameInvalid;
                    return Action::Redraw;
                }
                self.setup_name_len = self.input_len.min(USERNAME_MAX);
                self.setup_name[..self.setup_name_len]
                    .copy_from_slice(&self.input[..self.setup_name_len]);
                self.clear_input();
                self.stage = Stage::SetupPassword;
                self.status = Status::None;
                Action::Redraw
            }
            Stage::SetupPassword => {
                if self.input_len < PASSWORD_MIN {
                    self.status = Status::PasswordShort;
                    return Action::Redraw;
                }
                self.first_password_len = self.input_len;
                self.first_password[..self.input_len]
                    .copy_from_slice(&self.input[..self.input_len]);
                self.clear_input();
                self.stage = Stage::SetupConfirm;
                self.status = Status::None;
                Action::Redraw
            }
            Stage::SetupConfirm => {
                if !constant_time_equal(
                    self.input(),
                    &self.first_password[..self.first_password_len],
                ) {
                    self.clear_input();
                    self.status = Status::PasswordMismatch;
                    return Action::Redraw;
                }
                let record = Record::create(
                    &self.setup_name[..self.setup_name_len],
                    &self.first_password[..self.first_password_len],
                    tick,
                    None,
                );
                self.pending_record = Some(record);
                self.clear_secrets();
                self.stage = Stage::SavingSetup;
                Action::Persist(record)
            }
            Stage::LoginPassword => {
                let valid = self
                    .record
                    .as_ref()
                    .is_some_and(|record| record.verify(self.input()));
                self.clear_input();
                if valid {
                    self.unlocked = true;
                    self.stage = Stage::Desktop;
                    self.status = Status::SignedIn;
                } else {
                    self.status = Status::WrongPassword;
                }
                Action::Redraw
            }
            Stage::SettingsHome => {
                self.begin_change();
                Action::Redraw
            }
            Stage::ChangeCurrent => {
                let valid = self
                    .record
                    .as_ref()
                    .is_some_and(|record| record.verify(self.input()));
                self.clear_input();
                if valid {
                    self.stage = Stage::ChangeNew;
                    self.status = Status::None;
                } else {
                    self.status = Status::WrongPassword;
                }
                Action::Redraw
            }
            Stage::ChangeNew => {
                if self.input_len < PASSWORD_MIN {
                    self.status = Status::PasswordShort;
                    return Action::Redraw;
                }
                self.first_password_len = self.input_len;
                self.first_password[..self.input_len]
                    .copy_from_slice(&self.input[..self.input_len]);
                self.clear_input();
                self.stage = Stage::ChangeConfirm;
                self.status = Status::None;
                Action::Redraw
            }
            Stage::ChangeConfirm => {
                if !constant_time_equal(
                    self.input(),
                    &self.first_password[..self.first_password_len],
                ) {
                    self.clear_input();
                    self.status = Status::PasswordMismatch;
                    return Action::Redraw;
                }
                let Some(previous) = self.record else {
                    self.status = Status::SaveFailed;
                    return Action::Redraw;
                };
                let record = Record::create(
                    previous.username(),
                    &self.first_password[..self.first_password_len],
                    tick,
                    Some(&previous),
                );
                self.pending_record = Some(record);
                self.clear_secrets();
                self.stage = Stage::SavingChange;
                Action::Persist(record)
            }
            Stage::Desktop | Stage::SavingSetup | Stage::SavingChange | Stage::Damaged => {
                Action::None
            }
        }
    }

    pub fn persisted(&mut self, success: bool) {
        let setup = self.stage == Stage::SavingSetup;
        let change = self.stage == Stage::SavingChange;
        if !setup && !change {
            return;
        }
        if success {
            self.record = self.pending_record.take();
            self.unlocked = true;
            self.stage = if setup {
                Stage::Desktop
            } else {
                Stage::SettingsHome
            };
            self.status = if setup {
                Status::SignedIn
            } else {
                Status::PasswordChanged
            };
        } else {
            self.pending_record = None;
            self.unlocked = !setup;
            self.stage = if setup {
                Stage::SetupPassword
            } else {
                Stage::ChangeNew
            };
            self.status = Status::SaveFailed;
        }
    }

    pub fn begin_settings(&mut self) {
        if self.unlocked && self.stage == Stage::Desktop {
            self.clear_secrets();
            self.stage = Stage::SettingsHome;
            self.status = Status::None;
        }
    }

    pub fn leave_settings(&mut self) {
        if self.unlocked {
            self.clear_secrets();
            self.stage = Stage::Desktop;
            self.status = Status::None;
        }
    }

    pub fn begin_change(&mut self) {
        if self.unlocked {
            self.clear_secrets();
            self.stage = Stage::ChangeCurrent;
            self.status = Status::None;
        }
    }

    pub fn lock(&mut self) {
        if self.record.is_none() {
            return;
        }
        self.clear_secrets();
        self.unlocked = false;
        self.stage = Stage::LoginPassword;
        self.status = Status::Locked;
    }

    fn clear_input(&mut self) {
        self.input.fill(0);
        self.input_len = 0;
    }

    fn clear_secrets(&mut self) {
        self.clear_input();
        self.first_password.fill(0);
        self.first_password_len = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn type_text(state: &mut State, text: &[u8], tick: u64) -> Action {
        for byte in text {
            let _ = state.apply(Key::Char(*byte), tick);
        }
        state.apply(Key::Enter, tick)
    }

    fn create_account() -> (State, Record) {
        let mut state = State::new(None);
        assert_eq!(type_text(&mut state, b"whisez", 10), Action::Redraw);
        assert_eq!(type_text(&mut state, b"secret1", 11), Action::Redraw);
        let Action::Persist(record) = type_text(&mut state, b"secret1", 12) else {
            panic!("setup did not request persistence");
        };
        state.persisted(true);
        (state, record)
    }

    #[test]
    fn record_round_trips_without_storing_the_password() {
        let record = Record::create(b"whisez", b"secret1", 44, None);
        let encoded = record.encode();
        assert!(!encoded.windows(7).any(|window| window == b"secret1"));
        assert_eq!(Record::decode(&encoded), Some(record));
        assert!(record.verify(b"secret1"));
        assert!(!record.verify(b"secret2"));
    }

    #[test]
    fn corruption_is_refused() {
        let record = Record::create(b"owner", b"password", 1, None);
        let mut encoded = record.encode();
        encoded[40] ^= 0x80;
        assert_eq!(Record::decode(&encoded), None);
    }

    #[test]
    fn setup_requires_a_name_and_matching_passwords() {
        let mut state = State::new(None);
        assert_eq!(state.submit(0), Action::Redraw);
        assert_eq!(state.status(), Status::NameInvalid);
        type_text(&mut state, b"owner", 1);
        type_text(&mut state, b"123", 2);
        assert_eq!(state.status(), Status::PasswordShort);
        while state.input_len != 0 {
            state.apply(Key::Backspace, 2);
        }
        type_text(&mut state, b"password", 3);
        type_text(&mut state, b"different", 4);
        assert_eq!(state.status(), Status::PasswordMismatch);
        assert!(!state.unlocked());
    }

    #[test]
    fn saved_setup_unlocks_and_a_lock_requires_the_password() {
        let (mut state, record) = create_account();
        assert!(state.unlocked());
        state.lock();
        assert!(!state.unlocked());
        type_text(&mut state, b"wrong", 20);
        assert_eq!(state.status(), Status::WrongPassword);
        type_text(&mut state, b"secret1", 21);
        assert!(state.unlocked());
        assert_eq!(state.username(), record.username());
    }

    #[test]
    fn password_change_requires_the_old_password_and_persistence() {
        let (mut state, old) = create_account();
        state.begin_settings();
        state.begin_change();
        type_text(&mut state, b"wrong", 30);
        assert_eq!(state.status(), Status::WrongPassword);
        type_text(&mut state, b"secret1", 31);
        type_text(&mut state, b"newpass1", 32);
        let Action::Persist(new) = type_text(&mut state, b"newpass1", 33) else {
            panic!("change did not request persistence");
        };
        assert_ne!(old.salt, new.salt);
        state.persisted(true);
        state.lock();
        type_text(&mut state, b"secret1", 34);
        assert_eq!(state.status(), Status::WrongPassword);
        type_text(&mut state, b"newpass1", 35);
        assert!(state.unlocked());
    }

    #[test]
    fn a_failed_save_restarts_at_a_step_that_has_no_erased_secret() {
        let mut setup = State::new(None);
        type_text(&mut setup, b"owner", 1);
        type_text(&mut setup, b"password", 2);
        assert!(matches!(
            type_text(&mut setup, b"password", 3),
            Action::Persist(_)
        ));
        setup.persisted(false);
        assert_eq!(setup.stage(), Stage::SetupPassword);
        assert_eq!(setup.status(), Status::SaveFailed);

        let (mut change, _) = create_account();
        change.begin_settings();
        change.begin_change();
        type_text(&mut change, b"secret1", 4);
        type_text(&mut change, b"newpass1", 5);
        assert!(matches!(
            type_text(&mut change, b"newpass1", 6),
            Action::Persist(_)
        ));
        change.persisted(false);
        assert_eq!(change.stage(), Stage::ChangeNew);
        assert!(change.unlocked());
    }
}
