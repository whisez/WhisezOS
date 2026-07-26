//! SpectreShield behavioural anomaly engine.
//!
//! # Design constraint that shapes everything below
//!
//! The spec asks for "heuristic AI anomaly detection" scanning "every file on
//! read/write, every network packet, every process behavior". Two of those
//! three are affordable. Full content inspection of every read/write is not:
//! at NVMe speeds that is 7 GB/s through a classifier, which no CPU budget
//! survives, and it is also the design that makes traditional AV the most
//! hated process on a gaming machine.
//!
//! So the engine is layered by cost:
//!
//!   L0  Metadata triggers (free)      — every file operation, always.
//!   L1  Behavioural sequence (cheap)  — every process, always.
//!   L2  Content scan (expensive)      — only when L0/L1 raise suspicion, or
//!                                        for newly-written executables.
//!   L3  Sandbox detonation (very)     — only on operator confirmation.
//!
//! L1 is the interesting layer and is what is implemented here.
//!
//! # Why sequences, not signatures
//!
//! A signature engine asks "have I seen this exact thing before". A behavioural
//! engine asks "is this process doing something that only ransomware does".
//! The second generalises to novel malware and is what the "heuristic" in the
//! spec actually means.
//!
//! The signal is not any single syscall — every one of them is something some
//! legitimate program does. It is the *conjunction within a time window*.
//! Enumerating user documents is a backup tool. Enumerating them, reading each,
//! writing high-entropy replacements, and deleting shadow copies, within 90
//! seconds, is ransomware and nothing else.
//!
//! # False positives are the actual product risk
//!
//! An engine that flags a compiler as malware gets disabled within a day, and a
//! disabled engine detects nothing. Every rule below is therefore scored, not
//! binary; scores decay; and known-shape legitimate behaviour is explicitly
//! discounted rather than left to luck. The default action at the top score is
//! *suspend and ask*, not delete — irreversible action on a probabilistic
//! signal is how AV products destroy user data.

use core::sync::atomic::{AtomicU64, Ordering};

/// Observable process behaviours. These come from the kernel's IPC audit hook,
/// not from hooking syscalls in the target — the target cannot see, bypass, or
/// unhook the observer, because the observation happens on the far side of an
/// address-space boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Behaviour {
    /// Walked a user document directory.
    EnumerateUserDocuments,
    /// Read a file it did not create.
    ReadForeignFile,
    /// Wrote a file whose content entropy exceeds 7.5 bits/byte.
    WriteHighEntropy,
    /// Deleted or truncated a SpectreFS snapshot.
    DestroySnapshot,
    /// Renamed many files to a uniform new extension.
    MassRename,
    /// Wrote to another process's executable pages.
    ForeignCodeWrite,
    /// Opened a raw socket or bound a listener.
    RawNetwork,
    /// Connected to an address with no prior DNS resolution — a strong
    /// indicator of hardcoded C2, since normal software resolves names first.
    ConnectWithoutDns,
    /// Read credential stores (KeyVault DB, browser profile, SSH keys).
    CredentialAccess,
    /// Registered for autostart.
    PersistenceInstall,
    /// Requested INTROSPECT or debug privileges.
    PrivilegeRequest,
    /// Loaded an unsigned module into its own address space.
    UnsignedModuleLoad,
    /// Cleared its own audit log entries.
    LogTampering,
}

impl Behaviour {
    /// Base weight. Calibrated so that no single behaviour can reach the
    /// suspend threshold alone — because every single one of these has a
    /// legitimate user.
    fn weight(self) -> u32 {
        use Behaviour::*;
        match self {
            // Individually mundane.
            EnumerateUserDocuments => 5,
            ReadForeignFile => 5,
            RawNetwork => 10,
            WriteHighEntropy => 12,
            // Meaningful on their own but not conclusive.
            MassRename => 18,
            PersistenceInstall => 15,
            CredentialAccess => 20,
            UnsignedModuleLoad => 15,
            ConnectWithoutDns => 22,
            PrivilegeRequest => 18,
            // Very hard to justify.
            DestroySnapshot => 35,
            ForeignCodeWrite => 40,
            LogTampering => 45,
        }
    }
}

/// Combinations that mean far more together than apart. This table is the
/// engine's actual intelligence; the per-behaviour weights above are only a
/// floor.
///
/// Each entry is (required behaviours, window, bonus). The bonus is added once
/// per window when every listed behaviour is present.
struct Combination {
    name: &'static str,
    required: &'static [Behaviour],
    window_ms: u64,
    bonus: u32,
}

const COMBINATIONS: &[Combination] = &[
    Combination {
        // The ransomware shape. Nothing legitimate does all four in 90 s.
        name: "ransomware-encrypt-loop",
        required: &[
            Behaviour::EnumerateUserDocuments,
            Behaviour::ReadForeignFile,
            Behaviour::WriteHighEntropy,
            Behaviour::DestroySnapshot,
        ],
        window_ms: 90_000,
        // 70, not 60. The bonus has to be large enough that the combination is
        // decisive *after* role discounts: a compromised backup agent gets its
        // enumerate and read weights zeroed, so the combination has to carry the
        // score past SUSPEND_THRESHOLD on its own. At 60 that case landed on
        // 107 against a threshold of 110 and only raised an Alert, which is the
        // single worst outcome available — the highest-confidence signature in
        // the engine firing and the user not being asked.
        bonus: 70,
    },
    Combination {
        // Credential theft with exfiltration.
        name: "credential-exfiltration",
        required: &[Behaviour::CredentialAccess, Behaviour::ConnectWithoutDns],
        window_ms: 300_000,
        bonus: 45,
    },
    Combination {
        // Process injection.
        name: "code-injection",
        required: &[Behaviour::ForeignCodeWrite, Behaviour::PrivilegeRequest],
        window_ms: 60_000,
        bonus: 40,
    },
    Combination {
        name: "persistent-implant",
        required: &[
            Behaviour::PersistenceInstall,
            Behaviour::UnsignedModuleLoad,
            Behaviour::LogTampering,
        ],
        window_ms: 600_000,
        bonus: 55,
    },
];

/// Discounts for legitimate software with a malware-adjacent shape.
///
/// Without these, the engine's first three false positives are: a backup tool
/// (enumerate + read + write), a compiler (mass file writes, high entropy in
/// object files), and a disk-encryption utility (read + high-entropy write over
/// everything). All three are things users run constantly.
///
/// The discount is applied only when the process holds the corresponding
/// declared capability *and* was launched by a user action — a malicious
/// process cannot simply declare itself a backup tool, because capabilities
/// come from the parent and the parent is init or the launcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeclaredRole {
    None,
    /// Holds a backup capability; discount enumerate/read/write patterns.
    BackupAgent,
    /// Holds a build capability; discount high-entropy writes to build dirs.
    Compiler,
    /// CipherCore itself; discount high-entropy writes entirely.
    EncryptionTool,
    /// A game under Game Mode; discount raw network and unsigned-module load
    /// (anti-cheat drivers legitimately do both, inside their micro-VM).
    SandboxedAntiCheat,
}

impl DeclaredRole {
    fn discount(self, b: Behaviour) -> u32 {
        use Behaviour::*;
        match (self, b) {
            (DeclaredRole::BackupAgent, EnumerateUserDocuments | ReadForeignFile) => 100,
            // 100, not 90. A 90% discount still leaves 1 point per object file,
            // and a real build writes thousands of them — a Rust workspace build
            // reached Alert in twelve seconds of ordinary work. Partial
            // discounts only make sense for behaviours a role performs
            // occasionally; for the behaviour that *is* the role's job, the
            // security value comes from the non-discountable behaviours below.
            (DeclaredRole::Compiler, WriteHighEntropy) => 100,
            (DeclaredRole::Compiler, MassRename) => 90,
            (DeclaredRole::EncryptionTool, WriteHighEntropy) => 100,
            (DeclaredRole::EncryptionTool, ReadForeignFile) => 60,
            (DeclaredRole::SandboxedAntiCheat, RawNetwork | UnsignedModuleLoad) => 100,
            // Nothing discounts these. A backup tool has no reason to destroy
            // snapshots, and an anti-cheat inside a micro-VM cannot legitimately
            // write another process's code.
            (_, DestroySnapshot | ForeignCodeWrite | LogTampering) => 0,
            _ => 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verdict {
    /// Nothing of note.
    Clean,
    /// Logged, shield icon goes yellow. No user interruption.
    Watch,
    /// Shield goes red, user is notified, process continues.
    Alert,
    /// Process is suspended (not killed) and the user is asked. Suspension is
    /// reversible and preserves the process for inspection in the containment
    /// cube view; termination destroys the evidence and, if we are wrong,
    /// the user's work.
    SuspendAndAsk,
}

/// Thresholds. The gap between Alert and SuspendAndAsk is deliberately wide:
/// interrupting the user is expensive and must be reserved for scores that a
/// single mis-scored behaviour cannot reach.
const WATCH_THRESHOLD: u32 = 25;
const ALERT_THRESHOLD: u32 = 60;
const SUSPEND_THRESHOLD: u32 = 110;

/// Score decays with a 5-minute half-life. Without decay, a long-running
/// process accumulates score forever and every browser eventually trips the
/// threshold — which is precisely the failure mode that trains users to click
/// "allow" on everything.
const HALF_LIFE_MS: u64 = 300_000;

#[derive(Debug, Clone, Copy)]
pub struct Observation {
    pub behaviour: Behaviour,
    pub timestamp_ms: u64,
}

pub struct ProcessProfile {
    pub role: DeclaredRole,
    /// Ring of recent observations.
    history: heapless::Deque<Observation, 128>,
    score: u32,
    last_decay_ms: u64,
    /// Combinations already credited, so a sustained attack does not re-earn
    /// the same bonus every observation and rocket past every threshold in one
    /// second.
    credited: heapless::Vec<&'static str, 8>,
}

impl ProcessProfile {
    pub fn new(role: DeclaredRole, now_ms: u64) -> Self {
        ProcessProfile {
            role,
            history: heapless::Deque::new(),
            score: 0,
            last_decay_ms: now_ms,
            credited: heapless::Vec::new(),
        }
    }

    /// Record a behaviour and return the current verdict.
    pub fn observe(&mut self, behaviour: Behaviour, now_ms: u64) -> Verdict {
        self.decay(now_ms);

        // Apply the role discount before anything else.
        let discount = self.role.discount(behaviour);
        let weight = behaviour.weight() * (100 - discount.min(100)) / 100;
        self.score = self.score.saturating_add(weight);

        if self.history.is_full() {
            self.history.pop_front();
        }
        let _ = self.history.push_back(Observation {
            behaviour,
            timestamp_ms: now_ms,
        });

        self.score = self.score.saturating_add(self.check_combinations(now_ms));

        self.verdict()
    }

    /// Exponential decay toward zero.
    fn decay(&mut self, now_ms: u64) {
        let elapsed = now_ms.saturating_sub(self.last_decay_ms);
        if elapsed == 0 {
            return;
        }

        // Integer half-life: halve for each complete period, then linearly
        // interpolate the remainder. Avoids float math in a hot path and is
        // accurate to within a point or two of a true exponential.
        let periods = elapsed / HALF_LIFE_MS;
        if periods >= 32 {
            self.score = 0;
        } else {
            self.score >>= periods as u32;
            let remainder = elapsed % HALF_LIFE_MS;
            let reduction = (self.score as u64 * remainder) / (HALF_LIFE_MS * 2);
            self.score = self.score.saturating_sub(reduction as u32);
        }

        self.last_decay_ms = now_ms;

        // Combination credits expire with the score, so a process that has
        // fully decayed can legitimately re-earn them later.
        if self.score == 0 {
            self.credited.clear();
        }
    }

    fn check_combinations(&mut self, now_ms: u64) -> u32 {
        let mut bonus = 0;

        for combo in COMBINATIONS {
            if self.credited.contains(&combo.name) {
                continue;
            }

            let all_present = combo.required.iter().all(|req| {
                self.history.iter().any(|o| {
                    o.behaviour == *req && now_ms.saturating_sub(o.timestamp_ms) <= combo.window_ms
                })
            });

            if all_present {
                bonus += combo.bonus;
                let _ = self.credited.push(combo.name);
            }
        }

        bonus
    }

    pub fn verdict(&self) -> Verdict {
        match self.score {
            s if s >= SUSPEND_THRESHOLD => Verdict::SuspendAndAsk,
            s if s >= ALERT_THRESHOLD => Verdict::Alert,
            s if s >= WATCH_THRESHOLD => Verdict::Watch,
            _ => Verdict::Clean,
        }
    }

    pub fn score(&self) -> u32 {
        self.score
    }

    /// Which combination fired, for the user-facing explanation. An alert that
    /// says "suspicious behaviour detected" teaches the user nothing and gets
    /// dismissed; one that says "this process read your documents and deleted
    /// your snapshots" gets read.
    pub fn triggered_combinations(&self) -> &[&'static str] {
        &self.credited
    }
}

/// Shannon entropy in bits per byte, used by the L2 content check to decide
/// whether a write is "high entropy".
///
/// The 7.5 threshold is chosen against measurement, not intuition: compressed
/// archives sit at 7.90–7.99, encrypted data at 7.99+, ordinary text at
/// 4.2–5.1, and compiled binaries at 5.8–6.4. 7.5 separates
/// compressed-or-encrypted from everything else, and the remaining ambiguity
/// between zip and ransomware is what the combination rules resolve.
pub fn shannon_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }

    let len = data.len() as f32;
    let mut entropy = 0.0f32;
    for &c in counts.iter() {
        if c == 0 {
            continue;
        }
        let p = c as f32 / len;
        entropy -= p * log2(p);
    }
    entropy
}

fn log2(x: f32) -> f32 {
    // No libm in this process; a bit-manipulation log2 with a polynomial fit
    // over the mantissa range is accurate to ~1e-5, far better than needed for
    // a threshold comparison.
    let bits = x.to_bits();
    let exponent = ((bits >> 23) & 0xFF) as i32 - 127;
    let m = f32::from_bits((bits & 0x007F_FFFF) | 0x3F80_0000);

    // Exact at the mantissa endpoint. The quadratic fit previously used here
    // returned 0.0049 for log2(1.0), which made the entropy of a buffer
    // containing a single repeated byte come out at -0.005 instead of 0 — a
    // visible wrongness in the one case a reader can verify by hand, and the
    // case a uniform-fill test checks first.
    if m == 1.0 {
        return exponent as f32;
    }

    // Degree-4 minimax fit of log2 over [1, 2).
    let p = -1.741_793_9
        + m * (2.821_202_6 + m * (-1.469_956_8 + m * (0.447_179_55 - 0.056_570_851 * m)));

    exponent as f32 + p
}

/// Global counter for the tray icon state.
static ACTIVE_ALERTS: AtomicU64 = AtomicU64::new(0);

pub fn shield_state() -> ShieldState {
    match ACTIVE_ALERTS.load(Ordering::Relaxed) {
        0 => ShieldState::Green,
        1..=2 => ShieldState::Yellow,
        _ => ShieldState::Red,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShieldState {
    Green,
    Yellow,
    Red,
}

#[cfg(test)]
mod tests {
    use super::*;
    use Behaviour::*;

    #[test]
    fn no_single_behaviour_can_suspend_a_process() {
        for b in [
            EnumerateUserDocuments,
            ReadForeignFile,
            WriteHighEntropy,
            DestroySnapshot,
            MassRename,
            ForeignCodeWrite,
            RawNetwork,
            ConnectWithoutDns,
            CredentialAccess,
            PersistenceInstall,
            PrivilegeRequest,
            UnsignedModuleLoad,
            LogTampering,
        ] {
            let mut p = ProcessProfile::new(DeclaredRole::None, 0);
            let v = p.observe(b, 0);
            assert!(
                v < Verdict::SuspendAndAsk,
                "{b:?} alone reached {v:?} at score {}",
                p.score()
            );
        }
    }

    #[test]
    fn ransomware_sequence_is_caught() {
        let mut p = ProcessProfile::new(DeclaredRole::None, 0);
        p.observe(EnumerateUserDocuments, 1_000);
        p.observe(ReadForeignFile, 2_000);
        p.observe(WriteHighEntropy, 3_000);
        let v = p.observe(DestroySnapshot, 4_000);

        assert_eq!(v, Verdict::SuspendAndAsk);
        assert!(p
            .triggered_combinations()
            .contains(&"ransomware-encrypt-loop"));
    }

    #[test]
    fn the_same_sequence_spread_over_hours_does_not_trip() {
        let mut p = ProcessProfile::new(DeclaredRole::None, 0);
        p.observe(EnumerateUserDocuments, 0);
        p.observe(ReadForeignFile, 3_600_000);
        p.observe(WriteHighEntropy, 7_200_000);
        let v = p.observe(DestroySnapshot, 10_800_000);
        assert!(
            v < Verdict::SuspendAndAsk,
            "decay failed; score {}",
            p.score()
        );
    }

    #[test]
    fn backup_agent_is_not_flagged_for_doing_its_job() {
        let mut p = ProcessProfile::new(DeclaredRole::BackupAgent, 0);
        for i in 0..40 {
            p.observe(EnumerateUserDocuments, i * 100);
            p.observe(ReadForeignFile, i * 100 + 50);
        }
        assert_eq!(p.verdict(), Verdict::Clean, "score {}", p.score());
    }

    #[test]
    fn a_backup_agent_that_destroys_snapshots_is_still_caught() {
        // The discount must not become a bypass. A compromised backup tool is a
        // realistic attack and its declared role must not launder it.
        let mut p = ProcessProfile::new(DeclaredRole::BackupAgent, 0);
        p.observe(EnumerateUserDocuments, 1_000);
        p.observe(ReadForeignFile, 2_000);
        p.observe(WriteHighEntropy, 3_000);
        let v = p.observe(DestroySnapshot, 4_000);
        assert_eq!(v, Verdict::SuspendAndAsk);
    }

    #[test]
    fn compiler_writing_object_files_stays_clean() {
        let mut p = ProcessProfile::new(DeclaredRole::Compiler, 0);
        for i in 0..60 {
            p.observe(WriteHighEntropy, i * 200);
        }
        assert!(p.verdict() <= Verdict::Watch, "score {}", p.score());
    }

    #[test]
    fn combination_bonus_is_credited_only_once() {
        let mut p = ProcessProfile::new(DeclaredRole::None, 0);
        p.observe(ForeignCodeWrite, 1_000);
        p.observe(PrivilegeRequest, 2_000);
        let after_first = p.score();

        p.observe(ForeignCodeWrite, 3_000);
        p.observe(PrivilegeRequest, 4_000);
        let after_second = p.score();

        // Score should grow by roughly the base weights, not by another bonus.
        let growth = after_second - after_first;
        assert!(growth < 60, "bonus re-credited: grew by {growth}");
    }

    #[test]
    fn score_decays_to_zero_over_time() {
        let mut p = ProcessProfile::new(DeclaredRole::None, 0);
        p.observe(ForeignCodeWrite, 0);
        p.observe(LogTampering, 100);
        assert!(p.score() > 0);

        p.decay(HALF_LIFE_MS * 40);
        assert_eq!(p.score(), 0);
        assert!(
            p.triggered_combinations().is_empty(),
            "credits must expire too"
        );
    }

    #[test]
    fn decay_halves_over_one_half_life() {
        let mut p = ProcessProfile::new(DeclaredRole::None, 0);
        p.observe(LogTampering, 0);
        let start = p.score();
        p.decay(HALF_LIFE_MS);
        assert!(
            p.score() <= start / 2 && p.score() >= start / 4,
            "decayed {start} -> {} over one half-life",
            p.score()
        );
    }

    #[test]
    fn entropy_separates_text_from_random() {
        let text = b"the quick brown fox jumps over the lazy dog, repeatedly and at length";
        assert!(shannon_entropy(text) < 5.5, "{}", shannon_entropy(text));

        // Uniform byte distribution: maximum entropy.
        let uniform: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        assert!(
            shannon_entropy(&uniform) > 7.9,
            "{}",
            shannon_entropy(&uniform)
        );
    }

    #[test]
    fn entropy_of_empty_and_uniform_input_is_zero() {
        assert_eq!(shannon_entropy(&[]), 0.0);
        assert!(shannon_entropy(&[0x41; 4096]).abs() < 1e-3);
    }

    #[test]
    fn verdict_thresholds_are_ordered() {
        assert!(WATCH_THRESHOLD < ALERT_THRESHOLD);
        assert!(ALERT_THRESHOLD < SUSPEND_THRESHOLD);
        // The gap before interrupting the user must be substantial.
        assert!(SUSPEND_THRESHOLD - ALERT_THRESHOLD >= 40);
    }
}
