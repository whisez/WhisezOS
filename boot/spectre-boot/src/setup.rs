//! Staged setup sequence for the preview.
//!
//! # What this is, and what it is deliberately not
//!
//! This drives the *presentation* of a WhisezOS installation: an ordered list of
//! stages, how long each is expected to take, which detail lines have been
//! revealed so far, and the overall progress and time remaining. It is the
//! timing and sequencing model, and nothing else.
//!
//! It does **not** partition, format, or write to any storage device, and it is
//! not wired to anything that does. The production installer needs a verified
//! kernel handoff, a real block layer, and the rollback and recovery paths in
//! `ARCHITECTURE.md` before it can touch a disk; none of that exists yet. Every
//! stage below is therefore labelled as a rehearsal in the UI, and `Stage::acts`
//! records — per stage — whether the step performs real work today. Keeping that
//! flag in the model rather than in a comment is what stops the screen from
//! quietly turning into a convincing lie once someone starts filling stages in.
//!
//! Splitting it out from the renderer also makes the schedule testable: a fixed
//! sequence of `advance()` calls has to produce a monotonic progress curve and
//! land exactly on completion, which is not something you want to verify by
//! watching a framebuffer for a minute.

#![allow(dead_code)]

/// One step of the sequence.
pub struct Stage {
    /// Headline, shown in the stage list.
    pub label: &'static str,
    /// Detail lines, revealed evenly across the stage's duration.
    pub detail: &'static [&'static str],
    /// How long this stage runs, in milliseconds.
    pub duration_ms: u32,
    /// Whether this stage performs real work today. Every stage is currently
    /// `false`: the sequence is a rehearsal of the production flow.
    pub acts: bool,
}

/// The production installation order, rehearsed.
///
/// The order is the one the real installer will have to follow — you cannot
/// verify an image you have not read, or lay down a filesystem before the
/// partition table exists — so rehearsing it in the wrong order would teach
/// the wrong thing to whoever implements it next.
pub const STAGES: &[Stage] = &[
    Stage {
        label: "PLATFORM SURVEY",
        detail: &[
            "READING UEFI MEMORY MAP",
            "ENUMERATING SMBUS MEMORY MODULES",
            "CHECKING CPU FEATURE BASELINE",
            "PROBING GRAPHICS OUTPUT MODES",
        ],
        duration_ms: 5_200,
        acts: false,
    },
    Stage {
        label: "FIRMWARE INTEGRITY",
        detail: &[
            "READING SECURE BOOT STATE",
            "LOCATING TPM 2.0 INTERFACE",
            "RESERVING MEASUREMENT REGISTERS",
        ],
        duration_ms: 4_400,
        acts: false,
    },
    Stage {
        label: "IMAGE VERIFICATION",
        detail: &[
            "LOADING SIGNED BOOT MANIFEST",
            "HASHING KERNEL IMAGE SHA3-512",
            "HASHING USERLAND IMAGES",
            "COMPARING AGAINST MANIFEST DIGESTS",
        ],
        duration_ms: 6_800,
        acts: false,
    },
    Stage {
        label: "STORAGE LAYOUT",
        detail: &[
            "REHEARSAL ONLY - NO DISK IS TOUCHED",
            "PLANNING EFI SYSTEM PARTITION 512 MIB",
            "PLANNING SPECTREFS ROOT VOLUME",
            "PLANNING RECOVERY SLOT",
        ],
        duration_ms: 6_000,
        acts: false,
    },
    Stage {
        label: "VOLUME ENCRYPTION",
        detail: &[
            "DERIVING KEY WITH ARGON2ID",
            "PREPARING XCHACHA20-POLY1305 VAULT",
            "SEALING KEY TO PLATFORM STATE",
        ],
        duration_ms: 5_600,
        acts: false,
    },
    Stage {
        label: "SYSTEM FILES",
        detail: &[
            "STAGING MICROKERNEL",
            "STAGING INIT AND SERVICE MANAGER",
            "STAGING PRISM COMPOSITOR",
            "STAGING WHISEZ GUARD",
            "STAGING WALLPAPERS AND FONTS",
        ],
        duration_ms: 8_400,
        acts: false,
    },
    Stage {
        label: "CAPABILITY POLICY",
        detail: &[
            "BUILDING ROOT CAPABILITY SET",
            "RESTRICTING DRIVER PROCESSES",
            "DENYING W PLUS X MAPPINGS",
        ],
        duration_ms: 4_800,
        acts: false,
    },
    Stage {
        label: "RECOVERY PATH",
        detail: &[
            "WRITING RECOVERY DESCRIPTOR",
            "REGISTERING ROLLBACK SLOT",
            "TESTING FAILURE HANDLING",
        ],
        duration_ms: 5_200,
        acts: false,
    },
    Stage {
        label: "FINAL CHECKS",
        detail: &[
            "RE-READING EVERY STAGED DIGEST",
            "CONFIRMING BOOT ENTRY",
            "SETUP REHEARSAL COMPLETE",
        ],
        duration_ms: 4_600,
        acts: false,
    },
];

/// Fixed-point scale for progress values: `0..=PROGRESS_MAX`.
pub const PROGRESS_MAX: u16 = 1000;

/// Cursor into `STAGES`, advanced by elapsed time.
#[derive(Debug, Clone, Copy, Default)]
pub struct Setup {
    elapsed_ms: u32,
}

impl Setup {
    #[must_use]
    pub const fn new() -> Self {
        Self { elapsed_ms: 0 }
    }

    /// Total wall time of the whole sequence.
    #[must_use]
    pub fn total_ms() -> u32 {
        STAGES.iter().map(|s| s.duration_ms).sum()
    }

    /// Advances the clock. Saturates at the end rather than wrapping, so a long
    /// stall in the firmware cannot roll progress back to zero.
    pub fn advance(&mut self, delta_ms: u32) {
        self.elapsed_ms = self
            .elapsed_ms
            .saturating_add(delta_ms)
            .min(Self::total_ms());
    }

    /// Jumps to the end. Bound to Escape: nobody should be held hostage by a
    /// progress bar, least of all on a screen that is not installing anything.
    pub fn skip(&mut self) {
        self.elapsed_ms = Self::total_ms();
    }

    #[must_use]
    pub const fn elapsed_ms(&self) -> u32 {
        self.elapsed_ms
    }

    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.elapsed_ms >= Self::total_ms()
    }

    #[must_use]
    pub fn remaining_ms(&self) -> u32 {
        Self::total_ms().saturating_sub(self.elapsed_ms)
    }

    /// Index of the running stage. Once complete this stays on the last stage
    /// rather than running off the end of the slice.
    #[must_use]
    pub fn stage_index(&self) -> usize {
        let mut consumed = 0u32;
        for (index, stage) in STAGES.iter().enumerate() {
            consumed += stage.duration_ms;
            if self.elapsed_ms < consumed {
                return index;
            }
        }
        STAGES.len() - 1
    }

    #[must_use]
    pub fn stage(&self) -> &'static Stage {
        &STAGES[self.stage_index()]
    }

    /// Progress within the running stage, `0..=PROGRESS_MAX`.
    #[must_use]
    pub fn stage_progress(&self) -> u16 {
        let index = self.stage_index();
        let start: u32 = STAGES[..index].iter().map(|s| s.duration_ms).sum();
        let duration = STAGES[index].duration_ms.max(1);
        let into = self.elapsed_ms.saturating_sub(start).min(duration);
        ((into as u64 * PROGRESS_MAX as u64) / duration as u64) as u16
    }

    /// Progress across the whole sequence, `0..=PROGRESS_MAX`.
    #[must_use]
    pub fn overall_progress(&self) -> u16 {
        let total = Self::total_ms().max(1);
        ((self.elapsed_ms as u64 * PROGRESS_MAX as u64) / total as u64) as u16
    }

    /// Overall progress as a whole percentage, for display.
    #[must_use]
    pub fn percent(&self) -> u8 {
        (self.overall_progress() / 10) as u8
    }

    /// How many of the current stage's detail lines have been revealed. Always
    /// at least one, so the panel is never blank while a stage is running.
    #[must_use]
    pub fn revealed_detail(&self) -> usize {
        let stage = self.stage();
        let count = stage.detail.len();
        if count == 0 {
            return 0;
        }
        let shown = (self.stage_progress() as usize * count) / PROGRESS_MAX as usize + 1;
        shown.min(count)
    }

    /// The line to show as the current activity.
    #[must_use]
    pub fn current_detail(&self) -> &'static str {
        let stage = self.stage();
        match self.revealed_detail() {
            0 => stage.label,
            n => stage.detail[n - 1],
        }
    }

    /// True once every stage before `index` has finished.
    #[must_use]
    pub fn stage_done(&self, index: usize) -> bool {
        let end: u32 = STAGES[..=index.min(STAGES.len() - 1)]
            .iter()
            .map(|s| s.duration_ms)
            .sum();
        self.elapsed_ms >= end
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_stage_claims_to_perform_real_work_yet() {
        // If a stage is ever wired to real storage or crypto, this assertion is
        // the thing that forces the UI copy and the docs to be revisited with
        // it, rather than the screen silently gaining authority it has not
        // earned.
        assert!(
            STAGES.iter().all(|stage| !stage.acts),
            "a stage was marked as acting; update the setup screen copy, \
             INSTALL.md and INSTALL.en.md before relaxing this test"
        );
    }

    #[test]
    fn the_sequence_is_long_enough_to_be_worth_watching() {
        let total = Setup::total_ms();
        assert!(
            (45_000..90_000).contains(&total),
            "unexpected total duration: {total} ms"
        );
    }

    #[test]
    fn every_stage_has_a_label_and_detail_lines() {
        for stage in STAGES {
            assert!(!stage.label.is_empty());
            assert!(!stage.detail.is_empty(), "{} has no detail", stage.label);
            assert!(stage.duration_ms > 0, "{} is instantaneous", stage.label);
        }
    }

    #[test]
    fn progress_starts_at_zero_and_ends_at_full() {
        let mut setup = Setup::new();
        assert_eq!(setup.overall_progress(), 0);
        assert_eq!(setup.percent(), 0);
        assert!(!setup.is_complete());

        setup.advance(Setup::total_ms());
        assert_eq!(setup.overall_progress(), PROGRESS_MAX);
        assert_eq!(setup.percent(), 100);
        assert!(setup.is_complete());
    }

    #[test]
    fn progress_never_moves_backwards() {
        let mut setup = Setup::new();
        let mut previous = 0;
        for _ in 0..2_000 {
            setup.advance(50);
            let now = setup.overall_progress();
            assert!(now >= previous, "{now} < {previous}");
            previous = now;
        }
        assert_eq!(previous, PROGRESS_MAX);
    }

    #[test]
    fn advancing_past_the_end_saturates_rather_than_wrapping() {
        let mut setup = Setup::new();
        setup.advance(u32::MAX);
        setup.advance(u32::MAX);
        assert_eq!(setup.elapsed_ms(), Setup::total_ms());
        assert_eq!(setup.overall_progress(), PROGRESS_MAX);
    }

    #[test]
    fn stages_are_visited_in_order_and_none_is_skipped() {
        let mut setup = Setup::new();
        let mut seen = 0usize;
        for _ in 0..(Setup::total_ms() / 25) {
            setup.advance(25);
            let index = setup.stage_index();
            assert!(index >= seen, "stage went backwards: {index} after {seen}");
            assert!(index <= seen + 1, "jumped from {seen} to {index}");
            seen = index;
        }
        assert_eq!(seen, STAGES.len() - 1);
    }

    #[test]
    fn stage_progress_is_relative_to_the_stage_not_the_whole_run() {
        let mut setup = Setup::new();
        setup.advance(STAGES[0].duration_ms / 2);
        assert_eq!(setup.stage_index(), 0);
        let progress = setup.stage_progress();
        assert!((490..=510).contains(&progress), "stage progress {progress}");
        assert!(setup.overall_progress() < 200, "overall is much smaller");
    }

    #[test]
    fn skipping_completes_immediately_and_stays_complete() {
        let mut setup = Setup::new();
        setup.advance(1_000);
        setup.skip();
        assert!(setup.is_complete());
        assert_eq!(setup.remaining_ms(), 0);
        setup.advance(1_000);
        assert!(setup.is_complete());
    }

    #[test]
    fn detail_lines_are_revealed_progressively_and_never_out_of_range() {
        let mut setup = Setup::new();
        assert_eq!(setup.revealed_detail(), 1, "one line is shown immediately");

        for _ in 0..(Setup::total_ms() / 25) {
            setup.advance(25);
            let stage = setup.stage();
            let shown = setup.revealed_detail();
            assert!(shown >= 1 && shown <= stage.detail.len());
            assert_eq!(setup.current_detail(), stage.detail[shown - 1]);
        }
    }

    #[test]
    fn a_stage_is_done_only_once_its_time_has_fully_elapsed() {
        let mut setup = Setup::new();
        setup.advance(STAGES[0].duration_ms - 1);
        assert!(!setup.stage_done(0));
        setup.advance(1);
        assert!(setup.stage_done(0));
        assert!(!setup.stage_done(1));
    }

    #[test]
    fn remaining_time_falls_to_zero_and_matches_elapsed() {
        let mut setup = Setup::new();
        for _ in 0..40 {
            setup.advance(1_000);
            assert_eq!(setup.remaining_ms() + setup.elapsed_ms(), Setup::total_ms());
        }
        setup.skip();
        assert_eq!(setup.remaining_ms(), 0);
    }
}
