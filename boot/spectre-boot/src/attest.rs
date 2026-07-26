//! Pre-load integrity attestation.
//!
//! Every byte that will be mapped executable — the kernel image, each core
//! user-space driver, and the init system — is hashed with SHA3-512 and
//! compared against a manifest signed with the platform's Secure Boot key
//! before a single page of it is made executable.
//!
//! Ordering matters and is easy to get wrong: hash-then-load is not the same
//! as load-then-hash. We hash out of a buffer that is mapped `NX | RO` and
//! only flip it to `RX` after the comparison succeeds, so there is no window
//! in which unverified bytes are executable. The manifest itself is verified
//! first, against a key held in the firmware's `db`, so an attacker who can
//! rewrite the ESP cannot simply rewrite the manifest to match their kernel.

use core::fmt;
use sha3::{Digest, Sha3_512};

pub const DIGEST_LEN: usize = 64;
pub type Digest512 = [u8; DIGEST_LEN];

/// One entry in the signed boot manifest.
#[derive(Clone, Copy)]
pub struct ManifestEntry {
    /// Path on the ESP, e.g. `\SPECTRE\KERNEL.ELF`.
    pub path: &'static str,
    /// Expected SHA3-512 of the file's full contents.
    pub digest: Digest512,
    /// PCR index this measurement is extended into. Kernel → 8, drivers → 9,
    /// init → 10, matching the TCG "OS loader" PCR conventions closely enough
    /// that off-the-shelf remote-attestation verifiers can consume our quotes.
    pub pcr: u32,
}

#[derive(Debug, Clone, Copy)]
pub enum TamperKind {
    /// Manifest signature did not verify against the Secure Boot db key.
    ManifestForged,
    /// A file's hash did not match its manifest entry.
    ImageModified,
    /// A file listed in the manifest is absent.
    ImageMissing,
}

#[derive(Clone, Copy)]
pub struct Tamper {
    pub kind: TamperKind,
    pub path: &'static str,
    pub expected: Digest512,
    pub actual: Digest512,
}

impl fmt::Display for Tamper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KERNEL TAMPER DETECTED :: {}", self.path)
    }
}

/// Hash a loaded image buffer.
///
/// The buffer is taken as `&[u8]`, which by construction cannot alias an
/// executable mapping — the caller allocates with `EfiLoaderData` and NX set.
pub fn digest(bytes: &[u8]) -> Digest512 {
    let mut hasher = Sha3_512::new();
    hasher.update(bytes);
    let out = hasher.finalize();

    let mut d = [0u8; DIGEST_LEN];
    d.copy_from_slice(&out);
    d
}

/// Constant-time digest comparison.
///
/// A short-circuiting `==` here would leak the position of the first differing
/// byte through timing. That is a real, if slow, oracle: an attacker with
/// physical access and a reset button can grind out a matching prefix byte by
/// byte. The cost of doing it right is 64 XORs.
pub fn digests_equal(a: &Digest512, b: &Digest512) -> bool {
    let mut diff: u8 = 0;
    for i in 0..DIGEST_LEN {
        diff |= a[i] ^ b[i];
    }
    // Reduce to a bool without a branch on `diff` itself.
    core::hint::black_box(diff) == 0
}

/// Verify one manifest entry against the bytes actually read from disk.
pub fn verify_image(entry: &ManifestEntry, bytes: Option<&[u8]>) -> Result<Digest512, Tamper> {
    let Some(bytes) = bytes else {
        return Err(Tamper {
            kind: TamperKind::ImageMissing,
            path: entry.path,
            expected: entry.digest,
            actual: [0u8; DIGEST_LEN],
        });
    };

    let actual = digest(bytes);
    if digests_equal(&actual, &entry.digest) {
        Ok(actual)
    } else {
        Err(Tamper {
            kind: TamperKind::ImageModified,
            path: entry.path,
            expected: entry.digest,
            actual,
        })
    }
}

/// TPM 2.0 operations the loader needs. Backed by `EFI_TCG2_PROTOCOL` at
/// runtime; a mock in tests.
pub trait Tpm {
    /// Extend `digest` into PCR `index` with the SHA3-512 bank.
    fn extend(&mut self, index: u32, digest: &Digest512) -> Result<(), ()>;

    /// Evict all persistent handles in the owner hierarchy and clear the
    /// storage primary seed. This is `TPM2_Clear` — it invalidates every key
    /// sealed to this TPM, including the disk-encryption key.
    fn clear_owner_hierarchy(&mut self) -> Result<(), ()>;
}

/// Measure a verified image into the TPM event log.
///
/// Called only on the success path. Measuring a *failed* image would let an
/// attacker steer PCR values by feeding us garbage, which is the opposite of
/// what measured boot is for.
pub fn measure<T: Tpm>(tpm: &mut T, entry: &ManifestEntry, d: &Digest512) -> Result<(), ()> {
    tpm.extend(entry.pcr, d)
}

/// The tamper response: destroy sealed key material, then hand off to the
/// halt screen.
///
/// `TPM2_Clear` is deliberate and irreversible. Its purpose is to guarantee
/// that a tampered boot chain cannot unseal the disk key even if the attacker
/// subsequently restores the original kernel — the window where a modified
/// kernel could have been measured is closed by making every key sealed to
/// this TPM permanently unusable. The disk remains recoverable *only* via the
/// user's Argon2id passphrase, which is why WhisezOS refuses to complete
/// installation until the recovery passphrase has been confirmed twice.
///
/// This is a data-loss event for anyone who skipped that step, and it is
/// documented as such in the installer. It is not "physically wiping" the TPM
/// in a hardware sense — that would require destroying the chip. It renders
/// its stored secrets cryptographically unrecoverable, which is the property
/// actually wanted.
pub fn wipe_sealed_keys<T: Tpm>(tpm: &mut T) -> Result<(), ()> {
    tpm.clear_owner_hierarchy()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENTRY: ManifestEntry = ManifestEntry {
        path: "\\SPECTRE\\KERNEL.ELF",
        digest: [0u8; DIGEST_LEN],
        pcr: 8,
    };

    #[test]
    fn matching_bytes_verify() {
        let bytes = b"spectre kernel image";
        let entry = ManifestEntry {
            digest: digest(bytes),
            ..ENTRY
        };
        assert!(verify_image(&entry, Some(bytes)).is_ok());
    }

    #[test]
    fn single_flipped_bit_is_caught() {
        let good = b"spectre kernel image";
        let bad = b"spectre kernel imagf";
        let entry = ManifestEntry {
            digest: digest(good),
            ..ENTRY
        };
        assert!(matches!(
            verify_image(&entry, Some(bad)),
            Err(Tamper {
                kind: TamperKind::ImageModified,
                ..
            })
        ));
    }

    #[test]
    fn missing_image_is_tamper_not_skip() {
        assert!(matches!(
            verify_image(&ENTRY, None),
            Err(Tamper {
                kind: TamperKind::ImageMissing,
                ..
            })
        ));
    }

    #[test]
    fn comparison_is_length_independent() {
        let a = [0xAAu8; DIGEST_LEN];
        let mut b = a;
        b[0] ^= 1;
        assert!(!digests_equal(&a, &b));
        b[0] ^= 1;
        b[DIGEST_LEN - 1] ^= 1;
        assert!(!digests_equal(&a, &b));
        assert!(digests_equal(&a, &a));
    }
}
