//! Whisez Guard: local, defensive security checks for WhisezOS development hosts.
//!
//! The scanner never executes input, never uploads data, and never deletes or
//! quarantines files. Findings are evidence for a human decision, not verdicts.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use walkdir::WalkDir;

const MANIFEST_VERSION: u32 = 1;
const MAX_HASH_FILE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_SCAN_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Parser)]
#[command(
    name = "whisez-guard",
    version,
    about = "WhisezOS defensive posture and file-integrity guard"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Audit Windows security controls without changing the system.
    Audit {
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Create a SHA3-256 integrity baseline for files or directories.
    Baseline {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        #[arg(short, long, default_value = "whisez-guard-baseline.json")]
        output: PathBuf,
    },
    /// Compare current files with a saved integrity baseline.
    Verify {
        #[arg(default_value = "whisez-guard-baseline.json")]
        manifest: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Re-check a baseline on an interval; Ctrl+C stops the monitor.
    Monitor {
        #[arg(default_value = "whisez-guard-baseline.json")]
        manifest: PathBuf,
        #[arg(short, long, default_value_t = 5)]
        interval: u64,
        /// Check once, useful for automation and health probes.
        #[arg(long)]
        once: bool,
    },
    /// Inspect files offline for high-risk script and binary indicators.
    Scan {
        path: PathBuf,
        #[arg(long, default_value_t = 10_000)]
        max_files: usize,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Severity {
    Ok,
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Serialize)]
struct Finding {
    check: String,
    severity: Severity,
    detail: String,
}

#[derive(Debug, Serialize)]
struct AuditReport {
    product: &'static str,
    generated_unix: u64,
    score: u8,
    findings: Vec<Finding>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Baseline {
    product: String,
    version: u32,
    created_unix: u64,
    files: Vec<BaselineEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct BaselineEntry {
    path: PathBuf,
    size: u64,
    modified_unix: u64,
    sha3_256: String,
}

#[derive(Debug, Serialize)]
struct VerifyReport {
    product: &'static str,
    manifest: PathBuf,
    unchanged: usize,
    findings: Vec<Finding>,
}

#[derive(Debug, Serialize)]
struct ScanReport {
    product: &'static str,
    root: PathBuf,
    files_inspected: usize,
    bytes_inspected: u64,
    truncated: bool,
    findings: Vec<Finding>,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Commands::Audit { json } => print_audit(audit_host(), json),
        Commands::Baseline { paths, output } => create_baseline(&paths, &output),
        Commands::Verify { manifest, json } => {
            let report = verify_baseline(&manifest)?;
            print_verify(&report, json);
            if report
                .findings
                .iter()
                .any(|f| f.severity == Severity::Critical)
            {
                std::process::exit(2);
            }
            Ok(())
        }
        Commands::Monitor {
            manifest,
            interval,
            once,
        } => {
            if interval == 0 {
                bail!("--interval must be at least one second");
            }
            loop {
                let report = verify_baseline(&manifest)?;
                print_verify(&report, false);
                if once {
                    return Ok(());
                }
                thread::sleep(Duration::from_secs(interval));
            }
        }
        Commands::Scan {
            path,
            max_files,
            json,
        } => {
            let report = scan_path(&path, max_files)?;
            print_scan(&report, json);
            if report
                .findings
                .iter()
                .any(|f| f.severity == Severity::Critical)
            {
                std::process::exit(3);
            }
            Ok(())
        }
    }
}

fn audit_host() -> AuditReport {
    let mut findings = Vec::new();

    if cfg!(windows) {
        check_bool(
            &mut findings,
            "windows-firewall",
            "(Get-NetFirewallProfile | Where-Object Enabled).Count -eq (Get-NetFirewallProfile).Count",
            "All Windows Firewall profiles are enabled",
            "One or more Windows Firewall profiles are disabled",
            Severity::Critical,
        );
        check_bool(
            &mut findings,
            "defender-realtime",
            "$s=Get-MpComputerStatus; $s.AntivirusEnabled -and $s.RealTimeProtectionEnabled -and $s.BehaviorMonitorEnabled",
            "Microsoft Defender antivirus, real-time protection, and behavior monitoring are enabled",
            "Microsoft Defender protection is incomplete or disabled",
            Severity::Critical,
        );
        check_bool(
            &mut findings,
            "uac",
            "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System').EnableLUA -eq 1",
            "User Account Control is enabled",
            "User Account Control is disabled",
            Severity::Critical,
        );
        check_bool(
            &mut findings,
            "secure-boot",
            "try { Confirm-SecureBootUEFI } catch { 'Unsupported' }",
            "UEFI Secure Boot is enabled",
            "Secure Boot is disabled or unavailable",
            Severity::Warning,
        );

        match run_powershell("(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Measure-Object).Count") {
            Some(value) => findings.push(Finding {
                check: "listening-sockets".into(),
                severity: Severity::Info,
                detail: format!("Listening TCP endpoints visible to the host: {}", value.trim()),
            }),
            None => unavailable(&mut findings, "listening-sockets"),
        }
    } else {
        findings.push(Finding {
            check: "platform".into(),
            severity: Severity::Info,
            detail: "Host posture checks are currently implemented for Windows; integrity and scan commands are cross-platform".into(),
        });
    }

    let penalty: u16 = findings
        .iter()
        .map(|f| match f.severity {
            Severity::Critical => 30,
            Severity::Warning => 12,
            Severity::Info | Severity::Ok => 0,
        })
        .sum();

    AuditReport {
        product: "Whisez Guard",
        generated_unix: now_unix(),
        score: 100u16.saturating_sub(penalty).min(100) as u8,
        findings,
    }
}

fn check_bool(
    findings: &mut Vec<Finding>,
    check: &str,
    script: &str,
    ok: &str,
    failed: &str,
    failure_severity: Severity,
) {
    match run_powershell(script).as_deref().map(str::trim) {
        Some(value) if value.eq_ignore_ascii_case("true") => findings.push(Finding {
            check: check.into(),
            severity: Severity::Ok,
            detail: ok.into(),
        }),
        Some("Unsupported") => findings.push(Finding {
            check: check.into(),
            severity: Severity::Warning,
            detail: failed.into(),
        }),
        Some(_) => findings.push(Finding {
            check: check.into(),
            severity: failure_severity,
            detail: failed.into(),
        }),
        None => unavailable(findings, check),
    }
}

fn unavailable(findings: &mut Vec<Finding>, check: &str) {
    findings.push(Finding {
        check: check.into(),
        severity: Severity::Warning,
        detail: "Check unavailable without changing system state".into(),
    });
}

fn run_powershell(script: &str) -> Option<String> {
    let output = Command::new("powershell.exe")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ])
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn create_baseline(paths: &[PathBuf], output: &Path) -> Result<()> {
    let output_abs = absolute_path(output)?;
    let files = collect_files(paths, usize::MAX)?;
    let mut entries = Vec::with_capacity(files.len());

    for path in files {
        if absolute_path(&path)? == output_abs {
            continue;
        }
        let metadata = fs::metadata(&path)
            .with_context(|| format!("reading metadata for {}", path.display()))?;
        if metadata.len() > MAX_HASH_FILE_BYTES {
            bail!("{} exceeds the 4 GiB baseline safety limit", path.display());
        }
        entries.push(BaselineEntry {
            path: absolute_path(&path)?,
            size: metadata.len(),
            modified_unix: modified_unix(&metadata),
            sha3_256: hash_file(&path)?,
        });
    }

    let baseline = Baseline {
        product: "Whisez Guard".into(),
        version: MANIFEST_VERSION,
        created_unix: now_unix(),
        files: entries,
    };
    let json = serde_json::to_vec_pretty(&baseline)?;
    fs::write(output, json).with_context(|| format!("writing {}", output.display()))?;
    println!(
        "[OK] baseline saved: {} ({} files)",
        output.display(),
        baseline.files.len()
    );
    Ok(())
}

fn verify_baseline(path: &Path) -> Result<VerifyReport> {
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let baseline: Baseline = serde_json::from_slice(&bytes).context("invalid baseline JSON")?;
    if baseline.product != "Whisez Guard" || baseline.version != MANIFEST_VERSION {
        bail!("unsupported or foreign baseline manifest");
    }

    let mut unchanged = 0;
    let mut findings = Vec::new();
    for entry in baseline.files {
        if !entry.path.exists() {
            findings.push(Finding {
                check: "integrity-missing".into(),
                severity: Severity::Critical,
                detail: entry.path.display().to_string(),
            });
            continue;
        }
        let metadata = fs::metadata(&entry.path)?;
        let current_hash = hash_file(&entry.path)?;
        if metadata.len() != entry.size || current_hash != entry.sha3_256 {
            findings.push(Finding {
                check: "integrity-changed".into(),
                severity: Severity::Critical,
                detail: entry.path.display().to_string(),
            });
        } else {
            unchanged += 1;
        }
    }

    if findings.is_empty() {
        findings.push(Finding {
            check: "integrity".into(),
            severity: Severity::Ok,
            detail: "Every baselined file matches its SHA3-256 digest".into(),
        });
    }

    Ok(VerifyReport {
        product: "Whisez Guard",
        manifest: absolute_path(path)?,
        unchanged,
        findings,
    })
}

fn scan_path(path: &Path, max_files: usize) -> Result<ScanReport> {
    if max_files == 0 {
        bail!("--max-files must be greater than zero");
    }
    let files = collect_files(&[path.to_path_buf()], max_files.saturating_add(1))?;
    let truncated = files.len() > max_files;
    let mut inspected = 0usize;
    let mut bytes_inspected = 0u64;
    let mut findings = Vec::new();

    for file in files.into_iter().take(max_files) {
        let metadata = match fs::metadata(&file) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let read_limit = metadata.len().min(MAX_SCAN_BYTES);
        let mut reader = BufReader::new(File::open(&file)?).take(read_limit);
        let mut bytes = Vec::with_capacity(read_limit as usize);
        reader.read_to_end(&mut bytes)?;
        inspected += 1;
        bytes_inspected += bytes.len() as u64;

        let lower = bytes.iter().map(u8::to_ascii_lowercase).collect::<Vec<_>>();
        let indicators = indicator_matches(&lower);
        if indicators.len() >= 2 {
            findings.push(Finding {
                check: "offline-content-indicators".into(),
                severity: if indicators.len() >= 4 {
                    Severity::Critical
                } else {
                    Severity::Warning
                },
                detail: format!(
                    "{} | indicators: {} | sha3-256: {}",
                    file.display(),
                    indicators.join(", "),
                    hash_file(&file)?
                ),
            });
        }
    }

    if findings.is_empty() {
        findings.push(Finding {
            check: "offline-scan".into(),
            severity: Severity::Ok,
            detail: "No multi-indicator high-risk content pattern was found".into(),
        });
    }

    Ok(ScanReport {
        product: "Whisez Guard",
        root: absolute_path(path)?,
        files_inspected: inspected,
        bytes_inspected,
        truncated,
        findings,
    })
}

fn indicator_matches(bytes: &[u8]) -> Vec<&'static str> {
    // Split signatures keep a self-scan from matching the scanner's own
    // source file. They are joined only by the comparison routine and are
    // never assembled into executable content.
    const INDICATORS: [(&str, &[u8], &[u8]); 11] = [
        ("encoded-command", b"power", b"shell -enc"),
        ("base64-loader", b"frombase", b"64string"),
        ("remote-download", b"download", b"string("),
        ("dynamic-execution", b"invoke-", b"expression"),
        ("process-injection", b"writeprocess", b"memory"),
        ("executable-memory", b"virtual", b"alloc"),
        ("signed-binary-proxy", b"regsvr32", b" /s"),
        ("url-cache", b"certutil", b" -urlcache"),
        ("shadow-copy-delete", b"vssadmin", b" delete shadows"),
        ("boot-policy-change", b"bcdedit", b" /set"),
        ("credential-tool-marker", b"sekurlsa::", b"logonpasswords"),
    ];
    INDICATORS
        .iter()
        .filter_map(|(name, first, second)| contains_joined(bytes, first, second).then_some(*name))
        .collect()
}

fn contains_joined(haystack: &[u8], first: &[u8], second: &[u8]) -> bool {
    let width = first.len() + second.len();
    width > 0
        && haystack
            .windows(width)
            .any(|window| window[..first.len()] == *first && window[first.len()..] == *second)
}

fn collect_files(paths: &[PathBuf], limit: usize) -> Result<Vec<PathBuf>> {
    let mut files = BTreeSet::new();
    for root in paths {
        if root.is_file() {
            files.insert(root.clone());
            continue;
        }
        if !root.is_dir() {
            bail!("path does not exist: {}", root.display());
        }
        for entry in WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_map(|entry| entry.ok())
        {
            if entry.file_type().is_file() {
                files.insert(entry.into_path());
                if files.len() >= limit {
                    break;
                }
            }
        }
    }
    Ok(files.into_iter().collect())
}

fn hash_file(path: &Path) -> Result<String> {
    let mut reader = BufReader::new(File::open(path)?);
    let mut hasher = Sha3_256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.exists() {
        return fs::canonicalize(path)
            .with_context(|| format!("canonicalizing {}", path.display()));
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path.file_name().context("path has no file name")?;
    Ok(fs::canonicalize(parent)?.join(name))
}

fn modified_unix(metadata: &fs::Metadata) -> u64 {
    metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs())
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn print_audit(report: AuditReport, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("Whisez Guard | posture score: {}/100", report.score);
        print_findings(&report.findings);
    }
    Ok(())
}

fn print_verify(report: &VerifyReport, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(report).unwrap_or_default()
        );
    } else {
        println!("Whisez Guard | integrity | {} unchanged", report.unchanged);
        print_findings(&report.findings);
    }
}

fn print_scan(report: &ScanReport, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(report).unwrap_or_default()
        );
    } else {
        println!(
            "Whisez Guard | offline scan | {} files | {} bytes{}",
            report.files_inspected,
            report.bytes_inspected,
            if report.truncated {
                " | LIMIT REACHED"
            } else {
                ""
            }
        );
        print_findings(&report.findings);
    }
}

fn print_findings(findings: &[Finding]) {
    for finding in findings {
        let label = match finding.severity {
            Severity::Ok => "OK",
            Severity::Info => "INFO",
            Severity::Warning => "WARN",
            Severity::Critical => "CRITICAL",
        };
        println!("[{label}] {}: {}", finding.check, finding.detail);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn baseline_round_trip_and_change_detection() {
        let temp = tempdir().unwrap();
        let watched = temp.path().join("watched.txt");
        let manifest = temp.path().join("baseline.json");
        fs::write(&watched, b"trusted").unwrap();
        create_baseline(std::slice::from_ref(&watched), &manifest).unwrap();

        let clean = verify_baseline(&manifest).unwrap();
        assert_eq!(clean.unchanged, 1);
        assert!(!clean
            .findings
            .iter()
            .any(|f| f.severity == Severity::Critical));

        fs::write(&watched, b"changed").unwrap();
        let changed = verify_baseline(&manifest).unwrap();
        assert!(changed
            .findings
            .iter()
            .any(|f| f.check == "integrity-changed"));
    }

    #[test]
    fn scanner_requires_multiple_indicators_to_reduce_false_positives() {
        let one = concat!("documentation mentions Virtual", "Alloc only").as_bytes();
        assert_eq!(
            indicator_matches(&one.iter().map(u8::to_ascii_lowercase).collect::<Vec<_>>()).len(),
            1
        );
        let multiple = concat!(
            "Power",
            "Shell -Enc AAA FromBase",
            "64String Invoke-",
            "Expression"
        )
        .as_bytes();
        assert!(
            indicator_matches(
                &multiple
                    .iter()
                    .map(u8::to_ascii_lowercase)
                    .collect::<Vec<_>>()
            )
            .len()
                >= 3
        );
    }

    #[test]
    fn offline_scan_never_executes_input_and_reports_evidence() {
        let temp = tempdir().unwrap();
        let sample = temp.path().join("sample.ps1");
        let content = concat!(
            "power",
            "shell -enc AAA; FromBase",
            "64String('AA=='); Invoke-",
            "Expression $x"
        );
        fs::write(&sample, content.as_bytes()).unwrap();
        let report = scan_path(temp.path(), 10).unwrap();
        assert_eq!(report.files_inspected, 1);
        assert!(report
            .findings
            .iter()
            .any(|f| f.severity == Severity::Warning));
    }
}
