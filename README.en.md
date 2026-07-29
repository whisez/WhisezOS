<div align="center">

# WhisezOS

### Experimental operating system and defensive tooling built in Rust

**[Türkçe](README.md) · [English](README.en.md)**

[![CI](https://github.com/whisez/WhisezOS/actions/workflows/ci.yml/badge.svg)](https://github.com/whisez/WhisezOS/actions/workflows/ci.yml)
![Status](https://img.shields.io/badge/status-work%20in%20progress-orange)
[![Release](https://img.shields.io/badge/release-v0.1.0%20preview-00bcd4)](https://github.com/whisez/WhisezOS/releases/tag/v0.1.0)
[![License](https://img.shields.io/badge/license-MPL--2.0-blue)](LICENSE)

</div>

WhisezOS is an experimental project combining a capability-oriented Rust
microkernel design, a real UEFI desktop preview that runs in QEMU, and a local
defensive utility named **Whisez Guard**.

> [!WARNING]
> **WhisezOS is not a complete operating system yet.** The project is under
> active development. Run it only in a QEMU virtual machine; do not attempt to
> install it on a physical disk or real hardware.

## Project status

| Component | Status | Details |
|---|:---:|---|
| UEFI preview | ✅ Working | Boots on QEMU/OVMF and displays the WhisezOS animation and desktop |
| Mouse and keyboard | ✅ Working | Card and file selection, left-click to open, right-click to return, and keyboard shortcuts |
| Setup screen | ✅ Working | A staged installation rehearsal with progress bars; it touches no disk |
| Whisez Guard | ✅ Working | Windows security audit, offline scan, SHA3-256 baseline verification, and monitoring |
| Build and packaging | ✅ Working | Produces an EFI application, Guard binary, and 4K wallpaper package with one command |
| Automated tests | ✅ 628 tests | Kernel, file-system, account security, desktop, boot, and Guard tests |
| Production loader | ✅ Working | Reads, validates, and loads the kernel ELF, then exits boot services and hands off |
| Kernel screen console | ✅ Working | The kernel draws its own log to the framebuffer the firmware left running; `cargo xtask boot-run` shows it in a window |
| Production kernel | ✅ Boots in QEMU | GDT, IDT, serial console, frame allocator, and its own page tables; `cargo xtask boot-test` proves it from the serial log |
| Interrupt controller and timer | ✅ Working | x2APIC, a 100 Hz LAPIC timer calibrated against the PIT, and full-register context switching |
| User space | ✅ First process runs | `init` starts in ring 3 in its own address space, calls back through `syscall`, and has its boundary violations refused |
| Process management | ✅ Working | Preemptive round-robin, process teardown, and slot reuse; the kernel verifies on every boot that no frames leaked |
| Device authority | ✅ Working | A process cannot name a physical address; it asks for a device the kernel listed, by index. The framebuffer is mapped and drawn to from ring 3 |
| Storage driver | ✅ Working in QEMU | Ring 3 VirtIO-blk driver; folders, text files, and the local account record persist on the 16 MiB test disk |
| Network driver | ✅ Working in QEMU | VirtIO-net with ARP and DNS probes reports real QEMU user-network state; a general HTTP/TLS client is not implemented yet |
| IPC | ✅ Working | Synchronous rendezvous: `call`/`receive`/`reply`, blocking processes, and endpoint authority. The full design (`ipc.rs`, page grants, capability transfer) is not linked yet |
| Desktop session | ✅ Working in QEMU | Ring 3 session with a Windows-style taskbar, Start menu, movable/maximizable windows, Files, Notepad, Settings, and Assistant |
| Local account | ✅ Working | First-run local account, password sign-in, lock screen, and password changes in Settings; a salted iterative verifier is stored instead of plaintext |
| System assistant | 🚧 In progress | Offline Turkish/English system commands and real device-state answers work; no LLM/model runtime is connected yet |
| Physical installation | ❌ Not ready | Requires a disk installer, hardware compatibility work, and a recovery path |

The boot preview is deliberately kept separate from the unfinished production
loader. This lets the project test its UEFI, framebuffer, input, visual assets,
build, and virtual-machine path without presenting the system as more complete
than it is.

## Gallery

![WhisezOS UEFI boot preview](docs/whisezos-boot-preview.png)

![WhisezOS desktop and mouse preview](docs/whisezos-mouse-preview.png)

![Whisez Guard UEFI screen](docs/whisezos-guard-preview.png)

## Easiest way to try it

Download the ready-made developer package if you do not want to build the
source first:

**[Download the WhisezOS v0.1.0 Developer Preview](https://github.com/whisez/WhisezOS/releases/download/v0.1.0/WhisezOS-v0.1.0-developer-preview.zip)**

> The EFI file in the package is not a Windows executable. The recommended way
> to run the UEFI preview is the source-based QEMU workflow below.

### Run from source on Windows

Open PowerShell or Windows Terminal and install the required tools:

```powershell
winget install --id Git.Git --exact
winget install --id Rustlang.Rustup --exact
winget install --id SoftwareFreedomConservancy.QEMU --exact
```

Close and reopen the terminal, then clone the project and launch it in QEMU:

```powershell
git clone https://github.com/whisez/WhisezOS.git
Set-Location WhisezOS
cargo xtask setup
cargo xtask run
```

This workflow does not modify the Windows bootloader, physical disks, or
BIOS/UEFI settings. See the **[English installation guide](INSTALL.en.md)** for
full instructions and troubleshooting, or switch to the
**[Türkçe kurulum rehberi](INSTALL.md)**.

## Controls

On first boot, enter a username and a password of at least six characters.
Later boots require that password on the secure sign-in screen. The password is
not written to disk as plaintext. Never add a test password to source, an issue,
or a commit.

On the desktop:

- Double-click an icon or use the Start menu to open an application.
- Drag windows by their title bar and use the minimize, maximize, and close controls.
- Create folders or text documents in **Files**. Text documents open in Notepad and save with `Ctrl+S`.
- Use **Settings → Accounts** to change the password or lock the session.
- Ask **Assistant** about `files`, `network`, `drivers`, `tasks`, or use their Turkish equivalents.
- Type `help` in **Shell** to list the available commands.

## Whisez Guard

Whisez Guard operates locally and is intended only for defensive use. It does
not execute inspected files, upload them, delete them, or quarantine them
automatically.

```powershell
# Audit Windows Firewall, Defender, UAC, Secure Boot, and listening ports
cargo run --release -p whisez-guard -- audit

# Scan a directory offline
cargo run --release -p whisez-guard -- scan C:\directory-to-scan

# Create and verify a SHA3-256 file-integrity baseline
cargo run --release -p whisez-guard -- baseline C:\important --output baseline.json
cargo run --release -p whisez-guard -- verify baseline.json

# Repeat the verification every five seconds
cargo run --release -p whisez-guard -- monitor baseline.json --interval 5
```

Add `--json` to the `audit`, `scan`, or `verify` command for automation.

## Development roadmap

- [x] Real UEFI preview that boots on QEMU/OVMF
- [x] Animated desktop with mouse and keyboard input
- [x] Whisez Guard defensive utility
- [x] One-command build, test, and developer package workflow
- [x] Ring 3 desktop, VirtIO disk/network drivers, and persistent text files
- [x] Local account, sign-in lock, and password changes in Settings
- [ ] Complete the transition from the production loader to the Rust microkernel
- [ ] Expand beyond QEMU to additional disk, network, audio, and display devices
- [ ] Add multiple users, recovery, permissions, and a secure credential vault
- [ ] Add an optional local-model runtime and secure network client for Assistant
- [ ] Build a secure update, recovery, and disk-installation system
- [ ] Publish a hardware compatibility matrix and stable release

These items are not delivery-date commitments. WhisezOS remains a research and
development project, with progress delivered in small, testable steps.

## Build and verification

Create the developer package:

```powershell
cargo xtask bundle
```

The output is written to `dist/WhisezOS`. Run every supported check with:

```powershell
cargo xtask test
```

This command runs 628 tests, Clippy checks, release builds, and a real QEMU boot
test.

## Repository layout

```text
boot/spectre-boot/       Production loader design and UEFI preview
kernel/spectre-kernel/   Capabilities, IPC, scheduler, vault, and platform code
userland/prism/          Vulkan compositor and animation engine
userland/init/           Ring 3 desktop, applications, account, and device drivers
userland/whisez-guard/   Working local defensive command-line utility
userland/winbridge/      PE loader and Windows compatibility research
userland/spectreshield/  Heuristic process-risk engine
fs/spectrefs/            Copy-on-write file-system research
assets/wallpapers/       WhisezOS desktop artwork
xtask/                   Build, package, test, and QEMU automation
verify/                  Host-executed logic tests
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for the long-term design and
[BUILD.md](BUILD.md) for the full production toolchain.

## Contributing and security

- Read [CONTRIBUTING.en.md](CONTRIBUTING.en.md) before contributing.
- Use either the Turkish or English GitHub Issue forms for bugs and proposals.
- Do not disclose vulnerabilities in public issues; use the private reporting
  path described in [SECURITY.en.md](SECURITY.en.md).
- Never include passwords, access tokens, personal email addresses, user-folder
  paths, or private file contents in an issue or pull request.

## License

WhisezOS is licensed under the Mozilla Public License 2.0. See
[LICENSE](LICENSE) for details.
