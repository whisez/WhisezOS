# WhisezOS

[![CI](https://github.com/whisez/WhisezOS/actions/workflows/ci.yml/badge.svg)](https://github.com/whisez/WhisezOS/actions/workflows/ci.yml)

WhisezOS is an experimental, cyberpunk-themed operating-system project built
around a capability-secured Rust microkernel design. The repository now has a
real bootable UEFI visual preview, a local defensive security tool, and a
packaged 4K desktop wallpaper.

![WhisezOS UEFI boot preview](docs/whisezos-boot-preview.png)

![WhisezOS desktop preview with mouse cursor](docs/whisezos-mouse-preview.png)

![Whisez Guard UEFI screen](docs/whisezos-guard-preview.png)

## What works today

| Component | Status |
|---|---|
| UEFI preview | Boots in QEMU/OVMF, renders the WhisezOS dragon, then enters the desktop preview |
| Desktop input | Visible cyan cursor, PS/2 and USB mouse input, hover selection, left-click open, and right-click back |
| Boot animation | Time-limited smooth reveal and fade; it no longer remains on the loading screen |
| Whisez Guard | Windows posture audit, offline content scan, SHA3-256 baselines, verification, and monitoring |
| Wallpaper | 3840x2160 WhisezOS dragon wallpaper |
| Logic harness | 231 kernel/filesystem/boot logic tests |
| Production OS | Architecture and core logic exist; kernel handoff, drivers, installer, and desktop session are not complete |

The boot preview is deliberately separate from the unfinished production
loader. It proves the UEFI, framebuffer, asset, build, packaging, and VM path
without pretending the full operating system is ready.

## Quick start on Windows

Requirements: Rustup and QEMU. QEMU can be installed with:

```powershell
winget install --id SoftwareFreedomConservancy.QEMU --exact
```

Build and open the WhisezOS UEFI preview:

```powershell
cargo xtask run
```

Desktop controls:

- Move the mouse over a card to select it; left-click opens it
- Right-click returns to the desktop; the on-screen back button also accepts a left-click
- QEMU keeps the host pointer visible and scales the guest desktop to the window; `Ctrl+Alt+G` releases input capture
- `Up` / `Down` or `W` / `S`: select an application
- `Enter`: open the selected application
- `1`, `2`, `3`: open Guard, Terminal, or Files directly
- `Esc`: return to the desktop

Build a ready-to-copy bundle containing the EFI binary, Whisez Guard, and the
4K wallpaper:

```powershell
cargo xtask bundle
```

The result is written to `dist/WhisezOS`.

## Whisez Guard

Whisez Guard is defensive and local-only. It never executes inspected files,
uploads data, or automatically deletes/quarantines anything.

```powershell
# Windows Firewall, Defender, UAC, Secure Boot, and listening-socket posture
cargo run --release -p whisez-guard -- audit

# Offline multi-indicator scan
cargo run --release -p whisez-guard -- scan C:\path\to\inspect

# Build and verify a SHA3-256 file-integrity baseline
cargo run --release -p whisez-guard -- baseline C:\important --output baseline.json
cargo run --release -p whisez-guard -- verify baseline.json

# Re-check continuously every five seconds
cargo run --release -p whisez-guard -- monitor baseline.json --interval 5
```

Use `--json` with `audit`, `scan`, or `verify` for automation.

## Verification

```powershell
cargo test -p whisez-guard
Push-Location verify
cargo test
Pop-Location
cargo xtask demo
```

The QEMU boot path and real mouse input were visually verified at 1920x1080
with the installed EDK2/OVMF firmware. The captured result is the image above.

## Repository layout

```text
boot/spectre-boot/       Production-loader design plus bootable UEFI preview
kernel/spectre-kernel/   Capability, IPC, scheduler, vault, and platform work
userland/prism/          Vulkan compositor and animation engine
userland/whisez-guard/   Working defensive host security CLI
userland/winbridge/      PE-loader and Windows compatibility work
userland/spectreshield/  Heuristic process-risk engine
fs/spectrefs/            Copy-on-write filesystem work
assets/wallpapers/       WhisezOS desktop artwork
xtask/                   Cross-platform build, bundle, and QEMU orchestration
verify/                  Host-side logic verification harness
```

See [BUILD.md](BUILD.md) for production toolchain details and
[ARCHITECTURE.md](ARCHITECTURE.md) for the long-term system design.

## Security boundary

WhisezOS is not currently safe to install on real hardware. Test the preview in
QEMU only. The production loader's Secure Boot/TPM chain, storage drivers,
network service isolation, and desktop handoff remain development work.

Please report suspected vulnerabilities privately as described in
[SECURITY.md](SECURITY.md).

## License

WhisezOS is licensed under the Mozilla Public License 2.0. See
[LICENSE](LICENSE) for the full terms.
