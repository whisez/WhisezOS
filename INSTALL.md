# Install and run WhisezOS

WhisezOS currently ships as a developer preview for QEMU. It does not install
itself to a physical disk, change the Windows bootloader, or modify firmware.
Do not try to install the preview on real hardware.

## Supported setup

The verified setup is a 64-bit Windows 10 or Windows 11 machine with:

- Git for cloning the repository
- Rustup for the pinned Rust nightly toolchain
- QEMU with EDK2/OVMF firmware for the virtual machine

Install the prerequisites from PowerShell or Windows Terminal:

```powershell
winget install --id Git.Git --exact
winget install --id Rustlang.Rustup --exact
winget install --id SoftwareFreedomConservancy.QEMU --exact
```

Close and reopen the terminal after installation so the new commands are on
`PATH`.

## Run the UEFI preview

```powershell
git clone https://github.com/whisez/WhisezOS.git
Set-Location WhisezOS
cargo xtask setup
cargo xtask run
```

`cargo xtask setup` installs the toolchain components pinned by
`rust-toolchain.toml`. `cargo xtask run` builds the real UEFI preview, creates a
private QEMU firmware-variable image under `target`, and starts the virtual
machine. The first build may take several minutes while Rust dependencies are
downloaded.

QEMU controls:

- Move the mouse to select a card; left-click opens it.
- Right-click or press `Esc` to return to the desktop.
- Use `Up`/`Down` or `W`/`S` to select an application.
- Press `Enter` to open the selected application.
- Press `1`, `2`, or `3` to open Guard, Terminal, or Files directly.
- Press `Ctrl+Alt+G` to release QEMU's input capture.

Close the QEMU window to stop the preview.

## Build without starting QEMU

Build only the UEFI application:

```powershell
cargo xtask demo
```

The EFI binary is written to:

```text
target/x86_64-unknown-uefi/release/spectre-demo.efi
```

Build a portable developer bundle:

```powershell
cargo xtask bundle
```

The bundle is written to `dist/WhisezOS` and contains:

- `EFI/BOOT/BOOTX64.EFI` — bootable UEFI preview
- `Tools/whisez-guard.exe` — defensive Windows command-line tool
- `Wallpapers/whisezos-dragon-4k.png` — 4K wallpaper

## Use Whisez Guard only

Whisez Guard can be built and used without QEMU:

```powershell
cargo build --release -p whisez-guard
./target/release/whisez-guard.exe audit
./target/release/whisez-guard.exe scan C:\path\to\inspect
```

The scanner is local-only. It does not execute inspected files, upload data,
delete files, or quarantine anything automatically.

## Verify the checkout

Run every supported test, lint, and preview-build check:

```powershell
cargo xtask test
```

The supported verification boundary currently contains 234 tests: 231
host-side kernel/filesystem/boot logic tests and 3 Whisez Guard tests.

## Troubleshooting

### `QEMU not found`

Confirm that `C:\Program Files\qemu\qemu-system-x86_64.exe` exists. If it does
not, reinstall QEMU with the Winget command above. The build tool checks both
`PATH` and the standard Windows installation folders.

### `UEFI firmware not found`

The Windows QEMU package should include EDK2 firmware in its `share` folder.
Reinstall the current QEMU package if files such as
`edk2-x86_64-code.fd` are missing.

### Rust toolchain or target errors

Run the setup step again:

```powershell
cargo xtask setup
```

Do not replace the pinned nightly with a floating `nightly` toolchain; the
project intentionally uses a reproducible toolchain date.

### Other operating systems

Windows is the tested quick-start path. Linux and macOS developers should read
[BUILD.md](BUILD.md) for the required QEMU/OVMF paths and production-toolchain
notes.

## Remove the preview

WhisezOS does not install services or write to a physical disk. To remove the
checkout, close QEMU and delete the cloned `WhisezOS` folder. Rustup and QEMU
are separate tools and can be removed through Windows Settings if no longer
needed.
