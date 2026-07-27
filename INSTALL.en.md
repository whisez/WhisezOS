# WhisezOS installation and run guide

**[Türkçe](INSTALL.md) · [English](INSTALL.en.md)**

WhisezOS is currently a developer preview intended only for QEMU. It does not
install itself to a physical disk, modify the Windows bootloader, or change
firmware settings.

> [!CAUTION]
> Do not attempt to install this release on a real computer, USB drive, or
> alongside your primary operating system. The disk installer and hardware
> support are not ready.

## Requirements

The verified quick-start environment is 64-bit Windows 10 or Windows 11:

- Git for downloading the repository
- Rustup for the pinned Rust nightly toolchain
- QEMU with EDK2/OVMF firmware for the virtual machine
- An internet connection during the initial setup

## 1. Install the required tools

Open PowerShell or Windows Terminal:

```powershell
winget install --id Git.Git --exact
winget install --id Rustlang.Rustup --exact
winget install --id SoftwareFreedomConservancy.QEMU --exact
```

Close and reopen the terminal when installation finishes. Confirm that the
tools are available:

```powershell
git --version
rustup --version
qemu-system-x86_64 --version
```

## 2. Download WhisezOS

```powershell
git clone https://github.com/whisez/WhisezOS.git
Set-Location WhisezOS
```

## 3. Prepare the development environment

```powershell
cargo xtask setup
```

This installs the Rust version pinned in `rust-toolchain.toml` and the required
UEFI target. The first run may take a few minutes while dependencies download.

## 4. Launch the UEFI preview in QEMU

```powershell
cargo xtask run
```

The command automatically:

1. Builds the real UEFI application in release mode.
2. Creates a private, temporary firmware-variable file for QEMU.
3. Starts the virtual machine with EDK2/OVMF firmware.
4. Displays the WhisezOS boot animation, the staged setup rehearsal, and the
   desktop preview.

The setup screen runs for about a minute and walks through the production
installation order. It **reads and writes no disk**. Press `Esc` to skip it.

Closing the QEMU window stops the preview. Your computer's physical disk is not
attached to the virtual machine during this process.

## Controls

- Press `Esc` on the setup screen to skip the rehearsal.
- Move the pointer over a card or file icon to select it, then left-click to open it.
- Right-click or press `Esc` to return to the desktop.
- Use `Up` / `Down` or `W` / `S` to change the selection.
- Press `Tab` to switch between the application column and the file grid.
- Press `Enter` to open the selected item.
- Press `1`–`5` to open an application directly.
- Press `Ctrl+Alt+G` to release the pointer captured by QEMU.

### If the mouse does not work

Check the `POINTER` readout in the top bar. It reports how many pointing devices
were bound.

The OVMF firmware shipped with QEMU contains no mouse driver at all: it exposes
`EFI_SIMPLE_POINTER` and `EFI_ABSOLUTE_POINTER` only as the console splitter's
empty virtual instances, so no amount of mouse movement produces data. The
preview detects this and drives the PS/2 mouse directly through the i8042
auxiliary port instead; the readout then shows `POINTER 1`.

`NO POINTER DEVICE` means neither the firmware offers a device nor is an i8042
controller present. The whole preview remains usable from the keyboard.

## Running the production kernel

The preview does not boot a kernel. To run the real loader and microkernel in
QEMU:

```powershell
cargo xtask boot-run
```

This builds the production UEFI loader and the kernel ELF, stages them on a
temporary EFI system partition, and starts QEMU. The kernel's only output is the
serial port, so the command attaches serial to the terminal and opens no display
window.

Expect, in order: the loader's memory audit, validation of the kernel ELF, the
exit from boot services, the handoff, then the kernel's GDT, IDT, frame
allocator, and page-table lines, ending with `[kernel] stage 1 complete`.

To verify the same boot automatically:

```powershell
cargo xtask boot-test
```

This runs QEMU headless, captures the serial log, and asserts that eleven stages
appear in order. It also runs as part of `cargo xtask test`, and is skipped
with a warning when QEMU is not installed.

> The production loader enforces the project's own 8 GiB memory floor and
> refuses to boot a platform below it, which is why the VM is started with 9 GiB.

> The kernel does not start an init process yet; it halts after
> `stage 1 complete`. This is the first verifiable vertical slice, not a
> finished operating system.

## Build only

Build the EFI application without starting QEMU:

```powershell
cargo xtask demo
```

The output is:

```text
target/x86_64-unknown-uefi/release/spectre-demo.efi
```

Collect the EFI application, Whisez Guard, and 4K wallpaper in one directory:

```powershell
cargo xtask bundle
```

The package is written to `dist/WhisezOS`:

```text
dist/WhisezOS/
├── EFI/BOOT/BOOTX64.EFI
├── Tools/whisez-guard.exe
├── Wallpapers/whisezos-dragon-4k.png
└── README.txt
```

## Download the ready-made package

Inspect the files without building the source:

**[WhisezOS v0.1.0 Developer Preview ZIP](https://github.com/whisez/WhisezOS/releases/download/v0.1.0/WhisezOS-v0.1.0-developer-preview.zip)**

SHA-256 of the ZIP file:

```text
DC79DB14ECBA5F431DFBB23B5F70586CB95E2A7903175A19AA85F4AA0235819F
```

This package is not a Windows installer. The easiest and safest way to run the
UEFI preview is the source workflow using `cargo xtask run`.

## Use Whisez Guard only

Whisez Guard can be built and used independently without QEMU:

```powershell
cargo build --release -p whisez-guard
./target/release/whisez-guard.exe audit
./target/release/whisez-guard.exe scan C:\directory-to-scan
```

The utility runs locally. It does not execute, upload, delete, or automatically
quarantine inspected files.

## Verify the setup

Run every supported test, lint check, and UEFI build check:

```powershell
cargo xtask test
```

The verification boundary contains 234 tests: 231 kernel/file-system/boot-logic
tests and 3 Whisez Guard tests.

## Troubleshooting

### `QEMU not found`

Confirm that this file exists:

```text
C:\Program Files\qemu\qemu-system-x86_64.exe
```

If it is missing, reinstall QEMU with the Winget command above and reopen the
terminal.

### `UEFI firmware not found`

The Windows QEMU package should include EDK2 firmware files in its `share`
directory. Reinstall QEMU if files such as `edk2-x86_64-code.fd` are missing.

### Rust toolchain or target error

```powershell
cargo xtask setup
```

Do not replace the project's pinned nightly with an arbitrary `nightly`
toolchain. The dated version makes builds reproducible.

### QEMU opens but remains on a black screen

- Wait a few seconds; an initial build and boot may take longer.
- Check the terminal for error messages.
- Reinstall QEMU and the Rust toolchain using the current setup commands.
- If the problem continues, open a GitHub Issue with terminal output after
  removing personal information.

### Linux and macOS

The Windows quick-start path is verified. Linux and macOS developers should
read [BUILD.md](BUILD.md) for QEMU/OVMF paths and production-toolchain details.

## Uninstall

WhisezOS installs no Windows service and writes nothing to a physical disk.
Close QEMU and remove the cloned `WhisezOS` directory to uninstall it. Git,
Rustup, and QEMU are separate applications and can be removed from Windows
Settings if you no longer use them.
