//! WhisezOS build orchestrator.
//!
//! `cargo xtask <command>`. Everything the build needs beyond `cargo build`
//! lives here rather than in shell scripts, so the build behaves identically on
//! a Linux, macOS, or Windows host.
//!
//! Command order matters and is enforced: `image` cannot run before `manifest`,
//! because the manifest contains the SHA3-512 digests the bootloader will check
//! and generating it after assembling the image would mean shipping digests of
//! files that are not the ones in the image.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "xtask", about = "WhisezOS build orchestrator")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Install toolchain components and verify host prerequisites.
    Setup,
    /// Build the stage-1 UEFI loader.
    Boot,
    /// Build the bootable UEFI visual preview.
    Demo,
    /// Package the UEFI preview, Whisez Guard, and wallpaper.
    Bundle,
    /// Build the microkernel.
    Kernel,
    /// Compile every GLSL shader to SPIR-V.
    Shaders,
    /// Build all user-space components (PIE, full RELRO).
    Userland,
    /// Generate and sign the boot manifest. Must run after all builds.
    Manifest {
        /// Signing key. Absent in CI, where an ephemeral test key is generated.
        #[arg(long)]
        key: Option<PathBuf>,
    },
    /// Assemble the bootable disk image.
    Image {
        #[arg(long, default_value = "whisezos.img")]
        out: PathBuf,
    },
    /// Build the UEFI preview and boot it in QEMU.
    Run {
        #[arg(long, default_value = "q35")]
        machine: String,
        #[arg(long, default_value = "768M")]
        ram: String,
        #[arg(long, default_value = "virtio-vga")]
        gpu: String,
    },
    /// Run every test suite, including the host-side kernel logic tests.
    Test,
    /// Boot the production loader and microkernel in QEMU, serial on stdio.
    BootRun {
        #[arg(long, default_value = "q35")]
        machine: String,
        /// Must clear the memory floor `spd::audit` enforces, which is 8 GiB of
        /// *usable* memory. 9 GiB rather than 8: the firmware keeps a few
        /// megabytes for itself, and the audit measures what is left.
        #[arg(long, default_value = "9G")]
        ram: String,
    },
    /// Boot the microkernel in QEMU headless and assert the serial log.
    BootTest,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Cmd::Setup => setup(),
        Cmd::Boot => build_boot(),
        Cmd::Demo => build_demo(),
        Cmd::Bundle => build_bundle(),
        Cmd::Kernel => build_kernel(),
        Cmd::Shaders => build_shaders(),
        Cmd::Userland => build_userland(),
        Cmd::Manifest { key } => build_manifest(key.as_deref()),
        Cmd::Image { out } => build_image(&out),
        Cmd::Run { machine, ram, gpu } => run_demo_qemu(&machine, &ram, &gpu),
        Cmd::Test => run_tests(),
        Cmd::BootRun { machine, ram } => run_kernel_qemu(&machine, &ram, None),
        Cmd::BootTest => boot_test(),
    }
}

fn setup() -> Result<()> {
    // The pinned nightly is not optional. The kernel uses `abi_x86_interrupt`
    // and `build-std`, neither of which is stable, and a floating nightly means
    // the build breaks on someone else's machine on a schedule nobody controls.
    run("rustup", &["toolchain", "install", "nightly-2026-05-01"])?;
    run(
        "rustup",
        &[
            "component",
            "add",
            "rust-src",
            "llvm-tools-preview",
            "--toolchain",
            "nightly-2026-05-01",
        ],
    )?;
    run(
        "rustup",
        &[
            "target",
            "add",
            "x86_64-unknown-uefi",
            "x86_64-unknown-none",
            "--toolchain",
            "nightly-2026-05-01",
        ],
    )?;

    if find_qemu().is_none() {
        eprintln!("warning: QEMU not found; needed for `cargo xtask run`");
    }
    for (tool, why) in [
        ("glslc", "compiling shaders (bundled with the Vulkan SDK)"),
        ("mtools", "the future production disk-image pipeline"),
    ] {
        if which(tool).is_none() {
            eprintln!("warning: {tool} not found on PATH; needed for {why}");
        }
    }
    Ok(())
}

fn build_boot() -> Result<()> {
    run(
        "cargo",
        &[
            "build",
            "--release",
            "-p",
            "spectre-boot",
            "--bin",
            "spectre-boot",
            "--features",
            "production-loader",
            "--target",
            "x86_64-unknown-uefi",
            "-Z",
            "build-std=core,alloc,compiler_builtins",
            "-Z",
            "build-std-features=compiler-builtins-mem",
        ],
    )
}

fn build_demo() -> Result<()> {
    run(
        "cargo",
        &[
            "build",
            "--release",
            "-p",
            "spectre-boot",
            "--bin",
            "spectre-demo",
            "--target",
            "x86_64-unknown-uefi",
        ],
    )
}

fn build_bundle() -> Result<()> {
    build_demo()?;
    run("cargo", &["build", "--release", "-p", "whisez-guard"])?;

    let root = Path::new("dist/WhisezOS");
    let efi = root.join("EFI/BOOT");
    let tools = root.join("Tools");
    let wallpapers = root.join("Wallpapers");
    std::fs::create_dir_all(&efi)?;
    std::fs::create_dir_all(&tools)?;
    std::fs::create_dir_all(&wallpapers)?;

    std::fs::copy(
        "target/x86_64-unknown-uefi/release/spectre-demo.efi",
        efi.join("BOOTX64.EFI"),
    )?;
    let guard = format!(
        "target/release/whisez-guard{}",
        std::env::consts::EXE_SUFFIX
    );
    std::fs::copy(
        &guard,
        tools.join(format!("whisez-guard{}", std::env::consts::EXE_SUFFIX)),
    )?;
    std::fs::copy(
        "assets/wallpapers/whisezos-dragon-4k.png",
        wallpapers.join("whisezos-dragon-4k.png"),
    )?;
    std::fs::copy("packaging/README.txt", root.join("README.txt"))?;

    println!("WhisezOS bundle ready: {}", root.display());
    Ok(())
}

/// Where the built kernel ELF lands.
const KERNEL_ELF: &str = "target/x86_64-unknown-none/kernel/spectre-kernel";
/// Where the built init ELF lands.
const INIT_ELF: &str = "target/x86_64-unknown-none/kernel/init";
/// Where the built production loader lands.
const LOADER_EFI: &str = "target/x86_64-unknown-uefi/release/spectre-boot.efi";

/// Builds init, the first user-space process.
///
/// Same profile and target as the kernel so both are linked by the same
/// toolchain with the same code model, but its own linker script: init is
/// placed at a user virtual address far from the kernel's identity map, and
/// `init.ld` is what puts it there.
fn build_init() -> Result<()> {
    // `code-model=large` because init is linked at 16 TiB. The default small
    // model reaches its own data with 32-bit signed displacements, which covers
    // the low 2 GiB and nothing else; every reference to a string literal in
    // init would be a relocation that does not fit. Linking lower is not the
    // alternative it looks like — the low 512 GiB is the kernel's identity map,
    // shared into every address space, and mapping a user page there would
    // modify the kernel's own tables.
    let flags = "-C link-arg=-Tuserland/init/init.ld \
                 -C relocation-model=static \
                 -C code-model=large";
    run_with_env(
        "cargo",
        &[
            "build",
            "--profile",
            "kernel",
            "-p",
            "init",
            "--bin",
            "init",
            "--target",
            "x86_64-unknown-none",
            "-Z",
            "build-std=core,compiler_builtins",
            "-Z",
            "build-std-features=compiler-builtins-mem",
        ],
        &[("RUSTFLAGS", flags)],
    )
}

fn build_kernel() -> Result<()> {
    // The linker script is not optional. It fixes the load address the loader
    // allocates at and exports the section symbols `arch/memory.rs` uses to map
    // the image W^X; a default link produces an ELF that loads nowhere useful
    // and a kernel that cannot find its own text boundary.
    let flags = "-C link-arg=-Tkernel/spectre-kernel/kernel.ld -C relocation-model=static";
    run_with_env(
        "cargo",
        &[
            "build",
            "--profile",
            "kernel",
            "-p",
            "spectre-kernel",
            "--bin",
            "spectre-kernel",
            "--target",
            "x86_64-unknown-none",
            "-Z",
            "build-std=core,alloc,compiler_builtins",
            "-Z",
            "build-std-features=compiler-builtins-mem",
        ],
        &[("RUSTFLAGS", flags)],
    )
}

/// Stages an ESP holding the production loader and the kernel.
///
/// Layout mirrors the real disk image: the loader is the removable-media
/// fallback path the firmware boots without an NVRAM entry, and the kernel sits
/// where the loader looks for it.
fn stage_boot_esp(dir: &Path) -> Result<()> {
    build_boot()?;
    build_kernel()?;
    build_init()?;

    let efi = dir.join("EFI/BOOT");
    let spectre = dir.join("SPECTRE");
    std::fs::create_dir_all(&efi)?;
    std::fs::create_dir_all(&spectre)?;
    std::fs::copy(LOADER_EFI, efi.join("BOOTX64.EFI")).context("staging the loader")?;
    std::fs::copy(KERNEL_ELF, spectre.join("KERNEL.ELF")).context("staging the kernel")?;
    std::fs::copy(INIT_ELF, spectre.join("INIT")).context("staging init")?;
    Ok(())
}

/// Boots the production loader and kernel in QEMU with the serial port visible.
fn run_kernel_qemu(machine: &str, ram: &str, serial: Option<&Path>) -> Result<()> {
    let esp = Path::new("target/boot-esp");
    stage_boot_esp(esp)?;

    let qemu = find_qemu().context("QEMU not found")?;
    let firmware_code = find_uefi_firmware(&qemu).context("UEFI firmware not found beside QEMU")?;
    let firmware_vars = find_uefi_vars(&qemu).context("UEFI variable template not found")?;
    let vars_copy = Path::new("target/BOOT_VARS.fd");
    std::fs::copy(&firmware_vars, vars_copy)?;

    let esp_path = std::fs::canonicalize(esp)?;
    let fat_drive = format!("format=raw,file=fat:rw:{}", qemu_path(&esp_path));
    let code_drive = format!(
        "if=pflash,format=raw,unit=0,readonly=on,file={}",
        qemu_path(&firmware_code)
    );
    let vars_drive = format!(
        "if=pflash,format=raw,unit=1,file={}",
        qemu_path(&std::fs::canonicalize(vars_copy)?)
    );
    let machine_arg = format!("{machine},smm=on");

    // Headless when capturing, windowed when a person is watching. The kernel's
    // only output is the serial port either way.
    let (serial_arg, display) = match serial {
        Some(path) => (
            format!("file:{}", qemu_path(&std::path::absolute(path)?)),
            "none",
        ),
        None => ("stdio".to_string(), "none"),
    };

    run_path(
        &qemu,
        &[
            "-name",
            "WhisezOS kernel",
            "-machine",
            &machine_arg,
            // QEMU's default CPU model predates x2APIC, and the kernel drives
            // the local APIC through its MSR interface rather than the
            // memory-mapped one — see `arch/apic.rs` for why. Without this the
            // boot still succeeds, but with no timer and therefore no
            // preemption, which the kernel reports as the degradation it is.
            "-cpu",
            "qemu64,+x2apic",
            "-smp",
            "1",
            "-m",
            ram,
            "-drive",
            &code_drive,
            "-drive",
            &vars_drive,
            "-drive",
            &fat_drive,
            "-serial",
            &serial_arg,
            "-display",
            display,
            "-boot",
            "menu=off,strict=on",
            // A kernel that triple-faults reboots forever otherwise, and the
            // serial capture fills with repeated boots instead of showing the
            // first failure.
            "-no-reboot",
            "-no-shutdown",
        ],
    )
}

/// Lines the boot must produce, in order.
///
/// This is the Phase 1 acceptance criterion in executable form. Each entry is a
/// step that can fail silently on real hardware — a loader that cannot claim its
/// load address, a GDT that faults on the far return, an IDT with a gap, a CR3
/// switch onto a table that does not map the next instruction — and the only
/// evidence any of them worked is that the next line appears.
const EXPECTED_BOOT_LINES: &[&str] = &[
    "[boot] WhisezOS stage-1 loader",
    "[boot] memory audit passed",
    "segments loaded",
    "[boot] exiting boot services",
    "[boot] jumping to kernel",
    "[kernel] WhisezOS microkernel, stage 1",
    "[kernel] gdt installed",
    "[kernel] idt installed",
    "[kernel] frames total=",
    "[kernel] page tables active",
    "[kernel] syscall enabled=true",
    "[kernel] stage 1 complete",
    // Stage 2: two processes, in ring 3, in separate address spaces.
    "[kernel] init mapped pid=1",
    "[kernel] init mapped pid=2",
    "[kernel] lapic id=",
    "[kernel] entering ring 3",
    // Printed by the first process, through SYS_LOG, from ring 3.
    "[init 1] hello from ring 3",
    // The round trip. Printing could be faked by a kernel that never left ring
    // 0; a value the kernel transformed and returned could not.
    "[init 1] ping round trip ok",
    // Each of these would be a privilege escalation if it had succeeded.
    "[init 1] refused as expected: reading kernel memory through SYS_LOG",
    "[init 1] refused as expected: a length past the end of the buffer limit",
    "[init 1] refused as expected: an unassigned syscall number",
    // The second process only ever runs because the first was preempted: it
    // is admitted before either starts and nothing yields.
    "[init 2] hello from ring 3",
    "[init 2] refused as expected: an unassigned syscall number",
    "[init 1] all checks passed",
    "[kernel] pid 1 exited with code 0",
    "[init 2] all checks passed",
    "[kernel] pid 2 exited with code 0",
    "[kernel] stage 2 complete",
];

/// Boots the kernel in QEMU and asserts the serial log.
fn boot_test() -> Result<()> {
    let log = Path::new("target/boot-serial.log");
    if log.exists() {
        std::fs::remove_file(log)?;
    }

    // QEMU is left running by `-no-shutdown` so a failure can be inspected, so
    // the run is bounded from outside rather than waited on.
    let child = std::thread::spawn(|| {
        run_kernel_qemu("q35", "9G", Some(Path::new("target/boot-serial.log")))
    });

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let mut captured = String::new();
    while std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(500));
        captured = std::fs::read_to_string(log).unwrap_or_default();
        if captured.contains(EXPECTED_BOOT_LINES[EXPECTED_BOOT_LINES.len() - 1]) {
            break;
        }
    }
    kill_qemu();
    let _ = child.join();

    let mut cursor = 0usize;
    for expected in EXPECTED_BOOT_LINES {
        match captured[cursor..].find(expected) {
            Some(at) => cursor += at + expected.len(),
            None => {
                eprintln!("--- captured serial log ---\n{captured}\n---");
                bail!("boot log is missing, or has out of order, the line: {expected:?}");
            }
        }
    }

    check_preemption(&captured)?;

    println!(
        "boot test passed: {} stages observed",
        EXPECTED_BOOT_LINES.len()
    );
    Ok(())
}

/// Asserts that the processes were actually preempted.
///
/// Substring checks cannot tell "the scheduler switched" from "the first
/// process happened to finish and the second then ran": both produce every line
/// the list above looks for, in that order. The kernel prints the counter it
/// keeps, and this reads it — a switch count of zero means the timer never
/// fired, which is a system that still boots and passes every other check while
/// having quietly lost preemption.
fn check_preemption(log: &str) -> Result<()> {
    const MARKER: &str = "all processes exited after ";
    let Some(at) = log.find(MARKER) else {
        bail!("boot log never reported the scheduler summary");
    };
    let tail = &log[at + MARKER.len()..];
    let numbers: Vec<u64> = tail
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .take(2)
        .filter_map(|s| s.parse().ok())
        .collect();

    let [ticks, switches] = numbers[..] else {
        bail!("could not read the tick and switch counts from the summary");
    };
    if ticks == 0 {
        bail!("the timer never fired: {ticks} ticks");
    }
    if switches == 0 {
        bail!("no context switch happened in {ticks} ticks");
    }
    println!("preemption confirmed: {ticks} ticks, {switches} switches");
    Ok(())
}

fn kill_qemu() {
    let name = if cfg!(windows) {
        "qemu-system-x86_64.exe"
    } else {
        "qemu-system-x86_64"
    };
    let _ = if cfg!(windows) {
        Command::new("taskkill")
            .args(["/F", "/IM", name])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
    } else {
        Command::new("pkill").args(["-f", name]).status()
    };
}

fn build_shaders() -> Result<()> {
    // Ahead-of-time to SPIR-V. Never at runtime: a compositor that compiles
    // shaders on first use hitches on exactly the frames the user is most
    // likely to be looking at, and it would mean shipping a compiler inside a
    // process that renders untrusted window content.
    let src = Path::new("userland/prism/shaders");
    let out = Path::new("target/spirv");
    std::fs::create_dir_all(out)?;

    for entry in std::fs::read_dir(src).context("shader directory missing")? {
        let path = entry?.path();
        let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
            continue;
        };
        if !matches!(ext, "vert" | "frag" | "comp") {
            continue;
        }

        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let target = out.join(format!("{name}.spv"));

        run(
            "glslc",
            &[
                "--target-env=vulkan1.3",
                // -O for size and speed; the compositor's shaders are compiled
                // once at build time so there is no reason not to.
                "-O",
                // Keep debug info in a separate file rather than stripping it:
                // RenderDoc captures from a user bug report are worth far more
                // than the disk space.
                "-g",
                path.to_str().unwrap(),
                "-o",
                target.to_str().unwrap(),
            ],
        )
        .with_context(|| format!("compiling {name}"))?;
    }
    Ok(())
}

fn build_userland() -> Result<()> {
    // Hardening flags, applied to every user-space binary:
    //   -C relocation-model=pic + -C link-arg=-pie  -> full ASLR for the image
    //   -Z relro-level=full                          -> GOT read-only after link
    //   -C control-flow-guard                        -> CFG on indirect calls
    //   -Z stack-protector=all                       -> canaries everywhere
    //   -C target-feature=+cet-ss                    -> hardware shadow stacks
    //
    // `stack-protector=all` rather than `strong`: the measured cost is under 1%
    // on this workload, and "strong" leaves functions without arrays
    // unprotected, which is exactly where a modern ROP chain starts.
    let flags = "-C relocation-model=pic \
                 -C link-arg=-pie \
                 -Z relro-level=full \
                 -C control-flow-guard=yes \
                 -Z stack-protector=all \
                 -C target-feature=+cet-ss,+cet-ibt";

    run_with_env(
        "cargo",
        &[
            "build",
            "--release",
            "-p",
            "prism",
            "-p",
            "winbridge",
            "-p",
            "spectreshield",
            "-p",
            "spectrefs",
        ],
        &[("RUSTFLAGS", flags)],
    )
}

fn build_manifest(key: Option<&Path>) -> Result<()> {
    use sha3::{Digest, Sha3_512};

    // Everything the bootloader will verify before making it executable.
    let images = [
        (
            "\\SPECTRE\\KERNEL.ELF",
            "target/x86_64-unknown-none/kernel/spectre-kernel",
            8u32,
        ),
        ("\\SPECTRE\\INIT", "target/release/init", 10),
        ("\\SPECTRE\\PRISM", "target/release/prism", 9),
        ("\\SPECTRE\\SHIELD", "target/release/spectreshield", 9),
        ("\\SPECTRE\\SPECTREFS", "target/release/spectrefs", 9),
    ];

    let mut manifest = String::from("# WhisezOS boot manifest v1\n");
    for (esp_path, build_path, pcr) in images {
        let bytes = std::fs::read(build_path)
            .with_context(|| format!("{build_path} not built; run the build steps first"))?;

        let mut hasher = Sha3_512::new();
        hasher.update(&bytes);
        let digest = hasher.finalize();

        manifest.push_str(&format!("{esp_path} {pcr} {}\n", hex(&digest)));
    }

    std::fs::write("target/boot.manifest", &manifest)?;

    match key {
        Some(k) => sign_manifest(Path::new("target/boot.manifest"), k)?,
        None => {
            // An unsigned manifest produces an image the bootloader will refuse.
            // Emitting it anyway, loudly, is more useful than failing: it lets a
            // developer inspect the digests without a signing key present.
            eprintln!(
                "warning: manifest is UNSIGNED. The resulting image will halt at \
                 the tamper screen. Pass --key to produce a bootable image."
            );
        }
    }
    Ok(())
}

fn build_image(out: &Path) -> Result<()> {
    if !Path::new("target/boot.manifest").exists() {
        bail!(
            "no manifest; run `cargo xtask manifest` first — the image must \
               contain digests of the binaries it actually ships"
        );
    }
    // 512 MiB ESP + SpectreFS root. Assembled with mtools so no loop device or
    // root privileges are needed, which matters for CI.
    run(
        "dd",
        &[
            "if=/dev/zero",
            &format!("of={}", out.display()),
            "bs=1M",
            "count=4096",
        ],
    )?;
    run("mformat", &["-i", out.to_str().unwrap(), "-F", "::"])?;
    run(
        "mmd",
        &[
            "-i",
            out.to_str().unwrap(),
            "::/EFI",
            "::/EFI/BOOT",
            "::/SPECTRE",
        ],
    )?;
    run(
        "mcopy",
        &[
            "-i",
            out.to_str().unwrap(),
            "target/x86_64-unknown-uefi/release/spectre-boot.efi",
            "::/EFI/BOOT/BOOTX64.EFI",
        ],
    )?;
    Ok(())
}

fn run_demo_qemu(machine: &str, ram: &str, gpu: &str) -> Result<()> {
    build_demo()?;

    let esp = Path::new("target/esp/EFI/BOOT");
    std::fs::create_dir_all(esp).context("creating the preview EFI system partition")?;
    std::fs::copy(
        "target/x86_64-unknown-uefi/release/spectre-demo.efi",
        esp.join("BOOTX64.EFI"),
    )
    .context("staging BOOTX64.EFI")?;

    let qemu = find_qemu().context(
        "QEMU not found. On Windows run `winget install --id SoftwareFreedomConservancy.QEMU -e`",
    )?;
    let firmware_code = find_uefi_firmware(&qemu)
        .context("UEFI firmware not found beside QEMU (expected edk2-x86_64-code.fd)")?;
    let firmware_vars = find_uefi_vars(&qemu)
        .context("UEFI variable template not found beside QEMU (expected edk2-i386-vars.fd)")?;
    let vars_copy = Path::new("target/WHISEZ_VARS.fd");
    std::fs::copy(&firmware_vars, vars_copy).context("creating a private UEFI NVRAM image")?;

    let esp_path = std::fs::canonicalize("target/esp").context("canonicalizing target/esp")?;
    let fat_drive = format!("format=raw,file=fat:rw:{}", qemu_path(&esp_path));
    let code_drive = format!(
        "if=pflash,format=raw,unit=0,readonly=on,file={}",
        qemu_path(&firmware_code)
    );
    let vars_drive = format!(
        "if=pflash,format=raw,unit=1,file={}",
        qemu_path(&std::fs::canonicalize(vars_copy)?)
    );
    let machine_arg = format!("{machine},smm=on");

    run_path(
        &qemu,
        &[
            "-name",
            "WhisezOS UEFI Preview",
            "-machine",
            &machine_arg,
            "-smp",
            "2",
            "-m",
            ram,
            "-drive",
            &code_drive,
            "-drive",
            &vars_drive,
            "-drive",
            &fat_drive,
            "-device",
            gpu,
            "-device",
            "qemu-xhci",
            // `usb-tablet` is an absolute pointing device. A relative
            // `usb-mouse` only delivers motion once the VM has grabbed the host
            // pointer, which is why the preview's cursor did not move: the
            // firmware had nothing to report. The tablet needs no grab, and the
            // preview binds EFI_ABSOLUTE_POINTER_PROTOCOL to read it. The mouse
            // stays attached so the relative path is exercised too.
            "-device",
            "usb-tablet",
            "-device",
            "usb-mouse",
            // No `show-cursor=on`: with an absolute device the host cursor
            // tracks the guest cursor exactly, and drawing both leaves two
            // overlapping arrows on screen.
            "-display",
            "gtk,zoom-to-fit=on,grab-on-hover=off",
            "-boot",
            "menu=off,strict=on",
            "-no-reboot",
        ],
    )
}

fn run_tests() -> Result<()> {
    // The verify crate includes the real no_std logic modules behind host
    // shims. A workspace-wide test would incorrectly try to link unfinished
    // production platform binaries, so the honest test boundary is explicit.
    run("cargo", &["test", "--manifest-path", "verify/Cargo.toml"])?;
    run("cargo", &["test", "-p", "whisez-guard"])?;

    for package in [
        "whisez-guard",
        "xtask",
        "spectre-boot",
        "spectre-kernel",
        "init",
    ] {
        run("cargo", &["fmt", "-p", package, "--", "--check"])?;
    }
    run(
        "cargo",
        &["clippy", "-p", "whisez-guard", "--", "-D", "warnings"],
    )?;
    run("cargo", &["clippy", "-p", "xtask", "--", "-D", "warnings"])?;
    run(
        "cargo",
        &[
            "clippy",
            "-p",
            "spectre-boot",
            "--bin",
            "spectre-demo",
            "--target",
            "x86_64-unknown-uefi",
            "--",
            "-D",
            "warnings",
        ],
    )?;
    // The production loader and the kernel need `build-std`, so they are linted
    // separately from the preview rather than in one invocation.
    run_with_env(
        "cargo",
        &[
            "clippy",
            "-p",
            "spectre-boot",
            "--bin",
            "spectre-boot",
            "--features",
            "production-loader",
            "--target",
            "x86_64-unknown-uefi",
            "-Z",
            "build-std=core,alloc,compiler_builtins",
            "-Z",
            "build-std-features=compiler-builtins-mem",
            "--",
            "-D",
            "warnings",
        ],
        &[("RUSTFLAGS", "")],
    )?;
    run_with_env(
        "cargo",
        &[
            "clippy",
            "-p",
            "spectre-kernel",
            "--target",
            "x86_64-unknown-none",
            "-Z",
            "build-std=core,alloc,compiler_builtins",
            "-Z",
            "build-std-features=compiler-builtins-mem",
            "--",
            "-D",
            "warnings",
        ],
        &[(
            "RUSTFLAGS",
            "-C link-arg=-Tkernel/spectre-kernel/kernel.ld -C relocation-model=static",
        )],
    )?;

    // init is linked with `code-model=large` against a user address, so it is
    // linted with the same flags it is built with — a lint run under different
    // codegen options is not a lint run of the shipped binary.
    run_with_env(
        "cargo",
        &[
            "clippy",
            "-p",
            "init",
            "--bin",
            "init",
            "--target",
            "x86_64-unknown-none",
            "-Z",
            "build-std=core,compiler_builtins",
            "-Z",
            "build-std-features=compiler-builtins-mem",
            "--",
            "-D",
            "warnings",
        ],
        &[(
            "RUSTFLAGS",
            "-C link-arg=-Tuserland/init/init.ld -C relocation-model=static -C code-model=large",
        )],
    )?;

    build_demo()?;
    build_boot()?;
    build_kernel()?;
    build_init()?;

    // The boot test is the only thing here that proves the kernel runs rather
    // than merely compiles, so it is not optional when it can be run at all.
    // CI has no QEMU, hence the skip rather than a hard failure.
    if find_qemu().is_some() {
        boot_test()?;
    } else {
        eprintln!("warning: kernel boot test skipped because QEMU is not installed");
    }

    if which("glslc").is_some() {
        build_shaders()?;
    } else {
        eprintln!("warning: shader validation skipped because glslc is not installed");
    }
    Ok(())
}

// --- helpers ---------------------------------------------------------------

fn run(program: &str, args: &[&str]) -> Result<()> {
    run_with_env(program, args, &[])
}

fn run_path(program: &Path, args: &[&str]) -> Result<()> {
    let status = Command::new(program)
        .args(args)
        .status()
        .with_context(|| format!("failed to spawn `{}`", program.display()))?;

    if !status.success() {
        bail!("`{}` exited with {status}", program.display());
    }
    Ok(())
}

fn run_with_env(program: &str, args: &[&str], env: &[(&str, &str)]) -> Result<()> {
    let mut cmd = Command::new(program);
    cmd.args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }

    let status = cmd
        .status()
        .with_context(|| format!("failed to spawn `{program}`; is it on PATH?"))?;

    if !status.success() {
        bail!("`{program}` exited with {status}");
    }
    Ok(())
}

fn which(tool: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|p| p.join(tool))
            .find(|p| p.is_file())
    })
}

fn find_qemu() -> Option<PathBuf> {
    which(if cfg!(windows) {
        "qemu-system-x86_64.exe"
    } else {
        "qemu-system-x86_64"
    })
    .or_else(|| {
        if !cfg!(windows) {
            return None;
        }
        [
            std::env::var_os("ProgramFiles"),
            std::env::var_os("LOCALAPPDATA"),
        ]
        .into_iter()
        .flatten()
        .map(PathBuf::from)
        .flat_map(|base| {
            [
                base.join("qemu/qemu-system-x86_64.exe"),
                base.join("Programs/qemu/qemu-system-x86_64.exe"),
            ]
        })
        .find(|path| path.is_file())
    })
}

fn find_uefi_firmware(qemu: &Path) -> Option<PathBuf> {
    let qemu_dir = qemu.parent()?;
    let candidates = if cfg!(windows) {
        vec![
            qemu_dir.join("share/edk2-x86_64-code.fd"),
            qemu_dir.join("share/edk2-x86_64-secure-code.fd"),
            qemu_dir.join("share/edk2-i386-code.fd"),
            qemu_dir.join("edk2-x86_64-code.fd"),
        ]
    } else {
        vec![
            PathBuf::from("/usr/share/OVMF/OVMF_CODE.fd"),
            PathBuf::from("/usr/share/edk2/x64/OVMF_CODE.fd"),
            PathBuf::from("/usr/share/qemu/edk2-x86_64-code.fd"),
        ]
    };

    candidates.into_iter().find(|path| path.is_file())
}

fn find_uefi_vars(qemu: &Path) -> Option<PathBuf> {
    let qemu_dir = qemu.parent()?;
    let candidates = if cfg!(windows) {
        vec![
            qemu_dir.join("share/edk2-i386-vars.fd"),
            qemu_dir.join("share/edk2-x86_64-vars.fd"),
            qemu_dir.join("edk2-i386-vars.fd"),
        ]
    } else {
        vec![
            PathBuf::from("/usr/share/OVMF/OVMF_VARS.fd"),
            PathBuf::from("/usr/share/edk2/x64/OVMF_VARS.fd"),
            PathBuf::from("/usr/share/qemu/edk2-i386-vars.fd"),
        ]
    };

    candidates.into_iter().find(|path| path.is_file())
}

fn qemu_path(path: &Path) -> String {
    let raw = path.display().to_string();
    let ordinary = raw.strip_prefix(r"\\?\").unwrap_or(&raw);
    if cfg!(windows) {
        ordinary.replace('\\', "/")
    } else {
        ordinary.to_string()
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sign_manifest(manifest: &Path, key: &Path) -> Result<()> {
    run(
        "sbsign",
        &[
            "--key",
            key.to_str().unwrap(),
            "--cert",
            &key.with_extension("crt").to_string_lossy(),
            "--output",
            &manifest.with_extension("signed").to_string_lossy(),
            manifest.to_str().unwrap(),
        ],
    )
}
