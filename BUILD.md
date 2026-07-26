# Building WhisezOS

---

## 1. Host requirements

The build runs on Linux, macOS, or Windows. Linux is the best-supported host
because QEMU + KVM gives usable boot iteration times; on macOS and Windows the
image builds fine but boots under emulation and is slow.

| Tool | Version | Purpose |
|---|---|---|
| rustup / cargo | any recent | toolchain management |
| Rust | `nightly-2026-05-01` (pinned) | see §2 |
| QEMU | ≥ 8.2 | `-machine q35,smm=on`, TPM emulation |
| OVMF | with `.secboot` variant | Secure Boot enforcement |
| swtpm | ≥ 0.8 | measured-boot path |
| glslc | Vulkan SDK 1.3.280+ | GLSL → SPIR-V |
| mtools | ≥ 4.0.43 | ESP population without root |
| sbsigntool | ≥ 0.9.4 | manifest signing |
| clang / lld | ≥ 17 | assembly + linking |

```bash
cargo xtask setup
```

This installs the toolchain and warns about each missing external tool with the
step it will break. It deliberately does not install system packages for you.

### Why the nightly is pinned

The kernel needs `abi_x86_interrupt` and `-Z build-std`, neither stable. A
floating nightly means the build breaks on someone else's machine on a schedule
nobody controls. Bumping the pin is a deliberate PR, run against CI.

---

## 2. Dependency tree

Deliberately shallow. Every crate in kernel or bootloader space is `no_std`,
audited, and justified below — a microkernel that pulls 200 transitive
dependencies has given away the trust boundary it exists to provide.

### Bootloader (`spectre-boot`)

```
spectre-boot
├── uefi 0.36           UEFI protocol bindings          (no_std)
│   └── uguid
├── sha3 0.11           SHA3-512 attestation            (no_std)
│   └── digest → crypto-common → generic-array
├── bitflags 2.6
└── cc 1.2              [build] assembles halt.S
```

### Kernel (`spectre-kernel`)

```
spectre-kernel
├── chacha20poly1305 0.11   Vault Allocation AEAD       (no_std)
│   ├── chacha20 → cipher
│   ├── poly1305 → universal-hash
│   └── aead
├── zerocopy 0.8            safe repr(C) transmutes     (no_std)
├── bitflags 2.6            Rights, BlockFlags
├── spin 0.10               spinlocks (no futex here)
└── heapless 0.9            fixed-capacity collections
```

No `alloc`-dependent crates in the kernel beyond the slab allocator in
`vault.rs`. `heapless` is load-bearing: every collection in kernel space has a
compile-time capacity bound, so no kernel path can fail by exhausting a heap.

### Prism

```
prism
├── ash 0.39                thin Vulkan bindings
├── gpu-allocator 0.28      VRAM sub-allocation
├── raw-window-handle 0.6
└── shaderc 0.9             [build] GLSL → SPIR-V
```

`ash` over `vulkano`/`wgpu`: the compositor needs explicit control of
synchronisation, present timing, and swapchain acquisition. Every safe-wrapper
framework abstracts exactly the things the latency design in §4.1 of
ARCHITECTURE.md depends on.

### SpectreFS

```
spectrefs
├── blake3 1.5              block checksums     (no_std)
├── zstd-safe 7.2           compression
├── chacha20poly1305 0.11   per-file encryption
├── zerocopy 0.8
└── heapless 0.9
```

BLAKE3 over SHA-256 for block checksums: ~7× faster on the same hardware, and
block checksumming is on every read. SHA-3 is retained for boot attestation,
where speed is irrelevant and conservatism is worth more.

### Audit policy

`cargo deny` runs in CI with:
- no crate may introduce a `build.rs` that runs a network fetch,
- no duplicate major versions of a crypto crate,
- every dependency's licence must be MPL-2.0-compatible,
- `cargo audit` advisories are build failures, not warnings.

---

## 3. Build order

### Bootable developer preview (works now)

```bash
cargo xtask demo
cargo xtask run
cargo xtask bundle
```

`demo` builds the x86-64 UEFI application. `run` stages it as
`EFI/BOOT/BOOTX64.EFI` and launches QEMU with a private EDK2 NVRAM image.
`bundle` packages the EFI application, Whisez Guard, and the 4K wallpaper under
`dist/WhisezOS`.

### Production image pipeline (platform work remains)

The intended production order is enforced, not conventional. `image` refuses
to run without a manifest because a manifest generated after image assembly
would contain digests of files that are not the ones shipped.

```
setup → boot ─┐
        kernel ├→ manifest → image → run
      shaders ─┤
     userland ─┘
```

```bash
cargo xtask boot
```

```bash
cargo xtask kernel
```

```bash
cargo xtask shaders
```

```bash
cargo xtask userland
```

```bash
cargo xtask manifest --key keys/dev-signing.pem
```

```bash
cargo xtask image --out target/whisezos.img
```

These commands describe the production pipeline and are retained for platform
development. They do not yet produce a complete desktop OS.

---

## 4. Target and flag reference

### Bootloader — `x86_64-unknown-uefi`

```
--target x86_64-unknown-uefi
-Z build-std=core,alloc,compiler_builtins
-Z build-std-features=compiler-builtins-mem
panic = "abort"
```

PE32+ output, installed to `\EFI\BOOT\BOOTX64.EFI`. UEFI uses the **Microsoft
x64 ABI**, not SysV — `halt.S` reads arguments from RCX/RDX/R8 accordingly. This
is the single most common porting mistake in UEFI assembly.

### Kernel — `x86_64-unknown-none`

```
--target x86_64-unknown-none
--profile kernel
-Z build-std=core,alloc,compiler_builtins
```

Freestanding, no red zone (interrupt handlers would clobber it), no SSE in
kernel code paths that run before FPU state is saved.

### Userland — hardening flags

```
-C relocation-model=pic
-C link-arg=-pie
-Z relro-level=full
-C control-flow-guard=yes
-Z stack-protector=all
-C target-feature=+cet-ss,+cet-ibt
```

Rationale for each is in ARCHITECTURE.md §10. Note `overflow-checks = true` is
retained in the release profile — a silent wrap in a memory manager is a
vulnerability, not a rounding error, and the measured cost is ~1%.

### Shaders

Compiled ahead of time to SPIR-V with `-O -g`. Never at runtime: runtime shader
compilation hitches on exactly the frames the user is looking at, and it means
shipping a compiler inside a process that renders untrusted window content.
Debug info is kept in a sidecar rather than stripped — a RenderDoc capture from a
user bug report is worth far more than the disk space.

---

## 5. Testing

### Host verification harness (works today)

```bash
cd verify && cargo test
```

**231 tests, all passing.** This is the suite to run while the platform layer is
still being written. `verify/` includes the logic modules by `#[path]` — it
tests the real source files, not copies — and supplies deterministic stand-ins
for `arch`, `thread`, and `percpu` in `verify/src/shims.rs`. A shim whose
behaviour would change a test's meaning (`context_switch`, `with_message_buffer`)
calls `unimplemented!()` rather than returning a plausible no-op, so a test that
drifts into depending on real kernel state fails loudly instead of passing
against a fiction.

Only three external crates are needed (`heapless`, `spin`, `bitflags`) plus
`sha3` and `chacha20poly1305`; no QEMU, no OVMF, no Vulkan SDK.

Two tests touch process-global statics (`vault::defer_sweeps`,
`gamemode::ACTIVE`). Teardown now clears both, but if you add a test in that area
and see order-dependent failures, `--test-threads=1` will confirm the diagnosis
before you go looking elsewhere.

### Full build (needs the platform layer)

```bash
cargo xtask test
```

Runs three things:

1. **Host-side logic tests.** Schedulers, capabilities, Vault crypto, PE parsing,
   Shield heuristics, and SpectreFS layout are all written `no_std` but
   host-testable, specifically so their suites run in milliseconds instead of
   requiring a boot. This is why `sched.rs`, `vault.rs`, and `pe.rs` take their
   dependencies as traits and parameters rather than reaching for globals.
2. **Clippy with `-D warnings`.**
3. **Shader compilation**, so a GLSL error is a CI failure rather than a
   first-boot black screen.

Boot-path tests (`spectre-boot`) are excluded from the host run and execute in
QEMU under `tests/boot/`, driven through the serial console.

### What the test suites specifically cover

The tests are written against the failure modes described in ARCHITECTURE.md, not
for coverage percentage. A sample of what would break if someone regressed the
design:

- `spd.rs` — hypervisor hiding half the RAM; iGPU stolen memory staying in
  tolerance; unreadable SMBus degrading rather than bricking the boot.
- `attest.rs` — single flipped bit; missing image treated as tamper, not skip.
- `glitch.rs` — a requested 12 Hz pulse being clamped to 2.5 Hz, verified by
  counting actual zero-crossings over a 2-second sample.
- `cap.rs` — `derive` refusing to amplify rights; derived tokens differing from
  the parent.
- `ipc.rs` — the async ring dropping and counting rather than blocking; wrapping
  correctly over 4× its capacity.
- `vault.rs` — page relocation caught by AAD; two-epoch-old ciphertext failing
  loudly rather than decrypting to garbage; nonce uniqueness across 256
  (page, epoch) pairs.
- `sched.rs` — RT admission refusing the request that would exceed 70%; EEVDF
  skipping over-served threads.
- `gamemode.rs` — core 0 never isolated; single-core machine isolating nothing.
- `anim.rs` — identical output from 144 Hz and 30 Hz sampling of the same
  instant; the pathological `cubic-bezier(0,0,0,1)` not producing NaN.
- `wm.rs` — no discontinuity when a close interrupts an open.
- `startmenu.rs` — antipodal rotation not producing NaN; slerp taking the short
  path.
- `pe.rs` — `e_lfanew` of `0xFFFFFF00` not indexing out of bounds; raw-data
  offset overflow; W+X sections flagged.
- `heuristic.rs` — no single behaviour reaching suspend; a *compromised* backup
  agent still caught despite its role discount.
- `layout.rs` — a torn uberblock with a higher TXG not being selected.

---

## 6. Running

```bash
cargo xtask run
```

Today this command launches the bootable WhisezOS UEFI preview. On Windows it
finds the standard winget QEMU installation, maps the EDK2 code image read-only,
copies the NVRAM template into `target/WHISEZ_VARS.fd`, and boots a virtual FAT
EFI system partition. Close the QEMU window to stop it.

The preview normally reaches the animated dragon in a few seconds. It does not
start the unfinished production kernel. Secure Boot, TPM measurement, storage,
and the Prism desktop handoff remain requirements for the production path.

### Serial console

`-serial stdio` gives the kernel log. Halt screens also emit a POST code to port
0x80 before halting, so a hardware POST card diagnoses a boot failure with no
working video:

| Code | Meaning |
|---|---|
| `0xE0` | No SPD modules responded |
| `0xE1` | Usable memory under the 8 GiB floor |
| `0xE2` | SPD/memory-map mismatch |
| `0xE3` | Integrity attestation failed |

---

## 7. Real hardware

Not recommended yet. The GPU driver sandbox and the user-space NVMe driver are
`SPEC`, so a real-hardware boot currently reaches the kernel and stops at storage
enumeration.

When it is ready, the path is: enrol your own Secure Boot keys via
`spectrectl secureboot enrol`, sign the image, install to the ESP.

**Do not enrol keys and clear the platform key on a machine you cannot recover.**
On many consumer boards, clearing PK without a working restore path leaves you
unable to boot anything, including the vendor's own firmware update utility.
Test in QEMU first.

---

## 8. Contributing

Three rules that CI enforces mechanically:

1. **Unsafe blocks require a `// SAFETY:` comment.** `unsafe_op_in_unsafe_fn` is
   `deny` and `undocumented_unsafe_blocks` is `warn`-escalated-to-error.
2. **Kernel additions must justify why they cannot be user-space.** The default
   answer is that they can. Growth in kernel space is the failure mode this
   whole architecture exists to prevent.
3. **New animations must be interruptible and timestamp-sampled.** A PR adding
   `t += dt` will be rejected — see ARCHITECTURE.md §4.1.
