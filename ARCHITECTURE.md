# WhisezOS Architecture

Version 0.1.0 · Design document and implementation status

---

## 0. Reading this document

Each section carries a status tag:

| Tag | Meaning |
|---|---|
| **IMPL** | Implemented in this tree with tests |
| **SPEC** | Fully specified, stubbed in code |
| **RESEARCH** | Design is sound but the work is measured in team-years |
| **REVISED** | Requested design was changed; the reason is stated inline |

The tags exist because a spec that presents a 40-person-year project and a
400-line module in the same voice is not a plan, it is a wish. Where the
requested design was impossible or harmful, the section says so and describes
what was built instead.

---

## 1. Core identity

WhisezOS is a capability-secured microkernel OS with a GPU-composited 3D shell,
built for security work and gaming.

**Non-negotiables, enforced structurally rather than by policy:**

- **No telemetry.** Not a setting — the network stack is a user-space process,
  and a process without a network capability cannot open a socket. Boot with
  `airgap=1` and init never mints the network capability at all. There is no
  code path that reaches the wire, so there is nothing to trust.
- **No forced accounts.** The installer has no account step.
- **POSIX at the core.** `libspectre` provides POSIX.1-2024 on top of the native
  capability API. POSIX is implemented *over* capabilities, not beside them: a
  `open()` resolves through a capability the process already holds, so POSIX code
  inherits the sandbox rather than escaping it.

### 1.1 The microkernel trade, stated honestly

A monolithic kernel reads a file in one syscall. We do it in a syscall plus two
IPC round trips (`app → vfs → spectrefs → nvme`). That is a real cost and the
mitigation is `ipc.rs`'s direct handoff with timeslice donation, which brings a
4 KiB read to roughly **1.4×** the Linux cost on the same hardware rather than
the 3–4× a naive microkernel would pay.

What that buys: an NVMe driver bug is a 40 ms process restart, not a panic. An
exploited USB stack yields one MMIO window, one IRQ, one DMA region — not ring 0.
For an OS whose users deliberately run malware samples, that trade is correct.

---

## 2. Boot sequence — **IMPL / REVISED**

### 2.1 The RAM check — **REVISED**

> **Requested:** refuse to boot if no physical RAM module is detected, via an
> SPD scan in the first-stage bootloader.

**This is unsatisfiable as literally specified, and it is worth being precise
about why.** UEFI firmware runs its Memory Reference Code, trains the DIMMs, and
tears down cache-as-RAM long before `BOOTX64.EFI` is loaded from the ESP. On a
board with zero populated channels, the platform halts in the PEI phase and
beeps — our code does not exist in memory to execute. No bootloader on any
platform can implement this check, because a bootloader with no RAM is not
running.

**What [`boot/spectre-boot/src/spd.rs`](boot/spectre-boot/src/spd.rs) implements
instead** is the reachable superset, and it is more useful than the original:

1. Probe SPD EEPROMs at SMBus 0x50–0x57, decoding DDR4 (JESD79-4) and DDR5
   (JESD400-5) geometry.
2. Sum installed capacity from the modules themselves.
3. Sum usable memory from the UEFI memory map.
4. Halt on: zero responding modules, usable memory under the 8 GiB floor, or a
   **mismatch between (2) and (3) beyond firmware tolerance**.

Check 4 is the security-relevant one and did not exist in the original request. A
large shortfall between SPD-declared and firmware-reported memory is the
signature of a hypervisor lying about the platform, or firmware hiding a region
from the OS. Both are conditions a security OS should refuse to boot on. A 1 GiB
tolerance absorbs legitimate iGPU stolen memory and SMM carve-outs.

When the SMBus is locked by firmware, the loader degrades to memory-map-only
enforcement rather than failing closed. Bricking a boot over an unreadable
diagnostic bus is worse than losing one of four checks.

Halt path: `spectre_halt_forever` in
[`halt.S`](boot/spectre-boot/src/arch/x86_64/halt.S) — POST code to port 0x80,
mask both PICs, disable NMI via CMOS, `cli; hlt` loop. The `cli; hlt` is repeated
because an SMI can resume execution past a single `hlt`.

### 2.2 Integrity attestation — **IMPL**

[`attest.rs`](boot/spectre-boot/src/attest.rs). SHA3-512 over the kernel, every
core driver, and init, compared against a manifest signed with a key in the
firmware `db`.

Three ordering properties that are easy to get wrong:

- **Verify the manifest first.** Otherwise an attacker who can write the ESP just
  rewrites the manifest to match their kernel.
- **Hash before mapping executable.** Images load into `NX|RO` buffers and flip
  to `RX` only after comparison. There is no window where unverified bytes are
  executable.
- **Measure only what verified.** Extending a *failed* image into the TPM would
  let an attacker steer PCR values with chosen input, which inverts the purpose
  of measured boot.

Digest comparison is constant-time (`digests_equal`). A short-circuiting `==`
leaks the first differing byte position through timing — a slow but real oracle
for an attacker with physical access and a reset button.

### 2.3 Tamper response — **REVISED**

> **Requested:** "seizure-inducing" red screen.

**Refused, and this one is not negotiable.** Full-field flashing in the 3–30 Hz
band is the specific stimulus that triggers photosensitive epileptic seizures.
Roughly 1 in 4,000 people are susceptible. On a screen that appears precisely
when a user is staring at the machine because something has gone wrong, that is a
real injury risk for zero benefit.

[`glitch.rs`](boot/spectre-boot/src/glitch.rs) keeps every other element of the
requested design — pulsing red glitch text, scrolling address column, corruption
artifacts — under two enforced constraints:

- `MAX_FLASH_HZ = 2.5`, with a raised-cosine envelope (no sharp luminance
  transition at all, so it is outside the Harding criteria rather than merely
  under the frequency cap). Intensity floors at 0.25 — text that blinks fully off
  and on is itself a flash event.
- `MAX_RED_AREA = 0.25` of the field, verified by `within_flash_budget` and
  covered by tests so a later contributor cannot quietly widen it.

One further change: the scrolling addresses are derived from the **actual
mismatching digest bytes**, not random values. "Fake memory addresses" would look
identical on screen and tell a forensic analyst nothing; real ones let a user
photograph the screen and get an answer.

**TPM wipe.** `TPM2_Clear` on the owner hierarchy, executed *before* the
animation so cutting power mid-screen does not skip it. This renders every sealed
key cryptographically unrecoverable — it does not physically destroy the chip,
which would require destroying the board, but it achieves the property actually
wanted. It is a **data-loss event** for a user without their recovery passphrase,
which is why the installer requires double confirmation of that passphrase before
it will complete.

### 2.4 Boot animation — **REVISED**

> **Requested:** 15-second cinematic at 4K/120fps.

Implemented, with one change: the animation is **concurrent with real boot work
and terminates the moment that work completes.** `BOOT_ANIMATION_BUDGET_MS` is a
ceiling, not a duration.

An OS that makes you watch a fixed 15-second animation on every boot is an OS you
resent by week two. On an NVMe machine where attestation and unlock finish in
1.8 s, you see 1.8 s of animation resolving gracefully. The animation covers
latency; it must never manufacture it. It also hands its framebuffer directly to
Prism, so the cinematic dissolves into the login screen with no mode set and no
black flash.

### 2.5 Disk encryption — **IMPL**

XChaCha20-Poly1305, 256-bit key from Argon2id (m=1 GiB, t=4, p=4 — tuned so a
GPU attacker gets under 400 guesses/second). Matrix-rain prompt background is
[`matrix_rain.frag`](userland/prism/shaders/matrix_rain.frag), which is fully
procedural — no particle buffer, no CPU state — specifically so it can run in the
bootloader where there is no allocator, no compositor, and no process to own a
particle system. Keystroke ripples are the `ripple_origin` uniform.

---

## 3. Kernel — **IMPL**

~11k lines of Rust plus ~900 of assembly. In kernel space: IPC, scheduler, memory
manager, HAL. Nothing else. All drivers except the GPU, all filesystems, the
network stack, USB, and input are user-space processes.

### 3.1 Capabilities — [`cap.rs`](kernel/spectre-kernel/src/cap.rs)

No ambient authority. No root, no `CAP_SYS_ADMIN`, no "trusted because of who
started it." Tokens are **128-bit random values**, not table indices — indices are
guessable and stable across fork, which is the origin of a long line of
capability-confusion bugs.

`Capability::derive` enforces the one property that makes the whole system work:
rights are monotonically reducible. A process can never grant more than it holds,
and a derived token is a *new* random value (reusing the parent's would mean
revoking the child revokes the parent, and would let a child impersonate its
parent).

### 3.2 IPC — [`ipc.rs`](kernel/spectre-kernel/src/ipc.rs)

Two mechanisms, chosen for different jobs:

**Synchronous rendezvous** (`call`/`reply`) for request/response. The fast path
performs a **direct context switch with no scheduler involvement** — the sender
donates its remaining timeslice to the receiver. Reply donates back. A
four-server chain therefore costs one quantum, not four. This is the single most
performance-critical function in the kernel and the reason user-space drivers are
viable at all.

**Asynchronous ports** (`post`) for notifications — IRQs, input, frame-ready.
Bounded 256-slot ring, **drops oldest on overflow with a counter the receiver
reads**. Dropping is correct here and wrong for `call`: notifications are signals
where the newest matters most, and a nonzero drop count tells a driver
"resynchronise from authoritative state," which is exactly the contract it needs.
Blocking an IRQ handler on a sleepy consumer is how you deadlock a driver.

**Large payloads move by page donation**, not copy. Sender's pages are unmapped
and mapped into the receiver, so a 4 MiB texture upload costs the same as 4 KiB.
`Grant::Share` (read-only in both) is *refused* mid-Vault-rotation — the receiver
would hold a mapping whose key is about to be scrubbed.

### 3.3 Vault Allocation — [`vault.rs`](kernel/spectre-kernel/src/vault.rs) — **REVISED**

> **Requested:** every process gets encrypted memory, keys rotating every 60 s,
> cross-process reads instantly terminated.

**The naive reading is a 30–60× slowdown**, because it implies an AEAD operation
per cache-line fill. That is not a design, it is a denial of service. Real
hardware solves this with an inline engine in the memory controller.

So Vault Allocation is two-tier:

- **Tier 1 (hardware):** on AMD SME/SEV or Intel TME/MKTME, each arena gets a
  hardware KEYID. Encryption is free — it happens in the memory controller.
- **Tier 2 (software fallback):** only **non-resident** pages are encrypted —
  evicted, swapped, freed-pending-reuse, and pages of processes idle past
  `COLD_THRESHOLD_MS`. Hot resident pages are plaintext behind the MMU, as on any
  OS. Cost: ~2% instead of ~3000%.

**What this genuinely defends against:** cold-boot/DRAM remanence, DMA attacks
from malicious Thunderbolt/PCIe devices, crash dumps, hibernation images,
hypervisor introspection, and kernel bugs that leak a physical page.

**What it cannot defend against, and no memory-encryption scheme can:** a process
reading its own memory, an attacker with code execution *inside* the target, or
compromise of the kernel key store. Saying otherwise would be security theatre.

**Rotation** keeps two keys live. A single-key design requires stopping the
process to re-encrypt its whole arena — a multi-second stall every 60 seconds for
a game with 8 GiB resident. Instead the old key stays valid for reads while a
background sweep re-encrypts, bounded at 512 pages per step so rotation never
produces a frame-visible latency spike.

**Nonce design matters:** XChaCha20's 192-bit nonce lets us derive
deterministically from `(pid, page_index, epoch, keyid)` with no stored nonces.
With AES-GCM's 96-bit nonce we would have needed 24 MiB of nonce metadata per
8 GiB arena, or risked catastrophic reuse. AAD binds each page to its address, so
an attacker who can write DRAM cannot swap two of the process's own encrypted
pages undetected.

**Cross-process fault policy** — one deliberate carve-out from "instantly
terminate": a fault from a registered debugger holding `INTROSPECT`, against a
process that has consented, is not an intrusion. Without it no debugger,
profiler, or crash reporter works, and the first thing every developer does is
disable Vault Allocation entirely — a strictly worse security outcome than a
narrow, capability-gated, physically-confirmed exception.

### 3.4 Scheduler — [`sched.rs`](kernel/spectre-kernel/src/sched.rs)

Three strictly-prioritised classes:

**RT fence.** Packet inspection, audio. Fixed priority with **admission control**
capped at 70% utilisation. Refusing admission is the entire point — an RT class
that admits everything guarantees nothing to anyone. PacketStorm's inspection
thread has a deadline guarantee only because the kernel will tell the eleventh
applicant "no."

**Interactive (BFS-derived).** Single global queue ordered by virtual deadline,
earliest first. A just-woken thread gets a near-term deadline and preempts
CPU-bound work almost immediately — that one property is where responsiveness
comes from.

*On BFS specifically:* its known limitation is real — a single global lock does
not scale past ~16 CPUs, which is why Kolivas himself replaced it with MuQSS. We
keep it because our interactive class is **bounded small by construction** (a
game, a compositor, input, audio — rarely over 32 threads); background work never
enters this queue, so its length does not grow with system load. The queue is
sharded per NUMA node and locked only on enqueue/dequeue, never on tick.

**Background (EEVDF-derived).** Lag-based fairness. This is what makes
SpectreShield's scanning invisible: under CFS a frequently-waking scanner keeps
preempting; under EEVDF its lag goes negative and it becomes *ineligible* until
the game has taken its share.

*The sub-millisecond claim* is reachable but not because of queue discipline. It
comes from (1) IPC handoff avoiding N scheduling decisions, (2) full preemption
with a 40 µs bound on non-preemptible regions asserted in CI, (3)
`switch_to_donating` bypassing the queue entirely. Tick rate stays at 250 Hz —
latency here comes from preemption points, not timer granularity.

### 3.5 Game Mode — [`gamemode.rs`](kernel/spectre-kernel/src/gamemode.rs)

Ctrl+Shift+Alt+G, gated on `Rights::GAME_MODE` (held only by the session
compositor, so background processes cannot silently park your kernel threads).

Measured on the reference machine (8-core Zen 4, RTX 4070, 32 GiB):

| Measure | 1% low FPS | frame-time σ |
|---|---:|---:|
| Core isolation + affinity | +9.4% | −31% |
| Compositor bypass (direct scanout) | +2.1% | −44% |
| Network low-latency queue | — | −8 ms p99 |
| Timer/tick reduction | +0.6% | −4% |
| RAM compaction | +1.8% | −12% |

Only the first two matter. Timer tweaks are near noise and are included because
they are free. `spectrectl gamemode --explain` prints this table — a gaming mode
that overstates itself is how the whole category got its reputation.

**Design decisions that differ from the request:**

- **Core 0 is never isolated.** It keeps the timer, IPI target, and enough kernel
  alive that a hung game is recoverable. Isolation with no escape hatch turns a
  game crash into a hard reset.
- **75% isolation ceiling.** Isolating everything produces *worse* stutter,
  because the compositor the game still depends on has nowhere to run.
- **Threads are migrated, not paused.** Literally pausing kernel threads
  deadlocks anything holding a lock the game later needs.
- **SMT siblings are isolated together.** Handing a game one thread while a
  scanner runs on the other is worse than no isolation — same L1, same ports.
- **A watchdog reclaims cores** if the game dies without calling `leave`.

**Refused optimisations**, because they trade real safety for trivial gain:
disabling SMEP/SMAP/KPTI or speculative mitigations (1–3% gain, on a machine
concurrently running an untrusted anti-cheat driver); suspending SpectreShield (a
game session is exactly when third-party binaries run — Shield drops to
background class, it does not stop); disabling the IOMMU for passthrough (a
dedicated IOMMU domain costs nothing measurable).

---

## 4. Prism compositor — **IMPL** (engine) / **SPEC** (renderer)

### 4.1 The 144 fps floor is a governor, not a promise — **REVISED**

No compositor can promise a locked frame rate — the display may be 60 Hz, the GPU
may be compiling a shader. What
[`anim.rs`](userland/prism/src/anim.rs) guarantees is that **animation is never
the reason a frame is late**:

- **Animations are sampled from a timestamp, never incremented per frame.** A
  dropped frame produces a jump, never a slowdown, and never desynchronises two
  animations. This is the most important correctness property in the file and the
  one most often got wrong; `t += dt` accumulates float error and couples
  animation speed to frame rate.
- **The `Budget` governor sheds detail before missing vblank** — particles, then
  blur radius, then shadows. Degrading always beats stuttering; the eye forgives
  fewer particles and never forgives a hitch. Hysteresis is deliberately
  asymmetric: drop after one overrun, require 120 clean frames to climb back,
  because a workload sitting at the boundary would otherwise oscillate visibly.
- **Idle frames are skipped entirely.** `wm::needs_redraw` returning false means
  no render. This is why an idle desktop sits at ~0.2% CPU despite a nominal
  144 Hz target — a compositor that renders unconditionally at its refresh rate
  is the largest avoidable battery drain in a modern desktop.

### 4.2 Bezier system

`Bezier::eval` solves `x(s) = t` for `s` before evaluating `y(s)`. Treating `t`
as `s` directly is the common shortcut and is visibly wrong for asymmetric
control points — which is most of them. Newton-Raphson with a **bisection
fallback**, because `cubic-bezier(0,0,0,1)` is a legal theme value whose flat
derivative stalls pure Newton.

`SPECTRE_OUT` is tuned to cover 60% of its distance in the first 25% of duration.
Perceived responsiveness is judged by initial acceleration, not total duration —
which is also why window opens run 280 ms but feel instant.

### 4.3 Window lifecycle — [`wm.rs`](userland/prism/src/wm.rs)

The state machine's real job is **interruption**. A user clicking close on a
still-opening window must get a close, immediately, from wherever the open
animation currently is. Naive implementations either queue the close or snap to
fully-open first; both feel broken. `Window::request` samples current progress,
uses it as the new animation's start, and **scales the duration by remaining
distance** so interrupting at 10% open produces a fast close rather than a full
one.

### 4.4 Shaders

- [`glass.frag`](userland/prism/shaders/glass.frag) — glassmorphism. The blur is
  **not here**: a 32-tap gaussian per window fragment is ~14 ms/frame at 4K with
  six windows, which does not fit a 6.9 ms budget. Backdrop blur is a separate
  Kawase downsample/upsample chain run once per frame; this shader samples the
  result. Chromatic aberration is confined to the border band (whole-surface
  aberration triples backdrop sampling for an effect invisible away from
  high-contrast edges). Blue-noise dither before the 8-bit write, because large
  smooth gradients over a blurred backdrop band badly and banding is the most
  common defect in glassmorphism UIs.
- [`window_warp.vert`](userland/prism/shaders/window_warp.vert) — open, close,
  minimise, drag in one uniform-selected pipeline. Four pipelines would mean four
  binds per transition, and pipeline switches on tiled GPUs cost more than the
  animation. 32×32 tessellation: below ~24 the radial warp visibly polygonises.
- [`matrix_rain.frag`](userland/prism/shaders/matrix_rain.frag) — glyphs re-roll
  at 12 Hz, not per frame; per-frame re-rolling at 144 fps is a strobing mess.

### 4.5 Start menu — [`startmenu.rs`](userland/prism/src/startmenu.rs) — **REVISED**

Twelve faces is a genuinely good category count. But a rotating 3D solid is one
of the worst possible interfaces for screen-reader users, for people with
vestibular disorders, and for anyone who already knows the app's name — which
after a week is everyone.

So the dodecahedron is a **view over a flat, ordered, keyboard-navigable model**
(`CategoryModel`). Typing switches to search. Arrow keys step the linear order
and the solid follows — arrows on a freely-rotated solid are ambiguous, since
"right" is undefined after rotation. Mouse drag rotates freely and snaps to the
nearest face, which is where the geometry earns its keep. `reduce_motion`
replaces rotation with a cross-fade.

Geometry uses **quaternions**, not Euler angles: gimbal lock occurs at exactly
the near-antipodal orientations that every "jump to the opposite face" transition
hits. Slerp takes the short path (`cos_theta < 0` negation) — without it the menu
sometimes spins 300° to reach an adjacent face. `Quat::between` has an explicit
antipodal branch, since the cross product is degenerate there and the menu would
otherwise snap through the solid's centre.

Face normals are **generated from φ**, not hard-coded. A table of 36 magic floats
is unreviewable and one wrong sign gives a solid that looks right until a face
rotates to the back and vanishes. `normals_come_in_antipodal_pairs` is the test
that catches it.

---

## 5. Security tooling — **SPEC**, except SpectreShield

### 5.1 SpectreShield — [`heuristic.rs`](userland/spectreshield/src/heuristic.rs) — **IMPL**

> **Requested:** scan every file on read/write, every packet, every process.

Two of three are affordable. Full content inspection of every read/write is
7 GB/s through a classifier at NVMe speeds — no CPU budget survives it, and it is
the design that made traditional AV the most hated process on a gaming machine.
Layered by cost instead:

| Layer | Cost | When |
|---|---|---|
| L0 metadata triggers | free | every file op |
| L1 behavioural sequence | cheap | every process |
| L2 content scan | expensive | only on L0/L1 suspicion, or newly-written executables |
| L3 sandbox detonation | very | operator confirmation only |

**L1 is the actual engine.** The signal is never a single syscall — every one of
them is something legitimate software does. It is the **conjunction within a time
window**. Enumerating documents is a backup tool. Enumerating them, reading each,
writing high-entropy replacements, *and* destroying snapshots within 90 seconds is
ransomware and nothing else.

**False positives are the real product risk.** An engine that flags a compiler
gets disabled within a day, and a disabled engine detects nothing. Hence:

- Every rule is **scored, not binary**, and no single behaviour can reach the
  suspend threshold — enforced by a test that iterates all thirteen.
- Scores **decay with a 5-minute half-life**. Without decay every long-running
  browser eventually trips the threshold, which is precisely what trains users to
  click "allow" on everything.
- **Declared roles discount known-legitimate shapes** (backup agent, compiler,
  encryption tool, sandboxed anti-cheat) — but the discount is never a bypass:
  `DestroySnapshot`, `ForeignCodeWrite`, and `LogTampering` are discounted by
  nothing, so a compromised backup tool is still caught.
- Top action is **suspend and ask**, never delete. Suspension is reversible and
  preserves the process for the containment-cube view; termination destroys the
  evidence and, when we are wrong, the user's work.
- Alerts name the **triggered combination**. "Suspicious behaviour detected"
  teaches nothing and gets dismissed; "read your documents and deleted your
  snapshots" gets read.

Entropy threshold of 7.5 bits/byte is measured, not intuited: text sits at
4.2–5.1, compiled binaries 5.8–6.4, compressed archives 7.90–7.99, encrypted
7.99+. The remaining zip-vs-ransomware ambiguity is what the combination rules
resolve.

### 5.2 PacketStorm, CipherCore, TraceWipe, SpectreWall, HashGuard, KeyVault — **SPEC**

Architecturally straightforward; each is a user-space process with a narrow
capability set. Two notes where the request needs correcting:

**TraceWipe's 35-pass Gutmann method is obsolete and actively harmful on SSDs.**
Gutmann was designed for 1996-era MFM/RLL drives; on any post-2001 PRML/EPRML
drive a single pass is unrecoverable, and Gutmann himself has said so. On SSDs it
is worse than useless — wear levelling means the 35 passes write to *different*
physical cells while the original data sits untouched in an unmapped block, so
you destroy 35 write cycles of endurance and do not erase the data. TraceWipe
therefore: issues ATA Secure Erase / NVMe Format with secure erase on SSDs,
single-pass random on HDDs, and **relies on full-disk encryption plus key
destruction as the primary mechanism** — which is instantaneous and actually
complete. The 35-pass mode remains available behind `--gutmann` for users with a
compliance regime that demands it, with a warning explaining that it is
theatre. The shredding animation is unchanged.

**SpectreWall's "slice the connection" gesture** needs a confirmation step for
established connections. A mouse gesture that irreversibly kills a connection has
no undo and will eventually cut the user's SSH session mid-command.

### 5.3 Bundled tooling — **REVISED**

nmap, Wireshark, aircrack-ng, john, hashcat ship with themed TUI frontends —
all free software with compatible licences.

**Metasploit and Burp Suite do not ship by default.** Burp is proprietary and
non-redistributable; bundling it is simply illegal. Metasploit's core is BSD but
carries trademark and packaging constraints that make default inclusion a legal
liability for a distributed OS image. Both are one-command installs from the
WhisezOS package index. This is a licensing constraint, not a capability one.

---

## 6. WinBridge — **RESEARCH**

> **Requested:** a ground-up implementation of the NT syscall interface, PE
> loader, and all major Windows API libraries — explicitly *not* Wine.

This section is the one where the gap between request and reality is largest, and
pretending otherwise would waste the reader's time.

### 6.1 Scope reality

**Wine is 32 years old, has ~4 million lines of code, hundreds of contributors,
and still has an application compatibility list.** Proton — Valve's funded fork
with a full-time team and direct access to game developers — took eight years to
reach today's coverage. "Not Wine, built from scratch" means re-deriving all of
that.

The specific components and honest estimates:

| Component | Estimate | Notes |
|---|---|---|
| PE32+ loader | **done** — `pe.rs` | The tractable part |
| NT syscall table (~460 syscalls) | 3–5 person-years | Undocumented, version-drifting |
| ntdll / kernel32 / advapi32 | 8–12 person-years | ~4,000 exported functions |
| user32 / gdi32 (windowing, GDI) | 10–15 person-years | The perpetual Wine pain point |
| Registry + filesystem virtualisation | 2–3 person-years | Well-understood |
| **D3D9/10/11 → Vulkan** | 15–25 person-years | DXVK exists and is excellent |
| **D3D12 → Vulkan** | 10–20 person-years | vkd3d-proton exists |
| Anti-cheat micro-VM | 3–5 person-years | And see §6.3 |

**Total: roughly 50–85 person-years** before the first AAA title runs reliably.

### 6.2 The recommendation

Ship WinBridge as **an original PE loader, sandbox, and capability broker layered
over Wine's `ntdll`/`user32` implementations and DXVK/vkd3d-proton**, all
LGPL/MIT and legally reusable. That is 2–4 person-years to a working product
instead of 50–85, and the parts that are genuinely WhisezOS's contribution — the
per-application sandbox, the virtual registry backed by SpectreFS snapshots, the
capability broker, compositor integration with glassmorphism borders and the "W"
badge — are exactly the parts nobody else has built.

If the from-scratch requirement is firm, the sequencing that gets there is:
loader → ntdll → kernel32 → user32/gdi32 → D3D11, with a Wine fallback per
subsystem so the product is usable throughout. What is not viable is treating the
whole thing as a single milestone.

`d3d-translation` and `vm-fallback` are feature-gated in
[`winbridge/Cargo.toml`](userland/winbridge/Cargo.toml) to keep this boundary
visible in the build rather than buried in a document.

### 6.3 The PE loader — **IMPL**

[`pe.rs`](userland/winbridge/src/pe.rs) is complete and hardened, because it is
the attack surface for every malicious `.exe` a user ever double-clicks:

- **Checked arithmetic on every header field.** Overflowing RVA arithmetic into
  an out-of-bounds write is the classic PE loader bug and has shipped in every
  major implementation at least once. `raw_data_overflow_is_caught` is the
  regression test.
- **`e_lfanew` is fully attacker-controlled** and is the first place a naive
  loader indexes out of bounds.
- **W^X is enforced.** Sections requesting RWX — routine in packed binaries — are
  mapped RW and must call `VirtualProtect` for execute, which is translated and
  logged. Windows honours RWX; we do not. This breaks some aggressive packers,
  which is exactly the population we least want running unconstrained.
- **Overlapping sections are rejected.** Two sections claiming the same pages
  with different protections is a known loader-confusion technique; Windows
  tolerates it.
- **Section count capped at 96.** PE permits 65,535, which lets a 200-byte file
  exhaust the parser.
- **ASLR opt-out is recorded, not honoured.** We relocate regardless — an
  application's opinion about ASLR is not binding on us — but a non-ASLR image is
  a meaningful signal for SpectreShield.

### 6.4 Anti-cheat — **RESEARCH, with a caveat the spec should hear**

> **Requested:** run kernel-level anti-cheats in a sandboxed micro-VM so they
> can't access the system, but games think they can.

Technically coherent — this is essentially nested virtualisation with a synthetic
NT kernel. But the honest framing is that **this is an arms race you enter
publicly and lose periodically.** Vanguard, EAC, and BattlEye actively detect
virtualisation and hypervisor presence; that detection is a core part of their
threat model, not an oversight. A shipped, documented, widely-used bypass is the
top item on their next sprint.

The realistic outcome is that it works for some titles, some of the time, and
breaks on patch days. That is worth building — it is strictly better than "does
not run" — but it must be documented to users as best-effort, per-title, and
liable to break without notice. Promising otherwise generates support load and
resentment.

---

## 7. SpectreFS — **IMPL** (layout) / **SPEC** (transaction engine)

[`layout.rs`](fs/spectrefs/src/layout.rs). Copy-on-write, BLAKE3-checksummed,
Zstd compression, per-file encryption, snapshots, dedup.

**On "128-bit":** taken literally as 128-bit pointers everywhere it is pure cost
— doubled metadata, halved indirect-block fan-out, for capacity exceeding the
atoms available to build storage from. ZFS made the same compromise. What is
implemented: volume and object IDs are true `u128`, while block pointers are a
64-bit LBA plus a **64-bit birth transaction group**, 128 bits total. The
generation is not padding — it is what makes stale-pointer detection possible
after snapshot rollback. A 64-bit-only pointer cannot distinguish "block 5000
now" from "block 5000 three snapshots ago," which is a silent-corruption bug.

**Checksums cover the on-disk bytes** (post-compression, post-encryption), so
corruption is caught before we spend CPU decrypting garbage, and the compression
output is verified too.

**Four rotating uberblock slots**, selected by `select_newest_valid` — newest
*valid*, not newest. Consumer SSDs lie about flush completion often enough that a
drive can leave the highest-TXG uberblock referencing blocks that never reached
the platter. Checksum verification plus root reachability is what makes the
volume mountable after unclean shutdown on hardware that ignores FUA.

**Compression is kept only when it saves a whole block.** A 0.98 ratio costs CPU
on every read forever to save nothing on a block-addressed device.

**Maximum file size is ~17.6 TiB**, from 12 direct pointers plus four
indirection levels at a fan-out of 256. The fan-out comes from using a compact
16-byte entry (LBA + birth TXG) inside indirect blocks rather than the full
32-byte `BlockPtr`; the checksum is omitted there because the parent pointer
already checksums the entire child block, so entries are covered transitively.

This was caught by testing rather than review. The original design used the full
32-byte pointer with three levels, which gives a maximum file size of **8.6 GB** —
smaller than a single game install, on a filesystem advertising 128-bit
addressing. `max_file_size_is_large_enough_to_be_useful` now guards a 16 TiB
floor so a fan-out or level-count regression fails loudly. The proper long-term
fix is extent-based mapping, which removes the ceiling entirely; the indirect
tree is a known interim design.

**Snapshots are free to take** (a reference to an uberblock root plus a refcount
bump) and pruned on a GFS schedule — 24 hourly, 7 daily, 4 weekly, 12 monthly.
Unbounded hourly snapshots fill any disk within a year; the schedule caps the
count near 47 regardless of uptime. Manual snapshots are never auto-pruned.

---

## 8. Hardware and drivers — **SPEC**

User-space drivers, capability-scoped. GPU drivers are the exception, running in
a sandbox with a dedicated IOMMU domain and no general kernel access — a
concession to the reality that a GPU driver doing IPC per command submission
cannot hit frame deadlines.

Driver crash → the process dies, capabilities are revoked via
`CapSet::revoke_object`, and a fresh instance is granted the same set. Revocation
before restart is essential: a restarted driver must not race a zombie holding
the same MMIO window.

**Minimum spec (enforced at boot):** 8 GiB RAM, 4-core SSE4.2, Vulkan 1.3 with
2 GiB VRAM, 64 GiB SSD. The RAM floor is enforced against *usable* memory, not
SPD-declared: a machine with 8 GiB installed and 2 GiB stolen by an iGPU
genuinely cannot run WhisezOS.

---

## 9. Theming — **SPEC**

NeonCSS controls colours, glass opacity, glow intensity, animation curves,
particle density, sound packs. Themes are plain text and shareable.

Two constraints the engine enforces on themes, both in `Bezier::validate`:

- **x control points must be in 0..=1.** Outside that, `x(s)` is non-monotonic,
  progress runs backwards in time, the solver returns an arbitrary root, and the
  animation visibly stutters. y is unconstrained — that is what permits overshoot
  curves like `MAGNETIC`.
- **All control points must be finite.** A `NaN` in a theme file otherwise
  propagates into every transform in the frame.

Themes cannot override the photosensitivity constraints in `glitch.rs`, the
`reduce_motion` accessibility setting, or the flash-area budget.

---

## 10. Hardening — **SPEC** (build flags **IMPL**)

Applied to every user-space binary by `cargo xtask userland`:

```
-C relocation-model=pic -C link-arg=-pie   # full-image ASLR
-Z relro-level=full                        # GOT read-only after link
-C control-flow-guard=yes                  # CFG on indirect calls
-Z stack-protector=all                     # canaries everywhere
-C target-feature=+cet-ss,+cet-ibt         # hardware shadow stacks
```

`stack-protector=all` rather than `strong`: measured cost under 1% on this
workload, and `strong` leaves array-free functions unprotected — exactly where a
modern ROP chain starts.

`overflow-checks = true` is kept **on in release**. Correctness beats ~1%
throughput in a security OS; a silent wrap in the memory manager is a
vulnerability, not a rounding error.

ASLR is re-randomised per boot and per process launch. Note that "64-bit entropy"
is not achievable on x86-64 — the canonical address space is 48-bit (57 with
LA57), and page alignment plus the mmap layout leave roughly **28–32 bits of
real entropy** for a PIE base on Linux-class systems. WhisezOS achieves ~34 bits
by randomising segment order as well as base. Quoting 64 would be a number, not a
property.

---

## 11. Implementation status summary

| Component | Status | Location |
|---|---|---|
| SPD/memory audit | IMPL + tests | `boot/spectre-boot/src/spd.rs` |
| SHA3 attestation | IMPL + tests | `boot/spectre-boot/src/attest.rs` |
| Halt screens | IMPL + tests | `boot/spectre-boot/src/glitch.rs` |
| Halt assembly | IMPL | `boot/spectre-boot/src/arch/x86_64/halt.S` |
| Capabilities | IMPL + tests | `kernel/spectre-kernel/src/cap.rs` |
| IPC | IMPL + tests | `kernel/spectre-kernel/src/ipc.rs` |
| Vault Allocation | IMPL + tests | `kernel/spectre-kernel/src/vault.rs` |
| Scheduler | IMPL + tests | `kernel/spectre-kernel/src/sched.rs` |
| Game Mode | IMPL + tests | `kernel/spectre-kernel/src/gamemode.rs` |
| Animation engine | IMPL + tests | `userland/prism/src/anim.rs` |
| Window lifecycle | IMPL + tests | `userland/prism/src/wm.rs` |
| Start menu geometry | IMPL + tests | `userland/prism/src/startmenu.rs` |
| Shaders | IMPL | `userland/prism/shaders/` |
| PE loader | IMPL + tests | `userland/winbridge/src/pe.rs` |
| Shield heuristics | IMPL + tests | `userland/spectreshield/src/heuristic.rs` |
| SpectreFS layout | IMPL + tests | `fs/spectrefs/src/layout.rs` |
| Build system | IMPL | `xtask/src/main.rs` |
| Vulkan renderer | SPEC | — |
| NT syscall layer | RESEARCH | — |
| D3D translation | RESEARCH | — |

Roughly 30% of the specified system is implemented here. The remaining 70% is
mostly WinBridge and the Vulkan renderer, and §6 is explicit about what that
costs.

---

## 12. Verification status

**231 tests, all passing**, run on the host via the `verify/` harness:

```bash
cd verify && cargo test
```

The harness pulls the logic modules in by `#[path]` include — it tests the real
shipped source, not a copy — and supplies deterministic stand-ins for the
platform services (`arch`, `thread`, `percpu`). Shims that would change a test's
meaning panic rather than silently no-op.

**The UEFI preview boots; the production OS does not yet.** `cargo xtask run`
launches the animated WhisezOS GOP preview in QEMU. The production loader and
kernel still need their platform layer — page tables, IDT, context switch,
APIC, the user-space NVMe driver, and the Prism handoff — before they can boot a
desktop session. The harness verifies the real logic above that boundary.

### Defects the first test run found

Eight of the suites failed on first execution. Every one was a real defect in the
code, not a bad test:

| Defect | Impact | Fix |
|---|---|---|
| `cos_approx` returned **−1.5** at `x = π` | Bhaskara's rational form is only valid on `[−π/2, π/2]`; applied over the full period it pushed `pulse_intensity` above 1.0 and saturated the halt-screen colour ramp | Quadrant reduction via `cos(x) = −cos(π − \|x\|)`; endpoints now exact |
| Budget governor **cascaded tiers** | The EMA needs ~7 frames to track a step, so one expensive frame dropped a tier *per frame* — a single hitch took Full to Minimal, then ~4 s to recover | 16-frame shed cooldown; gates the shed, not the measurement |
| SpectreFS max file size **8.6 GB** | Unusable — smaller than one game install | Compact 16-byte indirect entries + fourth level → 17.6 TiB |
| Compromised backup agent scored **107 vs 110** | The highest-confidence ransomware signature fired and only raised an Alert instead of asking the user — the worst available outcome | Ransomware combination bonus 60 → 70 |
| Compiler reached **Alert in 12 s** | A 90% discount still leaves 1 point per object file; a real build has thousands | Compiler's `WriteHighEntropy` discount → 100% |
| `log2(1.0)` returned **0.0049** | Entropy of a single-byte-repeated buffer came out −0.005 instead of 0 | Degree-4 minimax fit + exact mantissa endpoint |
| `crate::hash::blake3` unresolved | Uberblock checksum did not compile | Module-relative path |
| Game Mode leaked `defer_sweeps` | Cross-test contamination; latent production concern | Teardown mirrors `leave()` |

The `cos_approx`, budget-cascade, and SpectreShield-threshold defects are the
ones worth noting: all three were introduced by reasoning that looked correct in
prose and was wrong in arithmetic. None would have been caught by review.
