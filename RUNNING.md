# Running WhisezOS

One command:

```
cargo xtask run
```

A window opens, the machine boots in about four seconds, and a desktop
appears with a shell in it. Type `help`.

That is the whole of it. If you want the serial log written to a file as well,
add `--log` and it lands in `target/boot-serial.log`.

## What you should see

A panel across the top with the uptime, a keystroke count, and the pointer
position. Two windows: what the kernel found on the bus, and a shell. A cursor
that follows the mouse. A marker sweeping under the panel, which moves on every
interrupt — if it is moving, the machine is running.

Commands the shell knows:

| | |
|---|---|
| `help` | the list |
| `devices` | what the kernel found |
| `uptime` | since the session started |
| `read <sector>` | one 512-byte sector off the disk, in hex |
| `echo <text>` | prints it back |
| `shutdown` | turns the machine off (`poweroff` and `halt` also work) |

`read 0` is the interesting one: it goes through a virtqueue to a real device
and prints what came back.

## If the window is not where you expect

It opens at whatever position the window manager chooses and it is not raised
to the front. If you cannot see it, it is behind something — look in the
taskbar for **QEMU (WhisezOS kernel)**.

This caused a long and unnecessary detour once. The guest was drawing
correctly, the screen capture proved it, and the window was simply not in
front. Worth knowing before concluding that something is broken.

## Other commands

| | |
|---|---|
| `cargo xtask test` | every host test — currently 519 |
| `cargo xtask boot-test` | boots headless in QEMU and asserts the serial log |
| `cargo xtask run-preview` | the UEFI installer mock-up, which is *not* the OS |

`run-preview` is a separate program that predates the kernel. It has a setup
screen and nothing behind it. It used to be what `cargo xtask run` did, which
is worth saying plainly: anybody typing the obvious command got a firmware demo
that goes nowhere and reasonably concluded the desktop never appeared.

## Looking at the screen from outside

The QEMU command line carries a control socket, and there are four scripts that
use it. They exist because the boot test reads text and three display bugs
shipped straight through it — a grey gradient, a torn frame, and a panel
reading `WHISEZOSSESSION`. Asserting that a line is present says nothing about
pixels.

```
powershell -File xtask/screendump.ps1 target/screen.ppm    # capture the screen
powershell -File xtask/topng.ps1 target/screen.ppm out.png # convert it
powershell -File xtask/type.ps1 "help"                     # type into the shell
powershell -File xtask/sendinput.ps1 3 200 150             # keys and mouse motion
powershell -File xtask/status.ps1                          # what the guest is doing
```

`status.ps1` matters more than it looks: `-no-shutdown` means a guest that
powered off leaves QEMU running with the CPU stopped rather than exiting, so
"the process is still there" says nothing about whether shutdown worked.

## What works

Boot through UEFI, GDT/IDT/paging with W^X, ring 3, a preemptive scheduler,
address-space teardown that accounts for every frame, synchronous IPC, PCI
enumeration, and four devices driven entirely from user space: a virtio disk
that reads and writes, a virtio sound card that enumerates its streams, the RTC
as a clock, and the i8042 for keyboard and mouse. Plus a desktop, a shell, and
shutdown.

The kernel does not know what a disk is, what a sound card is, or what a
keystroke means. It hands out one device at a time and everything else is a
process.

## What does not work

Being specific, because a list of features is easy to mistake for a system:

- **No filesystem.** Sectors can be read; there is no such thing as a file.
- **No network.** No driver, no TCP/IP, no TLS. Nothing can reach anything.
- **No way to run a program.** There is no loader for anything but init.
- **The windows are drawn, not real.** Nothing is behind them and nothing is
  clickable. They use the geometry a real window would so that the code already
  works when there is something to put behind them.
- **Audio does not play.** The card is found and its streams counted; the
  playback and capture queues are named and not driven.
- **Only virtio disks.** On real hardware the disk controller is NVMe or AHCI,
  and there is no driver for either — which is why this cannot be installed on
  a physical machine yet. It would boot and be unable to read the disk it was
  installed on.
- **No signed boot.** The loader says so every time: `WARNING images are NOT
  signature-verified in this build`.

## Installing it on a real machine

Not yet, and the blocker is not the installer. Four things have to exist first,
in this order: a filesystem, a driver for a real disk controller, a signed
manifest, and a bootable image (`cargo xtask image` cannot run here — no
`mtools`, no manifest, no key).

When those exist, the first target is booting from a USB stick: the internal
disk is never touched, nothing about Windows changes, and removing the stick
undoes it. Installing to an internal disk is a different and much larger
commitment, and it should not be the first thing tried.

Secure Boot has to be off either way, because nothing here is signed by a key
the firmware trusts.
