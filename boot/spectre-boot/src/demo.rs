//! Bootable WhisezOS UEFI preview.
//!
//! This target intentionally does one thing well: prove the host toolchain,
//! UEFI firmware, GOP framebuffer, pointer input, packaged artwork, and VM
//! launch path while the production kernel handoff is still under construction.
//!
//! It renders three things in order — a splash, a staged setup rehearsal, and a
//! desktop shell — and it is a *preview*: nothing here boots a kernel, mounts a
//! filesystem, or writes to storage. The screens say so where a user could
//! otherwise assume otherwise.
//!
//! Layout, input semantics, and the setup schedule live in `shell`, `pointer`,
//! and `setup`. Those modules are `no_std` and free of UEFI types, so the host
//! harness in `verify/` runs their tests without booting anything. This file is
//! the part that cannot be tested that way: protocol binding and drawing.

#![no_main]
#![no_std]

extern crate alloc;

mod pointer;
mod ps2;
mod setup;
mod shell;

use alloc::vec;
use alloc::vec::Vec;
use core::cmp::min;
use core::ffi::c_void;
use core::time::Duration;
use uefi::boot::{OpenProtocolAttributes, OpenProtocolParams, ScopedProtocol};
use uefi::prelude::*;
use uefi::proto::console::gop::{BltOp, BltPixel, BltRegion, GraphicsOutput};
use uefi::proto::console::pointer::Pointer;
use uefi::proto::console::text::{Key, ScanCode};
use uefi::proto::unsafe_protocol;

use pointer::{ButtonEdges, Buttons, Cursor, Motion, CURSOR_HEIGHT, CURSOR_WIDTH};
use setup::Setup;
use shell::{Focus, Rect, Rgb, Shell, Target, View};

const ART_SIDE: usize = 480;
const ART_RGB565: &[u8] = include_bytes!("../assets/whisez-dragon.rgb565");
const DESKTOP_WIDTH: usize = 960;
const DESKTOP_HEIGHT: usize = 540;
const DESKTOP_RGB565: &[u8] = include_bytes!("../assets/whisez-desktop.rgb565");

const BLACK: BltPixel = BltPixel::new(0, 0, 0);
const CYAN: BltPixel = rgb(shell::CYAN);
const VIOLET: BltPixel = rgb(shell::VIOLET);

/// Frame period for the animated screens. 40 ms is 25 fps, which is smooth
/// enough for a fade and cheap enough that a software-rendered OVMF framebuffer
/// keeps up without the progress bar stuttering.
const FRAME_MS: u32 = 40;

const fn rgb(c: Rgb) -> BltPixel {
    BltPixel::new(c.0, c.1, c.2)
}

// ---------------------------------------------------------------------------
// EFI_ABSOLUTE_POINTER_PROTOCOL
//
// uefi-rs wraps `EFI_SIMPLE_POINTER_PROTOCOL` but not the absolute one, and the
// absolute one is what actually works here. A relative USB mouse only delivers
// motion once the VM has grabbed the host pointer, which is why the cursor
// appeared frozen: the firmware was reporting no movement because QEMU was not
// sending any. A tablet-style digitiser reports a position instead and needs no
// grab, so binding this protocol is the difference between a dead cursor and a
// live one. Both are supported — real firmware may expose either or both.
// ---------------------------------------------------------------------------

#[derive(Debug)]
#[repr(C)]
struct AbsolutePointerMode {
    absolute_min: [u64; 3],
    absolute_max: [u64; 3],
    attributes: u32,
}

#[derive(Debug, Default)]
#[repr(C)]
struct AbsolutePointerState {
    current: [u64; 3],
    active_buttons: u32,
}

/// `ActiveButtons` bit 0: the primary contact ("touch active"). Bit 1: the
/// alternate contact, which QEMU's tablet maps to the right button.
const ABS_BUTTON_TOUCH: u32 = 1 << 0;
const ABS_BUTTON_ALT: u32 = 1 << 1;

#[derive(Debug)]
#[repr(C)]
#[unsafe_protocol("8d59d32b-c655-4ae9-9b15-f25904992a43")]
struct AbsolutePointer {
    reset: unsafe extern "efiapi" fn(*mut Self, u8) -> Status,
    get_state: unsafe extern "efiapi" fn(*mut Self, *mut AbsolutePointerState) -> Status,
    wait_for_input: *mut c_void,
    mode: *const AbsolutePointerMode,
}

impl AbsolutePointer {
    fn reset(&mut self) {
        // SAFETY: `self` is a live protocol instance held open for our image.
        unsafe {
            let _ = (self.reset)(self, 0);
        }
    }

    /// Returns the reading if the device reported a change since the last call.
    fn read(&mut self) -> Option<(Motion, Buttons)> {
        let mut state = AbsolutePointerState::default();
        // SAFETY: `self` is live and `state` is a valid, correctly sized
        // out-parameter for the duration of the call.
        let status = unsafe { (self.get_state)(self, &mut state) };
        if status != Status::SUCCESS {
            return None;
        }

        // SAFETY: the protocol guarantees `mode` points at a valid mode block
        // for the lifetime of the instance.
        let mode = unsafe { self.mode.as_ref() }?;

        Some((
            Motion::Absolute {
                x: state.current[0],
                y: state.current[1],
                min: (mode.absolute_min[0], mode.absolute_min[1]),
                max: (mode.absolute_max[0], mode.absolute_max[1]),
            },
            Buttons {
                left: state.active_buttons & ABS_BUTTON_TOUCH != 0,
                right: state.active_buttons & ABS_BUTTON_ALT != 0,
            },
        ))
    }
}

// ---------------------------------------------------------------------------
// i8042 auxiliary port
//
// Used only when the firmware provides no working pointing device — see the
// module comment in `ps2.rs` for why that is the common case here rather than
// an exotic one. Reading the controller directly is safe to attempt precisely
// because no firmware driver owns the auxiliary port on such a build; where a
// firmware mouse driver does exist, `probe` is never called.
// ---------------------------------------------------------------------------

const PS2_DATA: u16 = 0x60;
const PS2_STATUS: u16 = 0x64;
const PS2_COMMAND: u16 = 0x64;

/// Status register bit 0: a byte is waiting in the output buffer.
const STATUS_OUTPUT_FULL: u8 = 1 << 0;
/// Status register bit 1: the controller has not consumed our last write yet.
const STATUS_INPUT_FULL: u8 = 1 << 1;
/// Status register bit 5: the waiting byte came from the auxiliary port (the
/// mouse) rather than the keyboard. Never read a byte without checking this —
/// consuming a keystroke would break the firmware's keyboard driver.
const STATUS_FROM_AUX: u8 = 1 << 5;

/// SAFETY: reading an I/O port has no memory effects; `port` is one of the
/// fixed i8042 registers above.
unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    core::arch::asm!("in al, dx", out("al") value, in("dx") port, options(nomem, nostack, preserves_flags));
    value
}

/// SAFETY: as above; writes go only to the i8042 registers.
unsafe fn outb(port: u16, value: u8) {
    core::arch::asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags));
}

/// A directly driven PS/2 mouse.
struct Ps2Mouse {
    decoder: ps2::PacketDecoder,
    buttons: Buttons,
}

impl Ps2Mouse {
    /// Spins until the controller can accept a byte. Bounded: a controller that
    /// never drains is a controller that is not there, and blocking forever in
    /// a preview's startup is worse than having no mouse.
    fn wait_writable() -> bool {
        for _ in 0..100_000 {
            // SAFETY: status register read.
            if unsafe { inb(PS2_STATUS) } & STATUS_INPUT_FULL == 0 {
                return true;
            }
        }
        false
    }

    fn wait_readable() -> bool {
        for _ in 0..100_000 {
            // SAFETY: status register read.
            if unsafe { inb(PS2_STATUS) } & STATUS_OUTPUT_FULL != 0 {
                return true;
            }
        }
        false
    }

    fn command(byte: u8) -> bool {
        Self::wait_writable() && {
            // SAFETY: command register write.
            unsafe { outb(PS2_COMMAND, byte) };
            true
        }
    }

    fn write_data(byte: u8) -> bool {
        Self::wait_writable() && {
            // SAFETY: data register write.
            unsafe { outb(PS2_DATA, byte) };
            true
        }
    }

    /// Sends a byte to the mouse itself (rather than the controller) and waits
    /// for its acknowledgement.
    fn mouse_command(byte: u8) -> bool {
        if !Self::command(0xD4) || !Self::write_data(byte) || !Self::wait_readable() {
            return false;
        }
        // SAFETY: data register read, guarded by the status check above.
        unsafe { inb(PS2_DATA) == 0xFA }
    }

    /// Enables the auxiliary port and starts data reporting.
    fn probe() -> Option<Self> {
        // Enable the auxiliary device.
        if !Self::command(0xA8) {
            return None;
        }

        // Clear bit 5 of the configuration byte, which gates the auxiliary
        // clock. Interrupt enables are left exactly as the firmware set them:
        // this preview polls, and turning on IRQ12 for a handler that does not
        // exist would wedge the controller behind an unacknowledged interrupt.
        if Self::command(0x20) && Self::wait_readable() {
            // SAFETY: data register read, guarded above.
            let config = unsafe { inb(PS2_DATA) };
            if !Self::command(0x60) || !Self::write_data(config & !(1 << 5)) {
                return None;
            }
        }

        // Restore the defaults, then start streaming reports.
        if !Self::mouse_command(0xF6) || !Self::mouse_command(0xF4) {
            return None;
        }

        Some(Self {
            decoder: ps2::PacketDecoder::new(),
            buttons: Buttons::default(),
        })
    }

    /// Drains every auxiliary byte waiting and folds the packets into one
    /// movement. Draining rather than reading a single packet keeps the cursor
    /// tracking the hand during fast motion instead of lagging a frame behind.
    fn read(&mut self) -> Option<(Motion, Buttons)> {
        let mut dx = 0i32;
        let mut dy = 0i32;
        let mut saw_packet = false;

        for _ in 0..64 {
            // SAFETY: status register read.
            let status = unsafe { inb(PS2_STATUS) };
            if status & STATUS_OUTPUT_FULL == 0 || status & STATUS_FROM_AUX == 0 {
                break;
            }
            // SAFETY: a byte is waiting and it belongs to the auxiliary port.
            let byte = unsafe { inb(PS2_DATA) };

            if let Some(packet) = self.decoder.push(byte) {
                dx += packet.dx;
                dy += packet.dy;
                self.buttons = packet.buttons;
                saw_packet = true;
            }
        }

        saw_packet.then_some((Motion::Relative { dx, dy }, self.buttons))
    }
}

/// One bound pointing device, whichever protocol the firmware exposed it under.
enum Device {
    Relative(ScopedProtocol<Pointer>),
    Absolute(ScopedProtocol<AbsolutePointer>),
    Ps2(Ps2Mouse),
}

impl Device {
    fn read(&mut self) -> Option<(Motion, Buttons)> {
        match self {
            Self::Relative(p) => {
                let state = p.read_state().ok().flatten()?;
                Some((
                    Motion::Relative {
                        dx: state.relative_movement[0],
                        dy: state.relative_movement[1],
                    },
                    Buttons {
                        left: state.button[0],
                        right: state.button[1],
                    },
                ))
            }
            Self::Absolute(p) => p.read(),
            Self::Ps2(mouse) => mouse.read(),
        }
    }
}

/// Whether a handle is a real device rather than a virtual console instance.
///
/// The console splitter always publishes a `SimplePointer` and an
/// `AbsolutePointer` on its virtual console handle, even with no mouse driver
/// underneath. Those instances are indistinguishable from real ones by protocol
/// alone — they simply return `NOT_READY` forever — but they carry no device
/// path, because no hardware backs them. Counting them as working pointers is
/// what made the preview report bound devices while the cursor never moved.
fn has_device_path(handle: Handle) -> bool {
    use uefi::proto::device_path::DevicePath;
    // SAFETY: GET_PROTOCOL takes no ownership; the result is dropped at once.
    unsafe {
        uefi::boot::open_protocol::<DevicePath>(
            OpenProtocolParams {
                handle,
                agent: uefi::boot::image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
    }
    .is_ok()
}

/// Starts every driver the firmware has, on every handle it knows about.
///
/// Firmware started straight from `\EFI\BOOT\BOOTX64.EFI` connects only what it
/// needed to reach the boot device and the text console, so a pointer driver
/// that exists but was never bound publishes no protocol. Connecting
/// recursively is what UEFI shells do for the same reason. On a build that
/// simply has no mouse driver this changes nothing, which is why the direct
/// i8042 path exists as well.
///
/// Failures are ignored on purpose: `connect_controller` returns an error for
/// every handle that is not a controller, which is most of them.
fn connect_all_controllers() {
    let Ok(handles) = uefi::boot::locate_handle_buffer(uefi::boot::SearchType::AllHandles) else {
        return;
    };
    for handle in handles.iter() {
        let _ = uefi::boot::connect_controller(*handle, &[], None, true);
    }
}

/// Binds every pointing device the firmware offers, falling back to the i8042
/// auxiliary port when it offers none.
///
/// Protocols are opened with `GET_PROTOCOL` rather than exclusively. The console
/// splitter already holds these instances open on behalf of the firmware's own
/// text console; asking for exclusive access tears that down and can fail
/// outright, which on some builds leaves the preview with no pointer at all.
fn open_pointers() -> Vec<Device> {
    let agent = uefi::boot::image_handle();
    let mut devices = Vec::new();

    // Relative devices are bound first so that absolute ones are polled last
    // and therefore win when both report in the same tick — see `poll_pointers`.
    for handle in uefi::boot::find_handles::<Pointer>().unwrap_or_default() {
        if !has_device_path(handle) {
            continue;
        }
        // SAFETY: GET_PROTOCOL takes no ownership and installs no driver; the
        // returned reference is scoped and closed when dropped.
        let opened = unsafe {
            uefi::boot::open_protocol::<Pointer>(
                OpenProtocolParams {
                    handle,
                    agent,
                    controller: None,
                },
                OpenProtocolAttributes::GetProtocol,
            )
        };
        if let Ok(mut device) = opened {
            let _ = device.reset(false);
            devices.push(Device::Relative(device));
        }
    }

    for handle in uefi::boot::find_handles::<AbsolutePointer>().unwrap_or_default() {
        if !has_device_path(handle) {
            continue;
        }
        // SAFETY: as above.
        let opened = unsafe {
            uefi::boot::open_protocol::<AbsolutePointer>(
                OpenProtocolParams {
                    handle,
                    agent,
                    controller: None,
                },
                OpenProtocolAttributes::GetProtocol,
            )
        };
        if let Ok(mut device) = opened {
            device.reset();
            devices.push(Device::Absolute(device));
        }
    }

    // Only when the firmware gave us nothing real. Where a firmware mouse
    // driver exists it owns the controller, and a second party programming the
    // same registers would fight it for every byte.
    if devices.is_empty() {
        if let Some(mouse) = Ps2Mouse::probe() {
            devices.push(Device::Ps2(mouse));
        }
    }

    devices
}

/// Polls every device once and folds the results into the cursor.
///
/// Buttons are OR-ed across devices: with both a tablet and a mouse attached,
/// a press on either is a press. Movement is applied in the order devices were
/// bound, so an absolute device wins when both report in the same tick — an
/// absolute position is authoritative, a relative delta is not.
fn poll_pointers(devices: &mut [Device], cursor: &mut Cursor) -> (bool, Buttons) {
    let mut moved = false;
    let mut buttons = Buttons::default();

    for device in devices.iter_mut() {
        if let Some((motion, pressed)) = device.read() {
            moved |= cursor.apply(motion);
            buttons = buttons.or(pressed);
        }
    }
    (moved, buttons)
}

#[entry]
fn main() -> Status {
    if uefi::helpers::init().is_err() {
        return Status::ABORTED;
    }

    // A preview can stay open until the VM window is closed. Do not let the
    // firmware watchdog interpret that deliberate wait as a hung loader.
    let _ = uefi::boot::set_watchdog_timer(0, 0x10000, None);

    let Ok(handle) = uefi::boot::get_handle_for_protocol::<GraphicsOutput>() else {
        return Status::UNSUPPORTED;
    };
    let Ok(mut gop) = uefi::boot::open_protocol_exclusive::<GraphicsOutput>(handle) else {
        return Status::UNSUPPORTED;
    };
    connect_all_controllers();
    let mut devices = open_pointers();

    // Prefer a detailed but conservative mode. OVMF exposes this consistently,
    // and the cap avoids allocating a needlessly huge animation buffer.
    let preferred = gop
        .modes()
        .filter(|mode| {
            let (w, h) = mode.info().resolution();
            w >= 800 && h >= 600 && w <= 1280 && h <= 800
        })
        .max_by_key(|mode| {
            let (w, h) = mode.info().resolution();
            w * h
        });
    if let Some(mode) = preferred {
        let _ = gop.set_mode(&mode);
    }

    let (screen_w, screen_h) = gop.current_mode_info().resolution();
    if screen_w < 640 || screen_h < 480 {
        return Status::UNSUPPORTED;
    }

    show_splash(&mut gop, screen_w, screen_h);
    run_setup(&mut gop, screen_w, screen_h);
    show_desktop(&mut gop, screen_w, screen_h, &mut devices)
}

// --- splash -----------------------------------------------------------------

fn show_splash(gop: &mut GraphicsOutput, screen_w: usize, screen_h: usize) {
    let logo_side = min(
        ART_SIDE,
        min(screen_w.saturating_sub(40), screen_h.saturating_sub(100)),
    );
    if logo_side < 160 {
        return;
    }

    let panel_h = logo_side + 56;
    let panel_x = (screen_w - logo_side) / 2;
    let panel_y = (screen_h - panel_h) / 2;
    let mut panel = vec![BLACK; logo_side * panel_h];

    let _ = gop.blt(BltOp::VideoFill {
        color: BLACK,
        dest: (0, 0),
        dims: (screen_w, screen_h),
    });
    draw_accents(gop, panel_x, panel_y, logo_side, panel_h);

    // Smooth 1.2-second reveal. The image itself carries the glow; varying only
    // its envelope keeps the animation calm and photosensitivity-safe.
    for frame in 0..=48usize {
        let level = smoothstep_u8((frame * 255 / 48) as u16);
        render_panel(&mut panel, logo_side, panel_h, level, frame);
        blit(gop, &panel, panel_x, panel_y, logo_side, panel_h);
        uefi::boot::stall(Duration::from_millis(25));
    }

    // Resolve the splash instead of leaving the machine in an endless loading
    // loop. The short fade keeps the branded moment without delaying entry.
    for frame in 0..=18usize {
        let level = 255u8.saturating_sub(smoothstep_u8((frame * 255 / 18) as u16));
        render_panel(&mut panel, logo_side, panel_h, level, 36 + frame);
        blit(gop, &panel, panel_x, panel_y, logo_side, panel_h);
        uefi::boot::stall(Duration::from_millis(25));
    }
}

fn draw_accents(gop: &mut GraphicsOutput, x: usize, y: usize, w: usize, h: usize) {
    let span = min(72, w / 4);
    let segments = [
        (x.saturating_sub(12), y, span, 1, CYAN),
        (x.saturating_sub(12), y, 1, 22, CYAN),
        (x + w + 12 - span, y, span, 1, VIOLET),
        (x + w + 11, y, 1, 22, VIOLET),
        (x.saturating_sub(12), y + h, span, 1, VIOLET),
        (x.saturating_sub(12), y + h - 21, 1, 22, VIOLET),
        (x + w + 12 - span, y + h, span, 1, CYAN),
        (x + w + 11, y + h - 21, 1, 22, CYAN),
    ];

    for (dx, dy, dw, dh, color) in segments {
        let _ = gop.blt(BltOp::VideoFill {
            color,
            dest: (dx, dy),
            dims: (dw, dh),
        });
    }
}

fn render_panel(panel: &mut [BltPixel], width: usize, height: usize, level: u8, phase: usize) {
    panel.fill(BLACK);
    let scan_y = phase * width / 72;

    for y in 0..width {
        let source_y = y * ART_SIDE / width;
        for x in 0..width {
            let source_x = x * ART_SIDE / width;
            let source = (source_y * ART_SIDE + source_x) * 2;
            let packed = u16::from_le_bytes([ART_RGB565[source], ART_RGB565[source + 1]]);
            let mut r = (((packed >> 11) & 0x1f) * 255 / 31) as u8;
            let mut g = (((packed >> 5) & 0x3f) * 255 / 63) as u8;
            let mut b = ((packed & 0x1f) * 255 / 31) as u8;
            let is_lit = r != 0 || g != 0 || b != 0;

            // A narrow, soft scan glint makes the emblem feel alive without
            // flashing the whole display.
            let distance = y.abs_diff(scan_y);
            let glint = if distance < 3 {
                24 - distance as u8 * 8
            } else {
                0
            };
            r = scale_channel(r, level);
            g = scale_channel(g, level);
            b = scale_channel(b, level);
            if is_lit {
                r = r.saturating_add(glint / 3);
                g = g.saturating_add(glint);
                b = b.saturating_add(glint);
            }
            panel[y * width + x] = BltPixel::new(r, g, b);
        }
    }

    let title_level = level.saturating_add(12);
    draw_text_centered(panel, width, height, width + 6, 2, b"WHISEZOS", title_level);
    draw_text_centered(
        panel,
        width,
        height,
        width + 32,
        1,
        b"UEFI BOOT PREVIEW",
        level,
    );

    let bar_y = height - 5;
    let bar_width = width * level as usize / 255;
    for y in bar_y..height - 3 {
        for x in 0..bar_width {
            let blue_bias = (x * 80 / width) as u8;
            panel[y * width + x] = BltPixel::new(0x20u8.saturating_add(blue_bias), 0xD8, 0xFF);
        }
    }
}

// --- setup ------------------------------------------------------------------

/// Panel the setup screen draws inside. Only this rectangle is re-blitted each
/// frame; the wallpaper behind it is static, so a 25 fps progress animation
/// costs one panel-sized copy rather than a full-screen one.
fn setup_panel(width: usize, height: usize) -> Rect {
    let w = (width * 4 / 5).min(940);
    let h = (height * 3 / 4).min(620);
    Rect {
        x: (width - w) / 2,
        y: (height - h) / 2,
        w,
        h,
    }
}

fn run_setup(gop: &mut GraphicsOutput, width: usize, height: usize) {
    let panel = setup_panel(width, height);
    let mut frame = vec![BLACK; width * height];

    // Static layer: the dimmed wallpaper behind the panel, blitted once. The
    // panel itself is redrawn every frame, so nothing inside it belongs here —
    // an earlier version drew the headings into this layer and the per-frame
    // panel blit erased them on the very first tick.
    render_wallpaper(&mut frame, width, height, 52);
    blit(gop, &frame, 0, 0, width, height);

    let mut state = Setup::new();
    let mut scratch = vec![BLACK; panel.w * panel.h];

    loop {
        // Escape skips. A rehearsal that cannot be dismissed is just a wait.
        if let Some(Key::Special(ScanCode::ESCAPE)) =
            uefi::system::with_stdin(|input| input.read_key().ok().flatten())
        {
            state.skip();
        }

        render_setup_body(&mut scratch, panel, &state);
        blit(gop, &scratch, panel.x, panel.y, panel.w, panel.h);

        if state.is_complete() {
            break;
        }
        uefi::boot::stall(Duration::from_millis(FRAME_MS as u64));
        state.advance(FRAME_MS);
    }

    uefi::boot::stall(Duration::from_millis(700));
}

fn render_setup_body(scratch: &mut [BltPixel], panel: Rect, state: &Setup) {
    let (w, h) = (panel.w, panel.h);
    scratch.fill(BltPixel::new(5, 10, 26));
    draw_border(scratch, w, h, (0, 0), (w, h), CYAN);
    fill_rect(scratch, w, h, (0, 0), (w, 4), CYAN);

    let list_x = 40;
    let list_y = 140;

    draw_text_at(
        scratch,
        w,
        h,
        list_x,
        36,
        3,
        b"WHISEZOS SETUP",
        BltPixel::new(224, 249, 255),
    );
    // The single most important line on this screen.
    draw_text_at(
        scratch,
        w,
        h,
        list_x + 2,
        80,
        1,
        b"PREVIEW REHEARSAL - NO DISK IS READ OR WRITTEN",
        rgb(shell::AMBER),
    );
    draw_text_at(
        scratch,
        w,
        h,
        list_x + 2,
        98,
        1,
        b"THIS SHOWS THE PRODUCTION INSTALL ORDER - IT DOES NOT PERFORM IT",
        BltPixel::new(120, 152, 172),
    );
    let row_h = (h.saturating_sub(list_y + 150) / setup::STAGES.len().max(1)).clamp(20, 34);
    let current = state.stage_index();

    for (index, stage) in setup::STAGES.iter().enumerate() {
        let y = list_y + index * row_h;
        if y + row_h > h {
            break;
        }
        let done = state.stage_done(index);
        let active = index == current && !done;

        let (marker, text) = if done {
            (rgb(shell::MINT), BltPixel::new(150, 190, 178))
        } else if active {
            (rgb(shell::CYAN), BltPixel::new(224, 249, 255))
        } else {
            (BltPixel::new(40, 58, 78), BltPixel::new(84, 108, 128))
        };

        fill_rect(scratch, w, h, (list_x, y + 4), (10, 10), marker);
        if active {
            fill_rect(scratch, w, h, (list_x - 14, y), (4, row_h - 6), marker);
        }
        draw_text_at(
            scratch,
            w,
            h,
            list_x + 26,
            y,
            1,
            stage.label.as_bytes(),
            text,
        );
    }

    // Current activity.
    let detail_y = h.saturating_sub(120);
    draw_text_at(
        scratch,
        w,
        h,
        list_x,
        detail_y,
        2,
        state.current_detail().as_bytes(),
        BltPixel::new(176, 218, 230),
    );

    // Stage progress, then overall progress.
    draw_progress_bar(
        scratch,
        w,
        h,
        Rect {
            x: list_x,
            y: detail_y + 34,
            w: w.saturating_sub(list_x * 2),
            h: 6,
        },
        state.stage_progress(),
        rgb(shell::VIOLET),
    );
    draw_progress_bar(
        scratch,
        w,
        h,
        Rect {
            x: list_x,
            y: detail_y + 50,
            w: w.saturating_sub(list_x * 2),
            h: 14,
        },
        state.overall_progress(),
        rgb(shell::CYAN),
    );

    let mut readout = [b' '; 40];
    let written = format_readout(&mut readout, state);
    draw_text_at(
        scratch,
        w,
        h,
        list_x,
        detail_y + 76,
        1,
        &readout[..written],
        BltPixel::new(118, 255, 205),
    );

    let hint = b"ESC SKIP";
    let hint_w = hint.len() * 6;
    draw_text_at(
        scratch,
        w,
        h,
        w.saturating_sub(hint_w + 40),
        detail_y + 76,
        1,
        hint,
        BltPixel::new(96, 120, 140),
    );
}

/// Renders `"nn PERCENT - REMAINING m:ss"` into `out`, returning the length.
fn format_readout(out: &mut [u8; 40], state: &Setup) -> usize {
    let mut cursor = 0usize;
    let mut push = |bytes: &[u8], cursor: &mut usize| {
        for &b in bytes {
            if *cursor < out.len() {
                out[*cursor] = b;
                *cursor += 1;
            }
        }
    };

    let mut digits = [0u8; 3];
    let percent = write_u32(state.percent() as u32, &mut digits);
    push(percent, &mut cursor);
    push(b" PERCENT - REMAINING ", &mut cursor);

    let seconds = state.remaining_ms().div_ceil(1000);
    let mut minute_digits = [0u8; 3];
    push(write_u32(seconds / 60, &mut minute_digits), &mut cursor);
    push(b":", &mut cursor);
    let rest = seconds % 60;
    if rest < 10 {
        push(b"0", &mut cursor);
    }
    let mut second_digits = [0u8; 3];
    push(write_u32(rest, &mut second_digits), &mut cursor);
    cursor
}

/// Decimal-formats `value` into `buffer`, returning the written slice.
fn write_u32(value: u32, buffer: &mut [u8; 3]) -> &[u8] {
    let value = value.min(999);
    if value >= 100 {
        buffer[0] = b'0' + (value / 100) as u8;
        buffer[1] = b'0' + (value / 10 % 10) as u8;
        buffer[2] = b'0' + (value % 10) as u8;
        &buffer[..3]
    } else if value >= 10 {
        buffer[0] = b'0' + (value / 10) as u8;
        buffer[1] = b'0' + (value % 10) as u8;
        &buffer[..2]
    } else {
        buffer[0] = b'0' + value as u8;
        &buffer[..1]
    }
}

fn draw_progress_bar(
    target: &mut [BltPixel],
    width: usize,
    height: usize,
    rect: Rect,
    progress: u16,
    accent: BltPixel,
) {
    fill_rect(
        target,
        width,
        height,
        (rect.x, rect.y),
        (rect.w, rect.h),
        BltPixel::new(14, 24, 44),
    );
    let filled = rect.w * progress as usize / setup::PROGRESS_MAX as usize;
    for x in 0..filled {
        // A gentle left-to-right gradient rather than a flat block, and no
        // moving highlight: a bar that strobes is exactly the effect the
        // project's photosensitivity rule exists to avoid.
        let bias = (x * 60 / rect.w.max(1)) as u8;
        let color = BltPixel::new(
            accent.red.saturating_add(bias / 3),
            accent.green.saturating_sub(bias / 4),
            accent.blue,
        );
        for y in 0..rect.h {
            let px = rect.x + x;
            let py = rect.y + y;
            if px < width && py < height {
                target[py * width + px] = color;
            }
        }
    }
}

// --- desktop ----------------------------------------------------------------

fn show_desktop(
    gop: &mut GraphicsOutput,
    width: usize,
    height: usize,
    devices: &mut [Device],
) -> ! {
    let mut shell = Shell::new();
    let mut frame = vec![BLACK; width * height];

    for step in 0..=20usize {
        let level = smoothstep_u8((step * 255 / 20) as u16);
        render_desktop(&mut frame, width, height, level, &shell, 0, devices.len());
        blit(gop, &frame, 0, 0, width, height);
        uefi::boot::stall(Duration::from_millis(35));
    }

    let mut cursor = Cursor::centered(width, height);
    let mut edges = ButtonEdges::new();
    let mut cursor_surface = vec![BLACK; CURSOR_WIDTH * CURSOR_HEIGHT];
    let mut uptime_s = 0u32;
    let mut ticks = 0u32;

    render_view(&mut frame, width, height, &shell, uptime_s, devices.len());
    blit(gop, &frame, 0, 0, width, height);
    draw_cursor(gop, &frame, &mut cursor_surface, cursor, width, height);

    loop {
        let key = uefi::system::with_stdin(|input| input.read_key().ok().flatten());
        let mut redraw = false;

        if let Some(key) = key {
            redraw |= handle_key(&mut shell, key);
        }

        let previous = cursor.position();
        let (moved, buttons) = poll_pointers(devices, &mut cursor);
        let hovered = shell::hit_test(shell.view, width, height, cursor.x, cursor.y);
        if moved {
            redraw |= shell.hover(hovered);
        }

        let clicks = edges.update(buttons);
        if clicks.left {
            match hovered {
                Some(target) => redraw |= shell.open(target),
                // Clicking empty space on a detail screen goes back, which is
                // what people try before they find the button.
                None if !shell.on_desktop() => redraw |= shell.back(),
                None => {}
            }
        } else if clicks.right {
            redraw |= shell.back();
        }

        ticks += 1;
        if ticks * FRAME_MS >= 1_000 {
            ticks = 0;
            uptime_s += 1;
            if shell.on_desktop() {
                redraw = true;
            }
        }

        if redraw {
            render_view(&mut frame, width, height, &shell, uptime_s, devices.len());
            blit(gop, &frame, 0, 0, width, height);
        } else if moved {
            restore_cursor(gop, &frame, previous.0, previous.1, width, height);
        }
        if redraw || moved {
            draw_cursor(gop, &frame, &mut cursor_surface, cursor, width, height);
        }

        uefi::boot::stall(Duration::from_millis(FRAME_MS as u64));
    }
}

fn handle_key(shell: &mut Shell, key: Key) -> bool {
    match key {
        Key::Special(ScanCode::UP | ScanCode::LEFT) => shell.move_selection(-1),
        Key::Special(ScanCode::DOWN | ScanCode::RIGHT) => shell.move_selection(1),
        Key::Special(ScanCode::ESCAPE) => shell.back(),
        Key::Printable(character) => match char::from(character) {
            '\r' | '\n' => shell.open_selected(),
            '\t' => shell.toggle_focus(),
            '\u{8}' => shell.back(),
            'w' | 'W' => shell.move_selection(-1),
            's' | 'S' => shell.move_selection(1),
            digit @ '1'..='9' => {
                let index = digit as usize - '1' as usize;
                index < shell::APPS.len() && shell.open(Target::Card(index))
            }
            _ => false,
        },
        _ => false,
    }
}

fn render_view(
    target: &mut [BltPixel],
    width: usize,
    height: usize,
    shell: &Shell,
    uptime: u32,
    pointers: usize,
) {
    match shell.view {
        View::Desktop => render_desktop(target, width, height, 255, shell, uptime, pointers),
        View::App(index) => {
            let app = &shell::APPS[index];
            render_detail(
                target,
                width,
                height,
                app.name.as_bytes(),
                app.tagline.as_bytes(),
                app.rows,
                app.accent,
            );
        }
        View::File(index) => {
            let file = &shell::FILES[index];
            let rows = [
                ("TYPE", file.kind.label()),
                ("LOCATION IN BUNDLE", file.origin),
                ("DESCRIPTION", file.note),
                ("OPENED BY PREVIEW", "METADATA ONLY - NO FILE IS READ"),
            ];
            render_detail(
                target,
                width,
                height,
                file.name.as_bytes(),
                file.kind.label().as_bytes(),
                &rows,
                file.kind.accent(),
            );
        }
    }
}

fn render_wallpaper(target: &mut [BltPixel], width: usize, height: usize, level: u8) {
    for y in 0..height {
        let source_y = y * DESKTOP_HEIGHT / height;
        for x in 0..width {
            let source_x = x * DESKTOP_WIDTH / width;
            let source = (source_y * DESKTOP_WIDTH + source_x) * 2;
            let packed = u16::from_le_bytes([DESKTOP_RGB565[source], DESKTOP_RGB565[source + 1]]);
            let r = scale_channel((((packed >> 11) & 0x1f) * 255 / 31) as u8, level);
            let g = scale_channel((((packed >> 5) & 0x3f) * 255 / 63) as u8, level);
            let b = scale_channel(((packed & 0x1f) * 255 / 31) as u8, level);
            target[y * width + x] = BltPixel::new(r, g, b);
        }
    }
}

fn render_desktop(
    target: &mut [BltPixel],
    width: usize,
    height: usize,
    level: u8,
    shell: &Shell,
    uptime: u32,
    pointers: usize,
) {
    render_wallpaper(target, width, height, level);

    let top_h = shell::top_bar_height(height);
    let task_h = shell::taskbar_height(height);
    fill_rect(
        target,
        width,
        height,
        (0, 0),
        (width, top_h),
        scaled_color(8, 12, 28, level),
    );
    fill_rect(
        target,
        width,
        height,
        (0, height - task_h),
        (width, task_h),
        scaled_color(6, 10, 24, level),
    );

    draw_text_at(
        target,
        width,
        height,
        24,
        top_h / 2 - 7,
        2,
        b"WHISEZOS",
        scaled_color(86, 232, 255, level),
    );
    draw_text_at(
        target,
        width,
        height,
        24 + 9 * 12 + 16,
        top_h / 2 - 3,
        1,
        b"V0.1.0 PREVIEW",
        scaled_color(96, 130, 150, level),
    );

    // Uptime rather than a clock: the preview has no reliable time source, and
    // a wrong wall clock is worse than none.
    let mut buffer = [b' '; 24];
    let written = format_uptime(&mut buffer, uptime);
    let status_w = written * 6;
    draw_text_at(
        target,
        width,
        height,
        width.saturating_sub(status_w + 24),
        top_h / 2 - 3,
        1,
        &buffer[..written],
        scaled_color(118, 255, 205, level),
    );

    // How many pointing devices the firmware actually gave us. Whether the
    // mouse works is entirely a property of the firmware here, so showing the
    // count turns "the cursor is stuck" into a one-glance diagnosis instead of
    // a rebuild with print statements.
    let mut probe = [b' '; 24];
    let probe_len = format_pointer_status(&mut probe, pointers);
    draw_text_at(
        target,
        width,
        height,
        width.saturating_sub(status_w + probe_len * 6 + 48),
        top_h / 2 - 3,
        1,
        &probe[..probe_len],
        if pointers == 0 {
            scaled_color(255, 193, 77, level)
        } else {
            scaled_color(96, 130, 150, level)
        },
    );

    for (index, app) in shell::APPS.iter().enumerate() {
        let Some(rect) = shell::card_rect(width, height, index) else {
            continue;
        };
        let selected = shell.focus == Focus::Cards && shell.card == index;
        draw_app_card(target, width, height, rect, app, level, selected);
    }

    for (index, file) in shell::FILES.iter().enumerate() {
        let Some(rect) = shell::icon_rect(width, height, index) else {
            continue;
        };
        let selected = shell.focus == Focus::Icons && shell.icon == index;
        draw_file_icon(target, width, height, rect, file, level, selected);
    }

    draw_text_centered(
        target,
        width,
        height,
        height - task_h + task_h / 2 - 3,
        1,
        b"MOVE MOUSE TO SELECT - LEFT CLICK OPEN - RIGHT CLICK OR ESC BACK - TAB SWITCH",
        level,
    );
}

/// Renders `"POINTER n"` — or a warning when the firmware exposed none.
fn format_pointer_status(out: &mut [u8; 24], pointers: usize) -> usize {
    if pointers == 0 {
        let text = b"NO POINTER DEVICE";
        out[..text.len()].copy_from_slice(text);
        return text.len();
    }
    let mut cursor = 0usize;
    for &b in b"POINTER " {
        out[cursor] = b;
        cursor += 1;
    }
    let mut digits = [0u8; 3];
    for &b in write_u32(pointers as u32, &mut digits) {
        out[cursor] = b;
        cursor += 1;
    }
    cursor
}

/// Renders `"UPTIME m:ss"` into `out`, returning the length.
fn format_uptime(out: &mut [u8; 24], seconds: u32) -> usize {
    let mut cursor = 0usize;
    for &b in b"UPTIME " {
        out[cursor] = b;
        cursor += 1;
    }
    let mut digits = [0u8; 3];
    for &b in write_u32(seconds / 60, &mut digits) {
        out[cursor] = b;
        cursor += 1;
    }
    out[cursor] = b':';
    cursor += 1;
    let rest = seconds % 60;
    if rest < 10 {
        out[cursor] = b'0';
        cursor += 1;
    }
    let mut digits = [0u8; 3];
    for &b in write_u32(rest, &mut digits) {
        out[cursor] = b;
        cursor += 1;
    }
    cursor
}

fn draw_app_card(
    target: &mut [BltPixel],
    width: usize,
    height: usize,
    rect: Rect,
    app: &shell::App,
    level: u8,
    selected: bool,
) {
    let accent = scaled_pixel(rgb(app.accent), level);
    fill_rect(
        target,
        width,
        height,
        (rect.x, rect.y),
        (rect.w, rect.h),
        if selected {
            scaled_color(14, 28, 58, level)
        } else {
            scaled_color(8, 14, 34, level)
        },
    );
    draw_border(
        target,
        width,
        height,
        (rect.x, rect.y),
        (rect.w, rect.h),
        accent,
    );
    if selected && rect.w > 6 && rect.h > 6 {
        draw_border(
            target,
            width,
            height,
            (rect.x + 3, rect.y + 3),
            (rect.w - 6, rect.h - 6),
            accent,
        );
    }
    fill_rect(
        target,
        width,
        height,
        (rect.x + 16, rect.y + 16),
        (7, rect.h.saturating_sub(32)),
        accent,
    );
    draw_text_at(
        target,
        width,
        height,
        rect.x + 34,
        rect.y + 18,
        2,
        app.name.as_bytes(),
        scaled_color(215, 246, 255, level),
    );
    draw_text_at(
        target,
        width,
        height,
        rect.x + 34,
        rect.y + 44,
        1,
        app.tagline.as_bytes(),
        scaled_color(92, 181, 212, level),
    );
}

fn draw_file_icon(
    target: &mut [BltPixel],
    width: usize,
    height: usize,
    rect: Rect,
    file: &shell::DesktopFile,
    level: u8,
    selected: bool,
) {
    if selected {
        fill_rect(
            target,
            width,
            height,
            (rect.x, rect.y),
            (rect.w, rect.h),
            scaled_color(16, 32, 62, level),
        );
        draw_border(
            target,
            width,
            height,
            (rect.x, rect.y),
            (rect.w, rect.h),
            scaled_pixel(rgb(file.kind.accent()), level),
        );
    }

    let accent = scaled_pixel(rgb(file.kind.accent()), level);
    let glyph_w = 40;
    let glyph_h = 46;
    let gx = rect.x + (rect.w - glyph_w) / 2;
    let gy = rect.y + 8;

    // A sheet with a folded corner, tinted by kind. Cheap to draw and reads as
    // a file at this size without needing bitmap assets.
    fill_rect(
        target,
        width,
        height,
        (gx, gy),
        (glyph_w, glyph_h),
        scaled_color(16, 26, 48, level),
    );
    draw_border(target, width, height, (gx, gy), (glyph_w, glyph_h), accent);
    fill_rect(
        target,
        width,
        height,
        (gx + glyph_w - 14, gy),
        (14, 14),
        accent,
    );
    for row in 0..3 {
        fill_rect(
            target,
            width,
            height,
            (gx + 8, gy + 22 + row * 7),
            (glyph_w - 16, 2),
            scaled_color(90, 130, 160, level),
        );
    }

    let name = file.name.as_bytes();
    let text_w = name.len() * 6;
    draw_text_at(
        target,
        width,
        height,
        rect.x + rect.w.saturating_sub(text_w) / 2,
        gy + glyph_h + 8,
        1,
        name,
        scaled_color(206, 230, 244, level),
    );
}

fn render_detail(
    target: &mut [BltPixel],
    width: usize,
    height: usize,
    title: &[u8],
    subtitle: &[u8],
    rows: &[(&str, &str)],
    accent: Rgb,
) {
    render_wallpaper(target, width, height, 40);
    let accent = rgb(accent);
    let panel = shell::detail_panel(width, height);

    fill_rect(
        target,
        width,
        height,
        (panel.x, panel.y),
        (panel.w, panel.h),
        BltPixel::new(7, 13, 34),
    );
    draw_border(
        target,
        width,
        height,
        (panel.x, panel.y),
        (panel.w, panel.h),
        accent,
    );
    fill_rect(
        target,
        width,
        height,
        (panel.x, panel.y),
        (8, panel.h),
        accent,
    );

    draw_text_at(
        target,
        width,
        height,
        panel.x + 40,
        panel.y + 34,
        3,
        title,
        BltPixel::new(224, 249, 255),
    );
    draw_text_at(
        target,
        width,
        height,
        panel.x + 42,
        panel.y + 78,
        1,
        subtitle,
        accent,
    );

    let first_row = panel.y + 118;
    let available = panel.h.saturating_sub(190);
    let row_h = (available / rows.len().max(1)).clamp(22, 48);
    for (index, (label, state)) in rows.iter().enumerate() {
        let y = first_row + index * row_h;
        if y + row_h > panel.bottom() {
            break;
        }
        fill_rect(
            target,
            width,
            height,
            (panel.x + 44, y + 4),
            (10, 10),
            accent,
        );
        draw_text_at(
            target,
            width,
            height,
            panel.x + 68,
            y,
            1,
            label.as_bytes(),
            BltPixel::new(176, 218, 230),
        );
        let state = state.as_bytes();
        let state_w = state.len() * 6;
        draw_text_at(
            target,
            width,
            height,
            panel.right().saturating_sub(state_w + 44),
            y,
            1,
            state,
            BltPixel::new(118, 200, 176),
        );
    }

    let back = shell::back_rect(width, height);
    fill_rect(
        target,
        width,
        height,
        (back.x, back.y),
        (back.w, back.h),
        BltPixel::new(12, 22, 48),
    );
    draw_border(
        target,
        width,
        height,
        (back.x, back.y),
        (back.w, back.h),
        accent,
    );
    let label = b"BACK - ESC";
    let label_w = label.len() * 6 * 2;
    draw_text_at(
        target,
        width,
        height,
        back.x + back.w.saturating_sub(label_w) / 2,
        back.y + back.h / 2 - 7,
        2,
        label,
        BltPixel::new(224, 249, 255),
    );
}

// --- drawing primitives -----------------------------------------------------

fn blit(gop: &mut GraphicsOutput, buffer: &[BltPixel], x: usize, y: usize, w: usize, h: usize) {
    let _ = gop.blt(BltOp::BufferToVideo {
        buffer,
        src: BltRegion::Full,
        dest: (x, y),
        dims: (w, h),
    });
}

fn fill_rect(
    target: &mut [BltPixel],
    width: usize,
    height: usize,
    origin: (usize, usize),
    dims: (usize, usize),
    color: BltPixel,
) {
    let end_x = min(width, origin.0.saturating_add(dims.0));
    let end_y = min(height, origin.1.saturating_add(dims.1));
    for y in origin.1..end_y {
        for x in origin.0..end_x {
            target[y * width + x] = color;
        }
    }
}

fn draw_border(
    target: &mut [BltPixel],
    width: usize,
    height: usize,
    origin: (usize, usize),
    dims: (usize, usize),
    color: BltPixel,
) {
    if dims.0 == 0 || dims.1 == 0 {
        return;
    }
    fill_rect(target, width, height, origin, (dims.0, 1), color);
    fill_rect(
        target,
        width,
        height,
        (origin.0, origin.1 + dims.1 - 1),
        (dims.0, 1),
        color,
    );
    fill_rect(target, width, height, origin, (1, dims.1), color);
    fill_rect(
        target,
        width,
        height,
        (origin.0 + dims.0 - 1, origin.1),
        (1, dims.1),
        color,
    );
}

fn scaled_color(red: u8, green: u8, blue: u8, level: u8) -> BltPixel {
    BltPixel::new(
        scale_channel(red, level),
        scale_channel(green, level),
        scale_channel(blue, level),
    )
}

fn scaled_pixel(pixel: BltPixel, level: u8) -> BltPixel {
    scaled_color(pixel.red, pixel.green, pixel.blue, level)
}

fn restore_cursor(
    gop: &mut GraphicsOutput,
    frame: &[BltPixel],
    x: usize,
    y: usize,
    screen_w: usize,
    screen_h: usize,
) {
    let width = min(CURSOR_WIDTH, screen_w.saturating_sub(x));
    let height = min(CURSOR_HEIGHT, screen_h.saturating_sub(y));
    if width == 0 || height == 0 {
        return;
    }
    let _ = gop.blt(BltOp::BufferToVideo {
        buffer: frame,
        src: BltRegion::SubRectangle {
            coords: (x, y),
            px_stride: screen_w,
        },
        dest: (x, y),
        dims: (width, height),
    });
}

fn draw_cursor(
    gop: &mut GraphicsOutput,
    frame: &[BltPixel],
    surface: &mut [BltPixel],
    cursor: Cursor,
    screen_w: usize,
    screen_h: usize,
) {
    let (x, y) = cursor.position();
    let width = min(CURSOR_WIDTH, screen_w.saturating_sub(x));
    let height = min(CURSOR_HEIGHT, screen_h.saturating_sub(y));
    if width == 0 || height == 0 {
        return;
    }

    for py in 0..height {
        for px in 0..width {
            surface[py * CURSOR_WIDTH + px] = frame[(y + py) * screen_w + x + px];
        }
    }

    for py in 0..height {
        for px in 0..width {
            let body = cursor_mask(px as isize, py as isize);
            let outline = (-1..=1)
                .any(|oy| (-1..=1).any(|ox| cursor_mask(px as isize + ox, py as isize + oy)));
            if body {
                surface[py * CURSOR_WIDTH + px] = BltPixel::new(250, 255, 255);
            } else if outline {
                surface[py * CURSOR_WIDTH + px] = CYAN;
            }
        }
    }

    let _ = gop.blt(BltOp::BufferToVideo {
        buffer: surface,
        src: BltRegion::SubRectangle {
            coords: (0, 0),
            px_stride: CURSOR_WIDTH,
        },
        dest: (x, y),
        dims: (width, height),
    });
}

fn cursor_mask(px: isize, py: isize) -> bool {
    if px < 3 || py < 2 {
        return false;
    }
    let x = (px - 3) as usize;
    let y = (py - 2) as usize;
    let arrow = y < 31 && x <= y / 2;
    let stem = (21..45).contains(&y) && (9..16).contains(&x);
    arrow || stem
}

fn scale_channel(channel: u8, level: u8) -> u8 {
    (channel as u16 * level as u16 / 255) as u8
}

fn smoothstep_u8(t: u16) -> u8 {
    let t = t as u32;
    ((t * t * (765 - 2 * t)) / (255 * 255)) as u8
}

fn draw_text_centered(
    target: &mut [BltPixel],
    width: usize,
    height: usize,
    y: usize,
    scale: usize,
    text: &[u8],
    level: u8,
) {
    let text_width = (text.len() * 6 * scale).saturating_sub(scale);
    let start_x = width.saturating_sub(text_width) / 2;
    let color = BltPixel::new(
        scale_channel(0x72, level),
        scale_channel(0xEC, level),
        scale_channel(0xFF, level),
    );

    draw_text_at(target, width, height, start_x, y, scale, text, color);
}

#[allow(clippy::too_many_arguments)]
fn draw_text_at(
    target: &mut [BltPixel],
    width: usize,
    height: usize,
    start_x: usize,
    y: usize,
    scale: usize,
    text: &[u8],
    color: BltPixel,
) {
    for (index, character) in text.iter().copied().enumerate() {
        let rows = glyph(character);
        for (row, bits) in rows.iter().copied().enumerate() {
            for column in 0..5 {
                if bits & (1 << (4 - column)) == 0 {
                    continue;
                }
                for sy in 0..scale {
                    for sx in 0..scale {
                        let px = start_x + index * 6 * scale + column * scale + sx;
                        let py = y + row * scale + sy;
                        if px < width && py < height {
                            target[py * width + px] = color;
                        }
                    }
                }
            }
        }
    }
}

/// 5x7 uppercase font. Digits and the handful of punctuation marks below were
/// added for the setup readouts — a progress screen without digits is not a
/// progress screen.
fn glyph(c: u8) -> [u8; 7] {
    match c {
        b'A' => [0x0e, 0x11, 0x11, 0x1f, 0x11, 0x11, 0x11],
        b'B' => [0x1e, 0x11, 0x11, 0x1e, 0x11, 0x11, 0x1e],
        b'C' => [0x0f, 0x10, 0x10, 0x10, 0x10, 0x10, 0x0f],
        b'D' => [0x1e, 0x11, 0x11, 0x11, 0x11, 0x11, 0x1e],
        b'E' => [0x1f, 0x10, 0x10, 0x1e, 0x10, 0x10, 0x1f],
        b'F' => [0x1f, 0x10, 0x10, 0x1e, 0x10, 0x10, 0x10],
        b'G' => [0x0f, 0x10, 0x10, 0x13, 0x11, 0x11, 0x0f],
        b'H' => [0x11, 0x11, 0x11, 0x1f, 0x11, 0x11, 0x11],
        b'I' => [0x1f, 0x04, 0x04, 0x04, 0x04, 0x04, 0x1f],
        b'J' => [0x07, 0x02, 0x02, 0x02, 0x12, 0x12, 0x0c],
        b'K' => [0x11, 0x12, 0x14, 0x18, 0x14, 0x12, 0x11],
        b'L' => [0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x1f],
        b'M' => [0x11, 0x1b, 0x15, 0x15, 0x11, 0x11, 0x11],
        b'N' => [0x11, 0x19, 0x15, 0x13, 0x11, 0x11, 0x11],
        b'O' => [0x0e, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0e],
        b'P' => [0x1e, 0x11, 0x11, 0x1e, 0x10, 0x10, 0x10],
        b'Q' => [0x0e, 0x11, 0x11, 0x11, 0x15, 0x12, 0x0d],
        b'R' => [0x1e, 0x11, 0x11, 0x1e, 0x14, 0x12, 0x11],
        b'S' => [0x0f, 0x10, 0x10, 0x0e, 0x01, 0x01, 0x1e],
        b'T' => [0x1f, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04],
        b'U' => [0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0e],
        b'V' => [0x11, 0x11, 0x11, 0x11, 0x11, 0x0a, 0x04],
        b'W' => [0x11, 0x11, 0x11, 0x15, 0x15, 0x15, 0x0a],
        b'X' => [0x11, 0x11, 0x0a, 0x04, 0x0a, 0x11, 0x11],
        b'Y' => [0x11, 0x11, 0x0a, 0x04, 0x04, 0x04, 0x04],
        b'Z' => [0x1f, 0x01, 0x02, 0x04, 0x08, 0x10, 0x1f],
        b'0' => [0x0e, 0x11, 0x13, 0x15, 0x19, 0x11, 0x0e],
        b'1' => [0x04, 0x0c, 0x04, 0x04, 0x04, 0x04, 0x0e],
        b'2' => [0x0e, 0x11, 0x01, 0x02, 0x04, 0x08, 0x1f],
        b'3' => [0x1f, 0x02, 0x04, 0x02, 0x01, 0x11, 0x0e],
        b'4' => [0x02, 0x06, 0x0a, 0x12, 0x1f, 0x02, 0x02],
        b'5' => [0x1f, 0x10, 0x1e, 0x01, 0x01, 0x11, 0x0e],
        b'6' => [0x06, 0x08, 0x10, 0x1e, 0x11, 0x11, 0x0e],
        b'7' => [0x1f, 0x01, 0x02, 0x04, 0x08, 0x08, 0x08],
        b'8' => [0x0e, 0x11, 0x11, 0x0e, 0x11, 0x11, 0x0e],
        b'9' => [0x0e, 0x11, 0x11, 0x0f, 0x01, 0x02, 0x0c],
        b'.' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x0c],
        b',' => [0x00, 0x00, 0x00, 0x00, 0x0c, 0x04, 0x08],
        b':' => [0x00, 0x0c, 0x0c, 0x00, 0x0c, 0x0c, 0x00],
        b'-' => [0x00, 0x00, 0x00, 0x1f, 0x00, 0x00, 0x00],
        b'+' => [0x00, 0x04, 0x04, 0x1f, 0x04, 0x04, 0x00],
        b'/' => [0x01, 0x01, 0x02, 0x04, 0x08, 0x10, 0x10],
        b'_' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1f],
        b'(' => [0x02, 0x04, 0x08, 0x08, 0x08, 0x04, 0x02],
        b')' => [0x08, 0x04, 0x02, 0x02, 0x02, 0x04, 0x08],
        b' ' => [0; 7],
        _ => [0x1f, 0x11, 0x02, 0x04, 0x08, 0x00, 0x08],
    }
}
