//! Bootable WhisezOS UEFI preview.
//!
//! This target intentionally does one thing well: prove the host toolchain,
//! UEFI firmware, GOP framebuffer, packaged artwork, and VM launch path while
//! the production kernel handoff is still under construction.

#![no_main]
#![no_std]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::cmp::min;
use core::time::Duration;
use uefi::boot::ScopedProtocol;
use uefi::prelude::*;
use uefi::proto::console::gop::{BltOp, BltPixel, BltRegion, GraphicsOutput};
use uefi::proto::console::pointer::Pointer;
use uefi::proto::console::text::{Key, ScanCode};

const ART_SIDE: usize = 480;
const ART_RGB565: &[u8] = include_bytes!("../assets/whisez-dragon.rgb565");
const DESKTOP_WIDTH: usize = 960;
const DESKTOP_HEIGHT: usize = 540;
const DESKTOP_RGB565: &[u8] = include_bytes!("../assets/whisez-desktop.rgb565");
const CURSOR_WIDTH: usize = 34;
const CURSOR_HEIGHT: usize = 48;
const BLACK: BltPixel = BltPixel::new(0, 0, 0);
const CYAN: BltPixel = BltPixel::new(0x19, 0xE6, 0xFF);
const VIOLET: BltPixel = BltPixel::new(0x8A, 0x4D, 0xFF);

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
    // OVMF can expose both PS/2 and USB Simple Pointer instances. Listen to
    // every usable instance so the cursor follows whichever device QEMU (or
    // real firmware) routes the user's input through.
    let mut pointers = uefi::boot::find_handles::<Pointer>()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|handle| uefi::boot::open_protocol_exclusive::<Pointer>(handle).ok())
        .collect::<Vec<_>>();
    for pointer in &mut pointers {
        let _ = pointer.reset(false);
    }

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
    let logo_side = min(
        ART_SIDE,
        min(screen_w.saturating_sub(40), screen_h.saturating_sub(100)),
    );
    if logo_side < 160 {
        return Status::UNSUPPORTED;
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
    draw_accents(&mut gop, panel_x, panel_y, logo_side, panel_h);

    // Smooth 1.2-second reveal. The image itself carries the glow; varying only
    // its envelope keeps the animation calm and photosensitivity-safe.
    for frame in 0..=48usize {
        let t = (frame * 255 / 48) as u16;
        let level = smoothstep_u8(t);
        render_panel(&mut panel, logo_side, panel_h, level, frame);
        blit_panel(&mut gop, &panel, panel_x, panel_y, logo_side, panel_h);
        uefi::boot::stall(Duration::from_millis(25));
    }

    // Resolve the splash instead of leaving the machine in an endless loading
    // loop. The short fade keeps the branded moment without delaying entry.
    for frame in 0..=18usize {
        let t = (frame * 255 / 18) as u16;
        let level = 255u8.saturating_sub(smoothstep_u8(t));
        render_panel(&mut panel, logo_side, panel_h, level, 36 + frame);
        blit_panel(&mut gop, &panel, panel_x, panel_y, logo_side, panel_h);
        uefi::boot::stall(Duration::from_millis(25));
    }

    show_desktop(&mut gop, screen_w, screen_h, &mut pointers)
}

fn blit_panel(
    gop: &mut GraphicsOutput,
    panel: &[BltPixel],
    x: usize,
    y: usize,
    width: usize,
    height: usize,
) {
    let _ = gop.blt(BltOp::BufferToVideo {
        buffer: panel,
        src: BltRegion::Full,
        dest: (x, y),
        dims: (width, height),
    });
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

fn show_desktop(
    gop: &mut GraphicsOutput,
    width: usize,
    height: usize,
    pointers: &mut [ScopedProtocol<Pointer>],
) -> ! {
    let _ = gop.blt(BltOp::VideoFill {
        color: BLACK,
        dest: (0, 0),
        dims: (width, height),
    });

    let mut desktop = vec![BLACK; width * height];
    for frame in 0..=20usize {
        let t = (frame * 255 / 20) as u16;
        render_desktop(&mut desktop, width, height, smoothstep_u8(t), 0);
        blit_panel(gop, &desktop, 0, 0, width, height);
        uefi::boot::stall(Duration::from_millis(35));
    }

    // The desktop is ready and keyboard-driven. Arrow keys move between cards,
    // Enter opens one, Escape returns, and 1/2/3 are direct shortcuts.
    let mut selected = 0usize;
    let mut view = 0usize;
    let mut ticks = 0usize;
    let mut active = true;
    let mut left_down = false;
    let mut cursor_x = width / 2;
    let mut cursor_y = height / 2;
    let mut cursor_surface = vec![BLACK; CURSOR_WIDTH * CURSOR_HEIGHT];
    let status_x = width.saturating_sub(30);
    let status_y = 24;
    // Always paint the software cursor. It stays visible even when firmware
    // exposes no usable pointer protocol; any available instances still drive
    // movement and clicks.
    draw_cursor(
        gop,
        &desktop,
        &mut cursor_surface,
        cursor_x,
        cursor_y,
        width,
        height,
    );
    loop {
        let key = uefi::system::with_stdin(|input| input.read_key().ok().flatten());
        let mut redraw = false;
        let mut cursor_moved = false;
        let old_cursor = (cursor_x, cursor_y);

        if let Some(key) = key {
            match key {
                Key::Special(ScanCode::UP | ScanCode::LEFT) if view == 0 => {
                    selected = (selected + 2) % 3;
                    redraw = true;
                }
                Key::Special(ScanCode::DOWN | ScanCode::RIGHT) if view == 0 => {
                    selected = (selected + 1) % 3;
                    redraw = true;
                }
                Key::Special(ScanCode::ESCAPE) if view != 0 => {
                    view = 0;
                    redraw = true;
                }
                Key::Printable(character) => {
                    let character: char = character.into();
                    match character {
                        '\r' | '\n' if view == 0 => {
                            view = selected + 1;
                            redraw = true;
                        }
                        '1' => {
                            selected = 0;
                            view = 1;
                            redraw = true;
                        }
                        '2' => {
                            selected = 1;
                            view = 2;
                            redraw = true;
                        }
                        '3' => {
                            selected = 2;
                            view = 3;
                            redraw = true;
                        }
                        'w' | 'W' if view == 0 => {
                            selected = (selected + 2) % 3;
                            redraw = true;
                        }
                        's' | 'S' if view == 0 => {
                            selected = (selected + 1) % 3;
                            redraw = true;
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }

        let mut buttons = [false; 2];
        for pointer in pointers.iter_mut() {
            if let Ok(Some(state)) = pointer.read_state() {
                let dx = pointer_delta(state.relative_movement[0]);
                let dy = pointer_delta(state.relative_movement[1]);
                if dx != 0 || dy != 0 {
                    cursor_x = add_clamped(cursor_x, dx, width.saturating_sub(1));
                    cursor_y = add_clamped(cursor_y, dy, height.saturating_sub(1));
                    cursor_moved = true;

                    if view == 0 {
                        if let Some(hovered) = hovered_card(width, height, cursor_x, cursor_y) {
                            if hovered != selected {
                                selected = hovered;
                                redraw = true;
                            }
                        }
                    }
                }

                buttons[0] |= state.button[0];
                buttons[1] |= state.button[1];
            }
        }

        let clicked = buttons[0] && !left_down;
        let right_clicked = buttons[1] && !left_down;
        left_down = buttons[0] || buttons[1];
        if clicked {
            if view == 0 {
                if let Some(hovered) = hovered_card(width, height, cursor_x, cursor_y) {
                    selected = hovered;
                    view = selected + 1;
                    redraw = true;
                }
            } else if back_button_hit(width, height, cursor_x, cursor_y) {
                view = 0;
                redraw = true;
            }
        } else if right_clicked && view != 0 {
            view = 0;
            redraw = true;
        }

        if redraw {
            render_view(&mut desktop, width, height, view, selected);
            blit_panel(gop, &desktop, 0, 0, width, height);
        } else if cursor_moved {
            restore_cursor(gop, &desktop, old_cursor.0, old_cursor.1, width, height);
        }
        if redraw || cursor_moved {
            draw_cursor(
                gop,
                &desktop,
                &mut cursor_surface,
                cursor_x,
                cursor_y,
                width,
                height,
            );
        }

        ticks += 1;
        if ticks == 13 {
            let _ = gop.blt(BltOp::VideoFill {
                color: if active { CYAN } else { VIOLET },
                dest: (status_x, status_y),
                dims: (8, 8),
            });
            active = !active;
            ticks = 0;
        }
        uefi::boot::stall(Duration::from_millis(50));
    }
}

fn render_view(target: &mut [BltPixel], width: usize, height: usize, view: usize, selected: usize) {
    if view == 0 {
        render_desktop(target, width, height, 255, selected);
    } else {
        render_feature_screen(target, width, height, view);
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
    selected: usize,
) {
    render_wallpaper(target, width, height, level);

    let top_h = min(58, height / 10);
    let task_h = min(54, height / 11);
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
        19,
        2,
        b"WHISEZOS",
        scaled_color(86, 232, 255, level),
    );
    let status = b"SYSTEM READY";
    let status_width = status.len() * 6;
    draw_text_at(
        target,
        width,
        height,
        width.saturating_sub(status_width + 48),
        24,
        1,
        status,
        scaled_color(118, 255, 205, level),
    );

    let (card_x, first_y, card_w, card_h) = desktop_card_rect(width, height, 0);
    draw_app_card(
        target,
        width,
        height,
        card_x,
        first_y,
        card_w,
        card_h,
        b"WHISEZ GUARD",
        b"PROTECTION ACTIVE",
        CYAN,
        level,
        selected == 0,
    );
    let (_, second_y, _, _) = desktop_card_rect(width, height, 1);
    draw_app_card(
        target,
        width,
        height,
        card_x,
        second_y,
        card_w,
        card_h,
        b"TERMINAL",
        b"SECURE SHELL",
        VIOLET,
        level,
        selected == 1,
    );
    let (_, third_y, _, _) = desktop_card_rect(width, height, 2);
    draw_app_card(
        target,
        width,
        height,
        card_x,
        third_y,
        card_w,
        card_h,
        b"FILES",
        b"VAULT STORAGE",
        BltPixel::new(66, 160, 255),
        level,
        selected == 2,
    );

    draw_text_centered(
        target,
        width,
        height,
        height - task_h + 18,
        1,
        b"MOUSE SELECT   LEFT CLICK OPEN   RIGHT CLICK BACK",
        level,
    );
}

fn render_feature_screen(target: &mut [BltPixel], width: usize, height: usize, view: usize) {
    render_wallpaper(target, width, height, 70);
    fill_rect(
        target,
        width,
        height,
        (0, 0),
        (width, height),
        BltPixel::new(3, 7, 20),
    );

    let (title, subtitle, rows, accent): (&[u8], &[u8], [&[u8]; 3], BltPixel) = match view {
        1 => (
            b"WHISEZ GUARD",
            b"DEFENSIVE SECURITY CENTER",
            [
                b"FIREWALL STATUS READY",
                b"INTEGRITY MONITOR READY",
                b"OFFLINE SCANNER BUNDLED",
            ],
            CYAN,
        ),
        2 => (
            b"WHISEZ TERMINAL",
            b"SECURE COMMAND PREVIEW",
            [
                b"UEFI CONSOLE CONNECTED",
                b"WHISEZ GUARD AVAILABLE",
                b"FULL USERLAND PENDING",
            ],
            VIOLET,
        ),
        _ => (
            b"VAULT FILES",
            b"PACKAGE CONTENTS",
            [b"EFI BOOT", b"TOOLS WHISEZ GUARD", b"WALLPAPERS 4K"],
            BltPixel::new(66, 160, 255),
        ),
    };

    let panel_x = width / 10;
    let panel_y = height / 6;
    let panel_w = width * 4 / 5;
    let panel_h = height * 2 / 3;
    fill_rect(
        target,
        width,
        height,
        (panel_x, panel_y),
        (panel_w, panel_h),
        BltPixel::new(7, 13, 34),
    );
    draw_border(
        target,
        width,
        height,
        (panel_x, panel_y),
        (panel_w, panel_h),
        accent,
    );
    fill_rect(
        target,
        width,
        height,
        (panel_x, panel_y),
        (8, panel_h),
        accent,
    );

    draw_text_at(
        target,
        width,
        height,
        panel_x + 44,
        panel_y + 42,
        3,
        title,
        BltPixel::new(224, 249, 255),
    );
    draw_text_at(
        target,
        width,
        height,
        panel_x + 46,
        panel_y + 88,
        1,
        subtitle,
        accent,
    );

    for (index, row) in rows.iter().enumerate() {
        let y = panel_y + 156 + index * 76;
        fill_rect(
            target,
            width,
            height,
            (panel_x + 48, y),
            (12, 12),
            BltPixel::new(82, 255, 174),
        );
        draw_text_at(
            target,
            width,
            height,
            panel_x + 84,
            y,
            2,
            row,
            BltPixel::new(176, 218, 230),
        );
    }

    draw_text_centered(
        target,
        width,
        height,
        panel_y + panel_h - 54,
        2,
        b"ESC BACK",
        255,
    );
}

#[allow(clippy::too_many_arguments)]
fn draw_app_card(
    target: &mut [BltPixel],
    width: usize,
    height: usize,
    x: usize,
    y: usize,
    card_w: usize,
    card_h: usize,
    title: &[u8],
    subtitle: &[u8],
    accent: BltPixel,
    level: u8,
    selected: bool,
) {
    if y >= height.saturating_sub(60) {
        return;
    }
    let actual_h = min(card_h, height.saturating_sub(y + 60));
    fill_rect(
        target,
        width,
        height,
        (x, y),
        (card_w, actual_h),
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
        (x, y),
        (card_w, actual_h),
        scaled_pixel(accent, level),
    );
    if selected && card_w > 4 && actual_h > 4 {
        draw_border(
            target,
            width,
            height,
            (x + 3, y + 3),
            (card_w - 6, actual_h - 6),
            scaled_pixel(accent, level),
        );
    }
    fill_rect(
        target,
        width,
        height,
        (x + 18, y + 20),
        (8, min(48, actual_h.saturating_sub(30))),
        scaled_pixel(accent, level),
    );
    draw_text_at(
        target,
        width,
        height,
        x + 42,
        y + 20,
        2,
        title,
        scaled_color(215, 246, 255, level),
    );
    draw_text_at(
        target,
        width,
        height,
        x + 42,
        y + 52,
        1,
        subtitle,
        scaled_color(92, 181, 212, level),
    );
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

fn max_usize(a: usize, b: usize) -> usize {
    if a > b {
        a
    } else {
        b
    }
}

fn desktop_card_rect(width: usize, height: usize, index: usize) -> (usize, usize, usize, usize) {
    let top_h = min(58, height / 10);
    let card_w = min(260, width / 3);
    let card_h = min(112, height / 6);
    let card_x = max_usize(36, width / 14);
    let first_y = max_usize(top_h + 34, height / 4);
    (card_x, first_y + index * (card_h + 18), card_w, card_h)
}

fn hovered_card(width: usize, height: usize, cursor_x: usize, cursor_y: usize) -> Option<usize> {
    (0..3).find(|index| {
        let (x, y, w, h) = desktop_card_rect(width, height, *index);
        cursor_x >= x && cursor_x < x + w && cursor_y >= y && cursor_y < y + h
    })
}

fn back_button_hit(width: usize, height: usize, cursor_x: usize, cursor_y: usize) -> bool {
    let panel_y = height / 6;
    let panel_h = height * 2 / 3;
    let center_x = width / 2;
    cursor_x >= center_x.saturating_sub(100)
        && cursor_x <= min(width - 1, center_x + 100)
        && cursor_y >= panel_y + panel_h - 76
        && cursor_y <= min(height - 1, panel_y + panel_h - 18)
}

fn pointer_delta(raw: i32) -> isize {
    raw.clamp(-64, 64) as isize
}

fn add_clamped(value: usize, delta: isize, maximum: usize) -> usize {
    if delta < 0 {
        value.saturating_sub(delta.unsigned_abs()).min(maximum)
    } else {
        value.saturating_add(delta as usize).min(maximum)
    }
}

fn restore_cursor(
    gop: &mut GraphicsOutput,
    desktop: &[BltPixel],
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
        buffer: desktop,
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
    desktop: &[BltPixel],
    surface: &mut [BltPixel],
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

    for py in 0..height {
        for px in 0..width {
            surface[py * CURSOR_WIDTH + px] = desktop[(y + py) * screen_w + x + px];
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
                surface[py * CURSOR_WIDTH + px] = BltPixel::new(0x19, 0xE6, 0xFF);
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
    let text_width = text.len() * 6 * scale - scale;
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
        b'R' => [0x1e, 0x11, 0x11, 0x1e, 0x14, 0x12, 0x11],
        b'S' => [0x0f, 0x10, 0x10, 0x0e, 0x01, 0x01, 0x1e],
        b'T' => [0x1f, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04],
        b'U' => [0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0e],
        b'V' => [0x11, 0x11, 0x11, 0x11, 0x11, 0x0a, 0x04],
        b'W' => [0x11, 0x11, 0x11, 0x15, 0x15, 0x15, 0x0a],
        b'X' => [0x11, 0x11, 0x0a, 0x04, 0x0a, 0x11, 0x11],
        b'Y' => [0x11, 0x11, 0x0a, 0x04, 0x04, 0x04, 0x04],
        b'Z' => [0x1f, 0x01, 0x02, 0x04, 0x08, 0x10, 0x1f],
        b' ' => [0; 7],
        _ => [0x1f, 0x11, 0x02, 0x04, 0x08, 0x00, 0x08],
    }
}
