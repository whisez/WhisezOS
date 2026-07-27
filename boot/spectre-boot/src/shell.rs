//! Desktop shell model for the preview: what is on screen, where it is, and
//! what the pointer and keyboard do to it.
//!
//! Geometry lives here rather than in the renderer because hit testing and
//! drawing have to agree exactly. When each had its own copy of the card
//! rectangle, a card could highlight under the cursor while a click one pixel
//! away opened nothing. Both now call `card_rect` and `icon_rect`, and the tests
//! below check the two against each other across a range of screen sizes.
//!
//! Everything here is layout and state. The renderer in `demo.rs` reads this
//! model and draws it; it never decides what is where.

#![allow(dead_code)]

/// Accent colour as plain RGB, so this module stays free of UEFI types and can
/// be compiled and tested on the host.
pub type Rgb = (u8, u8, u8);

pub const CYAN: Rgb = (0x19, 0xE6, 0xFF);
pub const VIOLET: Rgb = (0x8A, 0x4D, 0xFF);
pub const AZURE: Rgb = (0x42, 0xA0, 0xFF);
pub const MINT: Rgb = (0x52, 0xFF, 0xAE);
pub const AMBER: Rgb = (0xFF, 0xC1, 0x4D);

/// An axis-aligned rectangle in screen space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rect {
    pub x: usize,
    pub y: usize,
    pub w: usize,
    pub h: usize,
}

impl Rect {
    #[must_use]
    pub const fn contains(&self, x: usize, y: usize) -> bool {
        x >= self.x && x < self.x + self.w && y >= self.y && y < self.y + self.h
    }

    #[must_use]
    pub const fn right(&self) -> usize {
        self.x + self.w
    }

    #[must_use]
    pub const fn bottom(&self) -> usize {
        self.y + self.h
    }
}

/// An application tile on the desktop.
pub struct App {
    pub name: &'static str,
    pub tagline: &'static str,
    pub accent: Rgb,
    /// Detail rows on the app's own screen. Each row is `(label, state)`; the
    /// state string is what keeps these screens honest, so a component that is
    /// not implemented says so on its own page instead of showing a green tick.
    pub rows: &'static [(&'static str, &'static str)],
}

/// The applications the preview presents.
///
/// Guard is first because it is the only one backed by a program that actually
/// runs today — it ships in the bundle as a host tool. The rest describe parts
/// of the system that exist as design or partial implementation, and each says
/// which it is on its own screen.
pub const APPS: &[App] = &[
    App {
        name: "WHISEZ GUARD",
        tagline: "DEFENSIVE TOOLKIT",
        accent: CYAN,
        rows: &[
            ("OFFLINE FILE SCANNER", "SHIPS IN BUNDLE"),
            ("INTEGRITY BASELINE", "SHIPS IN BUNDLE"),
            ("CHANGE MONITOR", "SHIPS IN BUNDLE"),
            ("RUNS ON", "WINDOWS HOST TODAY"),
            ("NEVER EXECUTES SCANNED FILES", "BY DESIGN"),
        ],
    },
    App {
        name: "TERMINAL",
        tagline: "SECURE CONSOLE",
        accent: VIOLET,
        rows: &[
            ("UEFI TEXT CONSOLE", "CONNECTED"),
            ("KEYBOARD INPUT", "CONNECTED"),
            ("USERLAND SHELL", "NOT IMPLEMENTED"),
            ("PROCESS EXECUTION", "NEEDS KERNEL HANDOFF"),
        ],
    },
    App {
        name: "FILES",
        tagline: "VAULT STORAGE",
        accent: AZURE,
        rows: &[
            ("DESKTOP ITEMS", "SHOWN ON DESKTOP"),
            ("SPECTREFS LAYOUT", "IMPLEMENTED AND TESTED"),
            ("BLOCK DEVICE BINDING", "NOT IMPLEMENTED"),
            ("READ AND WRITE PATH", "NEEDS DRIVER PROCESS"),
        ],
    },
    App {
        name: "SYSTEM",
        tagline: "PLATFORM STATUS",
        accent: MINT,
        rows: &[
            ("FIRMWARE", "UEFI X64"),
            ("GRAPHICS", "GOP FRAMEBUFFER"),
            ("POINTER", "SIMPLE PLUS ABSOLUTE"),
            ("MICROKERNEL", "NOT BOOTED IN PREVIEW"),
            ("BUILD", "V0.1.0 DEVELOPER PREVIEW"),
        ],
    },
    App {
        name: "NETWORK",
        tagline: "OFFLINE BY DEFAULT",
        accent: AMBER,
        rows: &[
            ("NETWORK STACK", "NOT IMPLEMENTED"),
            ("TELEMETRY", "NONE - NEVER ADDED"),
            ("REQUIRED ACCOUNT", "NONE"),
            ("OUTBOUND TRAFFIC", "ZERO IN THIS PREVIEW"),
        ],
    },
];

/// What a desktop item is, which drives its icon and its detail screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    Document,
    Executable,
    Image,
    Manifest,
}

impl FileKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Document => "DOCUMENT",
            Self::Executable => "PROGRAM",
            Self::Image => "IMAGE",
            Self::Manifest => "MANIFEST",
        }
    }

    #[must_use]
    pub const fn accent(self) -> Rgb {
        match self {
            Self::Document => AZURE,
            Self::Executable => CYAN,
            Self::Image => VIOLET,
            Self::Manifest => AMBER,
        }
    }
}

/// An item on the desktop.
pub struct DesktopFile {
    pub name: &'static str,
    pub kind: FileKind,
    /// Where the item lives in the released bundle, so the preview describes
    /// the real package layout rather than inventing a filesystem.
    pub origin: &'static str,
    pub note: &'static str,
}

/// Desktop items, mirroring what `cargo xtask bundle` actually produces.
pub const FILES: &[DesktopFile] = &[
    DesktopFile {
        name: "README",
        kind: FileKind::Document,
        origin: "WHISEZOS/README.TXT",
        note: "BILINGUAL PACKAGE NOTES",
    },
    DesktopFile {
        name: "BOOTX64",
        kind: FileKind::Executable,
        origin: "EFI/BOOT/BOOTX64.EFI",
        note: "THIS PREVIEW APPLICATION",
    },
    DesktopFile {
        name: "GUARD",
        kind: FileKind::Executable,
        origin: "TOOLS/WHISEZ-GUARD",
        note: "OFFLINE DEFENSIVE TOOLKIT",
    },
    DesktopFile {
        name: "DRAGON 4K",
        kind: FileKind::Image,
        origin: "WALLPAPERS/DRAGON-4K.PNG",
        note: "DESKTOP WALLPAPER SOURCE",
    },
    DesktopFile {
        name: "MANIFEST",
        kind: FileKind::Manifest,
        origin: "TARGET/BOOT.MANIFEST",
        note: "SHA3-512 IMAGE DIGESTS",
    },
    DesktopFile {
        name: "NOTES",
        kind: FileKind::Document,
        origin: "DOCS/ARCHITECTURE.MD",
        note: "IMPLEMENTATION STATUS",
    },
];

/// Icons per row in the desktop grid.
pub const ICON_COLUMNS: usize = 3;

/// What the shell is currently showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Desktop,
    App(usize),
    File(usize),
}

/// What the pointer is over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Card(usize),
    Icon(usize),
    Back,
}

/// Which group of the desktop the keyboard is driving.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Cards,
    Icons,
}

/// Desktop shell state.
#[derive(Debug, Clone, Copy)]
pub struct Shell {
    pub view: View,
    pub focus: Focus,
    pub card: usize,
    pub icon: usize,
}

impl Default for Shell {
    fn default() -> Self {
        Self::new()
    }
}

impl Shell {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            view: View::Desktop,
            focus: Focus::Cards,
            card: 0,
            icon: 0,
        }
    }

    #[must_use]
    pub fn on_desktop(&self) -> bool {
        self.view == View::Desktop
    }

    /// Moves the selection within the focused group. Returns whether anything
    /// changed, so the caller can skip a redraw.
    pub fn move_selection(&mut self, delta: isize) -> bool {
        if !self.on_desktop() {
            return false;
        }
        match self.focus {
            Focus::Cards => {
                let next = wrap(self.card, delta, APPS.len());
                let changed = next != self.card;
                self.card = next;
                changed
            }
            Focus::Icons => {
                let next = wrap(self.icon, delta, FILES.len());
                let changed = next != self.icon;
                self.icon = next;
                changed
            }
        }
    }

    /// Tab between the app column and the icon grid.
    pub fn toggle_focus(&mut self) -> bool {
        if !self.on_desktop() {
            return false;
        }
        self.focus = match self.focus {
            Focus::Cards => Focus::Icons,
            Focus::Icons => Focus::Cards,
        };
        true
    }

    /// Opens whatever is selected.
    pub fn open_selected(&mut self) -> bool {
        if !self.on_desktop() {
            return false;
        }
        self.view = match self.focus {
            Focus::Cards => View::App(self.card),
            Focus::Icons => View::File(self.icon),
        };
        true
    }

    /// Opens a specific target and syncs the selection and focus to it, so
    /// going back leaves the highlight where the user clicked.
    pub fn open(&mut self, target: Target) -> bool {
        match target {
            Target::Card(index) if index < APPS.len() => {
                self.card = index;
                self.focus = Focus::Cards;
                self.view = View::App(index);
                true
            }
            Target::Icon(index) if index < FILES.len() => {
                self.icon = index;
                self.focus = Focus::Icons;
                self.view = View::File(index);
                true
            }
            Target::Back => self.back(),
            _ => false,
        }
    }

    /// Returns to the desktop. Returns false when already there, so Escape on
    /// the desktop is a no-op rather than a pointless full redraw.
    pub fn back(&mut self) -> bool {
        if self.on_desktop() {
            return false;
        }
        self.view = View::Desktop;
        true
    }

    /// Hover highlight. Only the desktop has hoverable selection.
    pub fn hover(&mut self, target: Option<Target>) -> bool {
        if !self.on_desktop() {
            return false;
        }
        match target {
            Some(Target::Card(index)) if index != self.card || self.focus != Focus::Cards => {
                self.card = index;
                self.focus = Focus::Cards;
                true
            }
            Some(Target::Icon(index)) if index != self.icon || self.focus != Focus::Icons => {
                self.icon = index;
                self.focus = Focus::Icons;
                true
            }
            _ => false,
        }
    }
}

fn wrap(current: usize, delta: isize, len: usize) -> usize {
    if len == 0 {
        return 0;
    }
    let len_i = len as isize;
    let next = (current as isize + delta).rem_euclid(len_i);
    next as usize
}

// --- geometry ---------------------------------------------------------------

/// Height of the top status bar.
#[must_use]
pub fn top_bar_height(height: usize) -> usize {
    (height / 10).clamp(28, 58)
}

/// Height of the taskbar along the bottom.
#[must_use]
pub fn taskbar_height(height: usize) -> usize {
    (height / 11).clamp(26, 54)
}

/// Rectangle of application card `index`, or `None` when the screen is too
/// short to show it. The renderer must skip exactly the cards this skips.
#[must_use]
pub fn card_rect(width: usize, height: usize, index: usize) -> Option<Rect> {
    if index >= APPS.len() {
        return None;
    }
    let top = top_bar_height(height);
    let bottom = height.saturating_sub(taskbar_height(height));
    let w = (width / 4).clamp(150, 260);
    let x = (width / 20).max(20);
    let gap = 12;
    let available = bottom.saturating_sub(top + 24);
    let h = ((available / APPS.len()).saturating_sub(gap)).clamp(0, 96);
    if h < 44 {
        return None;
    }

    let y = top + 20 + index * (h + gap);
    if y + h > bottom {
        return None;
    }
    Some(Rect { x, y, w, h })
}

/// Rectangle of desktop icon `index`, or `None` when it does not fit.
#[must_use]
pub fn icon_rect(width: usize, height: usize, index: usize) -> Option<Rect> {
    if index >= FILES.len() {
        return None;
    }
    let top = top_bar_height(height);
    let bottom = height.saturating_sub(taskbar_height(height));

    // The grid starts to the right of the card column so the two never overlap,
    // which is a property the tests assert rather than something eyeballed.
    let cards_right = card_rect(width, height, 0).map_or(width / 4, |r| r.right());
    let left = cards_right + 40;
    let cell_w = 116;
    let cell_h = 92;
    let gap = 16;

    let column = index % ICON_COLUMNS;
    let row = index / ICON_COLUMNS;
    let x = left + column * (cell_w + gap);
    let y = top + 28 + row * (cell_h + gap);

    if x + cell_w > width || y + cell_h > bottom {
        return None;
    }
    Some(Rect {
        x,
        y,
        w: cell_w,
        h: cell_h,
    })
}

/// The "back" control on a detail screen.
#[must_use]
pub fn back_rect(width: usize, height: usize) -> Rect {
    let panel = detail_panel(width, height);
    let w = 200.min(panel.w);
    Rect {
        x: panel.x + (panel.w - w) / 2,
        y: panel.bottom().saturating_sub(72),
        w,
        h: 44,
    }
}

/// The panel that detail screens are drawn inside.
#[must_use]
pub fn detail_panel(width: usize, height: usize) -> Rect {
    Rect {
        x: width / 10,
        y: height / 6,
        w: width * 4 / 5,
        h: height * 2 / 3,
    }
}

/// Hit test for the given view. Returns the first target under the cursor.
#[must_use]
pub fn hit_test(view: View, width: usize, height: usize, x: usize, y: usize) -> Option<Target> {
    match view {
        View::Desktop => {
            for index in 0..APPS.len() {
                if card_rect(width, height, index).is_some_and(|r| r.contains(x, y)) {
                    return Some(Target::Card(index));
                }
            }
            for index in 0..FILES.len() {
                if icon_rect(width, height, index).is_some_and(|r| r.contains(x, y)) {
                    return Some(Target::Icon(index));
                }
            }
            None
        }
        View::App(_) | View::File(_) => back_rect(width, height)
            .contains(x, y)
            .then_some(Target::Back),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Screen sizes the preview can realistically be handed: the OVMF default,
    /// the mode the demo prefers, and a deliberately cramped one.
    const SIZES: [(usize, usize); 5] = [
        (800, 600),
        (1024, 768),
        (1280, 800),
        (1152, 864),
        (640, 480),
    ];

    #[test]
    fn every_app_and_file_is_fully_described() {
        for app in APPS {
            assert!(!app.name.is_empty());
            assert!(!app.tagline.is_empty());
            assert!(!app.rows.is_empty(), "{} has no rows", app.name);
        }
        for file in FILES {
            assert!(!file.name.is_empty());
            assert!(!file.origin.is_empty(), "{} has no origin", file.name);
            assert!(!file.note.is_empty(), "{} has no note", file.name);
        }
    }

    #[test]
    fn app_rows_name_their_real_state() {
        // Every row must resolve to a state string. A row whose state is blank
        // reads on screen as an unqualified claim that the feature works.
        for app in APPS {
            for (label, state) in app.rows {
                assert!(!label.is_empty(), "{} has an unlabelled row", app.name);
                assert!(!state.is_empty(), "{} / {label} has no state", app.name);
            }
        }
    }

    #[test]
    fn the_desktop_advertises_no_component_the_preview_cannot_reach() {
        // The preview has no network stack. If a NETWORK row ever claims to be
        // connected, this catches it before a user believes it.
        let network = APPS.iter().find(|a| a.name == "NETWORK").unwrap();
        assert!(network
            .rows
            .iter()
            .any(|(label, state)| *label == "NETWORK STACK" && *state == "NOT IMPLEMENTED"));
    }

    #[test]
    fn cards_never_overlap_each_other() {
        for (w, h) in SIZES {
            let rects: Vec<Rect> = (0..APPS.len()).filter_map(|i| card_rect(w, h, i)).collect();
            for pair in rects.windows(2) {
                assert!(
                    pair[0].bottom() <= pair[1].y,
                    "{w}x{h}: {:?} overlaps {:?}",
                    pair[0],
                    pair[1]
                );
            }
        }
    }

    #[test]
    fn icons_never_overlap_the_card_column() {
        for (w, h) in SIZES {
            let Some(card) = card_rect(w, h, 0) else {
                continue;
            };
            for index in 0..FILES.len() {
                if let Some(icon) = icon_rect(w, h, index) {
                    assert!(
                        icon.x >= card.right(),
                        "{w}x{h}: icon {index} {icon:?} runs into the cards"
                    );
                }
            }
        }
    }

    #[test]
    fn nothing_is_drawn_under_the_bars() {
        for (w, h) in SIZES {
            let top = top_bar_height(h);
            let bottom = h - taskbar_height(h);
            for index in 0..APPS.len() {
                if let Some(r) = card_rect(w, h, index) {
                    assert!(r.y >= top && r.bottom() <= bottom, "{w}x{h}: card {index}");
                }
            }
            for index in 0..FILES.len() {
                if let Some(r) = icon_rect(w, h, index) {
                    assert!(r.y >= top && r.bottom() <= bottom, "{w}x{h}: icon {index}");
                    assert!(r.right() <= w, "{w}x{h}: icon {index} off the right edge");
                }
            }
        }
    }

    #[test]
    fn hit_testing_agrees_with_the_drawn_geometry() {
        // The bug this guards: highlight and click resolving to different items.
        for (w, h) in SIZES {
            for index in 0..APPS.len() {
                let Some(r) = card_rect(w, h, index) else {
                    continue;
                };
                let probes = [
                    (r.x, r.y),
                    (r.right() - 1, r.bottom() - 1),
                    (r.x + r.w / 2, r.y + r.h / 2),
                ];
                for (x, y) in probes {
                    assert_eq!(
                        hit_test(View::Desktop, w, h, x, y),
                        Some(Target::Card(index)),
                        "{w}x{h}: card {index} at {x},{y}"
                    );
                }
            }
            for index in 0..FILES.len() {
                let Some(r) = icon_rect(w, h, index) else {
                    continue;
                };
                assert_eq!(
                    hit_test(View::Desktop, w, h, r.x + r.w / 2, r.y + r.h / 2),
                    Some(Target::Icon(index)),
                    "{w}x{h}: icon {index}"
                );
            }
        }
    }

    #[test]
    fn empty_desktop_space_hits_nothing() {
        assert_eq!(hit_test(View::Desktop, 1024, 768, 1, 1), None);
    }

    #[test]
    fn detail_screens_only_expose_the_back_control() {
        let (w, h) = (1024, 768);
        let back = back_rect(w, h);
        assert_eq!(
            hit_test(View::App(0), w, h, back.x + back.w / 2, back.y + back.h / 2),
            Some(Target::Back)
        );
        assert_eq!(hit_test(View::App(0), w, h, 4, 4), None);
        assert_eq!(
            hit_test(View::File(0), w, h, back.x + 1, back.y + 1),
            Some(Target::Back)
        );
    }

    #[test]
    fn the_back_control_stays_inside_its_panel() {
        for (w, h) in SIZES {
            let panel = detail_panel(w, h);
            let back = back_rect(w, h);
            assert!(
                back.x >= panel.x && back.right() <= panel.right(),
                "{w}x{h}"
            );
            assert!(back.bottom() <= panel.bottom(), "{w}x{h}");
        }
    }

    #[test]
    fn selection_wraps_in_both_directions() {
        let mut shell = Shell::new();
        assert!(shell.move_selection(-1));
        assert_eq!(shell.card, APPS.len() - 1);
        assert!(shell.move_selection(1));
        assert_eq!(shell.card, 0);
    }

    #[test]
    fn focus_switches_which_group_the_arrows_drive() {
        let mut shell = Shell::new();
        shell.move_selection(1);
        assert_eq!(shell.card, 1);
        assert_eq!(shell.icon, 0, "the icon grid was not touched");

        shell.toggle_focus();
        shell.move_selection(1);
        assert_eq!(shell.icon, 1);
        assert_eq!(shell.card, 1, "the card selection was preserved");
    }

    #[test]
    fn opening_and_going_back_preserves_the_highlight() {
        let mut shell = Shell::new();
        shell.open(Target::Icon(4));
        assert_eq!(shell.view, View::File(4));
        assert_eq!(shell.focus, Focus::Icons);
        assert!(shell.back());
        assert_eq!(shell.view, View::Desktop);
        assert_eq!(shell.icon, 4, "returns to what was opened");
    }

    #[test]
    fn back_on_the_desktop_is_a_no_op() {
        let mut shell = Shell::new();
        assert!(!shell.back(), "no redraw should be requested");
        assert_eq!(shell.view, View::Desktop);
    }

    #[test]
    fn navigation_is_inert_while_a_detail_screen_is_open() {
        let mut shell = Shell::new();
        shell.open(Target::Card(1));
        assert!(!shell.move_selection(1));
        assert!(!shell.toggle_focus());
        assert!(!shell.open_selected());
        assert_eq!(shell.view, View::App(1), "still on the same screen");
    }

    #[test]
    fn out_of_range_targets_are_refused() {
        let mut shell = Shell::new();
        assert!(!shell.open(Target::Card(APPS.len())));
        assert!(!shell.open(Target::Icon(FILES.len())));
        assert_eq!(shell.view, View::Desktop);
    }

    #[test]
    fn hovering_moves_the_highlight_but_only_on_the_desktop() {
        let mut shell = Shell::new();
        assert!(shell.hover(Some(Target::Card(2))));
        assert_eq!(shell.card, 2);
        assert!(!shell.hover(Some(Target::Card(2))), "no redundant redraw");
        assert!(shell.hover(Some(Target::Icon(1))));
        assert_eq!(shell.focus, Focus::Icons);

        shell.open_selected();
        assert!(!shell.hover(Some(Target::Card(0))));
    }

    #[test]
    fn hovering_empty_space_leaves_the_selection_alone() {
        let mut shell = Shell::new();
        shell.hover(Some(Target::Card(3)));
        assert!(!shell.hover(None));
        assert_eq!(shell.card, 3);
    }
}
