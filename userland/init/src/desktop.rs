//! Where things are on the desktop, and what a click on them means.
//!
//! No drawing and no syscalls, like `console.rs` and for the same reason: hit
//! testing is arithmetic, and arithmetic that decides what a click does is
//! worth testing without a machine. The session draws what this describes and
//! tells it where the pointer is.
//!
//! # What a click is
//!
//! A press, not a held button. The mouse reports its buttons in every movement
//! packet, so a driver that acts on "the button is down" acts on it sixty times
//! while somebody holds it. Only the edge — down now, up before — is a click.
//! That is what `Buttons::edge` is for, and forgetting it is the difference
//! between one context menu and a hundred.
//!
//! # Windows are furniture now, not fixtures
//!
//! Every window used to sit at a constant address, and three decisions were
//! built on that: the geometry was a `const fn`, windows were laid out so they
//! would not cover each other, and raising a covered window was the only answer
//! to overlap. All three were workarounds for the same missing thing.
//!
//! A window has a rectangle in this struct now. It can be dragged by its title
//! bar, minimised to the taskbar, maximised to fill the screen, and restored.
//! The layout constants are the *starting* positions and nothing more.

#![allow(dead_code)]

/// Icons on the desktop.
pub const ICON_COUNT: usize = 4;

/// What each icon is called.
pub const ICON_LABELS: [&[u8]; ICON_COUNT] = [b"FILES", b"ASSISTANT", b"SHELL", b"TASKS"];

/// Icon geometry. The session draws with these and so does the hit test, which
/// is the only way the two can agree.
pub const ICON_SIZE: u64 = 56;
pub const ICON_SPACING: u64 = 90;
pub const ICON_TOP: u64 = 40;
/// Distance from the left edge to the icons' left side. On the left, like every
/// desktop somebody has used: the right is where a window's controls are, and
/// icons there are icons under the mouse on the way to a close button.
pub const ICON_LEFT: u64 = 24;

/// The bar across the bottom, and the button at its left end.
pub const TASKBAR_HEIGHT: u64 = 40;
pub const START_WIDTH: u64 = 108;
/// One taskbar button per open window.
pub const TASK_BUTTON_WIDTH: u64 = 168;
pub const TASK_BUTTON_GAP: u64 = 4;

/// The start menu: where it sits relative to the button, and how big.
pub const START_ITEM_HEIGHT: u64 = 34;
pub const START_MENU_WIDTH: u64 = 240;

/// The title bar and the three boxes at its right end.
pub const TITLE_HEIGHT: u64 = 26;
pub const BUTTON_WIDTH: u64 = 30;
pub const BUTTON_HEIGHT: u64 = 20;
pub const BUTTON_INSET: u64 = 3;

/// One context menu entry.
pub const MENU_WIDTH: u64 = 200;
pub const MENU_ITEM_HEIGHT: u64 = 26;

/// The windows the session can show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Window {
    Shell,
    Devices,
    Tasks,
    Files,
    Assistant,
}

/// How many there are. Used to size every per-window array, so adding one to
/// the enum fails to compile rather than silently going unhandled.
pub const WINDOW_COUNT: usize = 5;

/// Every window, in a fixed order. Not a stacking order any more — that is in
/// `Desktop::order` and it changes.
pub const ALL_WINDOWS: [Window; WINDOW_COUNT] = [
    Window::Shell,
    Window::Devices,
    Window::Tasks,
    Window::Files,
    Window::Assistant,
];

impl Window {
    /// Where this window sits in the per-window arrays.
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::Shell => 0,
            Self::Devices => 1,
            Self::Tasks => 2,
            Self::Files => 3,
            Self::Assistant => 4,
        }
    }

    /// What the title bar says.
    #[must_use]
    pub const fn title(self) -> &'static [u8] {
        match self {
            Self::Shell => b"SHELL",
            Self::Devices => b"DEVICES",
            Self::Tasks => b"TASK MANAGER",
            Self::Files => b"FILES",
            Self::Assistant => b"ASSISTANT",
        }
    }

    /// A shorter name, for a taskbar button.
    #[must_use]
    pub const fn short(self) -> &'static [u8] {
        match self {
            Self::Shell => b"SHELL",
            Self::Devices => b"DEVICES",
            Self::Tasks => b"TASKS",
            Self::Files => b"FILES",
            Self::Assistant => b"ASSISTANT",
        }
    }

    /// Whether typing goes into this window.
    ///
    /// The two that take text are the two with a prompt in them. A keystroke
    /// with nowhere to go is better than one that goes somewhere invisible.
    #[must_use]
    pub const fn takes_text(self) -> bool {
        matches!(self, Self::Shell | Self::Assistant)
    }
}

/// A rectangle on the screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Rect {
    pub x: u64,
    pub y: u64,
    pub w: u64,
    pub h: u64,
}

impl Rect {
    #[must_use]
    pub const fn holds(&self, x: u64, y: u64) -> bool {
        x >= self.x && x < self.x + self.w && y >= self.y && y < self.y + self.h
    }
}

/// Where each window starts. Not where it stays — this is the layout somebody
/// finds on first opening it, and every one of them can be moved afterwards.
#[must_use]
pub const fn default_rect(window: Window) -> Rect {
    match window {
        Window::Devices => Rect {
            x: 200,
            y: 80,
            w: 520,
            h: 300,
        },
        Window::Tasks => Rect {
            x: 260,
            y: 120,
            w: 500,
            h: 300,
        },
        Window::Files => Rect {
            x: 150,
            y: 60,
            w: 520,
            h: 320,
        },
        // Wide enough for the longest line the assistant can say. Narrower and
        // the answers ran off the right edge, past the rectangle the redraw
        // clears — so the tails of old answers stayed on the desktop.
        Window::Assistant => Rect {
            x: 380,
            y: 300,
            w: 800,
            h: 340,
        },
        Window::Shell => Rect {
            x: 180,
            y: 380,
            w: 940,
            h: 340,
        },
    }
}

/// Which of a window's three title-bar buttons a point is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TitleButton {
    Minimise,
    Maximise,
    Close,
}

/// Where a title-bar button sits inside a window.
///
/// Right to left, closest first, in the order every desktop puts them: close on
/// the outside, then maximise, then minimise.
#[must_use]
pub const fn title_button_rect(rect: Rect, button: TitleButton) -> Rect {
    let from_right = match button {
        TitleButton::Close => 1,
        TitleButton::Maximise => 2,
        TitleButton::Minimise => 3,
    };
    Rect {
        x: rect.x + rect.w - from_right * (BUTTON_WIDTH + BUTTON_INSET),
        y: rect.y + (TITLE_HEIGHT - BUTTON_HEIGHT) / 2,
        w: BUTTON_WIDTH,
        h: BUTTON_HEIGHT,
    }
}

/// What the start menu offers, and what each entry opens.
pub const START_ITEMS: [&[u8]; 6] = [
    b"Files",
    b"Assistant",
    b"Shell",
    b"Task manager",
    b"Devices",
    b"Shut down",
];

/// Which window a start-menu entry opens, if it opens one.
#[must_use]
pub const fn start_window(index: usize) -> Option<Window> {
    match index {
        0 => Some(Window::Files),
        1 => Some(Window::Assistant),
        2 => Some(Window::Shell),
        3 => Some(Window::Tasks),
        4 => Some(Window::Devices),
        _ => None,
    }
}

/// What the desktop's own context menu offers.
///
/// Short, because everything else moved to the start menu where somebody would
/// look for it. A right-click menu that repeats the start menu is a second
/// place to keep the same list correct.
pub const MENU_ITEMS: [&[u8]; 3] = [b"New folder", b"Refresh", b"Task manager"];

/// Rows the FILES window shows, and where the first one starts.
///
/// The first row is the way out — `..` when somewhere other than the root. A
/// folder that can be entered and not left is a trap, and the way out belongs
/// in the list rather than in a gesture somebody has to already know.
pub const FILE_ROW_HEIGHT: u64 = 22;
pub const FILE_ROW_TOP: u64 = 40;

/// The task manager's column header, and the width of a row.
pub const TASK_HEADER: &[u8] = b"PID  STATE    DMA  DEVICES";
pub const TASK_ROW: usize = 26;

/// Formats one row of the task manager.
///
/// Here, with the header beside it, because the two are one thing: a row whose
/// columns do not line up under their headings is read as the wrong numbers
/// against the wrong names, and it looks like a rendering nicety rather than
/// like the mistake it is. The first version put the DMA count one place left
/// of its column and it read as ten times itself.
#[must_use]
pub fn task_row(pid: u64, state: &[u8], dma: u64, devices: u64) -> [u8; TASK_ROW] {
    let mut row = [b' '; TASK_ROW];
    write_number(&mut row[0..3], pid);
    for (slot, byte) in row[5..12].iter_mut().zip(state.iter()) {
        *slot = *byte;
    }
    write_number(&mut row[14..17], dma);
    write_number(&mut row[19..22], devices);
    row
}

/// Writes a number right-aligned into a field of digits.
///
/// Saturating rather than wrapping: a count too big for the field shows all
/// nines, which reads as "more than fits here" instead of as a small number.
pub fn write_number(field: &mut [u8], value: u64) {
    let mut left = value;
    for slot in field.iter_mut().rev() {
        *slot = b'0' + (left % 10) as u8;
        left /= 10;
    }
    if left > 0 {
        field.fill(b'9');
    }
}

/// What the session should do about a click.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Click {
    /// Nothing happened.
    None,
    /// This icon was selected.
    Select(usize),
    /// The desktop's context menu opened at this point.
    OpenMenu(u64, u64),
    /// A menu closed without a choice — the context menu or the start menu.
    CloseMenu,
    /// This context-menu entry was chosen.
    Menu(usize),
    /// This start-menu entry was chosen.
    Start(usize),
    /// The start menu opened.
    OpenStart,
    /// A window was opened or brought forward.
    Open(Window),
    /// A window was closed.
    Close(Window),
    /// A window was minimised to the taskbar.
    Minimise(Window),
    /// This row of the FILES window was clicked.
    File(usize),
    /// A window is being dragged. The session repaints and nothing else.
    Drag,
}

/// Which buttons are down, and which were down last time.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Buttons {
    pub left: bool,
    pub right: bool,
    previous_left: bool,
    previous_right: bool,
}

impl Buttons {
    /// Records the current state and reports which buttons were *just* pressed.
    ///
    /// The mouse repeats its button state in every movement packet, so acting
    /// on "down" acts on it for as long as somebody holds the button. Only the
    /// transition is a click.
    pub fn edge(&mut self, left: bool, right: bool) -> (bool, bool) {
        let pressed_left = left && !self.previous_left;
        let pressed_right = right && !self.previous_right;
        self.previous_left = left;
        self.previous_right = right;
        self.left = left;
        self.right = right;
        (pressed_left, pressed_right)
    }
}

/// A window being dragged, and where inside its title bar it was grabbed.
///
/// The offset is kept so the window does not jump its own corner to the pointer
/// on the first pixel of movement — it moves with the point that was grabbed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Drag {
    window: Window,
    hold_x: u64,
    hold_y: u64,
}

/// The desktop's interactive state.
#[derive(Debug, Clone, Copy)]
pub struct Desktop {
    /// Which icon is highlighted, if any.
    pub selected: Option<usize>,
    /// Where the context menu is, if it is open.
    pub menu: Option<(u64, u64)>,
    /// Whether the start menu is showing.
    pub start_open: bool,
    open: [bool; WINDOW_COUNT],
    minimised: [bool; WINDOW_COUNT],
    rects: [Rect; WINDOW_COUNT],
    /// Where a maximised window came from, so restoring puts it back rather
    /// than somewhere plausible.
    restore: [Rect; WINDOW_COUNT],
    maximised: [bool; WINDOW_COUNT],
    /// Stacking, back to front. Every window appears exactly once.
    order: [Window; WINDOW_COUNT],
    drag: Option<Drag>,
    /// Which folder the FILES window is showing. The root until somebody goes
    /// somewhere; back to the root when the window is closed, so opening it
    /// again does not land wherever it was left days ago with no way to tell.
    pub cwd: u16,
    /// Which window keystrokes go to. Set when a window is opened or clicked
    /// into, cleared when it closes — a window that keeps the keyboard after it
    /// is gone is where typing disappears to.
    pub focus: Option<Window>,
}

impl Default for Desktop {
    fn default() -> Self {
        Self::new()
    }
}

impl Desktop {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            selected: None,
            menu: None,
            start_open: false,
            open: [false; WINDOW_COUNT],
            minimised: [false; WINDOW_COUNT],
            rects: [
                default_rect(Window::Shell),
                default_rect(Window::Devices),
                default_rect(Window::Tasks),
                default_rect(Window::Files),
                default_rect(Window::Assistant),
            ],
            restore: [
                default_rect(Window::Shell),
                default_rect(Window::Devices),
                default_rect(Window::Tasks),
                default_rect(Window::Files),
                default_rect(Window::Assistant),
            ],
            maximised: [false; WINDOW_COUNT],
            order: ALL_WINDOWS,
            drag: None,
            cwd: 0,
            focus: None,
        }
    }

    /// Where a window is now.
    #[must_use]
    pub const fn rect(&self, window: Window) -> Rect {
        self.rects[window.index()]
    }

    /// Whether a window exists at all.
    #[must_use]
    pub const fn is_open(&self, window: Window) -> bool {
        self.open[window.index()]
    }

    /// Whether a window is minimised. Still open, still in the taskbar.
    #[must_use]
    pub const fn is_minimised(&self, window: Window) -> bool {
        self.minimised[window.index()]
    }

    /// Whether a window is on the screen: open and not minimised.
    #[must_use]
    pub const fn is_visible(&self, window: Window) -> bool {
        self.is_open(window) && !self.is_minimised(window)
    }

    #[must_use]
    pub const fn is_maximised(&self, window: Window) -> bool {
        self.maximised[window.index()]
    }

    /// The window on top, if any is.
    #[must_use]
    pub fn front(&self) -> Option<Window> {
        self.order
            .iter()
            .rev()
            .copied()
            .find(|window| self.is_visible(*window))
    }

    /// The stacking order, back to front. Every window, visible or not — the
    /// caller skips what it cannot see, and a window that is missing from this
    /// is a window that can never be drawn.
    #[must_use]
    pub const fn order(&self) -> [Window; WINDOW_COUNT] {
        self.order
    }

    /// Puts a window on top of the stack.
    fn raise(&mut self, window: Window) {
        let Some(at) = self.order.iter().position(|other| *other == window) else {
            return;
        };
        // Shift the rest down and put it last. A swap would put whatever was on
        // top into the middle of the stack, which reorders windows nobody
        // touched.
        for index in at..WINDOW_COUNT - 1 {
            self.order[index] = self.order[index + 1];
        }
        self.order[WINDOW_COUNT - 1] = window;
    }

    /// Opens a window, or brings it forward if it is already open.
    pub fn open(&mut self, window: Window) -> Click {
        self.open[window.index()] = true;
        self.minimised[window.index()] = false;
        self.raise(window);
        // Focus follows the window that takes text. Opening the task manager
        // while somebody is typing must not swallow the next key.
        if window.takes_text() {
            self.focus = Some(window);
        }
        self.start_open = false;
        Click::Open(window)
    }

    /// Closes a window.
    pub fn close(&mut self, window: Window) -> Click {
        self.open[window.index()] = false;
        self.minimised[window.index()] = false;
        if window == Window::Files {
            self.cwd = 0;
        }
        if self.focus == Some(window) {
            // Handed to whatever else is open and takes text, so that closing
            // one of two prompts does not leave the keyboard pointing at
            // nothing while a prompt is still on screen.
            self.focus =
                self.order.iter().rev().copied().find(|other| {
                    *other != window && self.is_visible(*other) && other.takes_text()
                });
        }
        Click::Close(window)
    }

    /// Hides a window without closing it.
    pub fn minimise(&mut self, window: Window) -> Click {
        self.minimised[window.index()] = true;
        if self.focus == Some(window) {
            self.focus =
                self.order.iter().rev().copied().find(|other| {
                    *other != window && self.is_visible(*other) && other.takes_text()
                });
        }
        Click::Minimise(window)
    }

    /// Fills the screen with a window, or puts it back where it was.
    ///
    /// The taskbar is not covered. A maximised window over the taskbar is a
    /// window with no way back to anything else.
    pub fn maximise(&mut self, window: Window, width: u64, height: u64) -> Click {
        let at = window.index();
        if self.maximised[at] {
            self.rects[at] = self.restore[at];
            self.maximised[at] = false;
        } else {
            self.restore[at] = self.rects[at];
            self.rects[at] = Rect {
                x: 0,
                y: 0,
                w: width,
                h: height.saturating_sub(TASKBAR_HEIGHT),
            };
            self.maximised[at] = true;
        }
        self.raise(window);
        Click::Open(window)
    }

    /// Where icon `index` sits.
    #[must_use]
    pub const fn icon_at(index: usize) -> (u64, u64) {
        (ICON_LEFT, ICON_TOP + index as u64 * ICON_SPACING)
    }

    /// Which icon is under a point, if any.
    #[must_use]
    pub fn icon_under(x: u64, y: u64) -> Option<usize> {
        for index in 0..ICON_COUNT {
            let (ix, iy) = Self::icon_at(index);
            if x >= ix && x < ix + ICON_SIZE && y >= iy && y < iy + ICON_SIZE {
                return Some(index);
            }
        }
        None
    }

    /// Which window an icon opens.
    #[must_use]
    pub const fn icon_window(index: usize) -> Option<Window> {
        match index {
            0 => Some(Window::Files),
            1 => Some(Window::Assistant),
            2 => Some(Window::Shell),
            3 => Some(Window::Tasks),
            _ => None,
        }
    }

    /// The start button.
    #[must_use]
    pub const fn start_button(height: u64) -> Rect {
        Rect {
            x: 0,
            y: height - TASKBAR_HEIGHT,
            w: START_WIDTH,
            h: TASKBAR_HEIGHT,
        }
    }

    /// Where the start menu sits when it is open.
    #[must_use]
    pub const fn start_menu_rect(height: u64) -> Rect {
        let tall = START_ITEM_HEIGHT * START_ITEMS.len() as u64 + 8;
        Rect {
            x: 0,
            y: height - TASKBAR_HEIGHT - tall,
            w: START_MENU_WIDTH,
            h: tall,
        }
    }

    /// Which start-menu entry a point is on.
    #[must_use]
    pub fn start_item_under(&self, x: u64, y: u64, height: u64) -> Option<usize> {
        if !self.start_open {
            return None;
        }
        let menu = Self::start_menu_rect(height);
        if !menu.holds(x, y) || y < menu.y + 4 {
            return None;
        }
        let index = ((y - menu.y - 4) / START_ITEM_HEIGHT) as usize;
        (index < START_ITEMS.len()).then_some(index)
    }

    /// The open windows, in taskbar order.
    ///
    /// Stacking order would move the buttons around whenever somebody clicked a
    /// window, which is a taskbar you cannot aim at. This is the fixed order
    /// instead, filtered to what is open.
    pub fn taskbar_windows(&self) -> impl Iterator<Item = Window> + '_ {
        ALL_WINDOWS.into_iter().filter(|w| self.is_open(*w))
    }

    /// Where the `index`-th taskbar button is.
    #[must_use]
    pub const fn taskbar_button(index: usize, height: u64) -> Rect {
        Rect {
            x: START_WIDTH + 6 + index as u64 * (TASK_BUTTON_WIDTH + TASK_BUTTON_GAP),
            y: height - TASKBAR_HEIGHT + 5,
            w: TASK_BUTTON_WIDTH,
            h: TASKBAR_HEIGHT - 10,
        }
    }

    /// Which window's taskbar button is under a point.
    #[must_use]
    pub fn taskbar_under(&self, x: u64, y: u64, height: u64) -> Option<Window> {
        self.taskbar_windows()
            .enumerate()
            .find(|(index, _)| Self::taskbar_button(*index, height).holds(x, y))
            .map(|(_, window)| window)
    }

    /// Which context-menu entry is under a point, if the menu is open there.
    #[must_use]
    pub fn menu_under(&self, x: u64, y: u64) -> Option<usize> {
        let (mx, my) = self.menu?;
        if x < mx || x >= mx + MENU_WIDTH || y < my {
            return None;
        }
        let index = ((y - my) / MENU_ITEM_HEIGHT) as usize;
        (index < MENU_ITEMS.len()).then_some(index)
    }

    /// Which row of the FILES window a point is on, if any.
    #[must_use]
    pub fn file_row_under(&self, y: u64, rows: usize) -> Option<usize> {
        let rect = self.rect(Window::Files);
        let top = rect.y + FILE_ROW_TOP;
        if y < top || y >= rect.y + rect.h - 12 {
            return None;
        }
        let row = ((y - top) / FILE_ROW_HEIGHT) as usize;
        (row < rows).then_some(row)
    }

    /// Handles a press at a point.
    ///
    /// `rows` is how many the FILES window shows, which the session knows and
    /// this does not — the table lives on the disk, and a file that reaches the
    /// disk is a file that cannot be tested without a machine.
    pub fn press(
        &mut self,
        x: u64,
        y: u64,
        right: bool,
        width: u64,
        height: u64,
        rows: usize,
    ) -> Click {
        // A menu is on top of everything while it is open, so a click anywhere
        // else closes it rather than reaching what is underneath.
        if self.start_open {
            if let Some(item) = self.start_item_under(x, y, height) {
                self.start_open = false;
                return Click::Start(item);
            }
            self.start_open = false;
            return Click::CloseMenu;
        }
        if self.menu.is_some() {
            if let Some(item) = self.menu_under(x, y) {
                self.menu = None;
                return Click::Menu(item);
            }
            self.menu = None;
            return Click::CloseMenu;
        }

        // The taskbar, before anything on the desktop: it is drawn over
        // everything, so it has to be clicked before everything.
        if y >= height.saturating_sub(TASKBAR_HEIGHT) {
            if Self::start_button(height).holds(x, y) {
                self.start_open = !right;
                return if self.start_open {
                    Click::OpenStart
                } else {
                    Click::CloseMenu
                };
            }
            if let Some(window) = self.taskbar_under(x, y, height) {
                // The button of the window already in front minimises it, the
                // way every taskbar behaves. Without it a taskbar button is a
                // control that does nothing once you have used it.
                if self.front() == Some(window) && !self.is_minimised(window) {
                    return self.minimise(window);
                }
                return self.open(window);
            }
            return Click::None;
        }

        if right {
            let height_needed = MENU_ITEM_HEIGHT * MENU_ITEMS.len() as u64;
            let mx = x.min(width.saturating_sub(MENU_WIDTH));
            let my = y.min(
                height
                    .saturating_sub(TASKBAR_HEIGHT)
                    .saturating_sub(height_needed),
            );
            self.menu = Some((mx, my));
            return Click::OpenMenu(mx, my);
        }

        // Windows, front to back, so a click finds the one on top.
        for window in self.order.into_iter().rev() {
            if !self.is_visible(window) {
                continue;
            }
            let rect = self.rect(window);
            if !rect.holds(x, y) {
                continue;
            }

            for button in [
                TitleButton::Close,
                TitleButton::Maximise,
                TitleButton::Minimise,
            ] {
                if title_button_rect(rect, button).holds(x, y) {
                    return match button {
                        TitleButton::Close => self.close(window),
                        TitleButton::Maximise => self.maximise(window, width, height),
                        TitleButton::Minimise => self.minimise(window),
                    };
                }
            }

            // The title bar drags. A maximised window does not, because there
            // is nowhere for it to go and dragging it would leave it the size
            // of the screen at an offset from it.
            if y < rect.y + TITLE_HEIGHT {
                let raised = self.front() != Some(window);
                self.open(window);
                if !self.is_maximised(window) {
                    self.drag = Some(Drag {
                        window,
                        hold_x: x - rect.x,
                        hold_y: y - rect.y,
                    });
                }
                return if raised {
                    Click::Open(window)
                } else {
                    Click::Drag
                };
            }

            // A click that raises a covered window does not also act inside it.
            // The window was covered, so whoever clicked could not read what
            // they were clicking on — treating the raise as a choice picks
            // something on their behalf out of what they had not seen.
            if self.front() != Some(window) {
                return self.open(window);
            }
            if window == Window::Files {
                if let Some(row) = self.file_row_under(y, rows) {
                    return Click::File(row);
                }
            }
            return self.open(window);
        }

        match Self::icon_under(x, y) {
            Some(index) => {
                self.selected = Some(index);
                match Self::icon_window(index) {
                    Some(window) => self.open(window),
                    None => Click::Select(index),
                }
            }
            None => {
                self.selected = None;
                Click::None
            }
        }
    }

    /// Moves a dragged window with the pointer.
    ///
    /// Clamped so the title bar always stays on the screen and above the
    /// taskbar. A window dragged out of reach cannot be dragged back, and there
    /// is no other way to move one.
    pub fn motion(&mut self, x: u64, y: u64, width: u64, height: u64) -> bool {
        let Some(drag) = self.drag else {
            return false;
        };
        let at = drag.window.index();
        let rect = self.rects[at];
        let max_x = width.saturating_sub(TITLE_HEIGHT);
        let max_y = height
            .saturating_sub(TASKBAR_HEIGHT)
            .saturating_sub(TITLE_HEIGHT);
        let new_x = x.saturating_sub(drag.hold_x).min(max_x);
        let new_y = y.saturating_sub(drag.hold_y).min(max_y);
        if new_x == rect.x && new_y == rect.y {
            return false;
        }
        self.rects[at].x = new_x;
        self.rects[at].y = new_y;
        true
    }

    /// Ends a drag. Called when the button comes up, whatever it was over.
    pub fn release(&mut self) {
        self.drag = None;
    }

    /// Whether a window is being dragged right now.
    #[must_use]
    pub const fn dragging(&self) -> bool {
        self.drag.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WIDTH: u64 = 1280;
    const HEIGHT: u64 = 800;

    fn icon_centre(index: usize) -> (u64, u64) {
        let (x, y) = Desktop::icon_at(index);
        (x + ICON_SIZE / 2, y + ICON_SIZE / 2)
    }

    #[test]
    fn nothing_is_open_when_the_session_starts() {
        // A desktop that begins covered in windows nobody asked for is a
        // screenshot of a desktop rather than a desktop.
        let desktop = Desktop::new();
        for window in ALL_WINDOWS {
            assert!(!desktop.is_open(window), "{window:?}");
        }
        assert_eq!(desktop.front(), None);
        assert_eq!(desktop.focus, None);
    }

    #[test]
    fn every_icon_opens_a_window() {
        for index in 0..ICON_COUNT {
            let window = Desktop::icon_window(index)
                .unwrap_or_else(|| panic!("icon {index} is a picture of nothing"));
            let mut desktop = Desktop::new();
            let (x, y) = icon_centre(index);
            assert_eq!(
                desktop.press(x, y, false, WIDTH, HEIGHT, 0),
                Click::Open(window)
            );
            assert!(desktop.is_open(window));
        }
    }

    #[test]
    fn every_icon_can_be_hit_and_the_gaps_between_them_cannot() {
        for index in 0..ICON_COUNT {
            let (x, y) = icon_centre(index);
            assert_eq!(Desktop::icon_under(x, y), Some(index));
        }
        let (_, first) = Desktop::icon_at(0);
        assert_eq!(Desktop::icon_under(ICON_LEFT, first + ICON_SIZE + 4), None);
        assert_eq!(Desktop::icon_under(ICON_LEFT + ICON_SIZE + 4, first), None);
    }

    #[test]
    fn every_window_has_its_own_slot() {
        // Two windows sharing an index is two windows that open and close
        // together, and nothing about the enum would show it.
        for (a, first) in ALL_WINDOWS.iter().enumerate() {
            for second in &ALL_WINDOWS[a + 1..] {
                assert_ne!(first.index(), second.index(), "{first:?} and {second:?}");
            }
            assert!(first.index() < WINDOW_COUNT);
        }
    }

    #[test]
    fn the_stack_holds_every_window_exactly_once() {
        // A window missing from the order can never be drawn; one appearing
        // twice is drawn underneath itself.
        let mut desktop = Desktop::new();
        for window in [Window::Shell, Window::Files, Window::Shell, Window::Tasks] {
            desktop.open(window);
            for check in ALL_WINDOWS {
                let times = desktop.order().iter().filter(|w| **w == check).count();
                assert_eq!(times, 1, "{check:?} appears {times} times");
            }
        }
    }

    #[test]
    fn opening_a_window_puts_it_on_top() {
        let mut desktop = Desktop::new();
        desktop.open(Window::Shell);
        desktop.open(Window::Files);
        assert_eq!(desktop.front(), Some(Window::Files));
        desktop.open(Window::Shell);
        assert_eq!(desktop.front(), Some(Window::Shell));
    }

    #[test]
    fn raising_a_window_does_not_reorder_the_others() {
        // A swap would drop whatever was on top into the middle of the stack,
        // reordering windows nobody touched.
        let mut desktop = Desktop::new();
        for window in [Window::Devices, Window::Tasks, Window::Files, Window::Shell] {
            desktop.open(window);
        }
        desktop.open(Window::Devices);
        let order = desktop.order();
        let position = |target: Window| order.iter().position(|w| *w == target).expect("in order");
        assert!(position(Window::Tasks) < position(Window::Files));
        assert!(position(Window::Files) < position(Window::Shell));
        assert_eq!(order[WINDOW_COUNT - 1], Window::Devices);
    }

    #[test]
    fn a_window_can_be_dragged_by_its_title_bar() {
        let mut desktop = Desktop::new();
        desktop.open(Window::Shell);
        let before = desktop.rect(Window::Shell);
        desktop.press(before.x + 40, before.y + 8, false, WIDTH, HEIGHT, 0);
        assert!(desktop.dragging());
        assert!(desktop.motion(before.x + 140, before.y + 58, WIDTH, HEIGHT));
        let after = desktop.rect(Window::Shell);
        assert_eq!((after.x, after.y), (before.x + 100, before.y + 50));
        assert_eq!((after.w, after.h), (before.w, before.h));
    }

    #[test]
    fn a_dragged_window_moves_with_the_point_that_was_grabbed() {
        // Without the offset the window jumps its own corner to the pointer on
        // the first pixel of movement.
        let mut desktop = Desktop::new();
        desktop.open(Window::Files);
        let before = desktop.rect(Window::Files);
        desktop.press(before.x + 200, before.y + 10, false, WIDTH, HEIGHT, 0);
        desktop.motion(before.x + 200, before.y + 10, WIDTH, HEIGHT);
        assert_eq!(desktop.rect(Window::Files), before, "it jumped");
    }

    #[test]
    fn a_window_cannot_be_dragged_off_the_screen() {
        // There is no other way to move a window, so one dragged out of reach
        // is one that cannot be brought back.
        let mut desktop = Desktop::new();
        desktop.open(Window::Shell);
        let start = desktop.rect(Window::Shell);
        desktop.press(start.x + 10, start.y + 8, false, WIDTH, HEIGHT, 0);
        desktop.motion(WIDTH * 2, HEIGHT * 2, WIDTH, HEIGHT);
        let rect = desktop.rect(Window::Shell);
        assert!(rect.x < WIDTH, "the title bar went off the right edge");
        assert!(
            rect.y + TITLE_HEIGHT <= HEIGHT - TASKBAR_HEIGHT,
            "the title bar went behind the taskbar"
        );
    }

    #[test]
    fn releasing_the_button_ends_the_drag() {
        let mut desktop = Desktop::new();
        desktop.open(Window::Shell);
        let rect = desktop.rect(Window::Shell);
        desktop.press(rect.x + 40, rect.y + 8, false, WIDTH, HEIGHT, 0);
        desktop.release();
        assert!(!desktop.dragging());
        assert!(!desktop.motion(900, 700, WIDTH, HEIGHT), "it kept moving");
    }

    #[test]
    fn clicking_the_body_of_a_window_does_not_drag_it() {
        let mut desktop = Desktop::new();
        desktop.open(Window::Shell);
        let rect = desktop.rect(Window::Shell);
        desktop.press(
            rect.x + 40,
            rect.y + TITLE_HEIGHT + 20,
            false,
            WIDTH,
            HEIGHT,
            0,
        );
        assert!(!desktop.dragging());
    }

    #[test]
    fn the_three_title_buttons_do_three_different_things() {
        for (button, expected) in [
            (TitleButton::Close, Click::Close(Window::Files)),
            (TitleButton::Minimise, Click::Minimise(Window::Files)),
            (TitleButton::Maximise, Click::Open(Window::Files)),
        ] {
            let mut desktop = Desktop::new();
            desktop.open(Window::Files);
            let rect = desktop.rect(Window::Files);
            let at = title_button_rect(rect, button);
            assert_eq!(
                desktop.press(at.x + 2, at.y + 2, false, WIDTH, HEIGHT, 0),
                expected,
                "{button:?}"
            );
        }
    }

    #[test]
    fn no_two_title_buttons_overlap() {
        // Overlapping buttons mean one of them can never be reached, and which
        // one depends on the order they are checked in.
        let rect = default_rect(Window::Shell);
        let all = [
            TitleButton::Minimise,
            TitleButton::Maximise,
            TitleButton::Close,
        ];
        for (index, button) in all.iter().enumerate() {
            let a = title_button_rect(rect, *button);
            assert!(a.x >= rect.x, "a button hangs off the left of its window");
            assert!(a.x + a.w <= rect.x + rect.w, "a button hangs off the right");
            assert!(
                a.y + a.h <= rect.y + TITLE_HEIGHT,
                "a button leaves the bar"
            );
            for other in &all[index + 1..] {
                let b = title_button_rect(rect, *other);
                assert!(
                    a.x + a.w <= b.x || b.x + b.w <= a.x,
                    "{button:?} overlaps {other:?}"
                );
            }
        }
    }

    #[test]
    fn a_minimised_window_is_still_open() {
        // It is off the screen, not gone: the taskbar has to keep showing it or
        // there is no way back to it.
        let mut desktop = Desktop::new();
        desktop.open(Window::Shell);
        desktop.minimise(Window::Shell);
        assert!(desktop.is_open(Window::Shell));
        assert!(!desktop.is_visible(Window::Shell));
        assert!(desktop.taskbar_windows().any(|w| w == Window::Shell));
    }

    #[test]
    fn a_minimised_window_cannot_be_clicked_where_it_used_to_be() {
        let mut desktop = Desktop::new();
        desktop.open(Window::Shell);
        let rect = desktop.rect(Window::Shell);
        desktop.minimise(Window::Shell);
        assert_eq!(
            desktop.press(rect.x + 40, rect.y + 40, false, WIDTH, HEIGHT, 0),
            Click::None
        );
    }

    #[test]
    fn the_taskbar_button_restores_a_minimised_window() {
        let mut desktop = Desktop::new();
        desktop.open(Window::Files);
        desktop.minimise(Window::Files);
        let at = Desktop::taskbar_button(0, HEIGHT);
        assert_eq!(
            desktop.press(at.x + 4, at.y + 4, false, WIDTH, HEIGHT, 0),
            Click::Open(Window::Files)
        );
        assert!(desktop.is_visible(Window::Files));
    }

    #[test]
    fn the_taskbar_button_of_the_front_window_minimises_it() {
        // Otherwise a taskbar button is a control that does nothing once you
        // have used it.
        let mut desktop = Desktop::new();
        desktop.open(Window::Files);
        let at = Desktop::taskbar_button(0, HEIGHT);
        assert_eq!(
            desktop.press(at.x + 4, at.y + 4, false, WIDTH, HEIGHT, 0),
            Click::Minimise(Window::Files)
        );
    }

    #[test]
    fn taskbar_buttons_do_not_move_when_windows_are_clicked() {
        // Stacking order would shuffle the buttons under the pointer, which is
        // a taskbar nobody can aim at.
        let mut desktop = Desktop::new();
        desktop.open(Window::Shell);
        desktop.open(Window::Files);
        let before: heapless::Vec<Window, WINDOW_COUNT> = desktop.taskbar_windows().collect();
        desktop.open(Window::Shell);
        let after: heapless::Vec<Window, WINDOW_COUNT> = desktop.taskbar_windows().collect();
        assert_eq!(before, after);
    }

    #[test]
    fn maximising_fills_the_screen_but_not_the_taskbar() {
        // A maximised window over the taskbar is a window with no way back to
        // anything else.
        let mut desktop = Desktop::new();
        desktop.open(Window::Shell);
        desktop.maximise(Window::Shell, WIDTH, HEIGHT);
        let rect = desktop.rect(Window::Shell);
        assert_eq!((rect.x, rect.y, rect.w), (0, 0, WIDTH));
        assert_eq!(rect.h, HEIGHT - TASKBAR_HEIGHT);
    }

    #[test]
    fn restoring_puts_a_window_back_where_it_was() {
        // Not somewhere plausible — where it was, including after a drag.
        let mut desktop = Desktop::new();
        desktop.open(Window::Files);
        let start = desktop.rect(Window::Files);
        desktop.press(start.x + 30, start.y + 8, false, WIDTH, HEIGHT, 0);
        desktop.motion(start.x + 130, start.y + 108, WIDTH, HEIGHT);
        desktop.release();
        let moved = desktop.rect(Window::Files);
        assert_ne!(moved, start);

        desktop.maximise(Window::Files, WIDTH, HEIGHT);
        desktop.maximise(Window::Files, WIDTH, HEIGHT);
        assert_eq!(desktop.rect(Window::Files), moved);
    }

    #[test]
    fn a_maximised_window_is_not_dragged() {
        // There is nowhere for it to go, and dragging it would leave it the
        // size of the screen at an offset from it.
        let mut desktop = Desktop::new();
        desktop.open(Window::Shell);
        desktop.maximise(Window::Shell, WIDTH, HEIGHT);
        desktop.press(200, 8, false, WIDTH, HEIGHT, 0);
        assert!(!desktop.dragging());
    }

    #[test]
    fn the_start_button_opens_and_closes_the_start_menu() {
        let mut desktop = Desktop::new();
        let button = Desktop::start_button(HEIGHT);
        assert_eq!(
            desktop.press(button.x + 10, button.y + 10, false, WIDTH, HEIGHT, 0),
            Click::OpenStart
        );
        assert!(desktop.start_open);
        assert_eq!(
            desktop.press(button.x + 10, button.y + 10, false, WIDTH, HEIGHT, 0),
            Click::CloseMenu
        );
        assert!(!desktop.start_open);
    }

    #[test]
    fn every_start_entry_is_reachable_and_distinct() {
        let mut desktop = Desktop::new();
        desktop.start_open = true;
        let menu = Desktop::start_menu_rect(HEIGHT);
        for index in 0..START_ITEMS.len() {
            let y = menu.y + 4 + index as u64 * START_ITEM_HEIGHT + START_ITEM_HEIGHT / 2;
            assert_eq!(
                desktop.start_item_under(menu.x + 10, y, HEIGHT),
                Some(index),
                "entry {index}"
            );
        }
        for a in 0..START_ITEMS.len() {
            for b in a + 1..START_ITEMS.len() {
                if let (Some(x), Some(y)) = (start_window(a), start_window(b)) {
                    assert_ne!(x, y, "two entries open the same window");
                }
            }
        }
    }

    #[test]
    fn every_window_can_be_reached_from_the_start_menu() {
        // A window that can only be opened by an icon is a window somebody who
        // covered the icons cannot open.
        for window in ALL_WINDOWS {
            assert!(
                (0..START_ITEMS.len()).any(|index| start_window(index) == Some(window)),
                "{window:?} is not in the start menu"
            );
        }
    }

    #[test]
    fn the_start_menu_sits_above_the_taskbar() {
        let menu = Desktop::start_menu_rect(HEIGHT);
        assert_eq!(menu.y + menu.h, HEIGHT - TASKBAR_HEIGHT);
        assert!(menu.y < HEIGHT - TASKBAR_HEIGHT, "the menu has no height");
    }

    #[test]
    fn a_start_entry_opens_its_window_and_closes_the_menu() {
        let mut desktop = Desktop::new();
        desktop.start_open = true;
        let menu = Desktop::start_menu_rect(HEIGHT);
        let click = desktop.press(menu.x + 10, menu.y + 4 + 8, false, WIDTH, HEIGHT, 0);
        assert_eq!(click, Click::Start(0));
        assert!(!desktop.start_open);
    }

    #[test]
    fn clicking_away_from_the_start_menu_closes_it_without_choosing() {
        // And does not reach whatever was underneath.
        let mut desktop = Desktop::new();
        desktop.open(Window::Shell);
        desktop.start_open = true;
        let rect = desktop.rect(Window::Shell);
        assert_eq!(
            desktop.press(rect.x + 40, rect.y + 40, false, WIDTH, HEIGHT, 0),
            Click::CloseMenu
        );
        assert!(!desktop.start_open);
    }

    #[test]
    fn right_clicking_opens_a_menu_that_stays_on_screen() {
        let mut desktop = Desktop::new();
        let click = desktop.press(
            WIDTH - 5,
            HEIGHT - TASKBAR_HEIGHT - 5,
            true,
            WIDTH,
            HEIGHT,
            0,
        );
        let Click::OpenMenu(mx, my) = click else {
            panic!("no menu");
        };
        assert!(mx + MENU_WIDTH <= WIDTH);
        assert!(my + MENU_ITEM_HEIGHT * MENU_ITEMS.len() as u64 <= HEIGHT - TASKBAR_HEIGHT);
    }

    #[test]
    fn a_menu_entry_is_chosen_and_the_menu_closes() {
        let mut desktop = Desktop::new();
        desktop.press(400, 300, true, WIDTH, HEIGHT, 0);
        let click = desktop.press(410, 300 + MENU_ITEM_HEIGHT + 5, false, WIDTH, HEIGHT, 0);
        assert_eq!(click, Click::Menu(1));
        assert!(desktop.menu.is_none());
    }

    #[test]
    fn a_click_away_from_the_menu_closes_it_rather_than_reaching_through() {
        let mut desktop = Desktop::new();
        desktop.press(400, 300, true, WIDTH, HEIGHT, 0);
        let (x, y) = icon_centre(0);
        assert_eq!(
            desktop.press(x, y, false, WIDTH, HEIGHT, 0),
            Click::CloseMenu
        );
        assert!(!desktop.is_open(Window::Files), "the click reached through");
    }

    #[test]
    fn every_menu_entry_is_reachable() {
        let mut desktop = Desktop::new();
        for index in 0..MENU_ITEMS.len() {
            desktop.press(300, 200, true, WIDTH, HEIGHT, 0);
            let y = 200 + index as u64 * MENU_ITEM_HEIGHT + MENU_ITEM_HEIGHT / 2;
            assert_eq!(
                desktop.press(310, y, false, WIDTH, HEIGHT, 0),
                Click::Menu(index)
            );
        }
    }

    #[test]
    fn every_icon_has_a_label_and_every_entry_has_text() {
        for label in ICON_LABELS {
            assert!(!label.is_empty());
        }
        for item in MENU_ITEMS {
            assert!(!item.is_empty());
        }
        for item in START_ITEMS {
            assert!(!item.is_empty());
        }
    }

    #[test]
    fn a_click_that_raises_a_window_does_not_also_choose_inside_it() {
        let mut desktop = Desktop::new();
        desktop.open(Window::Files);
        desktop.open(Window::Shell);
        let rect = desktop.rect(Window::Files);
        // Somewhere in FILES that the shell does not cover.
        let at = rect.y + FILE_ROW_TOP + 4;
        let x = rect.x + 40;
        if desktop.rect(Window::Shell).holds(x, at) {
            return;
        }
        assert_eq!(
            desktop.press(x, at, false, WIDTH, HEIGHT, 4),
            Click::Open(Window::Files)
        );
        assert_eq!(
            desktop.press(x, at, false, WIDTH, HEIGHT, 4),
            Click::File(0)
        );
    }

    #[test]
    fn each_row_of_the_files_window_is_its_own() {
        // Off-by-one here opens the name above or below the one that was
        // clicked, which looks like the filesystem being wrong.
        let desktop = Desktop::new();
        let rect = desktop.rect(Window::Files);
        for row in 0..5usize {
            let top = rect.y + FILE_ROW_TOP + row as u64 * FILE_ROW_HEIGHT;
            assert_eq!(desktop.file_row_under(top, 5), Some(row));
            assert_eq!(
                desktop.file_row_under(top + FILE_ROW_HEIGHT - 1, 5),
                Some(row)
            );
        }
    }

    #[test]
    fn the_rows_move_with_the_window() {
        // The listing is drawn from the live rectangle, so the hit test has to
        // read the same one. A dragged window whose rows stayed behind would
        // open the wrong name, or nothing.
        let mut desktop = Desktop::new();
        desktop.open(Window::Files);
        let start = desktop.rect(Window::Files);
        desktop.press(start.x + 30, start.y + 8, false, WIDTH, HEIGHT, 0);
        desktop.motion(start.x + 130, start.y + 68, WIDTH, HEIGHT);
        let moved = desktop.rect(Window::Files);
        assert_eq!(desktop.file_row_under(moved.y + FILE_ROW_TOP, 3), Some(0));
        assert_eq!(desktop.file_row_under(start.y + FILE_ROW_TOP, 3), None);
    }

    #[test]
    fn a_click_below_the_last_row_is_not_a_row() {
        let desktop = Desktop::new();
        let rect = desktop.rect(Window::Files);
        let below = rect.y + FILE_ROW_TOP + 2 * FILE_ROW_HEIGHT;
        assert_eq!(desktop.file_row_under(below, 2), None);
        assert_eq!(
            desktop.file_row_under(rect.y, 5),
            None,
            "the title bar is not a row"
        );
    }

    #[test]
    fn typing_goes_to_the_window_that_was_opened_last() {
        let mut desktop = Desktop::new();
        desktop.open(Window::Shell);
        assert_eq!(desktop.focus, Some(Window::Shell));
        desktop.open(Window::Assistant);
        assert_eq!(desktop.focus, Some(Window::Assistant));
    }

    #[test]
    fn a_window_that_takes_no_text_does_not_take_the_keyboard() {
        let mut desktop = Desktop::new();
        desktop.open(Window::Shell);
        desktop.open(Window::Tasks);
        assert_eq!(desktop.focus, Some(Window::Shell));
    }

    #[test]
    fn closing_or_minimising_the_focused_window_hands_the_keyboard_on() {
        // Keystrokes landing nowhere while a prompt is still on screen is the
        // worst of the three outcomes.
        let mut desktop = Desktop::new();
        desktop.open(Window::Shell);
        desktop.open(Window::Assistant);
        desktop.minimise(Window::Assistant);
        assert_eq!(desktop.focus, Some(Window::Shell));
        desktop.open(Window::Assistant);
        desktop.close(Window::Assistant);
        assert_eq!(desktop.focus, Some(Window::Shell));
        desktop.close(Window::Shell);
        assert_eq!(desktop.focus, None);
    }

    #[test]
    fn only_windows_with_a_prompt_take_text() {
        for window in ALL_WINDOWS {
            let expected = matches!(window, Window::Shell | Window::Assistant);
            assert_eq!(window.takes_text(), expected, "{window:?}");
        }
    }

    #[test]
    fn a_window_starts_on_the_screen_and_above_the_taskbar() {
        // The starting layout is the one somebody who has never dragged a
        // window sees, so it has to be usable without dragging one.
        for window in ALL_WINDOWS {
            let rect = default_rect(window);
            assert!(rect.x + rect.w <= WIDTH, "{window:?} starts off the right");
            assert!(
                rect.y + rect.h <= HEIGHT - TASKBAR_HEIGHT,
                "{window:?} starts under the taskbar"
            );
            assert!(rect.h > TITLE_HEIGHT, "{window:?} is all title bar");
        }
    }

    #[test]
    fn no_window_starts_on_top_of_the_icons() {
        // They are what a desktop with nothing open is for.
        let (_, last) = Desktop::icon_at(ICON_COUNT - 1);
        for window in ALL_WINDOWS {
            let rect = default_rect(window);
            assert!(
                rect.x >= ICON_LEFT + ICON_SIZE,
                "{window:?} starts over the icon column"
            );
        }
        assert!(
            last + ICON_SIZE < HEIGHT - TASKBAR_HEIGHT,
            "an icon is behind the taskbar"
        );
    }
}
