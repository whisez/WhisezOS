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

#![allow(dead_code)]

/// Icons on the desktop.
pub const ICON_COUNT: usize = 4;

/// What each icon is called and what opening it does.
pub const ICON_LABELS: [&[u8]; ICON_COUNT] = [b"FILES", b"ASSISTANT", b"SHELL", b"TASKS"];

/// Icon geometry. The session draws with these and so does the hit test, which
/// is the only way the two can agree.
pub const ICON_SIZE: u64 = 56;
pub const ICON_SPACING: u64 = 90;
pub const ICON_TOP: u64 = 52;
/// Distance from the right edge to the icons' left side.
pub const ICON_RIGHT_MARGIN: u64 = 140;

/// One context menu entry.
pub const MENU_WIDTH: u64 = 190;
pub const MENU_ITEM_HEIGHT: u64 = 26;

/// The two windows the session can show. Neither is open at startup: a desktop
/// that begins covered in windows nobody asked for is not a desktop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Window {
    Shell,
    Devices,
    Tasks,
    Files,
    Assistant,
}

impl Window {
    /// Whether typing goes into this window.
    ///
    /// The two that take text are the two with a prompt in them. A keystroke
    /// with nowhere to go is better than one that goes somewhere invisible.
    #[must_use]
    pub const fn takes_text(self) -> bool {
        matches!(self, Self::Shell | Self::Assistant)
    }
}

/// Every window, front to back. The order is the order a click finds them, so
/// it is the order they are drawn in reverse.
pub const ALL_WINDOWS: [Window; 5] = [
    Window::Assistant,
    Window::Shell,
    Window::Tasks,
    Window::Files,
    Window::Devices,
];

/// How tall the bar across the bottom is.
pub const TASKBAR_HEIGHT: u64 = 34;

/// The title bar, and the box at its right end that closes the window.
pub const TITLE_HEIGHT: u64 = 24;
pub const CLOSE_SIZE: u64 = 16;
pub const CLOSE_INSET: u64 = 8;

/// Where each window sits. Here rather than beside the drawing code for the
/// same reason the icon geometry is: a close box that is drawn in one place and
/// hit-tested from another is a close box that stops closing the window, and
/// the way it stops is that clicking it does nothing at all.
#[must_use]
pub const fn bounds(window: Window) -> (u64, u64, u64, u64) {
    match window {
        Window::Devices => (80, 90, 520, 300),
        // Stops short of the icon column. A window that covers the icons is a
        // window that has to be moved before anything else can be opened, and
        // nothing here can be moved.
        Window::Tasks => (620, 90, 480, 300),
        // Where DEVICES sits, one step down and across. They overlap, which is
        // what windows do; what they must not do is share a close box.
        Window::Files => (110, 130, 520, 300),
        // Wide enough for the longest line the assistant can say. Narrower and
        // the answers ran off the right edge, past the rectangle the redraw
        // clears — so the tails of old answers stayed on the desktop.
        Window::Assistant => (400, 420, 800, 340),
        Window::Shell => (80, 430, 1120, 330),
    }
}

/// The top-left corner of a window's close box.
#[must_use]
pub const fn close_at(window: Window) -> (u64, u64) {
    let (x, y, w, _) = bounds(window);
    (
        x + w - CLOSE_SIZE - CLOSE_INSET,
        y + (TITLE_HEIGHT - CLOSE_SIZE) / 2,
    )
}

/// Whether a point is on a window's close box.
#[must_use]
pub const fn on_close(window: Window, x: u64, y: u64) -> bool {
    let (cx, cy) = close_at(window);
    x >= cx && x < cx + CLOSE_SIZE && y >= cy && y < cy + CLOSE_SIZE
}

/// What the menu offers.
///
/// Every one of these does something. The first version opened with "Open
/// shell", which answered "the shell is already open below" — an entry that
/// exists to be clicked once and then never again. A menu whose items are
/// greyed out, or say something instead of doing something, is worse than no
/// menu: it tells somebody the system can do things it cannot.
pub const MENU_ITEMS: [&[u8]; 7] = [
    b"New folder",
    b"Open files",
    b"Open shell",
    b"Open assistant",
    b"Show devices",
    b"Task manager",
    b"Shut down",
];

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
    /// The menu opened at this point.
    OpenMenu(u64, u64),
    /// The menu closed without a choice.
    CloseMenu,
    /// This menu entry was chosen.
    Menu(usize),
    /// A window was opened or brought forward.
    Open(Window),
    /// A window was closed.
    Close(Window),
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

/// The desktop's interactive state.
#[derive(Debug, Clone, Copy, Default)]
pub struct Desktop {
    /// Which icon is highlighted, if any.
    pub selected: Option<usize>,
    /// Where the context menu is, if it is open.
    pub menu: Option<(u64, u64)>,
    pub shell_open: bool,
    pub devices_open: bool,
    pub tasks_open: bool,
    pub files_open: bool,
    pub assistant_open: bool,
    /// Which window keystrokes go to. Set when a window is opened or clicked
    /// into, cleared when it closes — a window that keeps the keyboard after it
    /// is gone is where typing disappears to.
    pub focus: Option<Window>,
}

impl Desktop {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            selected: None,
            menu: None,
            shell_open: false,
            devices_open: false,
            tasks_open: false,
            files_open: false,
            assistant_open: false,
            focus: None,
        }
    }

    /// Whether a window is showing.
    #[must_use]
    pub const fn is_open(&self, window: Window) -> bool {
        match window {
            Window::Shell => self.shell_open,
            Window::Devices => self.devices_open,
            Window::Tasks => self.tasks_open,
            Window::Files => self.files_open,
            Window::Assistant => self.assistant_open,
        }
    }

    /// Opens a window, or brings it forward if it is already open.
    pub fn open(&mut self, window: Window) -> Click {
        match window {
            Window::Shell => self.shell_open = true,
            Window::Devices => self.devices_open = true,
            Window::Tasks => self.tasks_open = true,
            Window::Files => self.files_open = true,
            Window::Assistant => self.assistant_open = true,
        }
        if window.takes_text() {
            self.focus = Some(window);
        }
        Click::Open(window)
    }

    /// Closes a window.
    pub fn close(&mut self, window: Window) -> Click {
        match window {
            Window::Shell => self.shell_open = false,
            Window::Devices => self.devices_open = false,
            Window::Tasks => self.tasks_open = false,
            Window::Files => self.files_open = false,
            Window::Assistant => self.assistant_open = false,
        }
        if self.focus == Some(window) {
            // Handed to whatever else is open and takes text, so that closing
            // one of two prompts does not leave the keyboard pointing at
            // nothing while a prompt is still on screen.
            self.focus = [Window::Shell, Window::Assistant]
                .into_iter()
                .find(|other| *other != window && self.is_open(*other));
        }
        Click::Close(window)
    }

    /// Which window a menu entry opens, if it opens one.
    ///
    /// Beside the labels, so the test below can hold the two against each
    /// other. An entry whose words promise a window and whose action opens
    /// nothing is the failure this whole menu started with.
    #[must_use]
    pub const fn menu_window(index: usize) -> Option<Window> {
        match index {
            1 => Some(Window::Files),
            2 => Some(Window::Shell),
            3 => Some(Window::Assistant),
            4 => Some(Window::Devices),
            5 => Some(Window::Tasks),
            _ => None,
        }
    }

    /// Which window an icon opens, if it opens one.
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

    /// Where icon `index` sits, given the screen width.
    #[must_use]
    pub fn icon_at(index: usize, width: u64) -> (u64, u64) {
        (
            width.saturating_sub(ICON_RIGHT_MARGIN),
            ICON_TOP + index as u64 * ICON_SPACING,
        )
    }

    /// Which icon is under a point, if any.
    #[must_use]
    pub fn icon_under(x: u64, y: u64, width: u64) -> Option<usize> {
        for index in 0..ICON_COUNT {
            let (ix, iy) = Self::icon_at(index, width);
            if x >= ix && x < ix + ICON_SIZE && y >= iy && y < iy + ICON_SIZE {
                return Some(index);
            }
        }
        None
    }

    /// Which menu entry is under a point, if the menu is open there.
    #[must_use]
    pub fn menu_under(&self, x: u64, y: u64) -> Option<usize> {
        let (mx, my) = self.menu?;
        if x < mx || x >= mx + MENU_WIDTH {
            return None;
        }
        if y < my {
            return None;
        }
        let index = ((y - my) / MENU_ITEM_HEIGHT) as usize;
        (index < MENU_ITEMS.len()).then_some(index)
    }

    /// Handles a press at a point. `width` and `height` are the screen's.
    pub fn press(&mut self, x: u64, y: u64, right: bool, width: u64, height: u64) -> Click {
        // The menu is checked first and always: while it is open it is on top
        // of everything, so a click anywhere else closes it rather than
        // reaching what is underneath. Anything else lets somebody select an
        // icon through an open menu.
        if self.menu.is_some() {
            if let Some(item) = self.menu_under(x, y) {
                self.menu = None;
                return Click::Menu(item);
            }
            self.menu = None;
            return Click::CloseMenu;
        }

        if right {
            // Placed so it stays on screen. A menu that opens off the bottom
            // edge is a menu whose last entry cannot be reached.
            let height_needed = MENU_ITEM_HEIGHT * MENU_ITEMS.len() as u64;
            let mx = x.min(width.saturating_sub(MENU_WIDTH));
            let my = y.min(height.saturating_sub(height_needed));
            self.menu = Some((mx, my));
            return Click::OpenMenu(mx, my);
        }

        // A window is above the desktop, so its close box is checked before
        // anything underneath. Shell first: it is drawn last and so is on top.
        for window in ALL_WINDOWS {
            if self.is_open(window) && on_close(window, x, y) {
                return self.close(window);
            }
        }

        match Self::icon_under(x, y, width) {
            Some(index) => {
                self.selected = Some(index);
                // An icon opens what it names. Selecting and then needing a
                // second gesture to open would be right if there were a
                // keyboard focus model to select *for*, and there is not.
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
}

#[cfg(test)]
mod tests {
    use super::*;

    const WIDTH: u64 = 1280;
    const HEIGHT: u64 = 800;

    fn icon_centre(index: usize) -> (u64, u64) {
        let (x, y) = Desktop::icon_at(index, WIDTH);
        (x + ICON_SIZE / 2, y + ICON_SIZE / 2)
    }

    #[test]
    fn a_button_held_down_is_one_click_and_not_many() {
        // The mouse repeats its button state in every movement packet. Acting
        // on "down" rather than on the transition opens a hundred menus while
        // somebody holds the button.
        let mut buttons = Buttons::default();
        assert_eq!(buttons.edge(true, false), (true, false));
        for _ in 0..60 {
            assert_eq!(buttons.edge(true, false), (false, false));
        }
        assert_eq!(buttons.edge(false, false), (false, false));
        assert_eq!(buttons.edge(true, false), (true, false));
    }

    #[test]
    fn the_two_buttons_are_tracked_separately() {
        let mut buttons = Buttons::default();
        assert_eq!(buttons.edge(true, true), (true, true));
        assert_eq!(buttons.edge(true, false), (false, false));
        assert_eq!(buttons.edge(true, true), (false, true));
    }

    #[test]
    fn clicking_an_icon_that_names_a_window_opens_it() {
        let mut desktop = Desktop::new();
        assert!(!desktop.shell_open);
        let (x, y) = icon_centre(2);
        assert_eq!(
            desktop.press(x, y, false, WIDTH, HEIGHT),
            Click::Open(Window::Shell)
        );
        assert!(desktop.shell_open);
        assert_eq!(desktop.selected, Some(2));
    }

    #[test]
    fn every_icon_opens_a_window() {
        // This replaces a test that checked the opposite: that an icon naming
        // no window merely highlights. That was right while two icons named
        // nothing, and the rule it protected — an icon must not pretend to open
        // something — is better served now by there being nothing left to
        // pretend about. An icon on this desktop opens something or it should
        // not be on this desktop.
        for index in 0..ICON_COUNT {
            let window = Desktop::icon_window(index)
                .unwrap_or_else(|| panic!("icon {index} is a picture of nothing"));
            let mut desktop = Desktop::new();
            let (x, y) = icon_centre(index);
            assert_eq!(
                desktop.press(x, y, false, WIDTH, HEIGHT),
                Click::Open(window)
            );
            assert!(desktop.is_open(window));
            assert_eq!(desktop.selected, Some(index));
        }
    }

    #[test]
    fn typing_goes_to_the_window_that_was_opened_last() {
        let mut desktop = Desktop::new();
        assert_eq!(desktop.focus, None, "the keyboard points somewhere at rest");
        desktop.open(Window::Shell);
        assert_eq!(desktop.focus, Some(Window::Shell));
        desktop.open(Window::Assistant);
        assert_eq!(desktop.focus, Some(Window::Assistant));
    }

    #[test]
    fn a_window_that_takes_no_text_does_not_take_the_keyboard() {
        // Opening the task manager while typing must not swallow the next key.
        let mut desktop = Desktop::new();
        desktop.open(Window::Shell);
        desktop.open(Window::Tasks);
        assert_eq!(desktop.focus, Some(Window::Shell));
    }

    #[test]
    fn closing_the_focused_window_hands_the_keyboard_on() {
        // And not to nothing, while a prompt is still on screen: keystrokes
        // that land nowhere while something asks for them is the worst of the
        // three outcomes.
        let mut desktop = Desktop::new();
        desktop.open(Window::Shell);
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
    fn every_task_column_starts_under_its_heading() {
        // The check the first version needed and did not have: find each
        // heading in the header, and insist the digits begin at the same place.
        let row = task_row(7, b"RUNNING", 6, 3);
        let header = TASK_HEADER;
        for (heading, first_digit) in [
            (&b"PID"[..], 0usize),
            (&b"DMA"[..], 14),
            (&b"DEVICES"[..], 19),
        ] {
            let at = header
                .windows(heading.len())
                .position(|w| w == heading)
                .expect("heading is in the header");
            assert_eq!(at, first_digit, "column moved out from under its heading");
        }
        // The row is as wide as the header; DEVICES is a longer word than the
        // count under it, so the tail is blank.
        assert_eq!(&row[..22], b"007  RUNNING  006  003");
        assert!(row[22..].iter().all(|byte| *byte == b' '));
    }

    #[test]
    fn a_count_too_wide_for_its_column_says_so() {
        // Wrapping would print 1000 DMA regions as 000, which is the one
        // reading that is worse than no reading.
        let row = task_row(0, b"READY", 1000, 0);
        assert_eq!(&row[14..17], b"999");
    }

    #[test]
    fn no_two_windows_share_a_close_box() {
        // They overlap on screen by design; two close boxes at the same point
        // would mean the top one is unclosable, because the scan finds the
        // other first.
        let all = ALL_WINDOWS;
        for (index, window) in all.iter().enumerate() {
            for other in &all[index + 1..] {
                let (cx, cy) = close_at(*window);
                assert!(!on_close(*other, cx, cy), "two windows, one close box");
            }
        }
    }

    #[test]
    fn every_icon_that_names_a_window_names_a_different_one() {
        // Two icons onto one window is two icons of which one is redundant, and
        // no way to tell from the desktop which.
        for a in 0..ICON_COUNT {
            for b in a + 1..ICON_COUNT {
                if let (Some(x), Some(y)) = (Desktop::icon_window(a), Desktop::icon_window(b)) {
                    assert_ne!(x, y, "two icons open the same window");
                }
            }
        }
    }

    #[test]
    fn a_close_box_sits_inside_its_own_title_bar() {
        for window in ALL_WINDOWS {
            let (x, y, w, _) = bounds(window);
            let (cx, cy) = close_at(window);
            assert!(cx >= x && cx + CLOSE_SIZE <= x + w, "past the window edge");
            assert!(
                cy >= y && cy + CLOSE_SIZE <= y + TITLE_HEIGHT,
                "off the bar"
            );
        }
    }

    #[test]
    fn the_close_box_closes_the_window_it_belongs_to() {
        let mut desktop = Desktop::new();
        desktop.open(Window::Shell);
        let (cx, cy) = close_at(Window::Shell);
        assert_eq!(
            desktop.press(cx + 2, cy + 2, false, 1280, 800),
            Click::Close(Window::Shell)
        );
        assert!(!desktop.is_open(Window::Shell));
    }

    #[test]
    fn a_closed_windows_close_box_is_not_clickable() {
        // Otherwise the box keeps swallowing clicks on whatever the window was
        // covering, which is a hole in the desktop where a window used to be.
        let mut desktop = Desktop::new();
        let (cx, cy) = close_at(Window::Devices);
        assert_ne!(
            desktop.press(cx + 2, cy + 2, false, 1280, 800),
            Click::Close(Window::Devices)
        );
    }

    #[test]
    fn no_window_hides_the_taskbar() {
        for window in ALL_WINDOWS {
            let (_, y, _, h) = bounds(window);
            assert!(y + h <= 800 - TASKBAR_HEIGHT, "a window covers the taskbar");
        }
    }

    #[test]
    fn nothing_is_open_when_the_session_starts() {
        // A desktop that begins covered in windows nobody asked for is not a
        // desktop.
        let desktop = Desktop::new();
        assert!(!desktop.is_open(Window::Shell));
        assert!(!desktop.is_open(Window::Devices));
    }

    #[test]
    fn a_window_can_be_closed_and_opened_again() {
        let mut desktop = Desktop::new();
        desktop.open(Window::Shell);
        assert_eq!(desktop.close(Window::Shell), Click::Close(Window::Shell));
        assert!(!desktop.shell_open);
        assert_eq!(desktop.open(Window::Shell), Click::Open(Window::Shell));
        assert!(desktop.shell_open);
    }

    #[test]
    fn clicking_the_background_clears_the_selection() {
        let mut desktop = Desktop::new();
        let (x, y) = icon_centre(0);
        desktop.press(x, y, false, WIDTH, HEIGHT);
        assert_eq!(desktop.press(10, 700, false, WIDTH, HEIGHT), Click::None);
        assert_eq!(desktop.selected, None);
    }

    #[test]
    fn every_icon_can_be_hit_and_the_gaps_between_them_cannot() {
        for index in 0..ICON_COUNT {
            let (x, y) = icon_centre(index);
            assert_eq!(Desktop::icon_under(x, y, WIDTH), Some(index));
        }
        // Between two icons, in the spacing. If this hit something, the boxes
        // would be larger than they are drawn and clicks would land on the
        // wrong one near the edges.
        let (_, y) = Desktop::icon_at(0, WIDTH);
        let gap = y + ICON_SIZE + (ICON_SPACING - ICON_SIZE) / 2;
        let (x, _) = Desktop::icon_at(0, WIDTH);
        assert_eq!(Desktop::icon_under(x + 10, gap, WIDTH), None);
    }

    #[test]
    fn right_clicking_opens_a_menu_where_the_pointer_is() {
        let mut desktop = Desktop::new();
        assert_eq!(
            desktop.press(400, 300, true, WIDTH, HEIGHT),
            Click::OpenMenu(400, 300)
        );
        assert_eq!(desktop.menu, Some((400, 300)));
    }

    #[test]
    fn a_menu_near_an_edge_is_moved_so_all_of_it_fits() {
        // A menu that opens off the bottom is one whose last entry cannot be
        // reached, which is worse than one that is not quite where the pointer
        // was.
        let mut desktop = Desktop::new();
        let click = desktop.press(WIDTH - 5, HEIGHT - 5, true, WIDTH, HEIGHT);
        let Click::OpenMenu(x, y) = click else {
            panic!("expected a menu, got {click:?}");
        };
        assert!(x + MENU_WIDTH <= WIDTH);
        assert!(y + MENU_ITEM_HEIGHT * MENU_ITEMS.len() as u64 <= HEIGHT);
    }

    #[test]
    fn choosing_a_menu_entry_reports_it_and_closes_the_menu() {
        let mut desktop = Desktop::new();
        desktop.press(400, 300, true, WIDTH, HEIGHT);
        let click = desktop.press(400 + 10, 300 + MENU_ITEM_HEIGHT + 5, false, WIDTH, HEIGHT);
        assert_eq!(click, Click::Menu(1));
        assert_eq!(desktop.menu, None);
    }

    #[test]
    fn clicking_away_from_an_open_menu_closes_it_and_does_nothing_else() {
        // While the menu is open it is on top of everything. A click elsewhere
        // dismisses it rather than reaching what is underneath — otherwise an
        // icon can be selected through an open menu.
        let mut desktop = Desktop::new();
        desktop.press(400, 300, true, WIDTH, HEIGHT);
        let (x, y) = icon_centre(0);
        assert_eq!(desktop.press(x, y, false, WIDTH, HEIGHT), Click::CloseMenu);
        assert_eq!(
            desktop.selected, None,
            "an icon was selected through a menu"
        );
        assert_eq!(desktop.menu, None);
    }

    #[test]
    fn a_second_right_click_while_the_menu_is_open_closes_it() {
        let mut desktop = Desktop::new();
        desktop.press(400, 300, true, WIDTH, HEIGHT);
        assert_eq!(
            desktop.press(700, 500, true, WIDTH, HEIGHT),
            Click::CloseMenu
        );
    }

    #[test]
    fn every_menu_entry_is_reachable() {
        // An entry whose row cannot be hit is an entry that does not exist.
        let mut desktop = Desktop::new();
        desktop.press(300, 200, true, WIDTH, HEIGHT);
        for index in 0..MENU_ITEMS.len() {
            let y = 200 + index as u64 * MENU_ITEM_HEIGHT + MENU_ITEM_HEIGHT / 2;
            assert_eq!(desktop.menu_under(300 + 5, y), Some(index), "entry {index}");
        }
        // And one row past the last is not an entry.
        let past = 200 + MENU_ITEMS.len() as u64 * MENU_ITEM_HEIGHT + 5;
        assert_eq!(desktop.menu_under(305, past), None);
    }

    #[test]
    fn a_point_left_of_the_menu_is_not_in_it() {
        let mut desktop = Desktop::new();
        desktop.press(300, 200, true, WIDTH, HEIGHT);
        assert_eq!(desktop.menu_under(299, 210), None);
        assert_eq!(desktop.menu_under(300 + MENU_WIDTH, 210), None);
        assert_eq!(desktop.menu_under(305, 199), None);
    }

    #[test]
    fn every_icon_has_a_label_and_every_menu_entry_has_text() {
        for label in ICON_LABELS {
            assert!(!label.is_empty());
        }
        for item in MENU_ITEMS {
            assert!(!item.is_empty());
        }
    }

    #[test]
    fn an_entry_that_promises_to_open_something_opens_something() {
        // This test used to forbid the word "Open" entirely, because "Open
        // shell" answered "the shell is already open below" — the shell was
        // always open and the entry was decoration. Windows start closed now,
        // so the word is honest again, and the rule becomes the one it should
        // have been: an entry may promise a window as long as it names one.
        //
        // One direction only. The reverse — that anything which opens a window
        // must be worded "Open" — is a naming rule rather than a truthfulness
        // one, and it fails on "Task manager", which is the clearest name for
        // an entry that opens the task manager.
        for (index, label) in MENU_ITEMS.iter().enumerate() {
            if label.starts_with(b"Open") || label.starts_with(b"Show") {
                assert!(
                    Desktop::menu_window(index).is_some(),
                    "entry {index} promises a window and names none"
                );
            }
        }
    }

    #[test]
    fn every_menu_entry_that_opens_a_window_actually_opens_it() {
        for index in 0..MENU_ITEMS.len() {
            let Some(window) = Desktop::menu_window(index) else {
                continue;
            };
            let mut desktop = Desktop::new();
            assert!(!desktop.is_open(window));
            desktop.open(window);
            assert!(desktop.is_open(window), "entry {index} opened nothing");
        }
    }

    #[test]
    fn no_two_menu_entries_open_the_same_window() {
        for a in 0..MENU_ITEMS.len() {
            for b in a + 1..MENU_ITEMS.len() {
                if let (Some(x), Some(y)) = (Desktop::menu_window(a), Desktop::menu_window(b)) {
                    assert_ne!(x, y, "two entries for one window");
                }
            }
        }
    }
}
