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
pub const ICON_LABELS: [&[u8]; ICON_COUNT] = [b"DISK", b"SOUND", b"SHELL", b"ABOUT"];

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

/// What the menu offers.
///
/// Every one of these does something. The first version opened with "Open
/// shell", which answered "the shell is already open below" — an entry that
/// exists to be clicked once and then never again. A menu whose items are
/// greyed out, or say something instead of doing something, is worse than no
/// menu: it tells somebody the system can do things it cannot.
pub const MENU_ITEMS: [&[u8]; 4] = [
    b"Clear shell",
    b"List devices",
    b"Read sector 0",
    b"Shut down",
];

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
}

impl Desktop {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            selected: None,
            menu: None,
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

        match Self::icon_under(x, y, width) {
            Some(index) => {
                self.selected = Some(index);
                Click::Select(index)
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
    fn clicking_an_icon_selects_it() {
        let mut desktop = Desktop::new();
        let (x, y) = icon_centre(2);
        assert_eq!(desktop.press(x, y, false, WIDTH, HEIGHT), Click::Select(2));
        assert_eq!(desktop.selected, Some(2));
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
    fn no_menu_entry_merely_describes_the_state_it_is_in() {
        // "Open shell" was an entry whose only effect was to say the shell was
        // already open. This is the assertion that keeps one from coming back:
        // an entry beginning with "Open" would have to open something, and
        // nothing here can be opened yet.
        for item in MENU_ITEMS {
            assert!(
                !item.starts_with(b"Open"),
                "an entry promises to open something",
            );
        }
    }
}
