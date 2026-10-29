//! What every screen and box is drawn from: the words of every key row, the
//! house box and its parts, the footer, the scrollbar, list blocks, and the
//! wrapped-row count a box sizes itself by.

use ratatui::prelude::*;
use ratatui::widgets::{
    Block, Borders, Padding, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState, Wrap,
};

// The words every footer and key row is built from, so a key reads the same on
// every screen and a hand-typed legend stands out.
pub(super) const CREATE: &str = "c create";
pub(super) const EDIT: &str = "e edit";
pub(super) const DEL: &str = "d del";
pub(super) const FIND: &str = "/ find";
pub(super) const REFRESH: &str = "r refresh";
pub(super) const QUIT: &str = "q quit";
pub(super) const HELP: &str = "? help";
pub(super) const SELECT: &str = "↵ select";
pub(super) const PICK: &str = "↵ pick";
pub(super) const NEXT_SUBMIT: &str = "↵ next/submit";
pub(super) const BACK: &str = "esc back";
pub(super) const CANCEL: &str = "esc cancel";
pub(super) const CLOSE: &str = "esc close";
pub(super) const REQUIRED: &str = "* required";
pub(super) const SEP: &str = " · ";

/// The key rows of the box kinds, each drawn by that kind's render function.
pub(super) const GATE_KEYS: &[&str] = &[SELECT, CANCEL];
pub(super) const FORM_KEYS: &[&str] = &[NEXT_SUBMIT, CANCEL];
pub(super) const PICKER_KEYS: &[&str] = &[PICK, CANCEL];
pub(super) const READER_KEYS: &[&str] = &[CLOSE];

/// Narrowest a box may be, so a two-word message still reads as a box.
const BOX_MIN_W: u16 = 24;
/// Widest, so one long line does not stretch a box across a wide screen.
const BOX_MAX_W: u16 = 88;
/// Rows the chrome costs: two borders and the one top padding row.
pub(super) const BOX_CHROME_H: u16 = 3;
/// Columns the chrome costs: two borders and two columns of padding a side.
const BOX_CHROME_W: u16 = 6;

/// How many rows `text` takes when word-wrapped to `width` the way ratatui's
/// `Wrap` breaks it, each `\n` starting a row of its own.
pub(super) fn wrapped_line_count(text: &str, width: usize) -> usize {
    text.split('\n').map(|l| wrapped_rows(l, width)).sum()
}

/// `wrapped_line_count` for one line with no breaks in it.
fn wrapped_rows(text: &str, width: usize) -> usize {
    if width == 0 {
        return 1;
    }
    let mut rows = 1;
    let mut col = 0;
    // Split on single spaces, since an indent or a double space is real columns
    // and collapsing them undercounts the rows and clips a box's last line.
    for (i, word) in text.split(' ').enumerate() {
        let w = word.chars().count();
        let need = if i == 0 { w } else { col + 1 + w };
        if need <= width {
            col = need;
        } else {
            rows += 1;
            col = w;
        }
        // A word longer than the whole row wraps across several.
        while col > width {
            rows += 1;
            col -= width;
        }
    }
    rows
}

/// How wide a box is on a screen this wide.
pub(super) fn box_width(screen_w: u16) -> u16 {
    screen_w.saturating_sub(4).clamp(BOX_MIN_W, BOX_MAX_W)
}

/// The columns a box's body gets, which is what it must be wrapped to.
pub(super) fn box_inner_width(width: u16) -> usize {
    usize::from(width.saturating_sub(BOX_CHROME_W).max(1))
}

/// How tall a box holding `body_rows` wrapped rows is, capped at the whole
/// screen: a box owns the screen while it is up, and a cap any lower only
/// cuts the end off a long one.
pub(super) fn box_height(body_rows: u16, screen_h: u16) -> u16 {
    let floor = BOX_CHROME_H + 1;
    body_rows
        .saturating_add(BOX_CHROME_H)
        .clamp(floor, screen_h.max(floor))
}

/// A box of at most `w` by `h`, centered in `area`.
pub(super) fn box_area(area: Rect, w: u16, h: u16) -> Rect {
    let (w, h) = (w.min(area.width), h.min(area.height));
    Rect {
        x: area.x + area.width.saturating_sub(w) / 2,
        y: area.y + area.height.saturating_sub(h) / 2,
        width: w,
        height: h,
    }
}

/// The frame every box wears: its title on the top border and nothing else
/// on it, in the colour of its kind (red gate, yellow alert, cyan the rest).
pub(super) fn box_block(colour: Color, title: &str) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(colour))
        // A blank row above the body and none below, since the key row is
        // the last thing in it.
        .padding(Padding::new(2, 2, 1, 0))
        .title(format!(" {} ", title.trim()))
}

/// The key row a box ends with, below a blank row, quieter than anything
/// else in it.
pub(super) fn box_hint(keys: &[&str]) -> Line<'static> {
    Line::from(Span::styled(
        keys.join(SEP),
        Style::default()
            .fg(Color::DarkGray)
            .add_modifier(Modifier::DIM),
    ))
}

/// The Yes/No row of a gate, the picked button filled with the border's
/// colour, since filled reads as what Enter does.
pub(super) fn box_buttons(colour: Color, yes: bool) -> Line<'static> {
    let button = |label: &str, picked: bool| {
        let style = if picked {
            Style::default()
                .fg(Color::Black)
                .bg(colour)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().add_modifier(Modifier::DIM)
        };
        Span::styled(format!(" {label} "), style)
    };
    Line::from(vec![
        button("Yes (y)", yes),
        Span::raw("  "),
        button("No (n)", !yes),
    ])
}

/// The row under a view: `lead` (a kept filter), then as many of `keys` as fit
/// in `width`, whole and in order, with `? help` pinned at the right edge,
/// since help is the way to every key that fell off.
pub(super) fn key_footer(lead: &[String], keys: &[&str], width: u16) -> Line<'static> {
    let width = usize::from(width);
    // A column of margin at each end, and a gap as wide as a separator before
    // `? help`, so it never reads as part of the last key.
    let room = width.saturating_sub(HELP.chars().count() + 2 + SEP.chars().count());
    let mut left = String::new();
    for entry in lead.iter().map(String::as_str).chain(keys.iter().copied()) {
        let next = if left.is_empty() {
            entry.to_string()
        } else {
            format!("{left}{SEP}{entry}")
        };
        if next.chars().count() > room {
            break;
        }
        left = next;
    }
    let pad = width.saturating_sub(left.chars().count() + HELP.chars().count() + 2);
    let dim = Style::default().add_modifier(Modifier::DIM);
    Line::from(vec![
        Span::styled(format!(" {left}"), dim),
        Span::raw(" ".repeat(pad.max(1))),
        Span::styled(format!("{HELP} "), dim),
    ])
}

/// A scrollbar on the right border of `area`, the bordered rect it sits on,
/// for `total` rows with `view` of them on screen from `top`; nothing when
/// every row fits.
pub(super) fn vscrollbar(f: &mut Frame, area: Rect, total: usize, top: usize, view: usize) {
    if total <= view {
        return;
    }
    let mut state = ScrollbarState::new(total - view).position(top);
    let bar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
        .begin_symbol(None)
        .end_symbol(None);
    f.render_stateful_widget(bar, area.inner(Margin::new(0, 1)), &mut state);
}

/// A list pane's block: `Name (n)`, or `Name (shown/total)` while a filter
/// hides some.
pub(super) fn counted(name: &str, shown: usize, total: usize) -> Block<'static> {
    let count = if shown == total {
        total.to_string()
    } else {
        format!("{shown}/{total}")
    };
    Block::default()
        .borders(Borders::ALL)
        .title(format!(" {name} ({count}) "))
}

/// A list pane in `block` with nothing to list, saying why.
pub(super) fn empty(f: &mut Frame, area: Rect, block: Block<'static>, msg: &str) {
    let para = Paragraph::new(msg.to_string())
        .block(block)
        .style(Style::default().add_modifier(Modifier::DIM))
        .wrap(Wrap { trim: false });
    f.render_widget(para, area);
}
