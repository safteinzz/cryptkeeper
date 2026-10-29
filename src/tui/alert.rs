//! The alert: a failure that already happened and has to be read. Yellow,
//! dismissed only, scrolled when long. It owns every key until it is closed,
//! because the status line fades and a screen that comes back unchanged reads
//! as a key that did nothing.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::prelude::*;
use ratatui::widgets::{Clear, Paragraph, Wrap};

use super::widgets::{
    BOX_CHROME_H, READER_KEYS, box_area, box_block, box_height, box_hint, box_inner_width,
    box_width, vscrollbar, wrapped_line_count,
};
use super::{App, is_ctrl_c};

pub(super) struct Alert {
    title: String,
    body: String,
    scroll: u16,
}

impl App {
    /// Raises one over anything already up: the newest failure is the one
    /// being reacted to.
    pub(super) fn alert(&mut self, title: impl Into<String>, body: impl Into<String>) {
        self.alert = Some(Alert {
            title: title.into(),
            body: body.into(),
            scroll: 0,
        });
    }

    /// Keys while an alert is up: movement scrolls it, a dismissal closes it,
    /// and anything else is swallowed so a stray key cannot close it unread.
    pub(super) fn alert_key(&mut self, key: KeyEvent) {
        let Some(a) = &mut self.alert else { return };
        if is_ctrl_c(key) {
            self.alert = None;
            return;
        }
        match key.code {
            KeyCode::Down | KeyCode::Char('j') | KeyCode::PageDown => {
                a.scroll = a.scroll.saturating_add(1)
            }
            KeyCode::Up | KeyCode::Char('k') | KeyCode::PageUp => {
                a.scroll = a.scroll.saturating_sub(1)
            }
            KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q' | ' ') => self.alert = None,
            _ => {}
        }
    }
}

pub(super) fn render_alert(f: &mut Frame, area: Rect, a: &mut Alert) {
    let width = box_width(area.width);
    let rows = wrapped_line_count(&a.body, box_inner_width(width)) as u16;
    // The body, a blank, the keys.
    let rect = box_area(area, width, box_height(rows + 2, area.height));
    let view = rect.height.saturating_sub(BOX_CHROME_H);
    // Clamped where the height is known, so scrolling past the end never
    // piles up presses that take as many to undo.
    a.scroll = a.scroll.min((rows + 2).saturating_sub(view));
    let top = a.scroll;
    f.render_widget(Clear, rect);
    let mut lines: Vec<Line> = a.body.lines().map(|l| Line::raw(l.to_string())).collect();
    lines.push(Line::raw(""));
    lines.push(box_hint(READER_KEYS));
    let para = Paragraph::new(lines)
        .block(box_block(Color::Yellow, &a.title))
        .wrap(Wrap { trim: false })
        .scroll((top, 0));
    f.render_widget(para, rect);
    vscrollbar(
        f,
        rect,
        usize::from(rows + 2),
        usize::from(top),
        usize::from(view),
    );
}
