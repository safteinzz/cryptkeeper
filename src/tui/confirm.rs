//! The boxes that ask first: the cyan offer of a fix, two buttons starting
//! on Yes, and the red typed gates in front of what cannot come back
//! (deleting a vault, wiping a drive), where Enter waits for the short name.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::prelude::*;
use ratatui::widgets::{Clear, Paragraph, Wrap};
use std::path::Path;

use super::widgets::{
    CANCEL, GATE_KEYS, box_area, box_block, box_buttons, box_height, box_hint, box_inner_width,
    box_width, wrapped_line_count,
};
use super::{Action, App, is_ctrl_c, line_edit};
use crate::listing::Entry;
use crate::vault::Kind;

pub(super) struct Gate {
    title: String,
    message: String,
    action: Action,
    /// Which button is picked.
    yes: bool,
    /// A gate rather than an offer, which is all that decides its colour.
    danger: bool,
}

impl Gate {
    /// The offer to install what `kind` vaults need by running `argv`.
    pub(super) fn install(what: &str, argv: Vec<String>) -> Gate {
        let line = argv.join(" ");
        Gate {
            title: format!("install {what}"),
            message: format!(
                "Run `{line}`?\n\nck hands it the terminal: sudo asks for your password, and the package manager may ask you to confirm."
            ),
            action: Action::Install(argv),
            yes: true,
            danger: false,
        }
    }
}

impl App {
    /// Keys while a gate is up: `y` goes ahead, `n`, Esc and Ctrl-C cancel,
    /// the arrows, `h`/`l` and Tab move between the buttons for Enter, and
    /// any other key is swallowed.
    pub(super) fn gate_key(&mut self, key: KeyEvent) -> Option<Action> {
        if is_ctrl_c(key) {
            self.gate = None;
            self.set_status("cancelled");
            return None;
        }
        match key.code {
            KeyCode::Left
            | KeyCode::Right
            | KeyCode::Char('h' | 'l')
            | KeyCode::Tab
            | KeyCode::BackTab => {
                if let Some(g) = &mut self.gate {
                    g.yes = !g.yes;
                }
                None
            }
            KeyCode::Char('n' | 'N') | KeyCode::Esc => {
                self.gate = None;
                self.set_status("cancelled");
                None
            }
            KeyCode::Char('y' | 'Y') => self.gate.take().map(|g| g.action),
            KeyCode::Enter => {
                let g = self.gate.take()?;
                if g.yes {
                    return Some(g.action);
                }
                self.set_status("cancelled");
                None
            }
            _ => None,
        }
    }
}

pub(super) fn render_gate(f: &mut Frame, area: Rect, g: &Gate) {
    let width = box_width(area.width);
    let rows = wrapped_line_count(&g.message, box_inner_width(width)) as u16;
    // The message, a blank, the buttons, a blank, the keys.
    let rect = box_area(area, width, box_height(rows + 4, area.height));
    let colour = if g.danger { Color::Red } else { Color::Cyan };
    f.render_widget(Clear, rect);
    let mut lines: Vec<Line> = g
        .message
        .lines()
        .map(|l| Line::raw(l.to_string()))
        .collect();
    lines.extend([
        Line::raw(""),
        box_buttons(colour, g.yes),
        Line::raw(""),
        box_hint(GATE_KEYS),
    ]);
    let para = Paragraph::new(lines)
        .block(box_block(colour, &g.title))
        .wrap(Wrap { trim: false });
    f.render_widget(para, rect);
}

/// The typed gate: a red box with no buttons in front of what cannot be taken
/// back, where Enter does nothing until the field holds the thing's exact
/// name, which the body shows so it is copied rather than guessed.
pub(super) struct Typed {
    title: String,
    message: String,
    name: String,
    typed: String,
    /// The cursor in `typed`, as characters after it.
    back: usize,
    /// What Enter does, for the key row.
    verb: &'static str,
    action: Action,
}

impl Typed {
    /// The gate in front of formatting the drive `dev`.
    pub(super) fn wipe(dev: &Path, action: Action) -> Typed {
        let dev = dev.display().to_string();
        let name = crate::vault::file_name(Path::new(&dev));
        Typed {
            title: "wipe drive".into(),
            message: format!(
                "Formatting `{dev}` destroys everything on it, for good.\n\nType `{name}` to go ahead."
            ),
            name,
            typed: String::new(),
            back: 0,
            verb: "↵ wipe",
            action,
        }
    }

    /// The gate in front of deleting the vault `e` for good, asking for the
    /// short name of what goes: a LUKS vault's image file, else the name the
    /// list shows.
    pub(super) fn delete(e: &Entry) -> Typed {
        // The body names what is removed in full; the field takes the short
        // name the list shows (a LUKS image by its file).
        let gone = &e.cipher;
        let name = crate::vault::file_name(match e.kind {
            Kind::Luks => &e.cipher,
            _ => &e.name,
        });
        Typed {
            title: "delete vault".into(),
            message: format!(
                "Deleting `{}` removes its encrypted files for good: nothing opens it again.\n\nType `{name}` to go ahead.",
                crate::tilde(gone)
            ),
            name,
            typed: String::new(),
            back: 0,
            verb: "↵ del",
            action: Action::Delete(e.name.clone()),
        }
    }
}

impl App {
    /// Keys while a typed gate is up: Esc and Ctrl-C cancel, Enter goes
    /// ahead only on the exact name, everything else edits the field.
    pub(super) fn typed_key(&mut self, key: KeyEvent) -> Option<Action> {
        let t = self.typed.as_mut()?;
        match key.code {
            _ if is_ctrl_c(key) => {}
            KeyCode::Esc => {}
            KeyCode::Enter if t.typed.trim() == t.name => {
                return self.typed.take().map(|t| t.action);
            }
            KeyCode::Enter => return None,
            _ => {
                line_edit::edit(&mut t.typed, &mut t.back, key);
                return None;
            }
        }
        self.typed = None;
        self.set_status("cancelled");
        None
    }
}

pub(super) fn render_typed(f: &mut Frame, area: Rect, t: &Typed) {
    let width = box_width(area.width);
    let rows = wrapped_line_count(&t.message, box_inner_width(width)) as u16;
    // The message, a blank, the field, a blank, the keys.
    let rect = box_area(area, width, box_height(rows + 4, area.height));
    f.render_widget(Clear, rect);
    let mut lines: Vec<Line> = t
        .message
        .lines()
        .map(|l| Line::raw(l.to_string()))
        .collect();
    let mut field = vec![Span::styled("▸ ", Style::default().fg(Color::Red))];
    field.extend(line_edit::with_cursor(&t.typed, t.back, Style::default()));
    let verb = t.verb;
    lines.extend([
        Line::raw(""),
        Line::from(field),
        Line::raw(""),
        box_hint(&[verb, CANCEL]),
    ]);
    let para = Paragraph::new(lines)
        .block(box_block(Color::Red, &t.title))
        .wrap(Wrap { trim: false });
    f.render_widget(para, rect);
}
