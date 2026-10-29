//! The pickers: what `c` creates, before any form asks for a path, and the
//! drive Ctrl-O fills into the LUKS form.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::prelude::*;
use ratatui::widgets::{Clear, Paragraph};

use super::form::Form;
use super::widgets::{PICKER_KEYS, box_area, box_block, box_height, box_hint, box_width};
use super::{App, is_ctrl_c};

/// What `c` offers, each with the line that says what it makes.
const CHOICES: [(&str, &str); 4] = [
    (
        "Encrypt a file",
        "turns one file into an encrypted `.age` file (age)",
    ),
    (
        "New encrypted folder",
        "an empty folder whose files are stored encrypted (gocryptfs)",
    ),
    (
        "New encrypted drive or image",
        "a whole drive, or one big file used as a disk (LUKS, asks sudo)",
    ),
    (
        "Add one you already have",
        "a folder, drive, image or file made before, by ck or not",
    ),
];

pub(super) struct Picker {
    title: &'static str,
    /// Each choice and the line under it.
    items: Vec<(String, String)>,
    sel: usize,
    /// What picking does.
    then: Then,
}

enum Then {
    /// Opens the form for the picked kind of vault.
    Create,
    /// Fills the picked drive into the form's path.
    Drive,
}

impl Picker {
    pub(super) fn create() -> Picker {
        Picker {
            title: "create",
            items: CHOICES
                .iter()
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .collect(),
            sel: 0,
            then: Then::Create,
        }
    }

    /// The drives ck would format, or `None` when no such drive is there.
    pub(super) fn drives() -> Option<Picker> {
        let items: Vec<(String, String)> = crate::luks::formattable()
            .into_iter()
            .map(|(dev, about)| (dev.display().to_string(), about))
            .collect();
        (!items.is_empty()).then_some(Picker {
            title: "pick a drive",
            items,
            sel: 0,
            then: Then::Drive,
        })
    }
}

impl App {
    /// Keys while the picker is up: the arrows and `j`/`k` move, Enter
    /// picks, Esc and Ctrl-C cancel, anything else is swallowed.
    pub(super) fn picker_key(&mut self, key: KeyEvent) {
        let Some(p) = &mut self.picker else { return };
        let last = p.items.len().saturating_sub(1);
        match key.code {
            _ if is_ctrl_c(key) => self.picker = None,
            KeyCode::Esc => self.picker = None,
            KeyCode::Down | KeyCode::Char('j') => p.sel = (p.sel + 1).min(last),
            KeyCode::Up | KeyCode::Char('k') => p.sel = p.sel.saturating_sub(1),
            KeyCode::Enter => {
                match p.then {
                    Then::Create => {
                        self.form = Some(match p.sel {
                            0 => Form::encrypt_file(),
                            1 => Form::new_folder(),
                            2 => Form::new_luks(),
                            _ => Form::add_existing(),
                        })
                    }
                    Then::Drive => {
                        if let (Some(form), Some((dev, _))) = (&mut self.form, p.items.get(p.sel)) {
                            form.set_path(dev);
                        }
                    }
                }
                self.picker = None;
            }
            _ => {}
        }
    }
}

pub(super) fn render_picker(f: &mut Frame, area: Rect, p: &Picker) {
    let mut lines = Vec::new();
    for (i, (name, what)) in p.items.iter().enumerate() {
        let picked = i == p.sel;
        let style = match picked {
            true => Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD),
            false => Style::default().add_modifier(Modifier::BOLD),
        };
        lines.push(Line::from(vec![
            Span::raw(if picked { "▸ " } else { "  " }),
            Span::styled(format!(" {name} "), style),
        ]));
        lines.push(Line::styled(
            format!("    {what}"),
            Style::default().add_modifier(Modifier::DIM),
        ));
    }
    lines.extend([Line::raw(""), box_hint(PICKER_KEYS)]);
    let width = box_width(area.width);
    let rect = box_area(area, width, box_height(lines.len() as u16, area.height));
    f.render_widget(Clear, rect);
    let para = Paragraph::new(lines).block(box_block(Color::Cyan, p.title));
    f.render_widget(para, rect);
}
