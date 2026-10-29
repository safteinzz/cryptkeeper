//! The panel beside the list: everything known about the selected row, from
//! what is already read, never a read of its own. It shows only when the
//! terminal is wide enough to keep a usable list beside it.

use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Padding, Paragraph, Wrap};

use super::{App, View, check_style, kind_about, state_style};
use crate::check::Check;
use crate::listing::Entry;
use crate::tilde;
use crate::vault::Kind;

/// The narrowest frame that keeps a usable list beside the panel.
const MIN_WIDTH_FOR_DETAIL: u16 = 96;
/// The panel's share of the frame.
pub(super) const DETAIL_PCT: u16 = 38;

pub(super) fn detail_fits(width: u16) -> bool {
    width >= MIN_WIDTH_FOR_DETAIL
}

pub(super) fn render_detail(f: &mut Frame, area: Rect, app: &App) {
    let lines = match app.view {
        View::Vaults => match app.selected_entry() {
            Some(e) => entry_lines(e, app.check_of(e.kind)),
            None if app.entries.is_empty() => vec![
                Line::styled("No vaults yet", dim()),
                Line::raw(""),
                Line::raw(
                    "`c` encrypts a file, makes an encrypted folder or drive, or adds one you already have.",
                ),
            ],
            None => vec![Line::styled("nothing matches the filter", dim())],
        },
        View::Check => match app.selected_check() {
            Some(c) => check_lines(c),
            None => vec![Line::styled("nothing selected", dim())],
        },
        View::Settings => match app.selected_setting() {
            Some(r) => setting_lines(&r),
            None => vec![Line::styled("nothing matches the filter", dim())],
        },
    };
    let para = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Details ")
                .padding(Padding::horizontal(1)),
        )
        .wrap(Wrap { trim: false });
    f.render_widget(para, area);
}

fn entry_lines(e: &Entry, check: Option<&Check>) -> Vec<Line<'static>> {
    let what = match e.kind {
        Kind::Luks if e.cipher.starts_with("/dev") => "luks drive",
        Kind::Luks => "luks image file",
        Kind::Gocryptfs => "gocryptfs folder",
        Kind::Age => "age file",
    };
    let what = match e.listed {
        true => what.to_string(),
        false => format!("{what}, found, not in the list"),
    };
    let state = match e.note.is_empty() {
        true => e.state.to_string(),
        false => format!("{} · {}", e.state, e.note),
    };
    let mut lines = vec![
        Line::styled(
            crate::vault::file_name(&e.name),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Line::styled(what, dim()),
        Line::raw(""),
        Line::styled(state, state_style(e.state)),
        Line::raw(""),
        row("Name", tilde(&e.name)),
    ];
    if e.cipher != e.name {
        lines.push(row("Encrypted", tilde(&e.cipher)));
    }
    if let Some(at) = e.at.as_ref().filter(|at| **at != e.name) {
        lines.push(row("Open at", tilde(at)));
    }
    if e.kind == Kind::Age {
        let id = e.identity.as_deref().map_or("a passphrase".into(), tilde);
        lines.push(row("Opens with", id));
    }
    if let Some(c) = check {
        lines.push(Line::raw(""));
        lines.push(Line::from(vec![
            label("This machine"),
            Span::styled(c.state, check_style(c.state)),
        ]));
        lines.push(Line::styled(
            c.fix.clone().unwrap_or_else(|| c.detail.clone()),
            dim(),
        ));
    }
    lines
}

fn check_lines(c: &Check) -> Vec<Line<'static>> {
    let (name, what) = kind_about(c.kind);
    let mut lines = vec![
        Line::styled(
            name,
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Line::styled(format!("{what}, through {}", c.kind.word()), dim()),
        Line::raw(""),
        Line::styled(c.state, check_style(c.state)),
        Line::raw(""),
        Line::raw(c.detail.clone()),
    ];
    if let Some(fix) = &c.fix {
        lines.push(Line::raw(""));
        lines.push(row("Fix", fix.clone()));
        if c.command().is_some() {
            lines.push(Line::styled("↵ runs it for you, asking first", dim()));
        }
    }
    lines
}

fn setting_lines(r: &crate::settings::Row) -> Vec<Line<'static>> {
    let heading = Style::default()
        .fg(Color::Cyan)
        .add_modifier(Modifier::BOLD);
    vec![
        Line::styled(r.label, heading),
        Line::styled(r.help, dim()),
        Line::raw(""),
        row("Value", r.value.clone()),
        row("Default", r.default.to_string()),
        row("In the file", format!("{} = {}", r.key, r.value)),
        Line::raw(""),
        Line::styled(tilde(&crate::settings::path()), dim()),
    ]
}

/// One `label   value` row, the label dim so the value reads first.
fn row(name: &str, value: String) -> Line<'static> {
    Line::from(vec![label(name), Span::raw(value)])
}

/// The dim label column that keeps values aligned, with a space after a
/// label that fills it, so it never runs into its value.
fn label(name: &str) -> Span<'static> {
    const W: usize = 13;
    let pad = W.saturating_sub(name.chars().count()).max(1);
    Span::styled(format!("{name}{}", " ".repeat(pad)), dim())
}

fn dim() -> Style {
    Style::default().add_modifier(Modifier::DIM)
}
