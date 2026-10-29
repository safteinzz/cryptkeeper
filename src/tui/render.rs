//! Drawing the frame: the tab bar, the list, the detail panel, the status
//! line, help, and whichever box is up, drawn last.

use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Tabs};

use super::alert::render_alert;
use super::confirm::{render_gate, render_typed};
use super::detail::{DETAIL_PCT, detail_fits, render_detail};
use super::form::render_form;
use super::picker::render_picker;
use super::widgets::{
    BACK, CREATE, DEL, EDIT, FIND, QUIT, READER_KEYS, REFRESH, SEP, box_area, box_block,
    box_height, box_hint, box_width, counted, empty, key_footer, vscrollbar,
};
use super::{
    App, VIEWS, View, check_mark, check_style, kind_about, kind_word, line_edit, state_style,
};
use crate::tilde;

/// The footer of the tab in view, `↵` first, then its own keys, then create,
/// edit and delete, then the shared tail; `key_footer` pins `? help` on the
/// right. `e` and `↵ install` are there only for a row they work on.
fn footer_keys(app: &App) -> Vec<&'static str> {
    let mut keys = Vec::new();
    match app.view {
        View::Vaults => {
            keys.push("↵ unlock/lock");
            if app.selected_entry().is_some_and(|e| !e.listed) {
                keys.push("a add");
            }
            keys.extend(["s shell", "p password", "b backup", "f forget", CREATE]);
            if app
                .selected_entry()
                .is_some_and(|e| e.kind == crate::vault::Kind::Age)
            {
                keys.push(EDIT);
            }
            keys.push(DEL);
        }
        View::Check => {
            if app.selected_check().is_some_and(|c| c.command().is_some()) {
                keys.push("↵ install");
            }
        }
        View::Settings => keys.extend(["↵ change", "d default"]),
    }
    keys.extend([FIND, REFRESH, QUIT]);
    keys
}

pub(super) fn ui(f: &mut Frame, app: &mut App) {
    let area = f.area();
    let [tabs, body, status] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(1),
        Constraint::Length(1),
    ])
    .areas(area);
    render_tabs(f, tabs, app);
    // The list keeps the whole width until a panel beside it would not
    // squeeze it, and below that the row says everything itself.
    if detail_fits(area.width) {
        let [list, detail] = Layout::horizontal([
            Constraint::Percentage(100 - DETAIL_PCT),
            Constraint::Percentage(DETAIL_PCT),
        ])
        .areas(body);
        render_body(f, list, app);
        render_detail(f, detail, app);
    } else {
        render_body(f, body, app);
    }
    render_status(f, status, app);
    if app.show_help {
        render_help(f, area, app);
    }
    if let Some(form) = &app.form {
        render_form(f, area, form, &app.known);
    }
    // After the form, since Ctrl-O raises one over it.
    if let Some(p) = &app.picker {
        render_picker(f, area, p);
    }
    if let Some(g) = &app.gate {
        render_gate(f, area, g);
    }
    if let Some(t) = &app.typed {
        render_typed(f, area, t);
    }
    // Last, so a failure is never drawn under what caused it.
    if let Some(a) = &mut app.alert {
        render_alert(f, area, a);
    }
}

fn render_tabs(f: &mut Frame, area: Rect, app: &App) {
    let idx = VIEWS.iter().position(|v| *v == app.view).unwrap_or(0);
    let tabs = Tabs::new(VIEWS.iter().map(|v| v.title()))
        .select(idx)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" cryptkeeper · ck "),
        )
        .divider("│")
        .highlight_style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );
    f.render_widget(tabs, area);
}

fn render_body(f: &mut Frame, area: Rect, app: &mut App) {
    let dim = Style::default().add_modifier(Modifier::DIM);
    let bold = Style::default().add_modifier(Modifier::BOLD);
    // The borders and the `▸ ` in front of the selected row.
    let inner = usize::from(area.width.saturating_sub(4));
    match app.view {
        View::Vaults => {
            let rows = app.vault_rows();
            let total = app.entries.len();
            let shown = rows.iter().flatten().count();
            let when_empty =
                "No vaults yet.\nPress `c` to make one, or to list one that exists by its path.";
            if let Some(msg) = nothing_here(app, total, shown, when_empty) {
                empty(f, area, counted("Vaults", 0, total), &msg);
                return;
            }
            let names: Vec<String> = rows
                .iter()
                .flatten()
                .map(|&i| tilde(&app.entries[i].name))
                .collect();
            // State and kind are as wide as their longest words.
            let nw = widest(&names).min(inner.saturating_sub(7 + 2 + 6 + 2 + 2).max(8));
            let items: Vec<ListItem> = rows
                .iter()
                .map(|row| {
                    let Some(i) = *row else {
                        // The heading, set off by a blank row, that the cursor steps over.
                        return ListItem::new(vec![
                            Line::raw(""),
                            Line::styled("found on this machine", dim),
                        ]);
                    };
                    let e = &app.entries[i];
                    let name = fit(&tilde(&e.name), nw);
                    let mut spans = cell(e.state, 7, state_style(e.state));
                    spans.push(Span::raw("  "));
                    spans.extend(cell(kind_word(e), 6, Style::default().fg(Color::Cyan)));
                    spans.push(Span::raw("  "));
                    spans.extend(cell(&name, nw, bold));
                    spans.push(Span::raw("  "));
                    spans.push(Span::styled(e.note.clone(), dim));
                    ListItem::new(Line::from(spans))
                })
                .collect();
            let block = counted("Vaults", shown, total);
            draw_list(f, area, items, block, &mut app.vault_state);
        }
        View::Settings => {
            let rows = app.setting_rows();
            let total = app.settings.rows().len();
            if let Some(msg) = nothing_here(app, total, rows.len(), "No settings.") {
                empty(f, area, counted("Settings", 0, total), &msg);
                return;
            }
            let lw = rows
                .iter()
                .map(|r| r.label.chars().count())
                .max()
                .unwrap_or(0);
            let vw = rows
                .iter()
                .map(|r| r.value.chars().count())
                .max()
                .unwrap_or(0);
            let items: Vec<ListItem> = rows
                .iter()
                .map(|r| {
                    // A value you chose stands out from one that came with ck.
                    let value_style = match r.is_default() {
                        true => Style::default(),
                        false => Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    };
                    let mut spans = cell(r.label, lw, bold);
                    spans.push(Span::raw("  "));
                    spans.extend(cell(&r.value, vw, value_style));
                    spans.push(Span::raw("  "));
                    spans.push(Span::styled(r.help, dim));
                    ListItem::new(Line::from(spans))
                })
                .collect();
            let block = counted("Settings", rows.len(), total);
            draw_list(f, area, items, block, &mut app.settings_state);
        }
        View::Check => {
            let rows = app.check_rows();
            let total = app.checks.len();
            if let Some(msg) = nothing_here(
                app,
                total,
                rows.len(),
                "Checking what this machine can open…",
            ) {
                empty(f, area, counted("This machine", 0, total), &msg);
                return;
            }
            let items: Vec<ListItem> = rows
                .iter()
                .map(|&i| {
                    let c = &app.checks[i];
                    let style = check_style(c.state);
                    let (name, what) = kind_about(c.kind);
                    let mut spans = vec![Span::styled(check_mark(c.state), style), Span::raw(" ")];
                    spans.extend(cell(name, 17, bold));
                    spans.push(Span::raw("  "));
                    spans.extend(cell(c.state, 9, style));
                    spans.push(Span::raw("  "));
                    // What it is for when it works, else what it takes.
                    let tail = match &c.fix {
                        Some(fix) => format!("to use them: {fix}"),
                        None => what.to_string(),
                    };
                    spans.push(Span::styled(tail, dim));
                    ListItem::new(Line::from(spans))
                })
                .collect();
            let block = counted("This machine", rows.len(), total);
            draw_list(f, area, items, block, &mut app.check_state);
        }
    }
}

/// A list pane with the selected row reversed behind a `▸ `, and its
/// scrollbar once it is longer than the pane.
fn draw_list(
    f: &mut Frame,
    area: Rect,
    items: Vec<ListItem>,
    block: Block<'static>,
    state: &mut ListState,
) {
    let total = items.len();
    let list = List::new(items)
        .block(block)
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol("▸ ");
    f.render_stateful_widget(list, area, state);
    let view = usize::from(area.height.saturating_sub(2));
    vscrollbar(f, area, total, state.offset(), view);
}

/// `text` in `style`, then the spaces out to `width` unstyled, so a reversed
/// row does not turn a coloured cell's padding into a block of colour.
fn cell(text: &str, width: usize, style: Style) -> Vec<Span<'static>> {
    let pad = width.saturating_sub(text.chars().count());
    vec![
        Span::styled(text.to_string(), style),
        Span::raw(" ".repeat(pad)),
    ]
}

fn widest(names: &[String]) -> usize {
    names.iter().map(|n| n.chars().count()).max().unwrap_or(0)
}

/// `text` in `width` columns, cut from the left behind a `…` when longer, so
/// a path keeps its last folders and the vault's own name.
fn fit(text: &str, width: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= width {
        return text.to_string();
    }
    if width == 0 {
        return String::new();
    }
    let tail: String = chars[chars.len() - (width - 1)..].iter().collect();
    format!("…{tail}")
}

/// The message for an empty pane, or `None` when there are rows: an empty
/// list and a filter that matched nothing get different words.
fn nothing_here(app: &App, total: usize, shown: usize, when_empty: &str) -> Option<String> {
    if total == 0 {
        Some(when_empty.to_string())
    } else if shown == 0 {
        Some(format!(
            "Nothing matches '{}'.\n`esc` clears the filter.",
            app.query
        ))
    } else {
        None
    }
}

fn render_status(f: &mut Frame, area: Rect, app: &App) {
    // While `/` is typed the row is the query's, the only place it shows.
    if app.searching {
        let mut spans = vec![Span::styled(
            " /",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )];
        spans.extend(line_edit::with_cursor(
            &app.query,
            app.query_back,
            Style::default().add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::styled(
            format!("   {} match   ↵ keep{SEP}{BACK}", app.row_count()),
            Style::default().add_modifier(Modifier::DIM),
        ));
        f.render_widget(Paragraph::new(Line::from(spans)), area);
        return;
    }
    let line = match app.live_status() {
        Some(msg) => Line::from(Span::styled(
            format!(" {msg}"),
            Style::default().fg(if app.status_failed {
                Color::Yellow
            } else {
                Color::Green
            }),
        )),
        None => {
            let keys = footer_keys(app);
            // A kept filter stays in front of the keys, since nothing else on
            // screen says why rows are missing.
            let lead = match app.query.is_empty() {
                true => Vec::new(),
                false => vec![format!("/{}", app.query), BACK.to_string()],
            };
            key_footer(&lead, &keys, area.width)
        }
    };
    f.render_widget(Paragraph::new(line), area);
}

/// One group of the help panel: a heading, then `(keys, what they do)` rows,
/// where a row with no keys is a note about the group.
type HelpSection = (&'static str, &'static [(&'static str, &'static str)]);

/// Every key the app answers to, grouped by where it works.
const HELP: &[HelpSection] = &[
    (
        "moving",
        &[
            ("j/k ↑↓", "move in the list"),
            ("g G", "the first, the last row"),
            ("h/l ←→", "the previous, next tab"),
            ("tab shift-tab", "the next, previous tab"),
        ],
    ),
    (
        "every tab",
        &[
            ("/", "find in the list, esc drops it"),
            (
                "r",
                "refresh: read every vault and check this machine again",
            ),
            ("?", "this help"),
            ("q ctrl-c", "quit (ctrl-c is esc in a box or a form)"),
        ],
    ),
    (
        "vaults",
        &[
            (
                "↵",
                "unlock a locked, dead or missing vault, lock an open one",
            ),
            ("s", "a shell in it, locked again after if it was locked"),
            (
                "a",
                "add a vault found to the list, opening nothing (ck add)",
            ),
            ("p", "change its password (ck passwd)"),
            ("b", "save its gocryptfs.conf or LUKS header (ck backup)"),
            ("c", "create: a new encrypted folder, an encrypted file,"),
            ("", "  or a vault that exists added to the list"),
            (
                "e",
                "edit an encrypted file in $VISUAL or $EDITOR (files only)",
            ),
            ("f", "forget it: drop it from the list, the vault stays"),
            ("d", "delete a locked vault for good, after typing its name"),
            (
                "",
                "open: unlocked · locked · missing: its encrypted side is gone",
            ),
            ("", "dead: its open side stopped answering, ↵ clears it"),
            (
                "",
                "exposed: an age file's plaintext left on disk, ↵ locks it",
            ),
            (
                "",
                "found on this machine: gocryptfs folders and age files in",
            ),
            (
                "",
                "  home, open gocryptfs and LUKS drives the list does not hold,",
            ),
            ("", "  `a` adds one to the list, opening nothing"),
            ("", "ck locks a drive only when its own unlock opened it"),
        ],
    ),
    (
        "this machine",
        &[
            ("↵", "install what a missing kind needs, asking first"),
            ("", "folders use gocryptfs, drives LUKS, files age"),
            ("", "ready · missing: a tool to install"),
            ("", "blocked: polkit or $XDG_RUNTIME_DIR stands in the way"),
            ("", "unchecked: polkit could not be asked"),
        ],
    ),
    (
        "settings",
        &[
            ("↵", "step a picked setting, or type a new value"),
            ("d", "put it back as ck ships it"),
            (
                "",
                "every change is saved at once, to ~/.config/cryptkeeper/settings",
            ),
        ],
    ),
    (
        "in a form",
        &[
            ("type", "fill the field"),
            ("ctrl-j/k ↑↓", "the next, previous field"),
            ("tab shift-tab", "the next, previous field"),
            ("↵", "the next field, and submit on the last"),
            ("esc", "cancel"),
        ],
    ),
    (
        "in a box",
        &[
            ("y n", "answer"),
            ("h/l ←→ tab", "move between the buttons"),
            ("↵", "select"),
            ("j/k ↑↓", "scroll an alert"),
            ("esc", "cancel or close"),
        ],
    ),
    (
        "in this help",
        &[
            ("j/k ↑↓", "scroll"),
            ("ctrl-d ctrl-u", "half a page down, up"),
            ("g G", "the top, the bottom"),
            ("esc q ?", "close"),
        ],
    ),
];

/// The width of the key column, so every description starts in one place.
const HELP_KEYS: usize = 16;

fn help_lines() -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    for (section, entries) in HELP {
        if !lines.is_empty() {
            lines.push(Line::raw(""));
        }
        lines.push(Line::styled(
            *section,
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ));
        for (keys, what) in *entries {
            if keys.is_empty() {
                lines.push(Line::styled(
                    format!("  {what}"),
                    Style::default().add_modifier(Modifier::DIM),
                ));
                continue;
            }
            lines.push(Line::from(vec![
                Span::styled(
                    format!("  {keys:<HELP_KEYS$}"),
                    Style::default().fg(Color::Yellow),
                ),
                Span::raw(*what),
            ]));
        }
    }
    lines
}

/// The help reader: the body scrolls under a key row that never moves, with
/// a scrollbar once it is taller than the box.
fn render_help(f: &mut Frame, area: Rect, app: &mut App) {
    let lines = help_lines();
    let width = box_width(area.width);
    // The body, then a blank and the key row.
    let rect = box_area(area, width, box_height(lines.len() as u16 + 2, area.height));
    f.render_widget(Clear, rect);
    let block = box_block(Color::Cyan, "help");
    let inner = block.inner(rect);
    f.render_widget(block, rect);
    let shown = usize::from(inner.height.saturating_sub(2));
    // Clamped here, where the height is known, so scrolling past the end
    // never piles up presses that take as many to undo.
    app.help_scroll = app.help_scroll.min(lines.len().saturating_sub(shown));
    let top = app.help_scroll;
    let body = Rect {
        height: shown as u16,
        ..inner
    };
    f.render_widget(Paragraph::new(lines[top..].to_vec()), body);
    let keys = Rect {
        y: inner.y + inner.height.saturating_sub(1),
        height: 1,
        ..inner
    };
    f.render_widget(Paragraph::new(box_hint(READER_KEYS)), keys);
    vscrollbar(f, rect, lines.len(), top, shown);
}
