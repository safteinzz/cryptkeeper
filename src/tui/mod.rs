//! The terminal UI bare `ck` opens on a terminal, in two tabs: Vaults (the
//! list, then every vault and LUKS drive found that it does not hold) and
//! This machine (what it can open, and installing what it lacks). The rows are read again every couple of seconds with the same
//! reads `ls` does. Every action runs the function its command runs, and the
//! screen steps aside only once a program asks on the terminal
//! (`out::hand_over`), then comes back with the result.

mod alert;
mod confirm;
mod detail;
mod filter;
mod form;
mod input;
mod line_edit;
mod picker;
mod render;
mod widgets;

use crate::check::{self, Check};
use crate::listing::{self, Entry};
use crate::run::Ran;
use crate::vault::{self, Kind, Vault};
use crate::{commands, out, registry, run, scan, settings, tilde};
use anyhow::{Result, bail};
use crossterm::event::{self, Event, KeyEventKind};
use crossterm::terminal::{self, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::{cursor, execute};
use form::{Form, Plan};
use input::is_ctrl_c;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::prelude::*;
use ratatui::widgets::ListState;
use std::fs;
use std::io::{self, Stdout, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

type Term = Terminal<CrosstermBackend<Stdout>>;

/// How often the rows are read again while nothing is pressed.
const READ_EVERY: Duration = Duration::from_secs(2);
/// How long a status line stays before the keys come back.
const STATUS_TTL: Duration = Duration::from_secs(3);
/// The widest one-line failure the status line takes; a longer one is an alert.
const STATUS_MAX: usize = 90;

/// The tabs, in the order Tab steps through them.
#[derive(Clone, Copy, PartialEq)]
enum View {
    Vaults,
    Check,
    Settings,
}

const VIEWS: [View; 3] = [View::Vaults, View::Check, View::Settings];

impl View {
    fn title(self) -> &'static str {
        match self {
            View::Vaults => "Vaults",
            View::Check => "This machine",
            View::Settings => "Settings",
        }
    }
}

/// A command a key asked for, run through the function `ck` runs for it.
enum Action {
    Unlock(PathBuf),
    Lock(PathBuf),
    Edit(PathBuf),
    Shell(PathBuf),
    Forget(PathBuf),
    Passwd(PathBuf),
    Backup(PathBuf),
    Delete(PathBuf),
    /// Lists a vault found, opening nothing.
    Add(PathBuf),
    Create {
        plan: Plan,
        identity: Option<PathBuf>,
    },
    /// Runs an install `ck check` names as the fix.
    Install(Vec<String>),
    /// Unlocks the gocryptfs vault in `cipher` into `at`, which lists it.
    OpenAt {
        cipher: PathBuf,
        at: PathBuf,
    },
}

impl Action {
    fn verb(&self) -> &'static str {
        match self {
            Action::Unlock(_) | Action::OpenAt { .. } => "unlock",
            Action::Lock(_) => "lock",
            Action::Edit(_) => "edit",
            Action::Shell(_) => "shell",
            Action::Forget(_) => "forget",
            Action::Passwd(_) => "password change",
            Action::Backup(_) => "backup",
            Action::Delete(_) => "delete",
            Action::Add(_) => "add",
            Action::Install(_) => "install",
            Action::Create { .. } => "create",
        }
    }

    /// The `ck` command that does the same, as it would be typed.
    fn command_line(&self) -> String {
        let word = |p: &Path| shell_word(&tilde(p));
        match self {
            Action::Unlock(p) => format!("ck unlock {}", word(p)),
            Action::Lock(p) => format!("ck lock {}", word(p)),
            Action::Edit(p) => format!("ck edit {}", word(p)),
            Action::Shell(p) => format!("ck shell {}", word(p)),
            Action::Forget(p) => format!("ck forget {}", word(p)),
            Action::Passwd(p) => format!("ck passwd {}", word(p)),
            Action::Backup(p) => format!("ck backup {}", word(p)),
            Action::Delete(p) => format!("ck delete {} --yes", word(p)),
            Action::Add(p) => format!("ck add {}", word(p)),
            Action::Install(argv) => argv.join(" "),
            Action::OpenAt { cipher, at } => {
                format!("ck unlock {} --at {}", word(cipher), word(at))
            }
            Action::Create { plan, identity } => {
                let mut line = match plan {
                    Plan::Luks {
                        path,
                        size: Some(size),
                        ..
                    } => format!("ck init --luks {} --size {size}", word(path)),
                    Plan::Luks { path, .. } => format!("ck init --luks {} --wipe", word(path)),
                    Plan::Init { name, dir, .. } => match dir {
                        Some(d) => format!("ck init {} --dir {}", shell_word(name), word(d)),
                        None => format!("ck init {}", shell_word(name)),
                    },
                };
                if let Some(id) = identity {
                    line.push_str(&format!(" -i {}", word(id)));
                }
                line
            }
        }
    }

    /// The vault it ends on, for the cursor to follow there.
    fn target(&self) -> Option<PathBuf> {
        let path = match self {
            Action::Unlock(p) | Action::Lock(p) | Action::Edit(p) | Action::Shell(p) => p.clone(),
            Action::Create {
                plan: Plan::Init { name, dir, .. },
                ..
            } => dir.clone().unwrap_or_default().join(name),
            Action::OpenAt { cipher, .. } => cipher.clone(),
            Action::Forget(_) | Action::Install(_) | Action::Delete(_) => return None,
            Action::Passwd(p) | Action::Backup(p) | Action::Add(p) => p.clone(),
            Action::Create {
                plan: Plan::Luks { path, .. },
                ..
            } => path.clone(),
        };
        std::path::absolute(path).ok()
    }

    /// Whether it makes a gocryptfs vault, whose master key gocryptfs prints
    /// on the terminal only this once.
    fn shows_master_key(&self) -> bool {
        matches!(
            self,
            Action::Create {
                plan: Plan::Init {
                    kind: Kind::Gocryptfs,
                    ..
                },
                ..
            }
        )
    }

    fn run(self) -> Result<()> {
        match self {
            Action::Unlock(p) => commands::unlock(Some(p), None, None, None, false),
            Action::OpenAt { cipher, at } => {
                commands::unlock(Some(cipher), None, None, Some(at), false)
            }
            Action::Lock(p) => commands::lock(Some(p), false, false),
            Action::Edit(p) => commands::edit(Some(p), None, false),
            Action::Shell(p) => commands::shell(Some(p), None, false),
            Action::Forget(p) => commands::forget(vec![p.display().to_string()], false),
            Action::Passwd(p) => commands::passwd(Some(p), false),
            Action::Backup(p) => commands::backup(Some(p), None, false),
            Action::Delete(p) => commands::delete(p, true, false),
            Action::Add(p) => commands::add(p, false),
            Action::Create {
                plan: Plan::Luks { path, size, wipe },
                ..
            } => commands::init_luks(path, size, wipe, false),
            Action::Install(argv) => {
                let line = argv.join(" ");
                let mut cmd = Command::new(&argv[0]);
                cmd.args(&argv[1..]);
                match run::prompting(&mut cmd) {
                    Ran::Done => {
                        say!("ran `{line}`");
                        Ok(())
                    }
                    Ran::Cancelled => bail!("cancelled, so nothing was installed"),
                    Ran::Failed(_) => bail!("`{line}` failed"),
                }
            }
            Action::Create {
                plan: Plan::Init { name, dir, .. },
                identity,
            } => commands::init(Some(name), dir, identity, false),
        }
    }
}

struct App {
    view: View,
    /// Every vault in the list, then every vault and LUKS drive found that
    /// it does not hold.
    entries: Vec<Entry>,
    /// How many of `entries` are in the list.
    listed: usize,
    /// The list as it was last read, for the create form's preview.
    known: Vec<Vault>,
    checks: Vec<Check>,
    vault_state: ListState,
    check_state: ListState,
    settings: settings::Settings,
    settings_state: ListState,
    form: Option<Form>,
    picker: Option<picker::Picker>,
    gate: Option<confirm::Gate>,
    typed: Option<confirm::Typed>,
    /// A failure that has to be read; it owns every key until closed.
    alert: Option<alert::Alert>,
    status: String,
    /// Whether the status is a failure, which is all that decides its colour.
    status_failed: bool,
    status_at: Option<Instant>,
    show_help: bool,
    /// The first help row on screen; the panel clamps it to the end.
    help_scroll: usize,
    should_quit: bool,
    /// What `/` filters the current list by; empty shows everything.
    query: String,
    /// The cursor in `query`, as characters after it.
    query_back: usize,
    /// Whether `/` is being typed, so keys go into the query.
    searching: bool,
    read_at: Instant,
    /// Why the list could not be read last time, so it is raised once.
    read_error: Option<String>,
    /// The vaults the last scan found that the list does not hold.
    found: Vec<Vault>,
    /// The checks and the scan still running, which hand over what they
    /// found when done.
    scanning: Option<Receiver<(Vec<Check>, Vec<Vault>)>>,
}

pub fn run() -> Result<()> {
    let restore = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        leave();
        restore(info);
    }));
    // Ctrl-C at a child's prompt must not take ck down with the terminal raw.
    run::catch_interrupts();
    let mut app = App::new();
    enter()?;
    let done = Terminal::new(CrosstermBackend::new(io::stdout()))
        .map_err(anyhow::Error::from)
        .and_then(|mut term| app.event_loop(&mut term));
    leave();
    done
}

fn enter() -> io::Result<()> {
    terminal::enable_raw_mode()?;
    execute!(io::stdout(), EnterAlternateScreen, cursor::Hide)
}

/// Gives the terminal back as it was, for a program, a panic or the exit.
fn leave() {
    let _ = terminal::disable_raw_mode();
    let _ = execute!(io::stdout(), LeaveAlternateScreen, cursor::Show);
}

impl App {
    fn new() -> App {
        let mut app = App {
            view: View::Vaults,
            entries: Vec::new(),
            listed: 0,
            known: Vec::new(),
            checks: Vec::new(),
            vault_state: ListState::default(),
            check_state: ListState::default(),
            settings: settings::load(),
            settings_state: ListState::default().with_selected(Some(0)),
            form: None,
            picker: None,
            gate: None,
            typed: None,
            alert: None,
            status: String::new(),
            status_failed: false,
            status_at: None,
            show_help: false,
            help_scroll: 0,
            should_quit: false,
            query: String::new(),
            query_back: 0,
            searching: false,
            read_at: Instant::now(),
            read_error: None,
            found: Vec::new(),
            scanning: None,
        };
        app.read();
        app.scan();
        if let Some(near) = app.nearest() {
            app.follow(Some(near));
        }
        app
    }

    fn event_loop(&mut self, term: &mut Term) -> Result<()> {
        while !self.should_quit {
            if let Some((checks, found)) = self.scanning.as_ref().and_then(|rx| rx.try_recv().ok())
            {
                self.checks = checks;
                self.found = found;
                self.scanning = None;
                self.read();
            }
            term.draw(|f| render::ui(f, self))?;
            let mut wait = READ_EVERY.saturating_sub(self.read_at.elapsed());
            // While a status shows or a scan runs, wake up soon enough to
            // take the status down on time and show the finds.
            if self.live_status().is_some() || self.scanning.is_some() {
                wait = wait.min(Duration::from_millis(200));
            }
            if !event::poll(wait)? {
                if self.read_at.elapsed() >= READ_EVERY {
                    self.read();
                }
                continue;
            }
            // crossterm also reports releases on some terminals; only a press acts.
            if let Event::Key(key) = event::read()?
                && key.kind == KeyEventKind::Press
                && let Some(action) = self.on_key(key)
            {
                self.act(term, action)?;
            }
        }
        Ok(())
    }

    /// Reads the list and every row again, keeping each tab's cursor on the
    /// row it was on, wherever that moved to.
    fn read(&mut self) {
        let keep = self.selected_vault().map(|e| e.cipher.clone());
        match registry::load() {
            Ok(known) => {
                self.listed = known.len();
                // A vault found and since deleted or moved is no longer found,
                // so it goes rather than turning `missing`.
                self.found
                    .retain(|v| fs::symlink_metadata(&v.cipher).is_ok());
                self.entries = listing::all(&known, &self.found);
                self.known = known;
                self.read_error = None;
            }
            Err(e) => {
                let why = e.to_string();
                if self.read_error.as_ref() != Some(&why) {
                    self.alert("the list cannot be read", format!("ck: {why}"));
                }
                self.read_error = Some(why);
                self.listed = 0;
                self.entries.clear();
                self.known.clear();
            }
        }
        let rows = self.vault_rows();
        let at = keep.and_then(|k| {
            rows.iter()
                .position(|r| r.is_some_and(|i| self.entries[i].cipher == k))
        });
        match at {
            Some(at) => self.vault_state.select(Some(at)),
            None => clamp(&mut self.vault_state, &landable(&rows)),
        }
        let slots = vec![true; self.check_rows().len()];
        clamp(&mut self.check_state, &slots);
        self.read_at = Instant::now();
    }

    /// Runs `ck check`'s probes and looks for vaults the list does not hold,
    /// off the loop, since a stuck udisks takes seconds to give up on and
    /// walking home takes a moment.
    fn scan(&mut self) {
        let known = self.known.clone();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let checks = check::all().into_iter().collect();
            let _ = tx.send((checks, scan::found(&known)));
        });
        self.scanning = Some(rx);
    }

    /// The vault nearest the current folder, as bare `ck` finds it.
    fn nearest(&self) -> Option<PathBuf> {
        let cwd = std::env::current_dir().ok()?;
        let found = vault::nearest(&cwd, &self.known).ok()??;
        Some(found.first()?.cipher.clone())
    }

    /// Runs `action` the way its command runs, then takes the terminal back
    /// when a program had it and says how it went.
    fn act(&mut self, term: &mut Term, action: Action) -> Result<()> {
        let cmd = action.command_line();
        let verb = action.verb();
        let target = action.target();
        let master_key = action.shows_master_key();
        let rescan = matches!(action, Action::Install(_) | Action::Delete(_));
        let (done, got) = out::capture(leave, || action.run());
        if got.left {
            if done.is_ok() && master_key {
                wait_for_key(
                    "gocryptfs printed the master key above, and only this once: keep it somewhere safe, then press a key to go back to ck",
                )?;
            }
            enter()?;
            term.clear()?;
        }
        match done {
            Ok(()) => {
                let said = got.lines.last().cloned();
                self.set_status(said.unwrap_or_else(|| format!("{verb}: done")));
            }
            Err(e) => self.report_failure(verb, &cmd, &e.to_string(), &got.heard),
        }
        self.read();
        self.follow(target);
        if rescan {
            self.scan();
        }
        Ok(())
    }

    /// Says a failure where it fits: a short line on its own is the status
    /// line, and anything with the program's own words, several lines or too
    /// long for the bar is an alert, the one place the command fits too.
    fn report_failure(&mut self, verb: &str, cmd: &str, err: &str, heard: &str) {
        // A cancel needs no reading, and its prompt is all the program said.
        let said: Vec<&str> = match run::interrupted() {
            true => Vec::new(),
            false => heard
                .lines()
                .map(str::trim_end)
                .filter(|l| !l.trim().is_empty() && !l.ends_with(':'))
                .collect(),
        };
        let said = &said[said.len().saturating_sub(5)..];
        let line = format!("ck: {err}");
        if said.is_empty() && !err.contains('\n') && line.chars().count() <= STATUS_MAX {
            self.set_failed(err);
            return;
        }
        let mut body = format!("{cmd}\n\n");
        for l in said {
            body.push_str(l);
            body.push('\n');
        }
        body.push_str(&line);
        self.alert(format!("{verb} failed"), body);
    }

    /// Puts the cursor on the listed vault `target` names, as a drive just
    /// unlocked or a vault just made is now.
    fn follow(&mut self, target: Option<PathBuf>) {
        let Some(target) = target else { return };
        let real = fs::canonicalize(&target).ok();
        let is = |e: &Entry| {
            e.name == target
                || e.cipher == target
                || (real.is_some() && fs::canonicalize(&e.cipher).ok() == real)
        };
        let Some(i) = (0..self.listed).find(|&i| is(&self.entries[i])) else {
            return;
        };
        if self.view != View::Vaults {
            self.goto_view(View::Vaults);
        }
        if let Some(pos) = self.vault_rows().iter().position(|&r| r == Some(i)) {
            self.vault_state.select(Some(pos));
        }
    }

    /// Sets the status line for what worked; it fades after `STATUS_TTL`.
    fn set_status(&mut self, msg: impl Into<String>) {
        self.status = msg.into();
        self.status_at = Some(Instant::now());
        self.status_failed = false;
    }

    /// The same line for what did not work, in yellow: red is for a gate in
    /// front of something about to be lost, and this already happened.
    fn set_failed(&mut self, msg: impl Into<String>) {
        self.set_status(msg);
        self.status_failed = true;
    }

    /// The status while it is fresh.
    fn live_status(&self) -> Option<&str> {
        let at = self.status_at?;
        (at.elapsed() < STATUS_TTL && !self.status.is_empty()).then_some(self.status.as_str())
    }

    fn entry_matches(&self, e: &Entry) -> bool {
        let name = tilde(&e.name);
        let cipher = tilde(&e.cipher);
        filter::matches(
            &self.query,
            &[&name, e.kind.word(), e.state, &e.note, &cipher],
        )
    }

    /// The rows of Vaults the query keeps, as indices into `entries`: the
    /// listed vaults, then `None` for the `found on this machine` heading and
    /// the vaults and drives found that the list does not hold, when there
    /// are any.
    fn vault_rows(&self) -> Vec<Option<usize>> {
        let keep = |from: usize, to: usize| {
            (from..to)
                .filter(|&i| self.entry_matches(&self.entries[i]))
                .map(Some)
                .collect::<Vec<_>>()
        };
        let mut rows = keep(0, self.listed);
        let found = keep(self.listed, self.entries.len());
        if !found.is_empty() {
            rows.push(None);
            rows.extend(found);
        }
        rows
    }

    fn check_rows(&self) -> Vec<usize> {
        (0..self.checks.len())
            .filter(|&i| {
                let c = &self.checks[i];
                let fix = c.fix.as_deref().unwrap_or("");
                filter::matches(&self.query, &[c.kind.word(), c.state, &c.detail, fix])
            })
            .collect()
    }

    /// How many rows the query keeps on the current tab, headings aside.
    fn row_count(&self) -> usize {
        match self.view {
            View::Vaults => self.vault_rows().iter().flatten().count(),
            View::Check => self.check_rows().len(),
            View::Settings => self.setting_rows().len(),
        }
    }

    /// The settings the query keeps.
    fn setting_rows(&self) -> Vec<settings::Row> {
        self.settings
            .rows()
            .into_iter()
            .filter(|r| filter::matches(&self.query, &[r.label, r.key, &r.value, r.help]))
            .collect()
    }

    fn selected_setting(&self) -> Option<settings::Row> {
        self.setting_rows()
            .into_iter()
            .nth(self.settings_state.selected()?)
    }

    /// Changes setting `key` with `change` and writes the file at once, so
    /// there is nothing unsaved to lose; checks again when what drives go
    /// through moved.
    fn change_setting(
        &mut self,
        key: &str,
        change: impl FnOnce(&mut settings::Settings) -> anyhow::Result<()>,
    ) {
        let done = change(&mut self.settings).and_then(|()| self.settings.save());
        match done {
            Ok(()) => {
                let row = self.settings.rows().into_iter().find(|r| r.key == key);
                if let Some(r) = row {
                    self.set_status(format!("{}: {}", r.label, r.value));
                }
                if key == "luks" {
                    self.scan();
                }
            }
            Err(e) => {
                // Read back, so the screen never shows a value that was not saved.
                self.settings = settings::load();
                self.set_failed(e.to_string());
            }
        }
    }

    /// Which rows of the current tab the cursor may rest on.
    fn slots(&self) -> Vec<bool> {
        match self.view {
            View::Vaults => landable(&self.vault_rows()),
            View::Check => vec![true; self.check_rows().len()],
            View::Settings => vec![true; self.setting_rows().len()],
        }
    }

    // A selection indexes the filtered rows, so every lookup goes through
    // them, or a hidden row would have the wrong one acted on.
    fn selected_vault(&self) -> Option<&Entry> {
        let row = *self.vault_rows().get(self.vault_state.selected()?)?;
        row.map(|i| &self.entries[i])
    }

    fn selected_entry(&self) -> Option<&Entry> {
        match self.view {
            View::Vaults => self.selected_vault(),
            View::Check | View::Settings => None,
        }
    }

    fn selected_check(&self) -> Option<&Check> {
        let i = *self.check_rows().get(self.check_state.selected()?)?;
        self.checks.get(i)
    }

    /// What `ck check` says about vaults of `kind` on this machine.
    fn check_of(&self, kind: Kind) -> Option<&Check> {
        self.checks.iter().find(|c| c.kind == kind)
    }

    fn state_of(&mut self, view: View) -> &mut ListState {
        match view {
            View::Vaults => &mut self.vault_state,
            View::Check => &mut self.check_state,
            View::Settings => &mut self.settings_state,
        }
    }

    /// Moves the cursor by `delta`, wrapping at either end and stepping
    /// over a heading.
    fn move_sel(&mut self, delta: i32) {
        let slots = self.slots();
        if !slots.contains(&true) {
            return;
        }
        let len = slots.len() as i32;
        let state = self.state_of(self.view);
        let mut at = state.selected().unwrap_or(0) as i32;
        loop {
            at = (at + delta).rem_euclid(len);
            if slots[at as usize] {
                break;
            }
        }
        state.select(Some(at as usize));
    }

    /// Moves the cursor to row `row`, or the last one when it is past the end.
    fn move_to(&mut self, row: usize) {
        let slots = self.slots();
        let state = self.state_of(self.view);
        state.select(Some(row));
        clamp(state, &slots);
    }

    fn cycle_view(&mut self, delta: i32) {
        let i = VIEWS.iter().position(|v| *v == self.view).unwrap_or(0) as i32;
        let next = (i + delta).rem_euclid(VIEWS.len() as i32) as usize;
        self.goto_view(VIEWS[next]);
    }

    /// Shows `view`. The filter belongs to the list it was typed over, so it
    /// is dropped rather than left hiding rows on the next.
    fn goto_view(&mut self, view: View) {
        self.view = view;
        if !self.query.is_empty() || self.searching {
            self.query.clear();
            self.query_back = 0;
            self.searching = false;
            self.requery();
        }
    }

    /// Puts every cursor on the first row the query keeps.
    fn requery(&mut self) {
        for view in VIEWS {
            self.state_of(view).select(Some(0));
        }
        let slots = landable(&self.vault_rows());
        clamp(&mut self.vault_state, &slots);
        let slots = vec![true; self.check_rows().len()];
        clamp(&mut self.check_state, &slots);
        let slots = vec![true; self.setting_rows().len()];
        clamp(&mut self.settings_state, &slots);
    }
}

/// Which of `rows` the cursor may rest on: every one but a heading.
fn landable(rows: &[Option<usize>]) -> Vec<bool> {
    rows.iter().map(Option::is_some).collect()
}

/// Keeps a selection on a row in `slots` the cursor may rest on, the nearest
/// one at or after it, else before it, and none when there is none.
fn clamp(state: &mut ListState, slots: &[bool]) {
    let at = state
        .selected()
        .unwrap_or(0)
        .min(slots.len().saturating_sub(1));
    let near = (at..slots.len())
        .find(|&i| slots[i])
        .or_else(|| (0..at).rev().find(|&i| slots[i]));
    state.select(near);
}

/// The word Vaults uses for what a vault is, in place of its tool.
fn kind_word(e: &Entry) -> &'static str {
    match e.kind {
        Kind::Gocryptfs => "folder",
        Kind::Age => "file",
        Kind::Luks if e.cipher.starts_with("/dev") => "drive",
        Kind::Luks => "image",
    }
}

/// What This machine calls each kind, and what it is for.
fn kind_about(kind: Kind) -> (&'static str, &'static str) {
    match kind {
        Kind::Gocryptfs => (
            "Encrypted folders",
            "a folder whose files are stored encrypted",
        ),
        Kind::Luks => ("Encrypted drives", "a whole drive or disk image, encrypted"),
        Kind::Age => ("Encrypted files", "one file, encrypted on its own"),
    }
}

/// How a vault state word is drawn.
fn state_style(state: &str) -> Style {
    match state {
        "open" => Style::default().fg(Color::Green),
        "dead" => Style::default().fg(Color::Yellow),
        "exposed" => Style::default().fg(Color::Red),
        "missing" => Style::default().add_modifier(Modifier::DIM),
        _ => Style::default(),
    }
}

/// How a `ck check` state word is drawn.
fn check_style(state: &str) -> Style {
    match state {
        "ready" => Style::default().fg(Color::Green),
        "missing" => Style::default().fg(Color::Red),
        "blocked" => Style::default().fg(Color::Yellow),
        _ => Style::default().add_modifier(Modifier::DIM),
    }
}

/// The mark in front of a `ck check` row.
fn check_mark(state: &str) -> &'static str {
    match state {
        "ready" => "✓",
        "unchecked" => "?",
        _ => "✗",
    }
}

/// `~/x` as a path under the home folder, anything else as typed.
fn expand(typed: &str) -> PathBuf {
    let home = || dirs::home_dir().unwrap_or_default();
    match typed.strip_prefix("~/") {
        Some(rest) => home().join(rest),
        None if typed == "~" => home(),
        None => PathBuf::from(typed),
    }
}

/// `s` as one shell word: as it is when nothing in it needs quoting, else
/// single-quoted, with a leading `~/` left outside so it still means home.
fn shell_word(s: &str) -> String {
    let plain = |t: &str| {
        !t.is_empty()
            && t.chars()
                .all(|c| c.is_alphanumeric() || "/._-+=:@%,~".contains(c))
    };
    if plain(s) {
        return s.to_string();
    }
    let (head, rest) = match s.strip_prefix("~/") {
        Some(rest) => ("~/", rest),
        None => ("", s),
    };
    format!("{head}'{}'", rest.replace('\'', r"'\''"))
}

/// Waits on the plain terminal for one key after `why`, so the lines above
/// it can be read before the screen is taken back.
fn wait_for_key(why: &str) -> io::Result<()> {
    print!("\n{why} ");
    io::stdout().flush()?;
    terminal::enable_raw_mode()?;
    let read = loop {
        match event::read() {
            Ok(Event::Key(k)) if k.kind == KeyEventKind::Press => break Ok(()),
            Ok(_) => {}
            Err(e) => break Err(e),
        }
    };
    terminal::disable_raw_mode()?;
    println!();
    read
}
