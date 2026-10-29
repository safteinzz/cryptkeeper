//! Key dispatch: help, then whichever box is up, then the `/` query, then the
//! keys every tab shares, then the tab's own.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::confirm::{Gate, Typed};
use super::form::Form;
use super::picker::Picker;
use super::{Action, App, View, line_edit};
use crate::vault::Kind;

/// Ctrl-C, which is Esc under a box or in a form and quits from a tab.
pub(super) fn is_ctrl_c(key: KeyEvent) -> bool {
    key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c')
}

impl App {
    /// Handles one key, returning the command it asks to run.
    pub(super) fn on_key(&mut self, key: KeyEvent) -> Option<Action> {
        if self.show_help {
            self.help_key(key);
            return None;
        }
        // An alert owns every key until it is closed: it holds the only copy
        // of why something failed.
        if self.alert.is_some() {
            self.alert_key(key);
            return None;
        }
        if self.gate.is_some() {
            return self.gate_key(key);
        }
        if self.typed.is_some() {
            return self.typed_key(key);
        }
        if self.picker.is_some() {
            self.picker_key(key);
            return None;
        }
        if self.form.is_some() {
            return self.form_key(key);
        }
        if self.searching {
            self.search_key(key);
            return None;
        }
        self.nav_key(key)
    }

    fn help_key(&mut self, key: KeyEvent) {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let half = 10;
        match key.code {
            _ if is_ctrl_c(key) => self.show_help = false,
            KeyCode::Char('?' | 'q') | KeyCode::Esc => self.show_help = false,
            KeyCode::Char('d') if ctrl => self.help_scroll += half,
            KeyCode::Char('u') if ctrl => self.help_scroll = self.help_scroll.saturating_sub(half),
            KeyCode::PageDown => self.help_scroll += half,
            KeyCode::PageUp => self.help_scroll = self.help_scroll.saturating_sub(half),
            KeyCode::Char('j') | KeyCode::Down => self.help_scroll += 1,
            KeyCode::Char('k') | KeyCode::Up => {
                self.help_scroll = self.help_scroll.saturating_sub(1)
            }
            KeyCode::Char('g') | KeyCode::Home => self.help_scroll = 0,
            // The panel clamps this to its last screenful.
            KeyCode::Char('G') | KeyCode::End => self.help_scroll = usize::MAX,
            _ => {}
        }
    }

    /// Typing a `/` query: every letter goes into it, so this runs before the
    /// tab's keys. Enter keeps it and hands the keys back to the list; Esc and
    /// Ctrl-C drop it.
    fn search_key(&mut self, key: KeyEvent) {
        if key.code == KeyCode::Esc || is_ctrl_c(key) {
            self.query.clear();
            self.query_back = 0;
            self.searching = false;
            self.requery();
            return;
        }
        match key.code {
            KeyCode::Enter => self.searching = false,
            KeyCode::Down => self.move_sel(1),
            KeyCode::Up => self.move_sel(-1),
            _ => {
                if line_edit::edit(&mut self.query, &mut self.query_back, key) {
                    self.requery();
                }
            }
        }
    }

    fn nav_key(&mut self, key: KeyEvent) -> Option<Action> {
        if is_ctrl_c(key) {
            self.should_quit = true;
            return None;
        }
        // Every other chord is left alone, so `ctrl-…` never fires a letter's action.
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            return None;
        }
        match key.code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Char('?') => {
                self.show_help = true;
                self.help_scroll = 0;
            }
            // Each `/` starts a new query rather than adding to the kept one.
            KeyCode::Char('/') => {
                self.query.clear();
                self.query_back = 0;
                self.searching = true;
                self.requery();
            }
            KeyCode::Esc if !self.query.is_empty() => {
                self.query.clear();
                self.requery();
                self.set_status("filter cleared");
            }
            KeyCode::Tab | KeyCode::Right | KeyCode::Char('l') => self.cycle_view(1),
            KeyCode::BackTab | KeyCode::Left | KeyCode::Char('h') => self.cycle_view(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_sel(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_sel(-1),
            KeyCode::Home | KeyCode::Char('g') => self.move_to(0),
            KeyCode::End | KeyCode::Char('G') => self.move_to(usize::MAX),
            KeyCode::Char('r') => {
                self.settings = crate::settings::load();
                self.read();
                self.scan();
                self.set_status("vaults read and this machine checked again");
            }
            _ => {
                return match self.view {
                    View::Vaults => self.vaults_key(key),
                    View::Check => self.machine_key(key),
                    View::Settings => self.settings_key(key),
                };
            }
        }
        None
    }

    fn vaults_key(&mut self, key: KeyEvent) -> Option<Action> {
        let picked = self
            .selected_entry()
            .map(|e| (e.kind, e.name.clone(), e.listed));
        match key.code {
            KeyCode::Enter => self.enter_key(),
            KeyCode::Char('s') => picked.map(|(_, name, _)| Action::Shell(name)),
            KeyCode::Char('p') => picked.map(|(_, name, _)| Action::Passwd(name)),
            KeyCode::Char('a') => match picked? {
                (_, name, false) => Some(Action::Add(name)),
                (_, name, true) => {
                    self.set_status(format!(
                        "`{}` is in your vaults already",
                        crate::tilde(&name)
                    ));
                    None
                }
            },
            KeyCode::Char('b') => picked.map(|(_, name, _)| Action::Backup(name)),
            KeyCode::Char('c') => {
                self.picker = Some(Picker::create());
                None
            }
            KeyCode::Char('e') => match picked? {
                (Kind::Age, name, _) => Some(Action::Edit(name)),
                _ => {
                    self.set_failed("`e` edits age files: `s` opens a shell in this one");
                    None
                }
            },
            KeyCode::Char('f') => match picked? {
                (_, name, true) => Some(Action::Forget(name)),
                (_, name, false) => {
                    self.set_failed(format!(
                        "`{}` is not in the list, so there is nothing to forget",
                        crate::tilde(&name)
                    ));
                    None
                }
            },
            KeyCode::Char('d') => {
                let e = self.selected_entry()?;
                let gate = Typed::delete(e);
                let (name, state, drive) = (
                    e.name.clone(),
                    e.state,
                    e.kind == Kind::Luks && e.cipher.starts_with("/dev"),
                );
                let shown = crate::tilde(&name);
                match state {
                    _ if drive => {
                        self.set_failed("a drive is never deleted: `f` only drops it from the list")
                    }
                    "locked" => self.typed = Some(gate),
                    "missing" => self.set_failed(format!(
                        "`{shown}` is missing, so there is nothing to delete: `f` forgets it"
                    )),
                    _ => {
                        self.set_failed(format!("`{shown}` is open: lock it first, then delete it"))
                    }
                }
                None
            }
            _ => None,
        }
    }

    /// Settings: Enter steps a picked one or opens a form for a typed one,
    /// `d` puts it back as ck ships it; each change is saved at once.
    fn settings_key(&mut self, key: KeyEvent) -> Option<Action> {
        let row = self.selected_setting()?;
        match key.code {
            KeyCode::Enter if row.choices.is_some() => {
                self.change_setting(row.key, |s| s.cycle(row.key));
            }
            KeyCode::Enter => self.form = Some(Form::setting(&row)),
            KeyCode::Char('d') => self.change_setting(row.key, |s| s.reset(row.key)),
            _ => {}
        }
        None
    }

    /// This machine: Enter offers to run the install a missing kind names.
    fn machine_key(&mut self, key: KeyEvent) -> Option<Action> {
        if key.code != KeyCode::Enter {
            return None;
        }
        let c = self.selected_check()?;
        let what = super::kind_about(c.kind).0.to_lowercase();
        match c.command() {
            Some(argv) => self.gate = Some(Gate::install(&what, argv)),
            None if c.state == "ready" => self.set_status(format!("{what} work here already")),
            None => {
                let fix = c.fix.clone().unwrap_or_else(|| c.detail.clone());
                self.set_failed(format!("ck cannot do this one for you: {fix}"));
            }
        }
        None
    }

    /// Enter: unlocks what is closed, locks what is open and ck may lock,
    /// and first asks where a gocryptfs folder opens when ck cannot tell.
    fn enter_key(&mut self) -> Option<Action> {
        let e = self.selected_entry()?;
        let (name, note) = (e.name.clone(), e.note.clone());
        // A vault found is taken on only by `a`, so Enter never lists one by surprise.
        if !e.listed {
            self.set_failed(format!(
                "`{}` is not in your vaults yet: `a` adds it",
                crate::tilde(&name)
            ));
            return None;
        }
        if e.kind == Kind::Gocryptfs && e.view.as_os_str().is_empty() && e.state == "locked" {
            let cipher = e.cipher.clone();
            let guess = crate::scan::opened_before(&cipher);
            self.form = Some(Form::open_at(cipher, guess));
            return None;
        }
        match e.state {
            "locked" | "dead" | "missing" => Some(Action::Unlock(name)),
            _ if e.lockable => Some(Action::Lock(name)),
            _ => {
                self.set_failed(format!("ck leaves this one alone: {note}"));
                None
            }
        }
    }
}
