//! The forms: the four `c` offers (a file to encrypt, a new encrypted
//! folder, a new LUKS image or drive, a vault you already have to list), the
//! folder a gocryptfs vault ck found opens into, and a typed setting. Each shows the `ck` command it will run while it is
//! typed.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::prelude::*;
use ratatui::widgets::{Clear, Paragraph, Wrap};
use std::fs;
use std::path::{Path, PathBuf};

use super::widgets::{
    FORM_KEYS, REQUIRED, SEP, box_area, box_block, box_height, box_hint, box_inner_width,
    box_width, wrapped_line_count,
};
use super::{Action, App, expand, is_ctrl_c, line_edit};
use crate::vault::{self, Kind, Vault};

struct Field {
    label: &'static str,
    /// What a blank submits, shown dim while the field is empty.
    default: &'static str,
    /// What the field takes, shown dim after `default` while it is empty.
    hint: &'static str,
    value: String,
    /// The cursor in `value`, as characters after it.
    back: usize,
    /// The submit refuses a blank here, so the label carries a red `*`.
    required: bool,
}

impl Field {
    fn placeholder(&self) -> String {
        [self.default, self.hint]
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join("  ")
    }
}

pub(super) struct Form {
    fields: Vec<Field>,
    /// The field the cursor is in.
    idx: usize,
    purpose: Purpose,
}

enum Purpose {
    /// A new gocryptfs folder.
    NewFolder,
    /// A new LUKS image file, or a drive formatted as one.
    NewLuks,
    /// An existing file encrypted into an age vault.
    EncryptFile,
    /// A vault that exists, unlocked so it is listed.
    AddExisting,
    /// The folder the gocryptfs vault in this encrypted folder opens into.
    OpenAt(PathBuf),
    /// A typed setting, by its word in the file.
    Setting(&'static str),
}

const PATH: usize = 0;
const IDENTITY: usize = 1;

/// The column the values start in, measured from the label, pushed out no
/// further than `LABEL_COL_MAX` by a long label.
const LABEL_COL: usize = 14;
const LABEL_COL_MAX: usize = 22;

fn field(label: &'static str, default: &'static str, hint: &'static str) -> Field {
    Field {
        label,
        default,
        hint,
        value: String::new(),
        back: 0,
        required: default.is_empty(),
    }
}

/// The identity field of a form that may make or open an age vault.
fn identity_field() -> Field {
    field("Identity", "a passphrase", "or type a key file")
}

impl Form {
    fn of(purpose: Purpose, fields: Vec<Field>) -> Form {
        Form {
            fields,
            idx: PATH,
            purpose,
        }
    }

    pub(super) fn new_folder() -> Form {
        Form::of(
            Purpose::NewFolder,
            vec![field("Folder", "", "a new folder, e.g. ~/private")],
        )
    }

    pub(super) fn new_luks() -> Form {
        Form::of(
            Purpose::NewLuks,
            vec![
                field(
                    "Path",
                    "",
                    "ctrl-o to pick a drive · or type an image, e.g. ~/vault.img",
                ),
                field("Size", "1G", "for an image, e.g. 500M or 4G"),
            ],
        )
    }

    pub(super) fn encrypt_file() -> Form {
        Form::of(
            Purpose::EncryptFile,
            vec![
                field("File", "", "a file to encrypt, e.g. ~/taxes.pdf"),
                identity_field(),
            ],
        )
    }

    pub(super) fn add_existing() -> Form {
        Form::of(
            Purpose::AddExisting,
            vec![field(
                "Path",
                "",
                "a vault, a drive or an image, e.g. ~/photos",
            )],
        )
    }

    /// Asks where the gocryptfs vault in `cipher` opens, starting from
    /// `guess` (where shell history last opened it).
    pub(super) fn open_at(cipher: PathBuf, guess: Option<PathBuf>) -> Form {
        let mut folder = field("Folder", "", "an empty folder, made when it is not there");
        folder.value = guess.map(|g| crate::tilde(&g)).unwrap_or_default();
        Form::of(Purpose::OpenAt(cipher), vec![folder])
    }

    /// Whether Ctrl-O picks a drive here: on the LUKS form's path.
    fn picks_drive(&self) -> bool {
        matches!(self.purpose, Purpose::NewLuks) && self.idx == PATH
    }

    /// Fills `path` in as the path, with the cursor after it.
    pub(super) fn set_path(&mut self, path: &str) {
        self.fields[PATH].value = path.to_string();
        self.fields[PATH].back = 0;
    }

    /// Asks for a new value of the typed setting `row`, starting from its own.
    pub(super) fn setting(row: &crate::settings::Row) -> Form {
        let mut value = field(row.label, "", row.help);
        value.value = row.value.clone();
        Form::of(Purpose::Setting(row.key), vec![value])
    }

    fn identity(&self) -> Option<PathBuf> {
        if !matches!(self.purpose, Purpose::EncryptFile) {
            return None;
        }
        let typed = self.fields.get(IDENTITY)?.value.trim();
        (!typed.is_empty()).then(|| expand(typed))
    }

    /// What submitting the form as it is would run, or why it would not:
    /// empty while nothing is typed yet, else the words the form shows.
    fn check(&self, known: &[Vault]) -> Result<Action, String> {
        let typed = self.fields[PATH].value.trim();
        if typed.is_empty() {
            return Err(String::new());
        }
        let path = if typed.starts_with("UUID=") {
            PathBuf::from(typed)
        } else {
            std::path::absolute(expand(typed)).unwrap_or_else(|_| expand(typed))
        };
        let shown = crate::tilde(&path);
        let meta = fs::symlink_metadata(&path).ok();
        let is_dir = meta.as_ref().is_some_and(|m| m.is_dir());
        let is_file = meta.as_ref().is_some_and(|m| m.is_file());
        let parent_there = path.parent().is_some_and(|d| d.is_dir());
        let plan = match &self.purpose {
            Purpose::NewFolder => {
                if meta.is_some() && !is_dir {
                    return Err(format!("`{shown}` is a file: pick Encrypt a file for it"));
                }
                if is_dir && fs::read_dir(&path).is_ok_and(|mut d| d.next().is_some()) {
                    return Err(format!(
                        "`{shown}` already has files in it: name a new folder"
                    ));
                }
                if !parent_there {
                    return Err(format!("the folder `{shown}` goes in does not exist"));
                }
                init(&path, Kind::Gocryptfs)
                    .ok_or_else(|| format!("`{shown}` cannot name a folder"))?
            }
            Purpose::NewLuks => {
                let drive = meta.as_ref().is_some_and(crate::luks::is_block);
                if meta.is_some() && !drive {
                    return Err(format!(
                        "`{shown}` exists already: name a new image file, or ctrl-o to pick a drive"
                    ));
                }
                let size = match self.fields[1].value.trim() {
                    "" => "1G".to_string(),
                    s => s.to_string(),
                };
                if !drive {
                    if !parent_there {
                        return Err(format!("the folder `{shown}` goes in does not exist"));
                    }
                    match crate::luks::parse_size(&size) {
                        None => {
                            return Err(format!(
                                "`{size}` is not a size: write it with a unit, like 500M or 4G"
                            ));
                        }
                        Some(n) if n < crate::luks::MIN_IMAGE => {
                            return Err(
                                "an image needs at least 32M: the LUKS header alone takes 16M"
                                    .into(),
                            );
                        }
                        Some(_) => {}
                    }
                }
                Plan::Luks {
                    path,
                    size: (!drive).then_some(size),
                    wipe: drive,
                }
            }
            Purpose::EncryptFile => {
                if meta.is_none() {
                    return Err(format!("`{shown}` does not exist: check the name"));
                }
                if !is_file {
                    return Err(format!(
                        "`{shown}` is not a file: pick New encrypted folder for a folder"
                    ));
                }
                init(&path, Kind::Age).ok_or_else(|| format!("`{shown}` cannot be encrypted"))?
            }
            Purpose::AddExisting => {
                // Resolved first: a gocryptfs view not made yet still names
                // its vault through the `.<name>` beside it.
                let names = typed.starts_with("UUID=")
                    || vault::resolve(&path, "unlock", known)
                        .is_ok_and(|v| vault::is_named_by(&v, &path));
                if !names && meta.is_none() {
                    return Err(format!("`{shown}` does not exist: check the name"));
                }
                if !names {
                    return Err(format!(
                        "`{shown}` is no vault ck can open: a gocryptfs folder, a LUKS drive or image, or an age file"
                    ));
                }
                // Listed as it is: opening it is Enter's job afterwards.
                return Ok(Action::Add(path));
            }
            Purpose::Setting(_) => return Err(String::new()),
            Purpose::OpenAt(cipher) => {
                return Ok(Action::OpenAt {
                    cipher: cipher.clone(),
                    at: path,
                });
            }
        };
        Ok(Action::Create {
            plan,
            identity: self.identity(),
        })
    }
}

/// What a create form runs.
pub(super) enum Plan {
    /// Makes a vault called `name` in `dir` (the current folder when `None`):
    /// a gocryptfs folder, or an age vault from the existing file `name`.
    Init {
        name: String,
        dir: Option<PathBuf>,
        kind: Kind,
    },
    /// Makes a LUKS vault: a new image of `size`, or with `wipe` the drive
    /// `path` names.
    Luks {
        path: PathBuf,
        size: Option<String>,
        wipe: bool,
    },
}

/// `ck init` making a `kind` vault at `path`.
fn init(path: &Path, kind: Kind) -> Option<Plan> {
    let name = path.file_name()?.to_string_lossy().into_owned();
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .map(Path::to_path_buf);
    Some(Plan::Init { name, dir, kind })
}

impl App {
    /// Keys while the form is up: Enter steps to the next field and submits on
    /// the last, Tab and Ctrl-j/k move between fields, Esc and Ctrl-C cancel,
    /// and everything else edits the field.
    pub(super) fn form_key(&mut self, key: KeyEvent) -> Option<Action> {
        let form = self.form.as_mut()?;
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let n = form.fields.len();
        match key.code {
            _ if is_ctrl_c(key) => self.form = None,
            KeyCode::Esc => self.form = None,
            KeyCode::Enter if form.idx + 1 < n => form.idx += 1,
            KeyCode::Enter => return self.submit_form(),
            KeyCode::Tab | KeyCode::Down => form.idx = (form.idx + 1) % n,
            KeyCode::Char('j') if ctrl => form.idx = (form.idx + 1) % n,
            KeyCode::BackTab | KeyCode::Up => form.idx = (form.idx + n - 1) % n,
            KeyCode::Char('k') if ctrl => form.idx = (form.idx + n - 1) % n,
            KeyCode::Char('o') if ctrl && form.picks_drive() => {
                match super::picker::Picker::drives() {
                    Some(p) => self.picker = Some(p),
                    None => self.set_failed("no drive ck could format is plugged in"),
                }
            }
            _ => {
                let field = &mut form.fields[form.idx];
                line_edit::edit(&mut field.value, &mut field.back, key);
            }
        }
        None
    }

    fn submit_form(&mut self) -> Option<Action> {
        let form = self.form.as_mut()?;
        if let Purpose::Setting(key) = form.purpose {
            let value = form.fields[PATH].value.trim().to_string();
            // Checked on a throwaway first, so a refused value keeps the form open.
            if let Err(e) = crate::settings::Settings::default().set(key, &value) {
                self.set_failed(e.to_string());
                return None;
            }
            self.form = None;
            self.change_setting(key, |s| s.set(key, &value));
            return None;
        }
        let action = match form.check(&self.known) {
            Ok(action) => action,
            Err(why) => {
                form.idx = PATH;
                let why = match why.is_empty() {
                    true => "type a path first".to_string(),
                    false => why,
                };
                self.set_failed(why);
                return None;
            }
        };
        self.form = None;
        // A drive formatted is everything on it gone, so its name is typed first.
        let wiped = match &action {
            Action::Create {
                plan: Plan::Luks {
                    path, wipe: true, ..
                },
                ..
            } => Some(path.clone()),
            _ => None,
        };
        if let Some(dev) = wiped {
            self.typed = Some(super::confirm::Typed::wipe(&dev, action));
            return None;
        }
        Some(action)
    }
}

/// The columns a label cell takes: the label, its star and the colon.
fn label_width(field: &Field) -> usize {
    field.label.chars().count() + usize::from(field.required) + 1
}

/// The form box: labels in one column and values in another, a note, then
/// the command the path would run.
pub(super) fn render_form(f: &mut Frame, area: Rect, form: &Form, known: &[Vault]) {
    let dim = Style::default().add_modifier(Modifier::DIM);
    let col = (form.fields.iter().map(label_width).max().unwrap_or(0) + 2)
        .clamp(LABEL_COL, LABEL_COL_MAX);
    let mut lines: Vec<Line> = Vec::new();
    // The plain text of every line, so the box is sized by what they wrap to.
    let mut texts: Vec<String> = Vec::new();
    for (i, field) in form.fields.iter().enumerate() {
        let active = i == form.idx;
        let label_style = if active {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            dim
        };
        let mark = if active { "▸ " } else { "  " };
        let star = if field.required { "*" } else { "" };
        let pad = " ".repeat(col.saturating_sub(label_width(field)).max(1));
        let mut spans = vec![
            Span::raw(mark),
            Span::styled(field.label, label_style),
            Span::styled(star, Style::default().fg(Color::Red)),
            Span::styled(format!(":{pad}"), label_style),
        ];
        let shown = if field.value.is_empty() {
            let placeholder = field.placeholder();
            spans.push(Span::raw(if active { "█ " } else { "" }));
            spans.push(Span::styled(placeholder.clone(), dim));
            format!("  {placeholder}")
        } else if active {
            spans.extend(line_edit::with_cursor(
                &field.value,
                field.back,
                Style::default(),
            ));
            format!("{} ", field.value)
        } else {
            spans.push(Span::raw(field.value.clone()));
            field.value.clone()
        };
        texts.push(format!("{mark}{}{star}:{pad}{shown}", field.label));
        lines.push(Line::from(spans));
    }
    let (title, note) = match &form.purpose {
        Purpose::NewFolder => (
            "new encrypted folder".to_string(),
            "gocryptfs makes it and asks for its password twice. What you put in it is stored encrypted, and locked it reads as nothing.",
        ),
        Purpose::NewLuks => (
            "new encrypted drive or image".to_string(),
            "cryptsetup asks the passphrase twice and once more, and sudo for your password, since only root may open it to make the filesystem inside. A drive is wiped.",
        ),
        Purpose::EncryptFile => (
            "encrypt a file".to_string(),
            "age encrypts it into <file>.age, then deletes the original, without wiping it. With no identity it asks the passphrase three times.",
        ),
        Purpose::AddExisting => (
            "add a vault".to_string(),
            "Adds it to the list as it is, opening nothing: a gocryptfs folder, a LUKS drive or image file, or an age file. Enter on it unlocks it after.",
        ),
        Purpose::Setting(key) => (
            format!("change {key}"),
            "Saved to ck's settings file as soon as it is submitted.",
        ),
        Purpose::OpenAt(cipher) => (
            format!("open {}", crate::vault::file_name(cipher)),
            "gocryptfs opens the vault into this folder, which has to be empty, and ck remembers it for next time.",
        ),
    };
    lines.extend([Line::raw(""), Line::styled(note, dim), Line::raw("")]);
    texts.extend([String::new(), note.to_string(), String::new()]);
    // The command row is there even before a path is, so typing the first
    // letter does not resize the box under the cursor.
    // The command it will run, or while it cannot, why not.
    let check = match form.purpose {
        Purpose::Setting(key) => {
            let typed = form.fields[PATH].value.trim();
            match crate::settings::Settings::default().set(key, typed) {
                Ok(()) => Ok(format!("{key} = {typed}")),
                Err(e) => Err(e.to_string()),
            }
        }
        _ => form.check(known).map(|a| a.command_line()),
    };
    let (label, runs, style) = match check {
        Ok(line) => ("  runs  ", line, Style::default().fg(Color::Green)),
        Err(why) => ("  why   ", why, Style::default().fg(Color::Yellow)),
    };
    texts.push(format!("{label}{runs}"));
    lines.push(Line::from(vec![
        Span::styled(label, dim),
        Span::styled(runs, style),
    ]));
    let mut keys = FORM_KEYS.to_vec();
    if form.fields.iter().any(|f| f.required) {
        keys.push(REQUIRED);
    }
    lines.extend([Line::raw(""), box_hint(&keys)]);
    texts.extend([String::new(), keys.join(SEP)]);

    let width = box_width(area.width);
    let rows: usize = texts
        .iter()
        .map(|t| wrapped_line_count(t, box_inner_width(width)))
        .sum();
    let rect = box_area(area, width, box_height(rows as u16, area.height));
    f.render_widget(Clear, rect);
    let para = Paragraph::new(lines)
        .block(box_block(Color::Cyan, &title))
        .wrap(Wrap { trim: false });
    f.render_widget(para, rect);
}
