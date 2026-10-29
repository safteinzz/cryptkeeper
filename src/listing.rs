//! What `ls`, `ls --json`, bare `ck` and the terminal UI show for each vault
//! and each LUKS drive the list does not hold, built once from the same reads,
//! none of which opens, mounts or asks anything.

use crate::luks::{self, Drive};
use crate::vault::{self, Kind, State, Vault};
use crate::{age, mounts, tilde};
use std::path::{Path, PathBuf};

pub struct Entry {
    pub kind: Kind,
    /// One of `open`, `locked`, `dead`, `exposed`, `missing`.
    pub state: &'static str,
    /// The name every command takes it by.
    pub name: PathBuf,
    pub cipher: PathBuf,
    pub view: PathBuf,
    /// Where it is open: a mountpoint, or an age file's plaintext.
    pub at: Option<PathBuf>,
    pub timeout: Option<String>,
    pub identity: Option<PathBuf>,
    pub listed: bool,
    pub note: String,
    /// Whether `lock` may close it: anything open in the list, and of the
    /// drives only one ck's own `unlock` opened.
    pub lockable: bool,
}

pub fn missing_note(v: &Vault) -> &'static str {
    match v.kind {
        Kind::Luks if v.cipher.starts_with("/dev") => "drive not plugged in",
        Kind::Gocryptfs => "drive not plugged in, or the folder moved",
        _ => "drive not plugged in, or the file moved",
    }
}

pub fn of_vault(v: &Vault, listed: bool) -> Entry {
    let (state, note) = match vault::state(v) {
        State::Missing => ("missing", missing_note(v).to_string()),
        State::Locked => ("locked", String::new()),
        State::Dead(note) => ("dead", note),
        State::Open(note) => ("open", note),
        State::Exposed(note) => ("exposed", note),
    };
    let open = matches!(state, "open" | "dead" | "exposed");
    let at = match v.kind {
        _ if !open => None,
        Kind::Gocryptfs => Some(v.view.clone()),
        Kind::Luks => luks::open_at(v),
        Kind::Age => age::open_at(v),
    };
    // A vault ck found itself says how to take it on, as a found drive does.
    let note = if !note.is_empty() || listed {
        note
    } else if v.kind == Kind::Gocryptfs && v.view.as_os_str().is_empty() {
        format!(
            "opens where you say: `ck unlock {} --at <folder>`",
            tilde(&v.cipher)
        )
    } else {
        format!("`ck add {}` lists it", tilde(v.name()))
    };
    let timeout = (v.kind == Kind::Gocryptfs && state == "open")
        .then(|| mounts::idle_timeout(&v.view))
        .flatten();
    Entry {
        kind: v.kind,
        state,
        name: v.shown(),
        cipher: v.cipher.clone(),
        view: v.view.clone(),
        at,
        timeout,
        identity: v.identity.clone(),
        listed,
        note,
        lockable: open && (v.kind != Kind::Luks || luks::untouchable(v).is_none()),
    }
}

fn of_drive(d: Drive) -> Entry {
    Entry {
        kind: Kind::Luks,
        state: if d.open { "open" } else { "locked" },
        name: d.dev,
        cipher: d.cipher,
        view: PathBuf::new(),
        at: d.at,
        timeout: None,
        identity: None,
        listed: false,
        note: d.note,
        lockable: d.ours,
    }
}

/// Every vault in `known`, then every vault in `found` it does not hold (as
/// `scan::found` finds them), then every LUKS drive it does not hold.
pub fn all(known: &[Vault], found: &[Vault]) -> Vec<Entry> {
    let new = found
        .iter()
        .filter(|f| !known.iter().any(|k| k.cipher == f.cipher));
    known
        .iter()
        .map(|v| of_vault(v, true))
        .chain(new.map(|v| of_vault(v, false)))
        .chain(luks::drives(known).into_iter().map(of_drive))
        .collect()
}

/// `vaults` as entries, each marked listed when `known` holds it.
pub fn of_vaults(vaults: &[Vault], known: &[Vault]) -> Vec<Entry> {
    vaults
        .iter()
        .map(|v| of_vault(v, known.iter().any(|k| k.cipher == v.cipher)))
        .collect()
}

/// One aligned `state  kind  name  note` line per entry.
pub fn rows(entries: &[Entry]) -> Vec<String> {
    let width = entries
        .iter()
        .map(|e| tilde(&e.name).chars().count())
        .max()
        .unwrap_or(0);
    entries
        .iter()
        .map(|e| {
            format!(
                "{:<8} {:<10} {:<width$}  {}",
                e.state,
                e.kind.word(),
                tilde(&e.name),
                e.note
            )
            .trim_end()
            .to_string()
        })
        .collect()
}

/// `entries` as a JSON array, one object a line, with the field names
/// `--help` promises.
pub fn json(entries: &[Entry]) -> String {
    let objects: Vec<String> = entries
        .iter()
        .map(|e| {
            format!(
                "{{\"kind\":{},\"state\":{},\"name\":{},\"cipher\":{},\"view\":{},\"where\":{},\"timeout\":{},\"identity\":{},\"listed\":{},\"note\":{}}}",
                string(e.kind.word()),
                string(e.state),
                path(&e.name),
                path(&e.cipher),
                path(&e.view),
                e.at.as_deref().map_or("null".into(), path),
                e.timeout.as_deref().map_or("null".into(), string),
                e.identity.as_deref().map_or("null".into(), path),
                e.listed,
                if e.note.is_empty() {
                    "null".into()
                } else {
                    string(&e.note)
                },
            )
        })
        .collect();
    array(&objects)
}

/// `objects`, each already JSON, as an array a line each.
pub fn array(objects: &[String]) -> String {
    if objects.is_empty() {
        return "[]".into();
    }
    format!("[\n  {}\n]", objects.join(",\n  "))
}

fn path(p: &Path) -> String {
    if p.as_os_str().is_empty() {
        return "null".into();
    }
    string(&p.to_string_lossy())
}

/// `s` as a JSON string.
pub fn string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
