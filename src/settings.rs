//! `$XDG_CONFIG_HOME/cryptkeeper/settings` (usually
//! `~/.config/cryptkeeper/settings`), as `key = value` lines, or the one under
//! `egc/` while this one does not exist. Every setting has a
//! default that works with no file at all, and a line that makes no sense keeps
//! its default rather than failing, so a broken file never locks you out. The
//! terminal UI's Settings tab edits it through `rows`, `set` and `save`.

use anyhow::{Result, bail};
use std::fs;
use std::path::{Path, PathBuf};

pub struct Settings {
    /// What `ck init` calls a vault when you give it no name.
    pub name: String,
    /// `luks = sudo`: open and mount LUKS drives with `sudo cryptsetup` and
    /// `sudo mount` instead of udisks, so sudo asks for a password once and
    /// remembers it, where polkit over ssh asks at every step.
    pub luks_sudo: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            name: "vault".into(),
            luks_sudo: false,
        }
    }
}

/// One setting as the Settings tab shows it.
pub struct Row {
    /// Its word in the file.
    pub key: &'static str,
    pub label: &'static str,
    pub value: String,
    pub default: &'static str,
    /// What it changes, in a line.
    pub help: &'static str,
    /// The answers Enter steps through, or `None` for one that is typed.
    pub choices: Option<&'static [&'static str]>,
}

impl Row {
    pub fn is_default(&self) -> bool {
        self.value == self.default
    }
}

const LUKS: &[&str] = &["udisks", "sudo"];

impl Settings {
    /// Every setting, in the order the tab lists them.
    pub fn rows(&self) -> Vec<Row> {
        vec![
            Row {
                key: "luks",
                label: "Drives through",
                value: (if self.luks_sudo { "sudo" } else { "udisks" }).into(),
                default: "udisks",
                help: "udisks needs no root; sudo asks once where polkit asks at every step",
                choices: Some(LUKS),
            },
            Row {
                key: "name",
                label: "New vault name",
                value: self.name.clone(),
                default: "vault",
                help: "what `ck init` calls a vault when it is given no name",
                choices: None,
            },
        ]
    }

    /// Sets `key` to `value`, refusing a value it cannot take.
    pub fn set(&mut self, key: &str, value: &str) -> Result<()> {
        let value = value.trim();
        match key {
            "luks" if LUKS.contains(&value) => self.luks_sudo = value == "sudo",
            "luks" => bail!("`{value}` is not one of {}", LUKS.join(", ")),
            "name"
                if value.is_empty()
                    || value.starts_with('.')
                    || value.contains(['/', '\t', '\n']) =>
            {
                bail!("`{value}` cannot name a vault: use a plain folder name, e.g. `photos`")
            }
            "name" => self.name = value.into(),
            _ => bail!("there is no setting `{key}`"),
        }
        Ok(())
    }

    /// Steps `key` to its next answer, for a setting that has a few.
    pub fn cycle(&mut self, key: &str) -> Result<()> {
        let Some(row) = self.rows().into_iter().find(|r| r.key == key) else {
            bail!("there is no setting `{key}`");
        };
        let Some(choices) = row.choices else {
            bail!("`{key}` is typed, not picked");
        };
        let at = choices.iter().position(|c| *c == row.value).unwrap_or(0);
        self.set(key, choices[(at + 1) % choices.len()])
    }

    /// Puts `key` back to how ck ships it.
    pub fn reset(&mut self, key: &str) -> Result<()> {
        let default = Settings::default();
        let Some(row) = default.rows().into_iter().find(|r| r.key == key) else {
            bail!("there is no setting `{key}`");
        };
        self.set(key, &row.value)
    }

    /// Writes every setting to `path()`, through a temp file and a rename.
    pub fn save(&self) -> Result<()> {
        let mut body = String::from("# ck's settings, which its Settings tab edits\n");
        for row in self.rows() {
            body.push_str(&format!("{} = {}\n", row.key, row.value));
        }
        crate::write_atomic(&path(), body.as_bytes(), "the settings")
    }
}

/// Where the settings are written.
pub fn path() -> PathBuf {
    crate::config_dir().join("settings")
}

pub fn load() -> Settings {
    let file = path();
    let old = crate::legacy_config_dir().join("settings");
    load_from(if !file.exists() && old.exists() {
        &old
    } else {
        &file
    })
}

fn load_from(path: &Path) -> Settings {
    let mut s = Settings::default();
    let Ok(text) = fs::read_to_string(path) else {
        return s;
    };
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let _ = s.set(key.trim(), value);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_setting_that_makes_no_sense_keeps_its_default() {
        let dir = crate::vault::tests::temp_dir("settings");
        let file = dir.join("settings");
        fs::write(&file, "luks = maybe\nname = .hidden\n").unwrap();
        let s = load_from(&file);
        fs::write(&file, "# mine\nluks = sudo\nname = photos\n").unwrap();
        let set = load_from(&file);
        fs::remove_dir_all(&dir).unwrap();

        assert!(!s.luks_sudo, "an unknown `luks` keeps udisks");
        assert_eq!(
            s.name, "vault",
            "a name ck could not make keeps the default"
        );
        assert!(
            set.luks_sudo && set.name == "photos",
            "good values are read"
        );
    }

    #[test]
    fn changing_a_setting_refuses_what_it_cannot_take() {
        let mut s = Settings::default();
        assert!(s.set("name", "a/b").is_err());
        assert!(s.set("luks", "root").is_err());
        s.cycle("luks").unwrap();
        assert!(s.luks_sudo, "stepping `luks` from udisks gives sudo");
        s.reset("luks").unwrap();
        assert!(!s.luks_sudo, "resetting puts udisks back");
    }
}
