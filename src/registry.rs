//! `$XDG_CONFIG_HOME/cryptkeeper/vaults` (usually
//! `~/.config/cryptkeeper/vaults`): every vault ck has made or opened, one
//! `<kind>\t<encrypted side>\t<view>` line each, paths absolute, with a fourth
//! field for an age vault's identity file. A two-field `<cipher>\t<view>` line
//! is a gocryptfs vault, as the list kept under `egc/` wrote it; that list is
//! read while this one does not exist yet, and never written or removed.

use crate::vault::{Kind, Vault};
use anyhow::{Result, bail};
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

fn path() -> PathBuf {
    crate::config_dir().join("vaults")
}

/// The whole list. A missing file is an empty list; one that exists but cannot
/// be read is an error, because treating it as empty would let the next save
/// wipe it.
pub fn load() -> Result<Vec<Vault>> {
    let file = path();
    let old = crate::legacy_config_dir().join("vaults");
    if !file.exists() && old.exists() {
        return load_from(&old);
    }
    load_from(&file)
}

fn load_from(file: &Path) -> Result<Vec<Vault>> {
    let text = match fs::read_to_string(file) {
        Ok(text) => text,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => bail!(
            "could not read `{}`: fix or remove it, ck will not overwrite it",
            crate::tilde(file)
        ),
    };
    Ok(text.lines().filter_map(parse_line).collect())
}

/// One line of the list, or `None` for a line ck did not write.
fn parse_line(line: &str) -> Option<Vault> {
    let fields: Vec<&str> = line.split('\t').collect();
    let (kind, cipher, view, identity) = match fields.as_slice() {
        [cipher, view] => (Kind::Gocryptfs, *cipher, *view, None),
        [kind, cipher, view] => (Kind::from_word(kind)?, *cipher, *view, None),
        [kind, cipher, view, id] => (Kind::from_word(kind)?, *cipher, *view, Some(*id)),
        _ => return None,
    };
    if cipher.is_empty() {
        return None;
    }
    Some(Vault {
        kind,
        cipher: PathBuf::from(cipher),
        view: PathBuf::from(view),
        identity: identity.filter(|i| !i.is_empty()).map(PathBuf::from),
    })
}

fn format_line(v: &Vault) -> String {
    let mut line = format!(
        "{}\t{}\t{}",
        v.kind.word(),
        v.cipher.display(),
        v.view.display()
    );
    if let Some(id) = &v.identity {
        line.push('\t');
        line.push_str(&id.display().to_string());
    }
    line.push('\n');
    line
}

/// Add `v`, or bring its line up to date when its view or identity moved.
pub fn remember(v: &Vault) -> Result<()> {
    check_storable(v)?;
    remember_into(&path(), load()?, v)
}

fn remember_into(file: &Path, mut all: Vec<Vault>, v: &Vault) -> Result<()> {
    match all.iter_mut().find(|known| known.cipher == v.cipher) {
        Some(known) if known == v => return Ok(()),
        Some(known) => *known = v.clone(),
        None => all.push(v.clone()),
    }
    save_to(file, &all)
}

/// Fails for a vault whose paths the one-line, tab-separated list cannot hold.
pub fn check_storable(v: &Vault) -> Result<()> {
    for p in [Some(&v.cipher), Some(&v.view), v.identity.as_ref()]
        .into_iter()
        .flatten()
    {
        if p.to_string_lossy().contains(['\t', '\n']) {
            bail!(
                "`{}` has a tab or a newline in its path, which ck's vault list cannot hold",
                crate::tilde(p)
            );
        }
    }
    Ok(())
}

/// Replace the whole list with `all`, through a temp file and a rename so an
/// interrupted save never leaves half a list.
pub fn save(all: &[Vault]) -> Result<()> {
    save_to(&path(), all)
}

fn save_to(file: &Path, all: &[Vault]) -> Result<()> {
    let mut body: String = all.iter().map(format_line).collect();
    // A line ck cannot read (a newer ck's, or a hand edit) is kept as it is,
    // since dropping it would forget that vault.
    if let Ok(old) = fs::read_to_string(file) {
        for line in old.lines() {
            if !line.trim().is_empty() && parse_line(line).is_none() {
                body.push_str(line);
                body.push('\n');
            }
        }
    }
    crate::write_atomic(file, body.as_bytes(), "the vault list")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::tests::temp_dir;

    fn sample() -> Vec<Vault> {
        vec![
            Vault::from_view(Path::new("/example/photos")),
            Vault {
                view: PathBuf::from("/media/user/stick"),
                ..Vault::luks(PathBuf::from(
                    "/dev/disk/by-uuid/00000000-0000-4000-8000-000000000000",
                ))
            },
            Vault {
                identity: Some(PathBuf::from("/example/key.txt")),
                ..Vault::age(Path::new("/example/taxes.pdf.age"))
            },
            Vault::age(Path::new("/example/notes.age")),
        ]
    }

    #[test]
    fn every_kind_of_vault_survives_a_save_and_a_load() {
        let dir = temp_dir("roundtrip");
        let file = dir.join("vaults");
        save_to(&file, &sample()).unwrap();
        let back = load_from(&file);
        fs::remove_dir_all(&dir).unwrap();

        assert_eq!(back.unwrap(), sample(), "a line came back different");
    }

    #[test]
    fn a_two_field_line_from_the_old_list_is_a_gocryptfs_vault() {
        let v = parse_line("/example/.photos\t/example/photos").unwrap();
        assert_eq!(v, Vault::from_view(Path::new("/example/photos")));
    }

    #[test]
    fn a_line_of_an_unknown_kind_is_skipped_not_misread() {
        assert_eq!(parse_line("zfs\t/example/pool\t/example/mnt"), None);
    }

    #[test]
    fn remembering_a_vault_again_updates_its_line_instead_of_adding_one() {
        let dir = temp_dir("upsert");
        let file = dir.join("vaults");
        let mut stick = sample()[1].clone();
        remember_into(&file, Vec::new(), &stick).unwrap();
        stick.view = PathBuf::from("/media/user/stick1");
        remember_into(&file, load_from(&file).unwrap(), &stick).unwrap();
        let back = load_from(&file);
        fs::remove_dir_all(&dir).unwrap();

        assert_eq!(back.unwrap(), [stick], "one drive must never get two lines");
    }

    #[test]
    fn an_unreadable_vault_list_is_never_overwritten() {
        let dir = temp_dir("registry");
        let file = dir.join("vaults");
        // Not UTF-8, as a hand edit in the wrong encoding leaves it.
        let before = b"/example/.a\t/example/a\n\xff\n".to_vec();
        fs::write(&file, &before).unwrap();

        let v = Vault::from_view(Path::new("/example/b"));
        let saved = load_from(&file).and_then(|all| remember_into(&file, all, &v));
        let after = fs::read(&file).unwrap();
        fs::remove_dir_all(&dir).unwrap();

        assert!(
            saved.is_err(),
            "adding to an unreadable list must fail, not start a new one"
        );
        assert_eq!(after, before, "the unreadable list was rewritten");
    }

    #[test]
    fn a_line_ck_cannot_read_is_kept_through_a_save() {
        let dir = temp_dir("keep-unknown");
        let file = dir.join("vaults");
        let unknown = "veracrypt\t/example/box.hc\t/example/box";
        fs::write(&file, format!("{unknown}\n")).unwrap();

        let v = Vault::from_view(Path::new("/example/photos"));
        remember_into(&file, load_from(&file).unwrap(), &v).unwrap();
        let after = fs::read_to_string(&file).unwrap();
        fs::remove_dir_all(&dir).unwrap();

        assert!(
            after.lines().any(|l| l == unknown),
            "a newer ck's line must survive a save by this one, got:\n{after}"
        );
    }
}
