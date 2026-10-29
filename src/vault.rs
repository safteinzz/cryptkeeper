//! What a vault is, and finding the one you mean from where you stand.
//!
//! A vault is one of three kinds, each an encrypted side (`cipher`) and the
//! place it opens to (`view`):
//! - gocryptfs: any folder holding `gocryptfs.conf`. A `.<name>` one opens
//!   into its sibling `<name>`; any other opens where it is mounted, where the
//!   list remembers, or where `unlock --at` says.
//! - luks: a drive, named by `/dev/disk/by-uuid/<uuid>` so a replugged stick is
//!   found again, or an image file; it opens wherever udisks mounts it.
//! - age: one `<name>.age` file, opening to a link `<name>` beside it that
//!   points at the plaintext copy in memory.

use crate::{age, luks};
use anyhow::{Result, bail};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Gocryptfs,
    Luks,
    Age,
}

impl Kind {
    /// The word the vault list and `ls` spell it with.
    pub fn word(self) -> &'static str {
        match self {
            Kind::Gocryptfs => "gocryptfs",
            Kind::Luks => "luks",
            Kind::Age => "age",
        }
    }

    pub fn from_word(word: &str) -> Option<Kind> {
        [Kind::Gocryptfs, Kind::Luks, Kind::Age]
            .into_iter()
            .find(|k| k.word() == word)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Vault {
    pub kind: Kind,
    pub cipher: PathBuf,
    /// Empty for a LUKS vault never mounted yet, since udisks picks the
    /// folder, and for a gocryptfs folder ck has not been told the view of.
    pub view: PathBuf,
    /// The identity an age vault decrypts with; `None` means a passphrase.
    pub identity: Option<PathBuf>,
}

impl Vault {
    /// The gocryptfs vault opening into `view`.
    pub fn from_view(view: &Path) -> Vault {
        Vault {
            kind: Kind::Gocryptfs,
            cipher: view.with_file_name(format!(".{}", file_name(view))),
            view: view.to_path_buf(),
            identity: None,
        }
    }

    /// The gocryptfs vault whose encrypted folder is `cipher`: a `.<name>`
    /// folder opens into `<name>` beside it, any other into where it is
    /// mounted now, and with neither its view stays empty for the list or
    /// `unlock --at` to give.
    pub fn from_cipher(cipher: &Path) -> Vault {
        let name = file_name(cipher);
        let view = match name.strip_prefix('.') {
            Some(bare) if !bare.is_empty() => cipher.with_file_name(bare),
            _ => mounted_at(cipher).unwrap_or_default(),
        };
        Vault {
            kind: Kind::Gocryptfs,
            cipher: cipher.to_path_buf(),
            view,
            identity: None,
        }
    }

    /// The age vault in `cipher`, which opens to the same name without `.age`.
    pub fn age(cipher: &Path) -> Vault {
        let name = file_name(cipher);
        Vault {
            kind: Kind::Age,
            cipher: cipher.to_path_buf(),
            view: cipher.with_file_name(name.strip_suffix(".age").unwrap_or(&name)),
            identity: None,
        }
    }

    pub fn luks(cipher: PathBuf) -> Vault {
        Vault {
            kind: Kind::Luks,
            cipher,
            view: PathBuf::new(),
            identity: None,
        }
    }

    /// What a message calls the vault: `name`, except that a drive never
    /// mounted is named by its device as `ls` names it (`/dev/sdb1`), the
    /// way the user typed it, rather than by its `/dev/disk/by-uuid` link.
    pub fn shown(&self) -> PathBuf {
        if self.kind == Kind::Luks
            && self.view.as_os_str().is_empty()
            && let Some(dev) = luks::device_name(self)
        {
            return dev;
        }
        self.name().to_path_buf()
    }

    /// What the list and every listing call the vault: its view, or before a
    /// LUKS vault has ever been mounted, its drive or image file.
    pub fn name(&self) -> &Path {
        if self.view.as_os_str().is_empty() {
            &self.cipher
        } else {
            &self.view
        }
    }
}

/// What a vault is doing now, with a note for `ls` where one helps.
pub enum State {
    Open(String),
    Locked,
    Dead(String),
    Missing,
    /// An age vault's plaintext sits on disk with no copy in memory.
    Exposed(String),
}

pub fn state(v: &Vault) -> State {
    match v.kind {
        Kind::Gocryptfs => crate::gocryptfs::state(v),
        Kind::Luks => luks::state(v),
        Kind::Age => age::state(v),
    }
}

/// The vault `arg` names, as the user typed it: a vault in `known` by the
/// name `ls` prints or by its encrypted side, `UUID=<uuid>` for a drive, a
/// LUKS drive or image file, an age file or the copy it opens to, or a folder
/// to walk up from as `find` does.
pub fn resolve(arg: &Path, verb: &str, known: &[Vault]) -> Result<Vault> {
    if let Some(v) = by_name(known, arg) {
        return Ok(v.clone());
    }
    let v = settle(detect(arg, verb, known)?);
    Ok(listed(known, v))
}

fn detect(arg: &Path, verb: &str, known: &[Vault]) -> Result<Vault> {
    if let Some(uuid) = arg.to_str().and_then(|s| s.strip_prefix("UUID=")) {
        let drive = luks::by_uuid(uuid);
        return Ok(by_name(known, &drive)
            .cloned()
            .unwrap_or_else(|| Vault::luks(drive)));
    }
    let Ok(meta) = fs::metadata(arg) else {
        return find(arg, verb, known);
    };
    if meta.is_dir() {
        return find(arg, verb, known);
    }
    let seen = crate::tilde(arg);
    if let Some(v) = age_view(arg) {
        return Ok(v);
    }
    if luks::is_block(&meta) {
        return luks::from_block(arg);
    }
    if !meta.is_file() {
        bail!("`{seen}` is neither a folder, a file nor a drive, so it holds no vault");
    }
    let abs = fs::canonicalize(arg).unwrap_or_else(|_| arg.to_path_buf());
    if age::is_age(&abs) {
        if !file_name(&abs).ends_with(".age") || file_name(&abs) == ".age" {
            bail!(
                "`{seen}` is an age file, but ck names its opened copy after it without `.age`: rename it to `{}.age`",
                file_name(&abs)
            );
        }
        return Ok(Vault::age(&abs));
    }
    if luks::is_luks_file(&abs) {
        return Ok(Vault::luks(abs));
    }
    bail!("`{seen}` is a file, but neither a LUKS image nor an age file")
}

/// Whether `path` names `v` itself, by its open or its encrypted side (a
/// drive by any name for its device), rather than a folder `v` was found
/// walking up from.
pub fn is_named_by(v: &Vault, path: &Path) -> bool {
    let at = real_parent(path);
    let real = fs::canonicalize(path).ok();
    let same = |p: &Path| p == at || (real.is_some() && fs::canonicalize(p).ok() == real);
    same(&v.view) || same(&v.cipher) || path.to_str().is_some_and(|s| s.starts_with("UUID="))
}

/// The vault in `known` that `name` spells, as its view or its encrypted
/// side; the name as given first, so a symlinked entry is not mistaken for
/// the one its link points at, resolved only when nothing matches as given.
pub fn by_name<'a>(known: &'a [Vault], name: &Path) -> Option<&'a Vault> {
    let path = std::path::absolute(name).unwrap_or_else(|_| name.to_path_buf());
    let is = |p: &Path| {
        known
            .iter()
            .find(|v| v.view == p || v.cipher == p || luks::same_drive(v, p))
    };
    is(&path)
        .or_else(|| is(&real_parent(&path)))
        .or_else(|| path.canonicalize().ok().and_then(|p| is(&p)))
}

/// `p` made absolute with every folder above it resolved through its
/// symlinks, and `p` itself left as named, since a view may not exist or may
/// be the link to an age copy.
pub fn real_parent(p: &Path) -> PathBuf {
    let abs = std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf());
    match (
        abs.parent().and_then(|d| fs::canonicalize(d).ok()),
        abs.file_name(),
    ) {
        (Some(dir), Some(name)) => dir.join(name),
        _ => abs,
    }
}

/// `v` as the list stores it: its encrypted side resolved through every
/// symlink, so a lock writes the real file and one vault never gets two
/// lines, and its view absolute under resolved folders.
fn settle(v: Vault) -> Vault {
    if v.kind == Kind::Luks {
        return v;
    }
    Vault {
        cipher: fs::canonicalize(&v.cipher).unwrap_or_else(|_| real_parent(&v.cipher)),
        view: real_parent(&v.view),
        ..v
    }
}

/// The listed line for `v`'s encrypted side when there is one, since it
/// carries the identity an age vault opened with.
fn listed(known: &[Vault], v: Vault) -> Vault {
    known
        .iter()
        .find(|k| k.cipher == v.cipher)
        .cloned()
        .unwrap_or(v)
}

/// The vault `start` is in, is, or sits beside: the nearest one walking up from
/// `start`. Fails when there is none, or when a folder on the way holds
/// several, rather than guessing; `verb` is the command the error suggests.
pub fn find(start: &Path, verb: &str, known: &[Vault]) -> Result<Vault> {
    let Some(mut found) = nearest(start, known)? else {
        bail!(
            "no vault in or above `{}`: make one with `ck init`, or name it",
            crate::tilde(start)
        );
    };
    if found.len() == 1 {
        return Ok(found.remove(0));
    }
    let names: Vec<String> = found.iter().map(|v| file_name(v.name())).collect();
    let dir = found[0].name().parent().unwrap_or(Path::new("/"));
    bail!(
        "`{}` holds several vaults ({}): name one, e.g. `ck {verb} {}`",
        crate::tilde(dir),
        names
            .iter()
            .map(|n| format!("`{n}`"))
            .collect::<Vec<_>>()
            .join(", "),
        crate::tilde(found[0].name())
    )
}

/// Every vault at the nearest level walking up from `start` that has any:
/// one when `start` is inside or is a vault, all of them when a folder holds
/// several, `None` when no folder above has one.
pub fn nearest(start: &Path, known: &[Vault]) -> Result<Option<Vec<Vault>>> {
    let Ok(start) = fs::canonicalize(start) else {
        // A view that was never made, or was removed while locked. Its parent
        // still exists, and resolving it keeps a symlinked path from becoming
        // a second name for the same vault.
        let abs = std::path::absolute(start).unwrap_or_else(|_| start.to_path_buf());
        let parent = abs.parent().and_then(|p| fs::canonicalize(p).ok());
        if let (Some(parent), Some(name)) = (parent, abs.file_name()) {
            let v = Vault::from_view(&parent.join(name));
            if is_cipher(&v.cipher) {
                return Ok(Some(vec![listed(known, settle(v))]));
            }
            if let Some(v) = age_view(&parent.join(name)) {
                return Ok(Some(vec![listed(known, settle(v))]));
            }
        }
        bail!("`{}` does not exist", start.display());
    };
    for dir in start.ancestors() {
        if let Some(v) = at(dir, known) {
            return Ok(Some(vec![listed(known, settle(v))]));
        }
        let found = vaults_in(dir, known);
        if !found.is_empty() {
            return Ok(Some(
                found
                    .into_iter()
                    .map(|v| listed(known, settle(v)))
                    .collect(),
            ));
        }
    }
    Ok(None)
}

/// `dir` itself as a vault: a gocryptfs vault's encrypted folder or its view
/// (by the list, by being mounted, or beside its `.<name>`), or the folder a
/// listed LUKS vault mounts on.
fn at(dir: &Path, known: &[Vault]) -> Option<Vault> {
    if let Some(v) = known.iter().find(|v| v.kind != Kind::Age && v.view == dir) {
        return Some(v.clone());
    }
    if is_cipher(dir) {
        return Some(Vault::from_cipher(dir));
    }
    let mounted = crate::mounts::gocryptfs_mounts()
        .into_iter()
        .find(|(_, point)| point == dir);
    if let Some((cipher, point)) = mounted {
        return Some(Vault {
            view: point,
            ..Vault::from_cipher(&cipher)
        });
    }
    dir.parent()?;
    let v = Vault::from_view(dir);
    is_cipher(&v.cipher).then_some(v)
}

/// The vaults right inside `dir`: folders holding `gocryptfs.conf`, `.age`
/// files, and the listed vaults opening there. A child that is a mountpoint
/// is never looked into, so a walk up through `/media` never stats a dead
/// FUSE mount and hangs, and a symlink is followed only to a dot folder.
fn vaults_in(dir: &Path, known: &[Vault]) -> Vec<Vault> {
    let mut found: Vec<Vault> = known
        .iter()
        .filter(|v| v.kind != Kind::Age && v.view.parent() == Some(dir))
        .cloned()
        .collect();
    let points = crate::mounts::points();
    if let Ok(entries) = fs::read_dir(dir) {
        for e in entries.flatten() {
            let p = e.path();
            if points.contains(&p) {
                continue;
            }
            let name = file_name(&p);
            let real_dir = e.file_type().is_ok_and(|t| t.is_dir());
            if (real_dir || name.starts_with('.')) && is_cipher(&p) {
                found.push(Vault::from_cipher(&p));
            } else if name.ends_with(".age") && name != ".age" && age::is_age(&p) {
                found.push(Vault::age(&p));
            }
        }
    }
    found.sort_by(|a, b| a.cipher.cmp(&b.cipher));
    found.dedup_by(|a, b| a.cipher == b.cipher);
    found.sort_by(|a, b| a.name().cmp(b.name()));
    found
}

/// Where the gocryptfs vault in `cipher` is mounted, when it is.
fn mounted_at(cipher: &Path) -> Option<PathBuf> {
    let real = fs::canonicalize(cipher).ok();
    crate::mounts::gocryptfs_mounts()
        .into_iter()
        .find(|(source, _)| source == cipher || real.as_ref() == Some(source))
        .map(|(_, point)| point)
}

/// The age vault whose opened copy is, or would be, `view`.
fn age_view(view: &Path) -> Option<Vault> {
    let view = real_parent(view);
    let cipher = view.with_file_name(format!("{}.age", file_name(&view)));
    if file_name(&view).is_empty() || !age::is_age(&cipher) {
        return None;
    }
    Some(Vault {
        view,
        ..Vault::age(&cipher)
    })
}

pub fn is_cipher(dir: &Path) -> bool {
    dir.join("gocryptfs.conf").is_file()
}

pub fn file_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// A throwaway folder under the temp dir, uniquely named per test and
    /// deleted by it, so no real vault is ever looked at.
    pub fn temp_dir(tag: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("ck-{tag}-{}-{stamp}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::canonicalize(dir).unwrap()
    }

    /// A folder that passes for a vault's encrypted half: `find` only checks
    /// for a `gocryptfs.conf` in it.
    fn fake_vault(cipher: &Path) {
        fs::create_dir_all(cipher).unwrap();
        fs::write(cipher.join("gocryptfs.conf"), "{}").unwrap();
    }

    /// A file that passes for an age file: detection reads only its header.
    fn fake_age(file: &Path) {
        fs::write(
            file,
            b"age-encryption.org/v1\n-> scrypt abc 18\nxyz\n--- mac\n",
        )
        .unwrap();
    }

    #[test]
    fn a_folder_holding_several_vaults_is_refused_not_guessed() {
        let dir = temp_dir("several");
        fake_vault(&dir.join(".a"));
        fake_vault(&dir.join(".b"));
        fs::create_dir(dir.join("sub")).unwrap();

        let found = nearest(&dir.join("sub"), &[]).unwrap().unwrap_or_default();
        let picked = find(&dir.join("sub"), "unlock", &[]);
        fs::remove_dir_all(&dir).unwrap();

        assert_eq!(
            found.len(),
            2,
            "both vaults beside the folder should be seen"
        );
        assert!(
            picked.is_err(),
            "with two vaults in reach, find must refuse rather than pick one"
        );
    }

    #[test]
    fn a_symlinked_path_resolves_to_the_vault_it_points_at() {
        let dir = temp_dir("symlink");
        fake_vault(&dir.join("other/.c"));
        std::os::unix::fs::symlink(dir.join("other"), dir.join("lnk")).unwrap();

        // `c` does not exist yet, the case where only its parent can be resolved.
        let v = find(&dir.join("lnk/c"), "unlock", &[]);
        fs::remove_dir_all(&dir).unwrap();

        let v = v.unwrap();
        assert_eq!(
            v.cipher,
            dir.join("other/.c"),
            "a link must not become a second name for the vault"
        );
        assert_eq!(v.view, dir.join("other/c"));
    }

    #[test]
    fn an_age_file_and_a_gocryptfs_vault_side_by_side_are_both_seen() {
        let dir = temp_dir("mixed");
        fake_vault(&dir.join(".photos"));
        fake_age(&dir.join("taxes.pdf.age"));
        // Not an age file despite the name, so not a vault.
        fs::write(dir.join("notes.age"), "plain text").unwrap();

        let found = nearest(&dir, &[]).unwrap().unwrap_or_default();
        fs::remove_dir_all(&dir).unwrap();

        let kinds: Vec<Kind> = found.iter().map(|v| v.kind).collect();
        assert_eq!(
            kinds,
            [Kind::Gocryptfs, Kind::Age],
            "a folder holds both vaults, and only real age files count"
        );
        assert_eq!(found[1].view, dir.join("taxes.pdf"));
    }

    #[test]
    fn an_age_vault_is_found_by_the_name_it_opens_to_while_locked() {
        let dir = temp_dir("ageview");
        fake_age(&dir.join("taxes.pdf.age"));

        let v = resolve(&dir.join("taxes.pdf"), "unlock", &[]);
        fs::remove_dir_all(&dir).unwrap();

        let v = v.unwrap();
        assert_eq!(v.kind, Kind::Age);
        assert_eq!(v.cipher, dir.join("taxes.pdf.age"));
    }

    #[test]
    fn a_listed_vault_is_found_by_its_view_even_when_that_folder_is_gone() {
        let dir = temp_dir("listed");
        let stick = Vault {
            view: dir.join("media/stick"),
            ..Vault::luks(PathBuf::from(
                "/dev/disk/by-uuid/00000000-0000-4000-8000-000000000000",
            ))
        };

        let v = resolve(
            &dir.join("media/stick"),
            "unlock",
            std::slice::from_ref(&stick),
        );
        fs::remove_dir_all(&dir).unwrap();

        assert_eq!(
            v.unwrap(),
            stick,
            "a locked drive's mountpoint is gone, but `ls` prints it as its name"
        );
    }

    #[test]
    fn any_folder_holding_gocryptfs_conf_is_a_vault_whatever_its_name() {
        let dir = temp_dir("plain-name");
        fake_vault(&dir.join("enc"));
        fs::create_dir(dir.join("other")).unwrap();

        let found = nearest(&dir.join("other"), &[])
            .unwrap()
            .unwrap_or_default();
        fs::remove_dir_all(&dir).unwrap();

        assert_eq!(
            found.len(),
            1,
            "the folder holding gocryptfs.conf is the vault"
        );
        assert_eq!(found[0].cipher, dir.join("enc"));
        assert!(
            found[0].view.as_os_str().is_empty(),
            "a vault not named `.<name>` and not open has no view until one is given"
        );
    }

    #[test]
    fn a_path_names_a_vault_only_by_its_own_sides() {
        let v = Vault::from_view(Path::new("/example/photos"));
        assert!(is_named_by(&v, Path::new("/example/photos")));
        assert!(is_named_by(&v, Path::new("/example/.photos")));
        assert!(
            !is_named_by(&v, Path::new("/example/photos/sub")),
            "a folder inside the vault is not the vault"
        );
        assert!(
            !is_named_by(&v, Path::new("/example")),
            "the folder holding it is not the vault"
        );
    }
}
