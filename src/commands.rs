//! One function per CLI command. Every command that changes something takes
//! `dry`, and a dry run prints the same lines the real run would.

use crate::run::{self, Ran};
use crate::settings;
use crate::vault::{self, Kind, State, Vault};
use crate::{age, gocryptfs, listing, luks, mounts, registry, scan, tilde};
use anyhow::{Result, bail};
use std::fs;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::Command;

pub fn init(
    name: Option<String>,
    dir: Option<PathBuf>,
    identity: Option<PathBuf>,
    dry: bool,
) -> Result<()> {
    let dir = match dir {
        Some(d) => d,
        None => cwd()?,
    };
    // An existing file, or anything that is not a folder, makes an age vault.
    if let Some(n) = &name
        && fs::symlink_metadata(dir.join(n)).is_ok_and(|m| !m.is_dir())
    {
        return age::init(&dir.join(n), identity, dry);
    }
    if identity.is_some() {
        bail!(
            "`-i` encrypts an existing file into an age vault, and no such file was named: drop `-i`"
        );
    }
    gocryptfs::need()?;
    let s = settings::load();
    let Ok(dir) = fs::canonicalize(&dir) else {
        bail!("`{}` does not exist", dir.display());
    };
    let name = match name {
        Some(n) => n,
        None if std::io::stdin().is_terminal() => ask_name(&s.name)?,
        // A piped stdin carries the password for gocryptfs, not a name.
        None => s.name.clone(),
    };
    if name.is_empty() || name.starts_with('.') || name.contains(['/', '\t', '\n']) {
        bail!("`{name}` cannot name a vault: use a plain folder name, e.g. `ck init photos`");
    }
    let v = Vault::from_view(&dir.join(&name));
    registry::check_storable(&v)?;
    // A vault list that cannot be saved to fails here, before a vault exists
    // that it would have to leave out.
    registry::load()?;
    // An empty one is what a cancelled `init` left behind, so it is reused.
    if v.cipher.exists() && !is_empty_dir(&v.cipher) {
        bail!(
            "`{}` already exists: pick another name with `ck init <name>`",
            tilde(&v.cipher)
        );
    }
    // gocryptfs will only open into an empty folder.
    if v.view.exists() && !is_empty_dir(&v.view) {
        bail!(
            "`{}` already has files in it: pick another name with `ck init <name>`",
            tilde(&v.view)
        );
    }
    if !dry {
        gocryptfs::init(&v)?;
    }
    say!("made `{}`: open it with `ck unlock`", tilde(&v.view));
    Ok(())
}

/// `ck init --luks`: a LUKS image of `size` (`1G`) at `path`, or with
/// `wipe` the drive `path` names.
pub fn init_luks(path: PathBuf, size: Option<String>, wipe: bool, dry: bool) -> Result<()> {
    let size = match size.as_deref() {
        Some(s) => match luks::parse_size(s) {
            Some(n) => Some(n),
            None => bail!("`{s}` is not a size: write it like `500M` or `4G`"),
        },
        None => None,
    };
    luks::init(&path, size, wipe, dry)
}

/// `ck add`: puts the vault `path` names in the list as it is, opening
/// nothing, so a vault found, or a drive ck never touches, shows as yours.
pub fn add(path: PathBuf, dry: bool) -> Result<()> {
    let known = registry::load()?;
    if let Some(v) = vault::by_name(&known, &path) {
        say!("already listed: `{}`", tilde(&v.shown()));
        return Ok(());
    }
    let v = vault::resolve(&path, "add", &known)?;
    if known.iter().any(|k| k.cipher == v.cipher) {
        say!("already listed: `{}`", tilde(&v.shown()));
        return Ok(());
    }
    registry::check_storable(&v)?;
    if !dry {
        registry::remember(&v)?;
    }
    say!("listed `{}`", tilde(&v.shown()));
    Ok(())
}

/// `ck passwd`: changes the password of the vault `path` names, through the
/// tool that made it.
pub fn passwd(path: Option<PathBuf>, dry: bool) -> Result<()> {
    let known = registry::load()?;
    let v = pick(path, "passwd", &known)?;
    if let State::Missing = vault::state(&v) {
        bail!(
            "`{}` is missing ({}): bring it back first",
            tilde(&v.shown()),
            listing::missing_note(&v)
        );
    }
    match v.kind {
        Kind::Gocryptfs => gocryptfs::passwd(&v, dry),
        Kind::Luks => luks::passwd(&v, dry),
        Kind::Age => {
            if let Some(id) = &v.identity {
                bail!(
                    "`{}` opens with the key in `{}`, not a passphrase, so there is none to change",
                    tilde(&v.shown()),
                    tilde(id)
                );
            }
            // Opened with the old passphrase, then locked again with the new one.
            let (v, _) = open_for(v, None, dry)?;
            let _held = run::take_terminal();
            if !dry {
                eprintln!("ck: now give it the new passphrase");
            }
            lock_one(&v, dry)?;
            say!("`{}` now opens with the new passphrase", tilde(&v.shown()));
            Ok(())
        }
    }
}

/// `ck backup`: saves the vault's own key material (gocryptfs's conf, a LUKS
/// header) to `to`, or to a new file under `$XDG_DATA_HOME/cryptkeeper/backups`.
pub fn backup(path: Option<PathBuf>, to: Option<PathBuf>, dry: bool) -> Result<()> {
    let known = registry::load()?;
    let v = pick(path, "backup", &known)?;
    if let State::Missing = vault::state(&v) {
        bail!(
            "`{}` is missing ({}): bring it back first",
            tilde(&v.shown()),
            listing::missing_note(&v)
        );
    }
    let suffix = match v.kind {
        Kind::Gocryptfs => "gocryptfs.conf",
        Kind::Luks => "luks-header",
        Kind::Age => bail!(
            "an age file has no header apart from itself: copy `{}` somewhere safe instead",
            tilde(&v.cipher)
        ),
    };
    let dest = match to {
        Some(p) => p,
        None => {
            let dir = dirs::data_dir()
                .unwrap_or_else(|| dirs::home_dir().unwrap_or_default().join(".local/share"))
                .join("cryptkeeper/backups");
            if !dry && fs::create_dir_all(&dir).is_err() {
                bail!("could not create `{}` to save the backup in", tilde(&dir));
            }
            let base = vault::file_name(&v.shown())
                .trim_start_matches('.')
                .to_string();
            (0..)
                .map(|n| match n {
                    0 => dir.join(format!("{base}.{suffix}")),
                    n => dir.join(format!("{base}.{suffix}.{n}")),
                })
                .find(|p| !p.exists())
                .unwrap_or_default()
        }
    };
    if dest.exists() {
        bail!(
            "`{}` exists already: name another with `--to`",
            tilde(&dest)
        );
    }
    match v.kind {
        Kind::Gocryptfs => gocryptfs::backup(&v, &dest, dry),
        _ => luks::backup(&v, &dest, dry),
    }
}

pub fn unlock(
    path: Option<PathBuf>,
    minutes: Option<u32>,
    identity: Option<PathBuf>,
    at: Option<PathBuf>,
    dry: bool,
) -> Result<()> {
    let known = registry::load()?;
    let mut v = pick(path, "unlock", &known)?;
    if let Some(at) = at {
        if v.kind != Kind::Gocryptfs {
            bail!(
                "`--at` works only on gocryptfs vaults, and `{}` is a {} vault: drop `--at`",
                tilde(&v.shown()),
                v.kind.word()
            );
        }
        let at = vault::real_parent(&at);
        let open = mounts::gocryptfs_mounts()
            .into_iter()
            .find(|(source, _)| *source == v.cipher)
            .map(|(_, point)| point);
        if let Some(open) = open.filter(|p| *p != at) {
            bail!(
                "`{}` is open at `{}` already: `ck lock {}` first",
                tilde(&v.cipher),
                tilde(&open),
                tilde(&open)
            );
        }
        v.view = at;
    }
    unlock_one(&v, minutes, identity, dry)
}

/// Unlocks `v` the way `ck unlock` does, after the checks every caller shares.
fn unlock_one(v: &Vault, minutes: Option<u32>, identity: Option<PathBuf>, dry: bool) -> Result<()> {
    registry::check_storable(v)?;
    if minutes.is_some() && v.kind != Kind::Gocryptfs {
        bail!(
            "`-t` works only on gocryptfs vaults, and `{}` is a {} vault: drop `-t`",
            tilde(&v.shown()),
            v.kind.word()
        );
    }
    if identity.is_some() && v.kind != Kind::Age {
        bail!(
            "`-i` works only on age files, and `{}` is a {} vault: drop `-i`",
            tilde(&v.shown()),
            v.kind.word()
        );
    }
    if let State::Missing = vault::state(v) {
        bail!(
            "`{}` is missing ({}): bring it back, or `ck forget` it",
            tilde(&v.shown()),
            listing::missing_note(v)
        );
    }
    match v.kind {
        Kind::Gocryptfs => gocryptfs::unlock(v, minutes, dry)?,
        Kind::Luks => luks::unlock(v, dry)?,
        Kind::Age => age::unlock(v, identity, dry)?,
    }
    // A shell already inside the view still sees the empty folder underneath.
    if v.kind == Kind::Gocryptfs && cwd().is_ok_and(|c| c.starts_with(&v.view)) {
        say!("you are inside it: `cd .` to see the files");
    }
    Ok(())
}

/// `ck edit`: the age vault `path` names, opened in `$VISUAL`, else
/// `$EDITOR`, else `vi`, and locked again when the editor exits if this run
/// unlocked it.
pub fn edit(path: Option<PathBuf>, identity: Option<PathBuf>, dry: bool) -> Result<()> {
    let known = registry::load()?;
    let v = pick(path, "edit", &known)?;
    if v.kind != Kind::Age {
        bail!(
            "`ck edit` opens age files, and `{}` is a {} vault: `ck shell {}` opens it",
            tilde(&v.shown()),
            v.kind.word(),
            tilde(&v.shown())
        );
    }
    let (v, unlocked) = open_for(v, identity, dry)?;
    let editor = ["VISUAL", "EDITOR"]
        .into_iter()
        .find_map(|k| std::env::var(k).ok().filter(|e| !e.trim().is_empty()))
        .unwrap_or_else(|| "vi".into());
    let edited = dry || {
        // Through `sh`, so an editor given with its flags (`code --wait`) runs as typed.
        let mut cmd = Command::new("sh");
        cmd.arg("-c")
            .arg(format!("{editor} \"$1\""))
            .arg("sh")
            .arg(&v.view);
        run::foreground(&mut cmd) == Ran::Done
    };
    close_after(&v, unlocked, dry)?;
    if !edited {
        bail!("`{editor}` did not exit cleanly: its own lines above say why");
    }
    Ok(())
}

/// `ck shell`: a shell in the vault `path` names (the view's folder for an
/// age file) with `CK_VAULT` set to its view, and the vault locked again when
/// the shell exits if this run unlocked it.
pub fn shell(path: Option<PathBuf>, identity: Option<PathBuf>, dry: bool) -> Result<()> {
    let known = registry::load()?;
    let v = pick(path, "shell", &known)?;
    let (v, unlocked) = open_for(v, identity, dry)?;
    if !dry {
        let dir = match v.kind {
            Kind::Age => v.view.parent().unwrap_or(Path::new("/")),
            _ => v.view.as_path(),
        };
        let shell = std::env::var("SHELL")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "/bin/sh".into());
        let found = Path::new(&shell).is_file() || run::on_path(&shell);
        if !found || !dir.is_dir() {
            close_after(&v, unlocked, false)?;
            bail!("could not start `{shell}` in `{}`", tilde(dir));
        }
        // The shell's own exit code is whatever its last command left, not a failure of ck's.
        let _ = run::foreground(
            Command::new(&shell)
                .current_dir(dir)
                .env("CK_VAULT", &v.view),
        );
    }
    close_after(&v, unlocked, dry)
}

/// `v` opened for `edit` or `shell`, and whether this run had to unlock it.
fn open_for(v: Vault, identity: Option<PathBuf>, dry: bool) -> Result<(Vault, bool)> {
    if matches!(vault::state(&v), State::Open(_) | State::Exposed(_)) {
        if v.kind != Kind::Luks {
            return Ok((v, false));
        }
        // A drive is used where it is mounted; one unlocked but not mounted gets mounted.
        if let Some(at) = luks::open_at(&v) {
            return Ok((Vault { view: at, ..v }, false));
        }
    }
    unlock_one(&v, None, identity, dry)?;
    // Unlocking a drive can move its view to wherever udisks mounted it.
    let v = registry::load()?
        .into_iter()
        .find(|k| k.cipher == v.cipher)
        .unwrap_or(v);
    Ok((v, true))
}

/// Locks `v` again when this run unlocked it, or says it was left open.
fn close_after(v: &Vault, unlocked: bool, dry: bool) -> Result<()> {
    if !unlocked {
        say!("left open: `{}`, as it was", tilde(&v.shown()));
        return Ok(());
    }
    if dry {
        say!("locked: `{}`", tilde(&v.shown()));
        return Ok(());
    }
    lock_one(v, false)
}

pub fn lock(path: Option<PathBuf>, all: bool, dry: bool) -> Result<()> {
    let known = registry::load()?;
    if all {
        return lock_all(&known, dry);
    }
    let away = path.is_none() && vault::nearest(&cwd()?, &known)?.is_none();
    let v = if away {
        // Away from every vault, the only open one is the obvious one to lock.
        match open_vaults(&known).as_slice() {
            [one] => one.clone(),
            [] => bail!("no vault in or above this folder, and none is unlocked"),
            _ => bail!("no vault in or above this folder: name one, or `ck lock --all`"),
        }
    } else {
        pick(path, "lock", &known)?
    };
    if !is_unlocked(&v) {
        say!("already locked: `{}`", tilde(&v.shown()));
        return Ok(());
    }
    lock_one(&v, dry)
}

/// Locks every open vault, carrying on past one that refuses and failing at
/// the end if any did.
fn lock_all(known: &[Vault], dry: bool) -> Result<()> {
    let open = open_vaults(known);
    if open.is_empty() {
        say!("nothing is unlocked");
        return Ok(());
    }
    let mut failed = 0;
    for (i, v) in open.iter().enumerate() {
        if let Err(e) = lock_one(v, dry) {
            eprintln!("ck: {e}");
            failed += 1;
            // Ctrl-C means stop, not ask the next vault for its password.
            if run::interrupted() {
                failed += open.len() - i - 1;
                break;
            }
        }
    }
    if failed > 0 {
        bail!("{failed} of {} vaults stayed unlocked", open.len());
    }
    Ok(())
}

fn lock_one(v: &Vault, dry: bool) -> Result<()> {
    let inside = !v.view.as_os_str().is_empty() && cwd().is_ok_and(|c| c.starts_with(&v.view));
    if inside {
        bail!(
            "your shell is inside `{}`: `cd` out of it, then `ck lock`",
            tilde(&v.view)
        );
    }
    match v.kind {
        Kind::Gocryptfs => gocryptfs::lock(v, dry),
        Kind::Luks => luks::lock(v, dry),
        Kind::Age => age::lock(v, dry),
    }
}

/// Whether `v` has anything for `lock` to close: a gocryptfs mount, dead or
/// alive, an unlocked LUKS device, or an age copy or the link left to it.
fn is_unlocked(v: &Vault) -> bool {
    match v.kind {
        Kind::Gocryptfs => mounts::is_mounted(&v.view),
        Kind::Luks => luks::is_unlocked(v),
        Kind::Age => matches!(
            vault::state(v),
            State::Open(_) | State::Dead(_) | State::Exposed(_)
        ),
    }
}

fn open_vaults(known: &[Vault]) -> Vec<Vault> {
    known.iter().filter(|v| is_unlocked(v)).cloned().collect()
}

pub fn ls(json: bool) -> Result<()> {
    let known = registry::load()?;
    let entries = listing::all(&known, &scan::found(&known));
    if json {
        println!("{}", listing::json(&entries));
        return Ok(());
    }
    if known.is_empty() {
        println!("no vaults yet: `ck init` makes one, `ck unlock <path>` adds one that exists");
    }
    let rows = listing::rows(&entries);
    let (listed, drives) = rows.split_at(known.len());
    for line in listed {
        println!("{line}");
    }
    // The drives the list does not hold, set apart.
    if !drives.is_empty() {
        println!();
    }
    for line in drives {
        println!("{line}");
    }
    Ok(())
}

/// Bare `ck`: the vaults nearest the current folder, as `ls` shows them.
pub fn status() -> Result<()> {
    let known = registry::load()?;
    match vault::nearest(&cwd()?, &known)? {
        Some(found) => {
            for line in listing::rows(&listing::of_vaults(&found, &known)) {
                println!("{line}");
            }
        }
        None => bail!(
            "no vault in or above this folder: `ck ls` lists every vault, `ck init` makes one"
        ),
    }
    Ok(())
}

/// Drops every vault whose encrypted side is gone from the list.
pub fn clear(dry: bool) -> Result<()> {
    let all = registry::load()?;
    let picked = (0..all.len())
        .filter(|&i| matches!(vault::state(&all[i]), State::Missing))
        .collect();
    drop_lines(all, picked, dry)
}

/// `ck delete`: removes a locked vault for good (a gocryptfs vault's
/// encrypted folder and its empty view, an `.age` file, a LUKS image) and
/// its line in the list. Refused for an open vault, a drive, and without
/// `yes`.
pub fn delete(path: PathBuf, yes: bool, dry: bool) -> Result<()> {
    let known = registry::load()?;
    let v = vault::resolve(&path, "delete", &known)?;
    let shown = tilde(&v.shown());
    // Only the vault named, never one found walking up from a folder in or beside it.
    if !vault::is_named_by(&v, &path) {
        bail!(
            "`{}` is not a vault itself, only in or beside `{shown}`: name the vault to delete, e.g. `ck delete {shown} --yes`",
            tilde(&path)
        );
    }
    if v.kind == Kind::Luks && v.cipher.starts_with("/dev") {
        bail!("a drive is never deleted: `ck forget {shown}` only drops it from the list");
    }
    match vault::state(&v) {
        State::Locked => {}
        State::Missing => bail!(
            "`{shown}` is missing, so there is nothing to delete: `ck forget {shown}` drops it from the list"
        ),
        _ => bail!("`{shown}` is open: `ck lock {shown}` first, then delete it"),
    }
    let doomed = match v.kind {
        Kind::Gocryptfs if !vault::is_cipher(&v.cipher) || mounts::points().contains(&v.cipher) => {
            bail!(
                "`{}` does not look like a gocryptfs folder any more, so ck leaves it alone",
                tilde(&v.cipher)
            )
        }
        _ => v.cipher.clone(),
    };
    if !yes {
        bail!(
            "deleting `{shown}` destroys `{}` for good: add `--yes` to go ahead",
            tilde(&doomed)
        );
    }
    if !dry {
        let gone = match v.kind {
            Kind::Gocryptfs => fs::remove_dir_all(&doomed),
            _ => fs::remove_file(&doomed),
        };
        if gone.is_err() {
            bail!("could not delete `{}`", tilde(&doomed));
        }
        // An empty view folder, or a link left to an age copy, goes with it.
        if v.kind == Kind::Gocryptfs && is_empty_dir(&v.view) {
            let _ = fs::remove_dir(&v.view);
        }
        if v.kind == Kind::Age
            && fs::symlink_metadata(&v.view).is_ok_and(|m| m.file_type().is_symlink())
        {
            let _ = fs::remove_file(&v.view);
        }
        let all = registry::load()?;
        if all.iter().any(|k| k.cipher == v.cipher) {
            let rest: Vec<Vault> = all.into_iter().filter(|k| k.cipher != v.cipher).collect();
            registry::save(&rest)?;
        }
    }
    say!("deleted `{}`", tilde(&doomed));
    Ok(())
}

/// Drops vaults from the list, missing or not: the ones `names` spells as `ls`
/// prints them, or with none the ones picked by number at a prompt. Never
/// touches a vault itself.
pub fn forget(names: Vec<String>, dry: bool) -> Result<()> {
    let all = registry::load()?;
    if all.is_empty() {
        say!("no vaults listed, so nothing to forget");
        return Ok(());
    }
    let picked = if names.is_empty() {
        ask(&all)?
    } else {
        names
            .iter()
            .map(|n| by_name(&all, n))
            .collect::<Result<Vec<_>>>()?
    };
    drop_lines(all, picked, dry)
}

/// The index of the vault in `all` that `name` spells, with `~` for home as
/// `ls` prints it.
fn by_name(all: &[Vault], name: &str) -> Result<usize> {
    let path = match name.strip_prefix("~/") {
        Some(rest) => dirs::home_dir().unwrap_or_default().join(rest),
        None => PathBuf::from(name),
    };
    let found = vault::by_name(all, &path).and_then(|v| all.iter().position(|a| a == v));
    match found {
        Some(i) => Ok(i),
        None => bail!("`{name}` is not in `ck ls`: nothing was forgotten"),
    }
}

/// Asks what to call a new vault, with Enter taking `default`.
fn ask_name(default: &str) -> Result<String> {
    eprint!("name [{default}]: ");
    let _ = std::io::Write::flush(&mut std::io::stderr());
    let mut answer = String::new();
    if std::io::stdin().read_line(&mut answer).is_err() {
        bail!("could not read a name: no vault was made");
    }
    let answer = answer.trim();
    Ok(if answer.is_empty() { default } else { answer }.to_string())
}

fn ask(all: &[Vault]) -> Result<Vec<usize>> {
    for (n, line) in listing::rows(&listing::of_vaults(all, all))
        .into_iter()
        .enumerate()
    {
        println!("{:>3}  {line}", n + 1);
    }
    eprint!("forget which? numbers, e.g. `1 3` (empty cancels): ");
    let _ = std::io::Write::flush(&mut std::io::stderr());
    let mut answer = String::new();
    if std::io::stdin().read_line(&mut answer).is_err() {
        bail!("could not read an answer: nothing was forgotten");
    }
    let mut picked = Vec::new();
    for word in answer
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|w| !w.is_empty())
    {
        match word.parse::<usize>() {
            Ok(n) if (1..=all.len()).contains(&n) => picked.push(n - 1),
            _ => bail!("`{word}` is not one of the numbers above: nothing was forgotten"),
        }
    }
    Ok(picked)
}

fn drop_lines(mut all: Vec<Vault>, mut picked: Vec<usize>, dry: bool) -> Result<()> {
    if picked.is_empty() {
        say!("nothing to forget");
        return Ok(());
    }
    picked.sort_unstable();
    picked.dedup();
    let gone: Vec<Vault> = picked.iter().rev().map(|&i| all.remove(i)).collect();
    if !dry {
        registry::save(&all)?;
    }
    for v in gone.iter().rev() {
        say!("forgot `{}`", tilde(&v.shown()));
    }
    Ok(())
}

/// The vault `path` names, or the one the current folder is in.
fn pick(path: Option<PathBuf>, verb: &str, known: &[Vault]) -> Result<Vault> {
    match path {
        Some(p) => vault::resolve(&p, verb, known),
        None => vault::find(&cwd()?, verb, known),
    }
}

fn cwd() -> Result<PathBuf> {
    match std::env::current_dir() {
        Ok(d) => Ok(d),
        Err(_) => bail!("the current folder is gone: `cd` somewhere that exists"),
    }
}

fn is_empty_dir(dir: &Path) -> bool {
    fs::read_dir(dir).is_ok_and(|mut d| d.next().is_none())
}
