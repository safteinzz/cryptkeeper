//! One function per CLI command. Every command that changes something takes
//! `dry`, and a dry run prints the same lines the real run would.

use crate::settings;
use crate::vault::{self, Vault};
use crate::{mounts, registry, tilde};
use anyhow::{Result, bail};
use std::fs;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};

pub fn init(name: Option<String>, dir: Option<PathBuf>, dry: bool) -> Result<()> {
    need_gocryptfs()?;
    let s = settings::load();
    let dir = match dir {
        Some(d) => d,
        None => cwd()?,
    };
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
        bail!("`{name}` cannot name a vault: use a plain folder name, e.g. `egc init photos`");
    }
    let v = Vault::from_view(&dir.join(&name));
    registry::check_storable(&v)?;
    // A vault list that cannot be saved to fails here, before a vault exists
    // that it would have to leave out.
    registry::load()?;
    // An empty one is what a cancelled `init` left behind, so it is reused.
    if v.cipher.exists() && !is_empty_dir(&v.cipher) {
        bail!(
            "`{}` already exists: pick another name with `egc init <name>`",
            tilde(&v.cipher)
        );
    }
    // gocryptfs will only open into an empty folder.
    if v.view.exists() && !is_empty_dir(&v.view) {
        bail!(
            "`{}` already has files in it: pick another name with `egc init <name>`",
            tilde(&v.view)
        );
    }
    if !dry {
        let made: Vec<&Path> = [v.cipher.as_path(), v.view.as_path()]
            .into_iter()
            .filter(|p| !p.exists())
            .collect();
        if fs::create_dir_all(&v.cipher).is_err() || fs::create_dir_all(&v.view).is_err() {
            bail!("could not create the vault's folders in `{}`", tilde(&dir));
        }
        // Without `-q`, so gocryptfs prints the master key, the one way back
        // in after a forgotten password, which it shows only this once.
        let mut cmd = Command::new("gocryptfs");
        cmd.arg("-init").arg(&v.cipher);
        let ran = run_gocryptfs(&mut cmd);
        if ran != Ran::Done {
            // Only the folders made above go, and remove_dir only takes an empty one.
            for p in made {
                let _ = fs::remove_dir(p);
            }
            match ran {
                Ran::Cancelled => bail!("cancelled, so no vault was made"),
                _ => bail!("`gocryptfs -init` failed, so no vault was made"),
            }
        }
        registry::remember(&v)?;
    }
    println!("made `{}`: open it with `egc unlock`", tilde(&v.view));
    Ok(())
}

pub fn unlock(path: Option<PathBuf>, minutes: Option<u32>, dry: bool) -> Result<()> {
    need_gocryptfs()?;
    let v = pick(path, "unlock")?;
    registry::check_storable(&v)?;
    registry::load()?;
    if mounts::is_mounted(&v.view) {
        if mounts::is_alive(&v.view) {
            if !dry {
                registry::remember(&v)?;
            }
            println!("already unlocked: `{}`", tilde(&v.view));
            return Ok(());
        }
        if !dry {
            mounts::unmount(&v.view, true)?;
        }
    }
    if !dry {
        if fs::create_dir_all(&v.view).is_err() {
            bail!(
                "could not create `{}` to open the vault into",
                tilde(&v.view)
            );
        }
        let mut cmd = Command::new("gocryptfs");
        cmd.arg("-q");
        // With no syslog to hand its messages to, the mount prints a "Unix syslog
        // delivery error" per stream and then drops every later warning, a
        // corrupt block included; `-nosyslog` keeps them on this terminal.
        if !Path::new("/dev/log").exists() {
            cmd.arg("-nosyslog");
        }
        if let Some(m) = minutes {
            cmd.args(["-i", &format!("{m}m")]);
        }
        cmd.arg(&v.cipher).arg(&v.view);
        match run_gocryptfs(&mut cmd) {
            Ran::Done => {}
            Ran::Cancelled => bail!("cancelled, so `{}` stays locked", tilde(&v.view)),
            Ran::Failed => bail!("could not unlock `{}`", tilde(&v.view)),
        }
        registry::remember(&v)?;
    }
    match minutes {
        Some(m) => println!("unlocked: `{}`, locks after {m}m unused", tilde(&v.view)),
        None => println!("unlocked: `{}`", tilde(&v.view)),
    }
    // A shell already inside the view still sees the empty folder underneath.
    if cwd().is_ok_and(|c| c.starts_with(&v.view)) {
        println!("you are inside it: `cd .` to see the files");
    }
    Ok(())
}

pub fn lock(path: Option<PathBuf>, all: bool, dry: bool) -> Result<()> {
    if all {
        return lock_all(dry);
    }
    let away = path.is_none() && vault::nearest(&cwd()?)?.is_none();
    let v = if away {
        // Away from every vault, the only open one is the obvious one to lock.
        match open_vaults()?.as_slice() {
            [one] => one.clone(),
            [] => bail!("no vault in or above this folder, and none is unlocked"),
            _ => bail!("no vault in or above this folder: name one, or `egc lock --all`"),
        }
    } else {
        pick(path, "lock")?
    };
    if !mounts::is_mounted(&v.view) {
        println!("already locked: `{}`", tilde(&v.view));
        return Ok(());
    }
    lock_one(&v, dry)
}

/// Locks every open vault, carrying on past one that refuses and failing at
/// the end if any did.
fn lock_all(dry: bool) -> Result<()> {
    let open = open_vaults()?;
    if open.is_empty() {
        println!("nothing is unlocked");
        return Ok(());
    }
    let mut failed = 0;
    for v in &open {
        if let Err(e) = lock_one(v, dry) {
            eprintln!("egc: {e}");
            failed += 1;
        }
    }
    if failed > 0 {
        bail!("{failed} of {} vaults stayed unlocked", open.len());
    }
    Ok(())
}

fn lock_one(v: &Vault, dry: bool) -> Result<()> {
    if cwd().is_ok_and(|c| c.starts_with(&v.view)) {
        bail!(
            "your shell is inside `{}`: `cd` out of it, then `egc lock`",
            tilde(&v.view)
        );
    }
    if !dry {
        mounts::unmount(&v.view, false)?;
    }
    println!("locked: `{}`", tilde(&v.view));
    Ok(())
}

fn open_vaults() -> Result<Vec<Vault>> {
    Ok(registry::load()?
        .into_iter()
        .filter(|v| mounts::is_mounted(&v.view))
        .collect())
}

pub fn ls() -> Result<()> {
    let all = registry::load()?;
    if all.is_empty() {
        println!("no vaults yet: `egc init` makes one, `egc unlock` adds one that exists");
        return Ok(());
    }
    print_rows(&all);
    Ok(())
}

/// Bare `egc`: the vaults nearest the current folder, as `ls` shows them.
pub fn status() -> Result<()> {
    match vault::nearest(&cwd()?)? {
        Some(found) => print_rows(&found),
        None => bail!(
            "no vault in or above this folder: `egc ls` lists every vault, `egc init` makes one"
        ),
    }
    Ok(())
}

/// Drops every vault whose folder is gone from the list.
pub fn clear(dry: bool) -> Result<()> {
    let all = registry::load()?;
    let picked = (0..all.len())
        .filter(|&i| !all[i].cipher.exists())
        .collect();
    drop_lines(all, picked, dry)
}

/// Drops vaults from the list, missing or not: the ones `names` spells as `ls`
/// prints them, or with none the ones picked by number at a prompt. Never
/// touches a vault's folders.
pub fn forget(names: Vec<String>, dry: bool) -> Result<()> {
    let all = registry::load()?;
    if all.is_empty() {
        println!("no vaults listed, so nothing to forget");
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

/// The vault in `all` that `name` spells, as a view or an encrypted folder,
/// with `~` for home as `ls` prints it.
fn by_name(all: &[Vault], name: &str) -> Result<usize> {
    let path = match name.strip_prefix("~/") {
        Some(rest) => dirs::home_dir().unwrap_or_default().join(rest),
        None => PathBuf::from(name),
    };
    let path = std::path::absolute(&path).unwrap_or(path);
    let is = |p: &Path| all.iter().position(|v| v.view == p || v.cipher == p);
    // The name as given first, so a symlinked entry is not mistaken for the
    // one its link points at; resolved only when nothing matches as given.
    let found = is(&path).or_else(|| path.canonicalize().ok().and_then(|p| is(&p)));
    match found {
        Some(i) => Ok(i),
        None => bail!("`{name}` is not in `egc ls`: nothing was forgotten"),
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
    for (n, line) in rows(all).into_iter().enumerate() {
        println!("{:>3}  {line}", n + 1);
    }
    eprint!("forget which? numbers, e.g. `1 3` (empty cancels):");
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
        println!("nothing to forget");
        return Ok(());
    }
    picked.sort_unstable();
    picked.dedup();
    let gone: Vec<Vault> = picked.iter().rev().map(|&i| all.remove(i)).collect();
    if !dry {
        registry::save(&all)?;
    }
    for v in gone.iter().rev() {
        println!("forgot `{}`", tilde(&v.view));
    }
    Ok(())
}

fn print_rows(vaults: &[Vault]) {
    for line in rows(vaults) {
        println!("{line}");
    }
}

/// One aligned `state  place  note` line per vault.
fn rows(vaults: &[Vault]) -> Vec<String> {
    let rows: Vec<(&str, String, String)> = vaults
        .iter()
        .map(|v| {
            let (state, note) = if !v.cipher.exists() {
                (
                    "missing",
                    "drive not plugged in, or the folder moved".to_string(),
                )
            } else if !mounts::is_mounted(&v.view) {
                ("locked", String::new())
            } else if !mounts::is_alive(&v.view) {
                ("dead", "gocryptfs died: `egc unlock` clears it".to_string())
            } else {
                let note = mounts::idle_timeout(&v.view)
                    .map(|t| format!("locks after {t} unused"))
                    .unwrap_or_default();
                ("open", note)
            };
            (state, tilde(&v.view), note)
        })
        .collect();
    let width = rows.iter().map(|r| r.1.chars().count()).max().unwrap_or(0);
    rows.into_iter()
        .map(|(state, place, note)| {
            format!("{state:<8} {place:<width$}  {note}")
                .trim_end()
                .to_string()
        })
        .collect()
}

/// The vault `path` names, or the one the current folder is in.
fn pick(path: Option<PathBuf>, verb: &str) -> Result<Vault> {
    let start = match path {
        Some(p) => p,
        None => cwd()?,
    };
    vault::find(&start, verb)
}

fn cwd() -> Result<PathBuf> {
    match std::env::current_dir() {
        Ok(d) => Ok(d),
        Err(_) => bail!("the current folder is gone: `cd` somewhere that exists"),
    }
}

#[derive(PartialEq)]
enum Ran {
    Done,
    Cancelled,
    Failed,
}

/// Runs gocryptfs in the foreground so it can ask for a password. Ctrl-C at
/// that prompt reaches the whole process group, so egc catches it instead of
/// dying with gocryptfs, and the caller gets `Cancelled` to clean up after.
fn run_gocryptfs(cmd: &mut Command) -> Ran {
    static INTERRUPTED: AtomicBool = AtomicBool::new(false);
    let _ = ctrlc::set_handler(|| INTERRUPTED.store(true, Ordering::SeqCst));
    let ok = cmd.status().is_ok_and(|st| st.success());
    if ok {
        Ran::Done
    } else if INTERRUPTED.load(Ordering::SeqCst) {
        // gocryptfs died mid-prompt, leaving the cursor after `Password:`.
        eprintln!();
        Ran::Cancelled
    } else {
        Ran::Failed
    }
}

fn is_empty_dir(dir: &Path) -> bool {
    fs::read_dir(dir).is_ok_and(|mut d| d.next().is_none())
}

fn need_gocryptfs() -> Result<()> {
    let found = std::env::var_os("PATH").is_some_and(|p| {
        std::env::split_paths(&p).any(|d| Path::new(&d).join("gocryptfs").is_file())
    });
    if !found {
        bail!(
            "`gocryptfs` is not installed: see https://github.com/rfjakob/gocryptfs#installation"
        );
    }
    Ok(())
}
