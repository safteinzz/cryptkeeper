//! The gocryptfs backend: making a vault, mounting it, and what state it is in.

use crate::run::{self, Ran};
use crate::vault::{State, Vault};
use crate::{mounts, registry, tilde};
use anyhow::{Result, bail};
use std::fs;
use std::path::Path;
use std::process::Command;

pub fn need() -> Result<()> {
    if !run::on_path("gocryptfs") {
        bail!(
            "`gocryptfs` is not installed: see https://github.com/rfjakob/gocryptfs#installation"
        );
    }
    Ok(())
}

pub fn state(v: &Vault) -> State {
    if !v.cipher.exists() {
        State::Missing
    } else if !mounts::is_mounted(&v.view) {
        State::Locked
    } else if !mounts::is_alive(&v.view) {
        State::Dead("gocryptfs died: `ck unlock` clears it".into())
    } else {
        State::Open(
            mounts::idle_timeout(&v.view)
                .map(|t| format!("locks after {t} unused"))
                .unwrap_or_default(),
        )
    }
}

/// Makes the vault `v` with `gocryptfs -init`, removing only the folders it
/// made itself when that fails or is cancelled.
pub fn init(v: &Vault) -> Result<()> {
    let made: Vec<&Path> = [v.cipher.as_path(), v.view.as_path()]
        .into_iter()
        .filter(|p| !p.exists())
        .collect();
    if fs::create_dir_all(&v.cipher).is_err() || fs::create_dir_all(&v.view).is_err() {
        let dir = v.view.parent().unwrap_or(Path::new("/"));
        bail!("could not create the vault's folders in `{}`", tilde(dir));
    }
    // Without `-q`, so gocryptfs prints the master key, the one way back in
    // after a forgotten password, which it shows only this once.
    let mut cmd = Command::new("gocryptfs");
    cmd.arg("-init").arg(&v.cipher);
    let ran = run::prompting(&mut cmd);
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
    registry::remember(v)
}

pub fn unlock(v: &Vault, minutes: Option<u32>, dry: bool) -> Result<()> {
    need()?;
    if v.view.as_os_str().is_empty() {
        let shown = tilde(&v.cipher);
        match crate::scan::opened_before(&v.cipher) {
            Some(p) => bail!(
                "where `{shown}` opens is not known yet: `ck unlock {shown} --at {}` opens it where your shell history last did",
                tilde(&p)
            ),
            None => bail!(
                "where `{shown}` opens is not known yet: name an empty folder with `ck unlock {shown} --at <folder>`"
            ),
        }
    }
    if mounts::is_mounted(&v.view) {
        if mounts::is_alive(&v.view) {
            if !dry {
                registry::remember(v)?;
            }
            say!("already unlocked: `{}`", tilde(&v.view));
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
        // The two exit codes `man gocryptfs` gives a mount, in ck's words, since
        // gocryptfs's own lines stay on the terminal it was handed.
        match run::foreground(&mut cmd) {
            Ran::Done => {}
            Ran::Cancelled => bail!("cancelled, so `{}` stays locked", tilde(&v.view)),
            Ran::Failed(Some(12)) => {
                bail!(
                    "could not unlock `{}`: the password is wrong",
                    tilde(&v.view)
                )
            }
            Ran::Failed(Some(10)) => bail!(
                "could not unlock `{}`: it has files in it, and gocryptfs opens only into an empty folder, so move them out first",
                tilde(&v.view)
            ),
            Ran::Failed(_) => bail!("could not unlock `{}`", tilde(&v.view)),
        }
        registry::remember(v)?;
    }
    match minutes {
        Some(m) => say!("unlocked: `{}`, locks after {m}m unused", tilde(&v.view)),
        None => say!("unlocked: `{}`", tilde(&v.view)),
    }
    Ok(())
}

/// Changes `v`'s password with `gocryptfs -passwd`, which asks for the old
/// one and the new one twice, open or locked.
pub fn passwd(v: &Vault, dry: bool) -> Result<()> {
    need()?;
    if !dry {
        let mut cmd = Command::new("gocryptfs");
        cmd.arg("-passwd").arg(&v.cipher);
        match run::prompting(&mut cmd) {
            Ran::Done => {}
            Ran::Cancelled => bail!("cancelled, so `{}` keeps its password", tilde(&v.shown())),
            Ran::Failed(_) => bail!("could not change the password of `{}`", tilde(&v.shown())),
        }
    }
    say!("changed the password of `{}`", tilde(&v.shown()));
    Ok(())
}

/// Copies `v`'s `gocryptfs.conf` to `dest`, readable only by this user: with
/// it and the password, `gocryptfs -config <dest>` opens the vault even when
/// its own copy is damaged.
pub fn backup(v: &Vault, dest: &Path, dry: bool) -> Result<()> {
    let conf = v.cipher.join("gocryptfs.conf");
    if !dry {
        use std::os::unix::fs::OpenOptionsExt;
        let copied = fs::read(&conf).and_then(|body| {
            use std::io::Write;
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(dest)?
                .write_all(&body)
        });
        if copied.is_err() {
            bail!("could not copy `{}` to `{}`", tilde(&conf), tilde(dest));
        }
    }
    say!(
        "saved the gocryptfs.conf of `{}` to `{}`",
        tilde(&v.shown()),
        tilde(dest)
    );
    Ok(())
}

pub fn lock(v: &Vault, dry: bool) -> Result<()> {
    if !dry {
        mounts::unmount(&v.view, false)?;
    }
    say!("locked: `{}`", tilde(&v.view));
    Ok(())
}
