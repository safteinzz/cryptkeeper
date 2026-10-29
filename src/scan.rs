//! Finding the vaults the list does not hold: every gocryptfs open
//! anywhere, and every gocryptfs folder, age file and LUKS image file under
//! home, by a walk bounded in depth and time that never enters another
//! mountpoint. Also where shell history says a gocryptfs folder was opened,
//! as a hint ck never acts on by itself.

use crate::vault::{self, Vault};
use crate::{age, luks, mounts};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// How deep under home the walk goes.
const DEPTH: usize = 6;
/// How long the walk may take before it stops with what it has.
const BUDGET: Duration = Duration::from_millis(1500);

/// Every vault found that `known` does not hold, by name.
pub fn found(known: &[Vault]) -> Vec<Vault> {
    let listed: HashSet<PathBuf> = known
        .iter()
        .map(|v| fs::canonicalize(&v.cipher).unwrap_or_else(|_| v.cipher.clone()))
        .collect();
    let mut walk = Walk {
        points: mounts::points().into_iter().collect(),
        until: Instant::now() + BUDGET,
        found: Vec::new(),
    };
    for (cipher, point) in mounts::gocryptfs_mounts() {
        walk.found.push(Vault {
            view: point,
            ..Vault::from_cipher(&cipher)
        });
    }
    if let Some(home) = dirs::home_dir().and_then(|h| fs::canonicalize(h).ok()) {
        walk.dir(&home, 0);
    }
    let mut found: Vec<Vault> = walk
        .found
        .into_iter()
        .filter(|v| !listed.contains(&v.cipher))
        .collect();
    found.sort_by(|a, b| a.cipher.cmp(&b.cipher));
    found.dedup_by(|a, b| a.cipher == b.cipher);
    found.sort_by(|a, b| a.name().cmp(b.name()));
    found
}

struct Walk {
    /// Every mountpoint, never entered: another drive, or a dead FUSE mount
    /// that would hang the first stat inside it.
    points: HashSet<PathBuf>,
    until: Instant,
    found: Vec<Vault>,
}

impl Walk {
    fn dir(&mut self, dir: &Path, depth: usize) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            if Instant::now() > self.until {
                return;
            }
            let p = e.path();
            let Ok(kind) = e.file_type() else { continue };
            let name = vault::file_name(&p);
            if kind.is_dir() {
                if self.points.contains(&p) {
                    continue;
                }
                if vault::is_cipher(&p) {
                    self.found.push(Vault::from_cipher(&p));
                } else if !name.starts_with('.') && name != "node_modules" && depth + 1 < DEPTH {
                    self.dir(&p, depth + 1);
                }
            } else if kind.is_file() && name.ends_with(".age") && name != ".age" && age::is_age(&p)
            {
                self.found.push(Vault::age(&p));
            } else if kind.is_file()
                // Bigger than the 16 MiB a LUKS2 header backup is, which has the
                // header's magic but nothing behind it to open.
                && e.metadata().is_ok_and(|m| m.len() > 16 << 20)
                && luks::is_luks_file(&p)
            {
                self.found.push(Vault::luks(p));
            }
        }
    }
}

/// Where shell history last opened the gocryptfs folder `cipher`, from a
/// `gocryptfs <cipher> <mountpoint>` line in bash's, zsh's or fish's history.
pub fn opened_before(cipher: &Path) -> Option<PathBuf> {
    let home = dirs::home_dir()?;
    let data = dirs::data_dir().unwrap_or_else(|| home.join(".local/share"));
    let real = fs::canonicalize(cipher).unwrap_or_else(|_| cipher.to_path_buf());
    let files = [
        home.join(".bash_history"),
        home.join(".zsh_history"),
        data.join("fish/fish_history"),
    ];
    let mut last = None;
    for file in files {
        let Ok(raw) = fs::read(&file) else { continue };
        for line in String::from_utf8_lossy(&raw).lines() {
            // zsh writes `: <when>:<took>;<command>`, fish `- cmd: <command>`.
            let line = line.strip_prefix("- cmd: ").unwrap_or(line);
            let line = match line.strip_prefix(": ") {
                Some(rest) => rest.split_once(';').map_or(line, |(_, cmd)| cmd),
                None => line,
            };
            if let Some((enc, point)) = mount_args(line, &home)
                && fs::canonicalize(&enc).unwrap_or(enc) == real
            {
                last = Some(point);
            }
        }
    }
    last.filter(|p| p.as_path() != real)
}

/// The encrypted folder and mountpoint of a `gocryptfs` command line, when
/// both are written so they mean the same from anywhere (absolute, or `~/`).
fn mount_args(line: &str, home: &Path) -> Option<(PathBuf, PathBuf)> {
    // The flags that take the next word as their value.
    const VALUED: [&str; 12] = [
        "config",
        "extpass",
        "passfile",
        "masterkey",
        "ko",
        "o",
        "i",
        "idle",
        "fsname",
        "notifypid",
        "ctlsock",
        "exclude",
    ];
    let mut words = line.split_whitespace();
    let program = words.next()?;
    if Path::new(program).file_name()? != "gocryptfs" {
        return None;
    }
    let mut args = Vec::new();
    while let Some(w) = words.next() {
        let flag = w.trim_start_matches('-');
        if w.starts_with('-') {
            if !flag.contains('=') && VALUED.contains(&flag) {
                words.next();
            }
            // `-init` and `-passwd` make or change a vault, opening nothing.
            if matches!(flag, "init" | "passwd" | "info" | "fsck") {
                return None;
            }
            continue;
        }
        args.push(w);
    }
    let [enc, point] = args.as_slice() else {
        return None;
    };
    let path = |w: &str| match w.strip_prefix("~/") {
        Some(rest) => Some(home.join(rest)),
        None => w.starts_with('/').then(|| PathBuf::from(w)),
    };
    Some((path(enc)?, path(point)?))
}
