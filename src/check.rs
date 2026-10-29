//! `ck check`: whether this machine can open each kind of vault, and what to
//! install or change when it cannot. It only reads, and writes nothing.

use crate::vault::Kind;
use crate::{age, listing, run};
use anyhow::Result;
use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

/// How long any one program may take to answer before ck stops waiting.
const LIMIT: Duration = Duration::from_secs(5);

/// The udisks actions `ck unlock` needs polkit to allow, with what each does.
const ACTIONS: [(&str, &str); 3] = [
    ("org.freedesktop.udisks2.encrypted-unlock", "unlock"),
    ("org.freedesktop.udisks2.filesystem-mount", "mount"),
    ("org.freedesktop.udisks2.loop-setup", "set up loop devices"),
];

pub struct Check {
    pub kind: Kind,
    /// One of `ready`, `missing`, `blocked`, `unchecked`.
    pub state: &'static str,
    pub detail: String,
    pub fix: Option<String>,
}

impl Check {
    /// The fix as a command ck can run for the user, when it is one: an
    /// install through this distro's package manager.
    pub fn command(&self) -> Option<Vec<String>> {
        let fix = self.fix.as_deref()?;
        fix.starts_with("sudo ")
            .then(|| fix.split_whitespace().map(str::to_string).collect())
    }
}

/// One check a kind, in the order `ck check` prints them.
pub fn all() -> [Check; 3] {
    [gocryptfs(), luks(), age()]
}

/// Prints one line per kind, or with `json` an array, and exits 1 unless
/// every kind is ready.
pub fn run(json: bool) -> Result<()> {
    let checks = all();
    if json {
        let objects: Vec<String> = checks
            .iter()
            .map(|c| {
                format!(
                    "{{\"kind\":{},\"state\":{},\"detail\":{},\"fix\":{}}}",
                    listing::string(c.kind.word()),
                    listing::string(c.state),
                    listing::string(&c.detail),
                    c.fix.as_deref().map_or("null".into(), listing::string)
                )
            })
            .collect();
        println!("{}", listing::array(&objects));
    } else {
        for c in &checks {
            let line = match &c.fix {
                Some(fix) => format!("{}: {fix}", c.detail),
                None => c.detail.clone(),
            };
            println!("{:<10} {:<9} {line}", c.kind.word(), c.state);
        }
    }
    if checks.iter().any(|c| c.state != "ready") {
        std::process::exit(1);
    }
    Ok(())
}

fn gocryptfs() -> Check {
    let missing: Vec<&str> = ["gocryptfs", "fusermount3"]
        .into_iter()
        .filter(|b| !run::on_path(b))
        .collect();
    if !missing.is_empty() {
        return Check {
            kind: Kind::Gocryptfs,
            state: "missing",
            detail: format!("{} not on PATH", names(&missing)),
            fix: Some(install(&missing)),
        };
    }
    let versions = format!(
        "{}, {}",
        version("gocryptfs", "-version"),
        version("fusermount3", "-V")
    );
    match fuse_problem() {
        Some((why, fix)) => Check {
            kind: Kind::Gocryptfs,
            state: "blocked",
            detail: format!("{versions}, but {why}"),
            fix: Some(fix),
        },
        None => Check {
            kind: Kind::Gocryptfs,
            state: "ready",
            detail: format!("{versions}, `/dev/fuse` usable"),
            fix: None,
        },
    }
}

/// Why `/dev/fuse` cannot be opened for reading and writing, judged from its
/// mode, owner and this user's groups without opening it.
fn fuse_problem() -> Option<(String, String)> {
    let Ok(m) = fs::metadata("/dev/fuse") else {
        return Some((
            "`/dev/fuse` is missing".into(),
            "load the fuse module with `sudo modprobe fuse`".into(),
        ));
    };
    let uid = fs::metadata("/proc/self")
        .map(|s| s.uid())
        .unwrap_or(u32::MAX);
    let rw = |shift: u32| m.mode() >> shift & 0o6 == 0o6;
    let usable = m.file_type().is_char_device()
        && (rw(0) || (m.uid() == uid && rw(6)) || (my_groups().contains(&m.gid()) && rw(3)));
    (!usable).then(|| {
        (
            "`/dev/fuse` is not open to you for reading and writing".into(),
            "ask an admin to make it `crw-rw-rw-`, as fuse3 installs it".into(),
        )
    })
}

fn my_groups() -> Vec<u32> {
    let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
    status
        .lines()
        .find_map(|l| l.strip_prefix("Groups:"))
        .map(|g| {
            g.split_whitespace()
                .filter_map(|n| n.parse().ok())
                .collect()
        })
        .unwrap_or_default()
}

fn luks() -> Check {
    let check = |state, detail: String, fix: Option<String>| Check {
        kind: Kind::Luks,
        state,
        detail,
        fix,
    };
    if crate::settings::load().luks_sudo {
        return match (crate::luks::admin_tool("cryptsetup"), run::on_path("sudo")) {
            (Ok(_), true) => check(
                "ready",
                "`luks = sudo` is set: ck opens and mounts drives through sudo, which asks for your password once".into(),
                None,
            ),
            (Err(_), _) => check(
                "missing",
                "`luks = sudo` is set, but `cryptsetup` is not installed".into(),
                Some(install(&["cryptsetup"])),
            ),
            (_, false) => check(
                "missing",
                "`luks = sudo` is set, but `sudo` is not installed".into(),
                Some(install(&["sudo"])),
            ),
        };
    }
    if !run::on_path("udisksctl") {
        return check(
            "missing",
            "`udisksctl` not on PATH".into(),
            Some(install(&["udisksctl"])),
        );
    }
    let status = run::bounded(Command::new("udisksctl").arg("status"), LIMIT);
    if !status.as_ref().is_some_and(|r| r.code == Some(0)) {
        let said = status.map(|r| r.said).unwrap_or_default();
        return check(
            "blocked",
            format!("udisks is not answering{said}"),
            Some("start it with `sudo systemctl start udisks2`".into()),
        );
    }
    if !run::on_path("pkcheck") {
        return check(
            "unchecked",
            "udisks answers, but polkit was not checked: `pkcheck` is not on PATH".into(),
            Some(install(&["pkcheck"])),
        );
    }
    let Some(me) = subject() else {
        return check(
            "unchecked",
            "udisks answers, but polkit was not checked: `/proc/self/stat` is unreadable".into(),
            None,
        );
    };
    let mut asks = Vec::new();
    let mut refuses = Vec::new();
    for (action, what) in ACTIONS {
        let ran = run::bounded(
            Command::new("pkcheck")
                .args(["--action-id", action, "--process"])
                .arg(&me),
            LIMIT,
        );
        // pkcheck's exit codes: 0 allowed, 1 refused, 2 allowed after an admin password.
        match ran {
            Some(r) if r.code == Some(0) => {}
            Some(r) if r.code == Some(2) => asks.push(what),
            Some(r) if r.code == Some(1) => refuses.push(what),
            r => {
                return check(
                    "unchecked",
                    format!(
                        "udisks answers, but `pkcheck` could not answer for `{action}`{}",
                        r.map(|r| r.said).unwrap_or_default()
                    ),
                    None,
                );
            }
        }
    }
    if !refuses.is_empty() {
        return check(
            "blocked",
            format!(
                "polkit refuses to let you {}",
                names(&refuses).replace('`', "")
            ),
            Some("ask an admin to allow the udisks actions for your user".into()),
        );
    }
    // Asking for a password is how polkit works outside the desktop session,
    // not something in the way: the drive still opens once it is typed.
    if !asks.is_empty() {
        return check(
            "ready",
            format!(
                "udisks answers; this is not the desktop session, so polkit asks for your password to {} each time (Drives through: sudo, in ck's Settings tab, asks once)",
                names(&asks).replace('`', "")
            ),
            None,
        );
    }
    check(
        "ready",
        "udisks answers, and polkit lets you unlock, mount and set up loop devices".into(),
        None,
    )
}

/// Whether polkit will ask for a password before udisks unlocks, mounts or
/// sets up a loop device for this process, as it does over ssh.
pub fn polkit_asks() -> bool {
    let Some(me) = subject() else { return false };
    run::on_path("pkcheck")
        && ACTIONS.iter().any(|(action, _)| {
            run::bounded(
                Command::new("pkcheck")
                    .args(["--action-id", action, "--process"])
                    .arg(&me),
                LIMIT,
            )
            .is_some_and(|r| r.code == Some(2))
        })
}

/// This process as `pkcheck --process` takes it: `pid,start-time,uid`.
fn subject() -> Option<String> {
    let stat = fs::read_to_string("/proc/self/stat").ok()?;
    // The command name in parentheses may hold spaces, so fields count from after it.
    let start = stat.rsplit_once(") ")?.1.split_whitespace().nth(19)?;
    let uid = fs::metadata("/proc/self").ok()?.uid();
    Some(format!("{},{start},{uid}", std::process::id()))
}

fn age() -> Check {
    let check = |state, detail: String, fix: Option<String>| Check {
        kind: Kind::Age,
        state,
        detail,
        fix,
    };
    let Some(bin) = ["age", "rage"].into_iter().find(|b| run::on_path(b)) else {
        return check(
            "missing",
            "no `age` or `rage` on PATH".into(),
            Some(install(&["age"])),
        );
    };
    let found = version(bin, "--version");
    match age::runtime_problem() {
        Some(why) => check("blocked", format!("{found}, but {why}"), None),
        None => check(
            "ready",
            format!(
                "{found}, plaintext kept in `{}` (in memory, private)",
                age::runtime_shown()
            ),
            None,
        ),
    }
}

/// The first line `bin flag` prints, cut at its first `;`.
fn version(bin: &str, flag: &str) -> String {
    let out = run::bounded(Command::new(bin).arg(flag), LIMIT)
        .map(|r| r.stdout)
        .unwrap_or_default();
    let line = out
        .lines()
        .next()
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim();
    match line {
        "" => format!("`{bin}`"),
        l if l.contains(bin) => l.replace("version: ", "").to_string(),
        l => format!("{bin} {l}"),
    }
}

fn names(bins: &[&str]) -> String {
    let quoted: Vec<String> = bins.iter().map(|b| format!("`{b}`")).collect();
    match quoted.as_slice() {
        [one] => one.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
        [] => String::new(),
    }
}

/// The command that installs the packages holding `bins` on this distro.
fn install(bins: &[&str]) -> String {
    let manager = package_manager();
    let packages: Vec<&str> = bins.iter().map(|b| package(manager, b)).collect();
    let packages = packages.join(" ");
    match manager {
        Some("apt") => format!("sudo apt install {packages}"),
        Some("dnf") => format!("sudo dnf install {packages}"),
        Some("pacman") => format!("sudo pacman -S {packages}"),
        Some("zypper") => format!("sudo zypper install {packages}"),
        _ => format!("install `{packages}` with your package manager"),
    }
}

fn package(manager: Option<&str>, bin: &str) -> &'static str {
    match (bin, manager) {
        ("fusermount3", _) => "fuse3",
        ("udisksctl", _) => "udisks2",
        ("pkcheck", Some("apt")) => "polkitd",
        ("pkcheck", _) => "polkit",
        ("gocryptfs", _) => "gocryptfs",
        ("cryptsetup", _) => "cryptsetup",
        ("sudo", _) => "sudo",
        _ => "age",
    }
}

/// The package manager `/etc/os-release` names through `ID` or `ID_LIKE`.
fn package_manager() -> Option<&'static str> {
    let text = fs::read_to_string(Path::new("/etc/os-release")).unwrap_or_default();
    let ids: Vec<String> = text
        .lines()
        .filter_map(|l| l.strip_prefix("ID=").or_else(|| l.strip_prefix("ID_LIKE=")))
        .flat_map(|v| {
            v.trim_matches('"')
                .split_whitespace()
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .collect();
    ids.iter().find_map(|id| match id.as_str() {
        "debian" | "ubuntu" => Some("apt"),
        "fedora" | "rhel" | "centos" => Some("dnf"),
        "arch" => Some("pacman"),
        i if i == "suse" || i.starts_with("opensuse") => Some("zypper"),
        _ => None,
    })
}
