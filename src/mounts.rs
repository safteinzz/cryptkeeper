//! What is mounted where, closing a gocryptfs view, and who keeps a view busy.
//! Linux only: reads `/proc` and shells out to `fusermount3`.

use anyhow::{Result, bail};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Whether `/proc/self/mounts` lists a gocryptfs mount on `view`. Anything
/// else mounted there is not this vault being open.
pub fn is_mounted(view: &Path) -> bool {
    let Ok(text) = fs::read_to_string("/proc/self/mounts") else {
        return false;
    };
    let want = view.to_string_lossy();
    text.lines().any(|l| {
        let mut fields = l.split(' ');
        let point = fields.nth(1);
        let kind = fields.next();
        kind == Some("fuse.gocryptfs") && point.is_some_and(|m| unescape(m) == want)
    })
}

/// A mount whose gocryptfs died stays listed but answers every read with
/// "Transport endpoint is not connected", so listed is not the same as open.
pub fn is_alive(view: &Path) -> bool {
    fs::read_dir(view).is_ok()
}

/// Unmount `view`, or with `lazy` detach it even while busy, which is only
/// for clearing a dead mount.
pub fn unmount(view: &Path, lazy: bool) -> Result<()> {
    let mut args = vec!["-u"];
    if lazy {
        args.push("-z");
    }
    let out = Command::new("fusermount3").args(&args).arg(view).output();
    let out = match out {
        Ok(out) => out,
        Err(_) => match Command::new("fusermount").args(&args).arg(view).output() {
            Ok(out) => out,
            Err(_) => {
                bail!("`fusermount3` is not installed: install `fuse3` with your package manager")
            }
        },
    };
    if out.status.success() {
        return Ok(());
    }
    let said = crate::run::said(&out);
    if lazy {
        bail!(
            "could not clear the dead mount at `{}`{said}",
            crate::tilde(view)
        )
    }
    bail!("{}", busy_error(view, &said))
}

/// The error for a lock of `view` that failed with `said`: when the unmount
/// said busy, it names the user's own processes keeping it busy.
pub fn busy_error(view: &Path, said: &str) -> String {
    let name = crate::tilde(view);
    if !said.to_lowercase().contains("busy") {
        return format!("could not lock `{name}`{said}");
    }
    let holders = holders(view);
    if holders.is_empty() {
        return format!(
            "could not lock `{name}`: something still uses it{said}\nnone of your own processes holds it: another user's may, or something mounted inside it"
        );
    }
    let mut lines: Vec<String> = holders
        .iter()
        .take(5)
        .map(|h| format!("  pid {:<7} {:<15} {}", h.pid, h.name, h.what))
        .collect();
    if holders.len() > 5 {
        lines.push(format!("  and {} more", holders.len() - 5));
    }
    format!(
        "could not lock `{name}`: something still uses it{said}\n{}\nclose those, or end them with `kill <pid>`, then `ck lock` again",
        lines.join("\n")
    )
}

/// One of the user's processes keeping a view busy, and what of it it holds.
pub struct Holder {
    pub pid: u32,
    pub name: String,
    pub what: String,
}

/// The user's own processes whose folder, root or an open file lies in
/// `view`, read from the `cwd`, `root` and `fd` links in `/proc` with
/// `readlink` alone and compared as paths, so nothing inside the mount is
/// ever stat'ed.
pub fn holders(view: &Path) -> Vec<Holder> {
    let me = fs::metadata("/proc/self")
        .map(|m| m.uid())
        .unwrap_or(u32::MAX);
    let mine = std::process::id();
    let Ok(procs) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut found: Vec<Holder> = Vec::new();
    for entry in procs.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        let dir = entry.path();
        if pid == mine || !fs::metadata(&dir).is_ok_and(|m| m.uid() == me) {
            continue;
        }
        let inside = |link: &Path| fs::read_link(link).ok().filter(|t| t.starts_with(view));
        let files: Vec<PathBuf> = fs::read_dir(dir.join("fd"))
            .map(|fds| fds.flatten().filter_map(|fd| inside(&fd.path())).collect())
            .unwrap_or_default();
        let what = if let Some(file) = files.first() {
            match files.len() {
                1 => format!("has `{}` open", crate::tilde(file)),
                n => format!("has `{}` and {} more open", crate::tilde(file), n - 1),
            }
        } else if let Some(cwd) = inside(&dir.join("cwd")) {
            format!("is in `{}`", crate::tilde(&cwd))
        } else if inside(&dir.join("root")).is_some() {
            "has its root inside".into()
        } else {
            continue;
        };
        let name = fs::read_to_string(dir.join("comm"))
            .map(|n| n.trim().to_string())
            .unwrap_or_default();
        found.push(Holder { pid, name, what });
    }
    found.sort_by_key(|h| h.pid);
    found
}

/// The idle timeout the gocryptfs serving `view` was started with (`100m`),
/// read from its command line in `/proc`.
pub fn idle_timeout(view: &Path) -> Option<String> {
    let want = view.to_string_lossy();
    for entry in fs::read_dir("/proc").ok()?.flatten() {
        let Ok(raw) = fs::read(entry.path().join("cmdline")) else {
            continue;
        };
        let argv: Vec<String> = raw
            .split(|b| *b == 0)
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .collect();
        let is_gocryptfs = argv
            .first()
            .is_some_and(|a| Path::new(a).file_name().is_some_and(|n| n == "gocryptfs"));
        if !is_gocryptfs || !argv.iter().any(|a| *a == want) {
            continue;
        }
        for (i, arg) in argv.iter().enumerate() {
            let flag = arg.trim_start_matches('-');
            if let Some((name, value)) = flag.split_once('=')
                && (name == "i" || name == "idle")
            {
                return Some(value.to_string());
            }
            if flag == "i" || flag == "idle" {
                return argv.get(i + 1).cloned();
            }
        }
        return None;
    }
    None
}

/// Every folder the block device numbered `dev` (`254:3`, as sysfs writes it)
/// is mounted on, from `/proc/self/mountinfo`.
pub fn mounts_of(dev: &str) -> Vec<PathBuf> {
    fs::read_to_string("/proc/self/mountinfo")
        .map(|text| points_in(&text, dev))
        .unwrap_or_default()
}

/// Every mountpoint on the machine, from `/proc/self/mountinfo`.
pub fn points() -> Vec<PathBuf> {
    mountinfo().into_iter().map(|(point, _, _)| point).collect()
}

/// Every gocryptfs mount as `(encrypted folder, mountpoint)`: gocryptfs names
/// its mount after the encrypted folder, which `mountinfo` gives as the source.
pub fn gocryptfs_mounts() -> Vec<(PathBuf, PathBuf)> {
    mountinfo()
        .into_iter()
        .filter(|(_, kind, _)| kind == "fuse.gocryptfs")
        .map(|(point, _, source)| (PathBuf::from(source), point))
        .collect()
}

/// `/proc/self/mountinfo` as `(mountpoint, type, source)`: the fifth field,
/// then the first two after the ` - ` that ends the optional fields.
fn mountinfo() -> Vec<(PathBuf, String, String)> {
    let text = fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
    text.lines()
        .filter_map(|l| {
            let (left, right) = l.split_once(" - ")?;
            let point = left.split(' ').nth(4)?;
            let mut right = right.split(' ');
            let kind = right.next()?.to_string();
            let source = unescape(right.next()?);
            Some((PathBuf::from(unescape(point)), kind, source))
        })
        .collect()
}

/// The mountpoints `mountinfo` lists for device `dev`: its third field is the
/// device number and its fifth the mountpoint.
fn points_in(mountinfo: &str, dev: &str) -> Vec<PathBuf> {
    mountinfo
        .lines()
        .filter_map(|l| {
            let mut fields = l.split(' ');
            let number = fields.nth(2)?;
            let point = fields.nth(1)?;
            (number == dev).then(|| PathBuf::from(unescape(point)))
        })
        .collect()
}

/// `/proc/mounts` writes a space, tab, newline or backslash in a path as a
/// three-digit octal escape (`\040`).
fn unescape(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let octal = bytes
            .get(i + 1..i + 4)
            .filter(|d| d.iter().all(|b| (b'0'..=b'7').contains(b)));
        if bytes[i] == b'\\'
            && let Some(digits) = octal
        {
            let n = digits
                .iter()
                .fold(0u8, |n, d| n.wrapping_mul(8) + (d - b'0'));
            out.push(n);
            i += 4;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mountpoint_with_a_space_is_read_back_whole() {
        let info = "\
29 1 254:1 / / rw,relatime shared:1 - ext4 /dev/mapper/vg-root rw
51 29 254:3 / /media/user/my\\040stick rw,nosuid shared:30 - ext4 /dev/dm-3 rw
52 29 254:3 /sub /srv/bind rw shared:30 - ext4 /dev/dm-3 rw
";
        assert_eq!(
            points_in(info, "254:3"),
            [
                PathBuf::from("/media/user/my stick"),
                PathBuf::from("/srv/bind")
            ],
            "every mount of the device, and only that device, with `\\040` as a space"
        );
        assert_eq!(points_in(info, "254:1"), [PathBuf::from("/")]);
    }
}
