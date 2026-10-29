//! The LUKS backend: drives and image files, unlocked and mounted through
//! `udisksctl` so no root is needed. Linux only: reads `/sys`, `/proc` and the
//! udev database in `/run/udev/data`.
//!
//! ck locks only what its own `unlock` opened, and proves it with a line in
//! `$XDG_STATE_HOME/cryptkeeper/opened` stamped with this boot's id, so a line
//! left from before a reboot never vouches for a device something else opened
//! since.

use crate::run::{self, Ran};
use crate::vault::{Kind, State, Vault, file_name};
use crate::{mounts, registry, tilde};
use anyhow::{Result, bail};
use std::fs::{self, Metadata};
use std::io::Read;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

const BY_UUID: &str = "/dev/disk/by-uuid";

/// Mountpoints that belong to the running system, never to ck.
const SYSTEM: [&str; 6] = ["/", "/boot", "/boot/efi", "/home", "/usr", "/var"];

pub fn need() -> Result<()> {
    if crate::settings::load().luks_sudo {
        admin_tool("cryptsetup")?;
        if !run::on_path("sudo") {
            bail!("`luks = sudo` needs `sudo`, which is not installed");
        }
        return Ok(());
    }
    if !run::on_path("udisksctl") {
        bail!("`udisksctl` is not installed: install `udisks2` with your package manager");
    }
    Ok(())
}

/// The name a drive keeps across replugs.
pub fn by_uuid(uuid: &str) -> PathBuf {
    Path::new(BY_UUID).join(uuid)
}

pub fn is_block(meta: &Metadata) -> bool {
    meta.file_type().is_block_device()
}

pub fn is_luks_file(path: &Path) -> bool {
    read_head(path).is_some_and(|h| header_uuid(&h).is_some())
}

/// Whether `dev`, a resolved `/dev` path, is the drive `v` names.
pub fn same_drive(v: &Vault, dev: &Path) -> bool {
    v.kind == Kind::Luks
        && v.cipher.starts_with(BY_UUID)
        && dev.starts_with("/dev")
        && fs::canonicalize(&v.cipher).is_ok_and(|c| c == dev)
}

/// The LUKS vault on block device `arg`, named by its UUID.
pub fn from_block(arg: &Path) -> Result<Vault> {
    let seen = tilde(arg);
    let dev = fs::canonicalize(arg).unwrap_or_else(|_| arg.to_path_buf());
    let udev = udev_record(&file_name(&dev));
    let kind = udev.as_deref().and_then(|t| udev_value(t, "ID_FS_TYPE"));
    let uuid = udev.as_deref().and_then(|t| udev_value(t, "ID_FS_UUID"));
    match (kind, uuid) {
        (Some("crypto_LUKS"), Some(uuid)) => Ok(Vault::luks(by_uuid(uuid))),
        (Some(""), _) | (None, _) => {
            // No udev record: the header itself, when this user may read the drive.
            match read_head(&dev).as_deref().and_then(header_uuid) {
                Some(uuid) => Ok(Vault::luks(by_uuid(&uuid))),
                None => bail!(
                    "`{seen}` is a drive, but ck cannot tell what it holds: udev has no record of it"
                ),
            }
        }
        (Some(other), _) => {
            bail!("`{seen}` is a drive, but not a LUKS one: it holds `{other}`")
        }
    }
}

pub fn state(v: &Vault) -> State {
    if !v.cipher.exists() {
        return State::Missing;
    }
    let Some(clear) = backing(v).and_then(|d| cleartext(&d)) else {
        return State::Locked;
    };
    let ours = uuid_of(v).is_ok_and(|u| Records::load().is_ok_and(|r| r.has(&u)));
    let points = points_of(&clear);
    if let Some(why) = refusal(&facts(&clear, ours), None) {
        return State::Open(why);
    }
    match points.as_slice() {
        [] => State::Open("not mounted: `ck unlock` mounts it".into()),
        [one] if *one == v.view => State::Open(String::new()),
        [one, ..] => State::Open(format!("mounted at `{}`", tilde(one))),
    }
}

/// Why ck must leave `v` alone while it is unlocked, as `lock` would refuse
/// it: the disk the system runs from, one unlocked outside ck, and the rest
/// `refusal` names. `None` when it is locked or ck may lock it.
pub fn untouchable(v: &Vault) -> Option<String> {
    let clear = backing(v).as_deref().and_then(cleartext)?;
    let ours = uuid_of(v)
        .ok()
        .zip(Records::load().ok())
        .is_some_and(|(uuid, r)| r.has(&uuid));
    let view = Some(v.view.as_path()).filter(|p| !p.as_os_str().is_empty());
    refusal(&facts(&clear, ours), view)
}

/// Whether `v` is unlocked, by ck or not.
pub fn is_unlocked(v: &Vault) -> bool {
    backing(v).and_then(|d| cleartext(&d)).is_some()
}

/// Where `v`'s unlocked side is mounted, when it is.
pub fn open_at(v: &Vault) -> Option<PathBuf> {
    let clear = backing(v).and_then(|d| cleartext(&d))?;
    points_of(&clear).into_iter().next()
}

/// A LUKS device on this machine that the list does not hold.
pub struct Drive {
    /// As `unlock` takes it: `/dev/sdb1`, or `/dev/mapper/<name>` for a mapping.
    pub dev: PathBuf,
    pub cipher: PathBuf,
    pub open: bool,
    /// Where its unlocked side, or what is built on it, is mounted.
    pub at: Option<PathBuf>,
    /// ck's own `unlock` opened it, so `lock` may close it.
    pub ours: bool,
    pub note: String,
}

/// Every LUKS device udev knows of that `known` does not list, read only from
/// sysfs and the udev database, so nothing is opened, mounted or asked.
pub fn drives(known: &[Vault]) -> Vec<Drive> {
    let luks: Vec<&Vault> = known.iter().filter(|v| v.kind == Kind::Luks).collect();
    let listed: Vec<String> = luks.iter().filter_map(|v| uuid_of(v).ok()).collect();
    let served: Vec<String> = luks.iter().filter_map(|v| backing(v)).collect();
    let records = Records::load().ok();
    let Ok(entries) = fs::read_dir("/sys/class/block") else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    let mut found = Vec::new();
    for name in names {
        let Some(record) = udev_record(&name) else {
            continue;
        };
        let (Some("crypto_LUKS"), Some(uuid)) = (
            udev_value(&record, "ID_FS_TYPE"),
            udev_value(&record, "ID_FS_UUID"),
        ) else {
            continue;
        };
        if listed.iter().any(|u| u == uuid) || served.contains(&name) {
            continue;
        }
        let dev = dev_name(&name);
        let label = ["ID_FS_LABEL", "ID_PART_ENTRY_NAME"]
            .into_iter()
            .find_map(|k| udev_value(&record, k).filter(|l| !l.is_empty()));
        let size = sys(&name, "size")
            .and_then(|s| s.parse::<u64>().ok())
            .map(|sectors| human_size(sectors * 512))
            .unwrap_or_default();
        let about = match label {
            Some(l) => format!("`{l}`, {size}"),
            None => size,
        };
        let ours = records.as_ref().is_some_and(|r| r.has(uuid));
        let drive = match cleartext(&name) {
            Some(clear) => {
                let f = facts(&clear, ours);
                let at = f.mounts.iter().chain(&f.stacked_mounts).next().cloned();
                let why = refusal(&f, None);
                Drive {
                    note: match &why {
                        Some(why) => format!("{about}: {why}"),
                        None => format!(
                            "{about}: opened by ck, `ck lock {}` closes it",
                            dev.display()
                        ),
                    },
                    ours: why.is_none(),
                    open: true,
                    at,
                    cipher: by_uuid(uuid),
                    dev,
                }
            }
            None => Drive {
                note: format!("{about}: `ck add {}` lists it", dev.display()),
                ours: false,
                open: false,
                at: None,
                cipher: by_uuid(uuid),
                dev,
            },
        };
        found.push(drive);
    }
    found
}

/// The device `v` is plugged in as, named the way `ls` names a drive, or
/// `None` for an image file or a drive that is not there.
pub fn device_name(v: &Vault) -> Option<PathBuf> {
    if is_image(v) {
        return None;
    }
    backing(v).map(|name| dev_name(&name))
}

/// `/dev/<name>`, or `/dev/mapper/<mapping>` for a device-mapper device.
fn dev_name(name: &str) -> PathBuf {
    match sys(name, "dm/name") {
        Some(mapped) => Path::new("/dev/mapper").join(mapped),
        None => dev_path(name),
    }
}

/// `bytes` for people, in binary units (`KiB`, `MiB`, `GiB`).
fn human_size(bytes: u64) -> String {
    let units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < units.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    if size < 10.0 && unit > 0 {
        format!("{size:.1} {}", units[unit])
    } else {
        format!("{size:.0} {}", units[unit])
    }
}

pub fn unlock(v: &Vault, dry: bool) -> Result<()> {
    need()?;
    let uuid = uuid_of(v)?;
    let mut records = Records::load()?;
    let ours = records.has(&uuid);
    let dev = backing(v);
    if let Some(clear) = dev.as_deref().and_then(cleartext) {
        let facts = facts(&clear, ours);
        if let Some(why) = refusal(&facts, None) {
            bail!("`{}` is unlocked already, and {why}", tilde(&v.shown()));
        }
        if let Some(point) = facts.mounts.first() {
            if !dry {
                registry::remember(&with_view(v, point))?;
            }
            say!("already unlocked: `{}`", tilde(point));
            return Ok(());
        }
        let point = if dry {
            v.view.clone()
        } else {
            mount(v, &clear)?
        };
        if !dry {
            registry::remember(&with_view(v, &point))?;
        }
        say!("unlocked: `{}`", tilde(with_view(v, &point).name()));
        return Ok(());
    }
    if dry {
        say!("unlocked: `{}`", tilde(&v.shown()));
        return Ok(());
    }
    forget_stale(&mut records, &uuid)?;
    let _held = run::take_terminal();
    if crate::settings::load().luks_sudo {
        return sudo_unlock(v, dev, &uuid, &mut records);
    }
    explain_prompts(true);
    let (dev, made_loop) = match dev {
        Some(d) => (d, None),
        None => {
            let l = loop_setup(&v.cipher)?;
            (l.clone(), Some(l))
        }
    };
    // A loop device just set up may not be probed as LUKS yet.
    wait_for(|| udev_record(&dev).filter(|r| udev_value(r, "ID_FS_TYPE") == Some("crypto_LUKS")));
    let mut cmd = Command::new("udisksctl");
    cmd.args(["unlock", "-b"]).arg(dev_path(&dev));
    let ran = run::prompting(&mut cmd);
    let clear = (ran == Ran::Done)
        .then(|| wait_for(|| cleartext(&dev)))
        .flatten();
    let Some(clear) = clear else {
        if let Some(l) = &made_loop {
            loop_delete(l, &v.cipher);
        }
        match ran {
            Ran::Cancelled => bail!("cancelled, so `{}` stays locked", tilde(&v.shown())),
            Ran::Failed(_) => bail!("could not unlock `{}`", tilde(&v.shown())),
            Ran::Done => bail!(
                "udisks unlocked `{}`, but ck cannot find the unlocked device: lock it with `udisksctl lock -b {}`",
                tilde(&v.shown()),
                dev_path(&dev).display()
            ),
        }
    };
    records.add(&uuid, made_loop.as_deref());
    records.save()?;
    let point = match mount(v, &clear) {
        Ok(p) => p,
        Err(e) => {
            // Closed again, so a drive that cannot be mounted is not left open.
            if udisksctl(&["lock", "-b"], &dev).is_ok() {
                if let Some(l) = &made_loop {
                    loop_delete(l, &v.cipher);
                }
                records.remove(&uuid);
                let _ = records.save();
            }
            return Err(e);
        }
    };
    let v = with_view(v, &point);
    registry::remember(&v)?;
    say!("unlocked: `{}`", tilde(&point));
    Ok(())
}

pub fn lock(v: &Vault, dry: bool) -> Result<()> {
    need()?;
    let uuid = uuid_of(v)?;
    let mut records = Records::load()?;
    let Some(clear) = backing(v).as_deref().and_then(cleartext) else {
        if !dry {
            forget_stale(&mut records, &uuid)?;
        }
        say!("already locked: `{}`", tilde(&v.shown()));
        return Ok(());
    };
    let dev = backing(v).unwrap_or_default();
    let facts = facts(&clear, records.has(&uuid));
    if let Some(why) = refusal(&facts, Some(&v.view)) {
        bail!("will not lock `{}`: {why}", tilde(&v.shown()));
    }
    if !dry && crate::settings::load().luks_sudo {
        let _held = run::take_terminal();
        sudo_lock(v, &clear, &facts)?;
        if let Some(l) = records.made_loop(&uuid) {
            loop_delete(&l, &v.cipher);
        }
        records.remove(&uuid);
        records.save()?;
    } else if !dry {
        let _held = run::take_terminal();
        explain_prompts(false);
        if !facts.mounts.is_empty()
            && let Err(said) = udisksctl(&["unmount", "-b"], &clear)
        {
            bail!("{}", mounts::busy_error(&v.view, &said));
        }
        if let Err(said) = udisksctl(&["lock", "-b"], &dev) {
            bail!("could not lock `{}`{said}", tilde(&v.shown()));
        }
        if let Some(l) = records.made_loop(&uuid) {
            loop_delete(&l, &v.cipher);
        }
        records.remove(&uuid);
        records.save()?;
    }
    say!("locked: `{}`", tilde(&v.shown()));
    Ok(())
}

/// Drops the line for `uuid`, a device found locked, so if something else
/// opens it later this boot, ck never takes it for its own.
fn forget_stale(records: &mut Records, uuid: &str) -> Result<()> {
    if records.has(uuid) {
        records.remove(uuid);
        records.save()?;
    }
    Ok(())
}

fn with_view(v: &Vault, point: &Path) -> Vault {
    Vault {
        view: point.to_path_buf(),
        ..v.clone()
    }
}

/// Mounts the unlocked device `clear` and returns where udisks put it.
fn mount(v: &Vault, clear: &str) -> Result<PathBuf> {
    if crate::settings::load().luks_sudo {
        return sudo_mount(v, clear);
    }
    if let Err(said) = udisksctl(&["mount", "-b"], clear) {
        bail!("could not mount `{}`{said}", tilde(&v.shown()));
    }
    match points_of(clear).into_iter().next() {
        Some(p) => Ok(p),
        None => bail!(
            "udisks mounted `{}`, but ck cannot see where",
            tilde(&v.shown())
        ),
    }
}

/// `luks = sudo`'s unlock: `sudo cryptsetup open` the drive, or the image
/// file (cryptsetup serves it from a loop device that goes when it closes),
/// as `luks-<uuid>`, then mount it the way `sudo_mount` does, closing it
/// again when that fails.
fn sudo_unlock(v: &Vault, dev: Option<String>, uuid: &str, records: &mut Records) -> Result<()> {
    let cs = admin_tool("cryptsetup")?;
    let source = match &dev {
        Some(d) => dev_path(d),
        None => target(v),
    };
    let name = format!("luks-{uuid}");
    let mut open = sudo(&cs);
    open.arg("open").arg(&source).arg(&name);
    match run::foreground(&mut open) {
        Ran::Done => {}
        Ran::Cancelled => bail!("cancelled, so `{}` stays locked", tilde(&v.shown())),
        Ran::Failed(_) => bail!("could not unlock `{}`", tilde(&v.shown())),
    }
    let mapped = Path::new("/dev/mapper").join(&name);
    let Some(clear) = wait_for(|| fs::canonicalize(&mapped).ok().map(|p| file_name(&p))) else {
        bail!(
            "cryptsetup opened `{}`, but ck cannot find `{}`: `sudo cryptsetup close {name}` locks it",
            tilde(&v.shown()),
            mapped.display()
        );
    };
    records.add(uuid, None);
    records.save()?;
    let point = match sudo_mount(v, &clear) {
        Ok(p) => p,
        Err(e) => {
            let _ = sudo(&cs)
                .arg("close")
                .arg(&name)
                .stdin(Stdio::inherit())
                .output();
            records.remove(uuid);
            let _ = records.save();
            return Err(e);
        }
    };
    registry::remember(&with_view(v, &point))?;
    say!("unlocked: `{}`", tilde(&point));
    Ok(())
}

/// The folder `sudo_mount` mounts in, where udisks would: `/run/media/<user>`.
fn media_dir() -> PathBuf {
    let user = std::env::var("USER")
        .ok()
        .filter(|u| !u.is_empty() && !u.contains('/'))
        .unwrap_or_else(|| "ck".into());
    Path::new("/run/media").join(user)
}

/// Mounts the unlocked device `clear` with `sudo mount` on
/// `/run/media/<user>/<label>` (its UUID when it has no label), giving a
/// FAT, exFAT or NTFS filesystem to this user, since those keep no owners.
fn sudo_mount(v: &Vault, clear: &str) -> Result<PathBuf> {
    let record = wait_for(|| udev_record(clear).filter(|r| udev_value(r, "ID_FS_TYPE").is_some()))
        .unwrap_or_default();
    let fs_type = udev_value(&record, "ID_FS_TYPE").unwrap_or("").to_string();
    let label = ["ID_FS_LABEL", "ID_FS_UUID"]
        .into_iter()
        .find_map(|k| udev_value(&record, k).filter(|l| !l.is_empty() && !l.contains('/')))
        .unwrap_or(clear)
        .to_string();
    let point = media_dir().join(label);
    if mounts::points().contains(&point) {
        bail!(
            "`{}` is in use already, so ck will not mount `{}` on it",
            tilde(&point),
            tilde(&v.shown())
        );
    }
    if run::foreground(Command::new("sudo").args(["mkdir", "-p"]).arg(&point)) != Ran::Done {
        bail!(
            "could not make `{}` to mount `{}` on",
            tilde(&point),
            tilde(&v.shown())
        );
    }
    let mut cmd = Command::new("sudo");
    cmd.arg("mount");
    if matches!(fs_type.as_str(), "vfat" | "exfat" | "ntfs" | "ntfs3") {
        let ids = owner().replace(':', ",gid=");
        cmd.args(["-o", &format!("uid={ids},umask=077")]);
    }
    cmd.arg(dev_path(clear)).arg(&point);
    if run::foreground(&mut cmd) != Ran::Done {
        let _ = run::foreground(Command::new("sudo").arg("rmdir").arg(&point));
        bail!(
            "could not mount `{}`: mount's own lines say why",
            tilde(&v.shown())
        );
    }
    Ok(point)
}

/// `luks = sudo`'s lock: `sudo umount` every mount of `clear`, `sudo
/// cryptsetup close` it, then remove the folder `sudo_mount` made for it.
fn sudo_lock(v: &Vault, clear: &str, facts: &Facts) -> Result<()> {
    let cs = admin_tool("cryptsetup")?;
    for point in &facts.mounts {
        let out = Command::new("sudo")
            .arg("umount")
            .arg(point)
            .stdin(Stdio::inherit())
            .output();
        match out {
            Ok(o) if o.status.success() => {}
            Ok(o) => bail!("{}", mounts::busy_error(point, &run::said(&o))),
            Err(_) => bail!("`sudo` could not be started"),
        }
    }
    let Some(name) = sys(clear, "dm/name") else {
        bail!(
            "could not tell which mapping `{}` is unlocked as",
            tilde(&v.shown())
        );
    };
    let out = sudo(&cs)
        .arg("close")
        .arg(&name)
        .stdin(Stdio::inherit())
        .output();
    if !out.as_ref().is_ok_and(|o| o.status.success()) {
        let said = out.as_ref().map(run::said).unwrap_or_default();
        bail!("could not lock `{}`{said}", tilde(&v.shown()));
    }
    for point in &facts.mounts {
        if point.starts_with(media_dir()) {
            let _ = run::foreground(Command::new("sudo").arg("rmdir").arg(point));
        }
    }
    Ok(())
}

/// Where `name` (`cryptsetup`, `mkfs.ext4`) is: on PATH, else in the
/// `sbin` folders a user's PATH often leaves out.
pub fn admin_tool(name: &str) -> Result<PathBuf> {
    if run::on_path(name) {
        return Ok(PathBuf::from(name));
    }
    let found = ["/usr/sbin", "/sbin"]
        .into_iter()
        .map(|d| Path::new(d).join(name))
        .find(|p| p.is_file());
    match found {
        Some(p) => Ok(p),
        None => bail!(
            "`{name}` is not installed: install `{}` with your package manager",
            if name == "cryptsetup" {
                "cryptsetup"
            } else {
                "e2fsprogs"
            }
        ),
    }
}

/// `tool` run as root through `sudo`, which asks for the user's password on
/// the terminal when it has to.
fn sudo(tool: &Path) -> Command {
    let mut cmd = Command::new("sudo");
    cmd.arg(tool);
    cmd
}

/// This user as `uid:gid`, for the root folder of a filesystem ck makes.
fn owner() -> String {
    use std::os::unix::fs::MetadataExt;
    fs::metadata("/proc/self")
        .map(|m| format!("{}:{}", m.uid(), m.gid()))
        .unwrap_or_else(|_| "0:0".into())
}

/// The smallest image `init` makes: the LUKS2 header takes 16 MiB of it.
pub const MIN_IMAGE: u64 = 32 << 20;

/// `1G`, `500M` or `2048K`, in binary units. A bare number is refused,
/// since nobody means bytes when they size a disk.
pub fn parse_size(text: &str) -> Option<u64> {
    let text = text.trim();
    let (digits, unit) = text.split_at(
        text.find(|c: char| !c.is_ascii_digit())
            .unwrap_or(text.len()),
    );
    let n: u64 = digits.parse().ok()?;
    let shift = match unit
        .trim()
        .to_ascii_uppercase()
        .trim_end_matches("IB")
        .trim_end_matches('B')
    {
        "K" => 10,
        "M" => 20,
        "G" => 30,
        "T" => 40,
        _ => return None,
    };
    n.checked_mul(1 << shift)
}

/// Why ck will not format the block device `name` (`sdb`, `sdb1`), if it
/// will not: anything mounted, built on, swapped to or split into
/// partitions is in use, and the unlocked side of another device is not a
/// drive at all.
fn in_use(name: &str) -> Option<String> {
    if name.starts_with("dm-") {
        return Some("it is the unlocked side of another device, not a drive".into());
    }
    if sys(name, "ro").as_deref() == Some("1") {
        return Some("it is read-only".into());
    }
    let parts: Vec<String> = fs::read_dir(Path::new("/sys/class/block").join(name))
        .map(|d| {
            d.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.starts_with(name) && sys(n, "partition").is_some())
                .collect()
        })
        .unwrap_or_default();
    if let Some(first) = parts.first() {
        return Some(format!(
            "it holds partitions: name the one to format, e.g. `/dev/{first}`"
        ));
    }
    let held = fs::read_dir(Path::new("/sys/class/block").join(name).join("holders"))
        .is_ok_and(|mut h| h.next().is_some());
    if held {
        return Some("something is built on it (it is unlocked, or part of LVM or RAID)".into());
    }
    if let Some(point) = points_of(name).first() {
        return Some(format!("it is mounted at `{}`", tilde(point)));
    }
    let swaps = fs::read_to_string("/proc/swaps").unwrap_or_default();
    if swaps
        .lines()
        .any(|l| l.split_whitespace().next() == Some(&format!("/dev/{name}")))
    {
        return Some("it is swap".into());
    }
    None
}

/// The drives and partitions worth offering to format, with what is on
/// each now (size, bus, filesystem and label), so the person sees what
/// formatting it would destroy: a disk or partition rather than a loop, RAM
/// or optical device, with media in it, big enough for a LUKS vault, not one
/// already (that is a vault to unlock), and nothing `in_use` refuses.
pub fn formattable() -> Vec<(PathBuf, String)> {
    let Ok(entries) = fs::read_dir("/sys/class/block") else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| {
            !["loop", "dm-", "ram", "zram", "sr", "nbd", "md"]
                .iter()
                .any(|p| n.starts_with(p))
        })
        .filter(|n| in_use(n).is_none())
        .filter(|n| bytes(n).is_some_and(|b| b >= MIN_IMAGE))
        .filter(|n| {
            udev_record(n).is_none_or(|r| udev_value(&r, "ID_FS_TYPE") != Some("crypto_LUKS"))
        })
        .collect();
    names.sort();
    names
        .into_iter()
        .map(|name| {
            let record = udev_record(&name).unwrap_or_default();
            let value = |k| udev_value(&record, k).filter(|v| !v.is_empty());
            let mut about = vec![bytes(&name).map(human_size).unwrap_or_default()];
            about.extend(value("ID_BUS").map(str::to_string));
            match (value("ID_FS_TYPE"), value("ID_FS_LABEL")) {
                (Some(fs), Some(label)) => {
                    about.push(format!("holds {fs} `{label}`, which formatting wipes"))
                }
                (Some(fs), None) => about.push(format!("holds {fs}, which formatting wipes")),
                _ => about.push("empty as far as ck can see".into()),
            }
            (dev_path(&name), about.join(" · "))
        })
        .collect()
}

/// The size of block device `name`, from the 512-byte sectors sysfs counts.
fn bytes(name: &str) -> Option<u64> {
    sys(name, "size")?
        .parse::<u64>()
        .ok()
        .map(|sectors| sectors * 512)
}

/// Makes a LUKS vault at `path`: a new image file of `size` bytes, or with
/// `wipe` the block device `path` names, destroying what is on it. The header
/// is written by `cryptsetup luksFormat` (through `sudo` for a drive), and the
/// ext4 inside, owned by this user, needs the device opened, which only root
/// can do, so that part always runs through `sudo`. cryptsetup asks for the
/// passphrase twice to make it and once more to open it.
pub fn init(path: &Path, size: Option<u64>, wipe: bool, dry: bool) -> Result<()> {
    let cs = admin_tool("cryptsetup")?;
    let mkfs = admin_tool("mkfs.ext4")?;
    if !run::on_path("sudo") {
        bail!("making a LUKS vault needs `sudo`, which is not installed");
    }
    let seen = tilde(path);
    match fs::metadata(path) {
        Ok(m) if is_block(&m) => {
            let dev = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
            if let Some(why) = in_use(&file_name(&dev)) {
                bail!("will not format `{}`: {why}", dev.display());
            }
            if !wipe {
                bail!(
                    "formatting `{}` destroys everything on it: add `--wipe` to go ahead",
                    dev.display()
                );
            }
            if !dry {
                let mut format = sudo(&cs);
                // No `-q`, so cryptsetup asks for an uppercase YES before it wipes a drive.
                format.args(["luksFormat", "--type", "luks2", "--verify-passphrase"]);
                format.arg(&dev);
                ran("format", &dev, run::foreground(&mut format))?;
                make_fs(&cs, &mkfs, &dev)?;
                let _held = run::take_terminal();
                let out = sudo(&cs)
                    .arg("luksUUID")
                    .arg(&dev)
                    .stdin(Stdio::inherit())
                    .output();
                let uuid = match out {
                    Ok(o) if o.status.success() => {
                        String::from_utf8_lossy(&o.stdout).trim().to_string()
                    }
                    _ => bail!(
                        "made `{}`, but could not read its UUID: `ck unlock {}` lists it",
                        dev.display(),
                        dev.display()
                    ),
                };
                registry::remember(&Vault::luks(by_uuid(&uuid)))?;
            }
            say!(
                "made `{}`: open it with `ck unlock {}`",
                dev.display(),
                dev.display()
            );
            Ok(())
        }
        Ok(_) => bail!("`{seen}` already exists: name a new image file, or a drive"),
        Err(_) => {
            let Some(size) = size else {
                bail!("a new image needs a size: `ck init --luks {seen} --size 1G`");
            };
            if size < MIN_IMAGE {
                bail!("an image needs at least 32M, since the LUKS header alone takes 16M");
            }
            let dir = path
                .parent()
                .filter(|d| !d.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            let Ok(dir) = fs::canonicalize(dir) else {
                bail!("`{}` does not exist", tilde(dir));
            };
            let file = dir.join(file_name(path));
            registry::check_storable(&Vault::luks(file.clone()))?;
            if !dry {
                let made = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&file);
                if made.and_then(|f| f.set_len(size)).is_err() {
                    let _ = fs::remove_file(&file);
                    bail!("could not make `{seen}`");
                }
                let mut format = Command::new(&cs);
                format.args(["luksFormat", "-q", "--type", "luks2", "--verify-passphrase"]);
                format.arg(&file);
                let done = ran("format", &file, run::foreground(&mut format))
                    .and_then(|()| make_fs(&cs, &mkfs, &file));
                if let Err(e) = done {
                    let _ = fs::remove_file(&file);
                    return Err(e);
                }
                registry::remember(&Vault::luks(file.clone()))?;
            }
            say!(
                "made `{}`: open it with `ck unlock {}`",
                tilde(&file),
                tilde(&file)
            );
            Ok(())
        }
    }
}

/// Turns a runner's verdict on `what` for `target` into ck's error.
fn ran(what: &str, target: &Path, ran: Ran) -> Result<()> {
    match ran {
        Ran::Done => Ok(()),
        Ran::Cancelled => bail!("cancelled, so `{}` was left as it was", tilde(target)),
        Ran::Failed(_) => bail!(
            "could not {what} `{}`: cryptsetup's own lines say why",
            tilde(target)
        ),
    }
}

/// Opens the new LUKS device in `target` under a name of ck's, makes an ext4
/// owned by this user inside, and closes it again, all through `sudo`.
fn make_fs(cs: &Path, mkfs: &Path, target: &Path) -> Result<()> {
    let name = format!("ck-new-{}", std::process::id());
    eprintln!("ck: type the passphrase once more: ck opens it to make its filesystem");
    let mut open = sudo(cs);
    open.arg("open").arg(target).arg(&name);
    ran("open", target, run::foreground(&mut open))?;
    let mut fs_cmd = sudo(mkfs);
    fs_cmd.args(["-q", "-E", &format!("root_owner={}", owner())]);
    fs_cmd.arg(Path::new("/dev/mapper").join(&name));
    let made = run::foreground(&mut fs_cmd);
    let mut close = sudo(cs);
    close.arg("close").arg(&name);
    let closed = run::foreground(&mut close);
    if made != Ran::Done {
        bail!(
            "could not make the filesystem inside `{}`: mkfs's own lines say why",
            tilde(target)
        );
    }
    if closed != Ran::Done {
        bail!(
            "made `{}`, but could not close it: `sudo cryptsetup close {name}`",
            tilde(target)
        );
    }
    Ok(())
}

/// The device or image file cryptsetup works on for `v`.
fn target(v: &Vault) -> PathBuf {
    fs::canonicalize(&v.cipher).unwrap_or_else(|_| v.cipher.clone())
}

/// `tool` for `v`: as this user for an image file, which is theirs, and
/// through `sudo` for a drive, which only root may write.
fn for_vault(tool: &Path, v: &Vault) -> Command {
    if is_image(v) {
        Command::new(tool)
    } else {
        sudo(tool)
    }
}

/// Changes `v`'s passphrase with `cryptsetup luksChangeKey`, which asks for
/// the old one and the new one twice.
pub fn passwd(v: &Vault, dry: bool) -> Result<()> {
    let cs = admin_tool("cryptsetup")?;
    if let Some(why) = untouchable(v) {
        bail!(
            "will not change the passphrase of `{}`: {why}",
            tilde(&v.shown())
        );
    }
    if !dry {
        let mut cmd = for_vault(&cs, v);
        cmd.arg("luksChangeKey").arg(target(v));
        match run::prompting(&mut cmd) {
            Ran::Done => {}
            Ran::Cancelled => bail!("cancelled, so `{}` keeps its passphrase", tilde(&v.shown())),
            Ran::Failed(_) => bail!("could not change the passphrase of `{}`", tilde(&v.shown())),
        }
    }
    say!("changed the passphrase of `{}`", tilde(&v.shown()));
    Ok(())
}

/// Copies `v`'s LUKS header to `dest` with `cryptsetup luksHeaderBackup`,
/// handed back to this user when `sudo` wrote it.
pub fn backup(v: &Vault, dest: &Path, dry: bool) -> Result<()> {
    let cs = admin_tool("cryptsetup")?;
    if !dry {
        let mut cmd = for_vault(&cs, v);
        cmd.arg("luksHeaderBackup")
            .arg(target(v))
            .arg("--header-backup-file")
            .arg(dest);
        if run::prompting(&mut cmd) != Ran::Done {
            bail!("could not back up the header of `{}`", tilde(&v.shown()));
        }
        if !is_image(v) {
            let _ = run::foreground(Command::new("sudo").args(["chown", &owner()]).arg(dest));
        }
    }
    say!(
        "saved the LUKS header of `{}` to `{}`",
        tilde(&v.shown()),
        tilde(dest)
    );
    Ok(())
}

/// Says which password each prompt wants when polkit will ask for one, since
/// `Passphrase:` (the drive's, from udisksctl) and `Password:` (polkit's, for
/// the account it names) otherwise read as the same question twice. Said
/// once per run, for `unlocking` or for locking.
fn explain_prompts(unlocking: bool) {
    static SAID: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if SAID.load(std::sync::atomic::Ordering::SeqCst) || !crate::check::polkit_asks() {
        return;
    }
    SAID.store(true, std::sync::atomic::Ordering::SeqCst);
    let (passphrase, steps) = match unlocking {
        true => (
            "\n  Passphrase:  the drive's own passphrase",
            "to unlock, then to mount",
        ),
        false => ("", "to unmount, then to lock"),
    };
    eprintln!(
        "ck: this is not the desktop session, so polkit asks for a password too:{passphrase}\n  Password:    polkit's, once {steps}, for the account on its\n               `Authenticating as:` line; it asks each time, as your polkit rules say\n  (Drives through: sudo, in ck's Settings tab, has sudo ask once instead)\n"
    );
}

/// Runs `udisksctl <args> /dev/<dev>` with its output captured; stdin stays
/// the terminal, so polkit can still ask for a password.
fn udisksctl(args: &[&str], dev: &str) -> std::result::Result<(), String> {
    let _held = run::take_terminal();
    let out = Command::new("udisksctl")
        .args(args)
        .arg(dev_path(dev))
        .stdin(Stdio::inherit())
        .output();
    match out {
        Ok(out) if out.status.success() => Ok(()),
        Ok(out) => Err(run::said(&out)),
        Err(_) => Err("\n`udisksctl` could not be started".into()),
    }
}

/// Serves `file` from a loop device, returning its name (`loop3`).
fn loop_setup(file: &Path) -> Result<String> {
    let _held = run::take_terminal();
    let out = Command::new("udisksctl")
        .args(["loop-setup", "-f"])
        .arg(file)
        .stdin(Stdio::inherit())
        .output();
    let out = match out {
        Ok(out) if out.status.success() => out,
        Ok(out) => bail!(
            "could not set up a loop device for `{}`{}",
            tilde(file),
            run::said(&out)
        ),
        Err(_) => bail!("`udisksctl` could not be started"),
    };
    let said = String::from_utf8_lossy(&out.stdout);
    match loop_for(file).or_else(|| mapped_loop(&said)) {
        Some(l) => Ok(l),
        None => bail!(
            "udisks set up a loop device for `{}`, but ck cannot find it",
            tilde(file)
        ),
    }
}

/// Deletes loop device `name` only while it still serves `file`, so a loop
/// the kernel reused for something else is left alone.
fn loop_delete(name: &str, file: &Path) {
    let file = fs::canonicalize(file).unwrap_or_else(|_| file.to_path_buf());
    if sys(name, "loop/backing_file").is_some_and(|b| Path::new(&b) == file)
        && let Err(said) = udisksctl(&["loop-delete", "-b"], name)
    {
        eprintln!(
            "ck: `{}` is locked, but its loop device stays{said}",
            tilde(&file)
        );
    }
}

/// `loop3` from udisksctl's `Mapped file <file> as /dev/loop3.`
fn mapped_loop(said: &str) -> Option<String> {
    let dev = said.trim().rsplit_once(" as ")?.1.trim_end_matches('.');
    Some(file_name(Path::new(dev))).filter(|n| n.starts_with("loop"))
}

fn dev_path(name: &str) -> PathBuf {
    Path::new("/dev").join(name)
}

/// Polls `f` for a moment, since udev may still be adding the device.
fn wait_for<T>(f: impl Fn() -> Option<T>) -> Option<T> {
    for _ in 0..30 {
        if let Some(t) = f() {
            return Some(t);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    None
}

/// The block device serving `v` right now (`sdb1`, `loop3`): the drive its
/// UUID names, or the loop device serving its image file.
fn backing(v: &Vault) -> Option<String> {
    if is_image(v) {
        return loop_for(&v.cipher);
    }
    let dev = fs::canonicalize(&v.cipher).ok()?;
    Some(file_name(&dev)).filter(|n| !n.is_empty())
}

fn is_image(v: &Vault) -> bool {
    !v.cipher.starts_with("/dev")
}

fn uuid_of(v: &Vault) -> Result<String> {
    let uuid = if is_image(v) {
        read_head(&v.cipher).as_deref().and_then(header_uuid)
    } else if v.cipher.starts_with(BY_UUID) {
        Some(file_name(&v.cipher))
    } else {
        None
    };
    match uuid {
        Some(u) => Ok(u),
        None => bail!("could not read the LUKS header of `{}`", tilde(&v.shown())),
    }
}

/// The loop device whose backing file is `file`.
fn loop_for(file: &Path) -> Option<String> {
    let want = fs::canonicalize(file).ok()?;
    fs::read_dir("/sys/block")
        .ok()?
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("loop"))
        .find(|n| sys(n, "loop/backing_file").is_some_and(|b| Path::new(&b) == want))
}

/// The dm-crypt device `dev` is unlocked as (`dm-3`).
fn cleartext(dev: &str) -> Option<String> {
    let holders = fs::read_dir(Path::new("/sys/class/block").join(dev).join("holders")).ok()?;
    holders
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .find(|h| sys(h, "dm/uuid").is_some_and(|u| u.starts_with("CRYPT-")))
}

fn sys(dev: &str, rel: &str) -> Option<String> {
    fs::read_to_string(Path::new("/sys/class/block").join(dev).join(rel))
        .ok()
        .map(|s| s.trim().to_string())
}

fn points_of(clear: &str) -> Vec<PathBuf> {
    sys(clear, "dev")
        .map(|n| mounts::mounts_of(&n))
        .unwrap_or_default()
}

/// What decides whether ck may touch an unlocked device.
struct Facts {
    by_ck: bool,
    /// Something sits on top of it, such as LVM.
    stacked: bool,
    /// It, or something stacked on it, is swap.
    swap: bool,
    mounts: Vec<PathBuf>,
    /// Where the devices stacked on it are mounted, so a disk under LVM is
    /// known to hold `/`.
    stacked_mounts: Vec<PathBuf>,
}

fn facts(clear: &str, by_ck: bool) -> Facts {
    let above = stacked_on(clear);
    let swaps: Vec<String> = fs::read_to_string("/proc/swaps")
        .map(|t| {
            t.lines()
                .skip(1)
                .filter_map(|l| l.split_whitespace().next())
                .filter_map(|p| fs::canonicalize(p).ok())
                .map(|p| file_name(&p))
                .collect()
        })
        .unwrap_or_default();
    Facts {
        by_ck,
        stacked: !above.is_empty(),
        swap: swaps.iter().any(|s| s == clear || above.contains(s)),
        mounts: points_of(clear),
        stacked_mounts: above.iter().flat_map(|d| points_of(d)).collect(),
    }
}

/// Every block device built on `dev`, however deep (LVM on LUKS, LUKS on
/// LVM), from the `holders` folders in sysfs.
fn stacked_on(dev: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    let mut next = vec![dev.to_string()];
    while let Some(d) = next.pop() {
        let Ok(holders) = fs::read_dir(Path::new("/sys/class/block").join(&d).join("holders"))
        else {
            continue;
        };
        for h in holders.flatten() {
            let name = h.file_name().to_string_lossy().into_owned();
            if !found.contains(&name) && found.len() < 64 {
                found.push(name.clone());
                next.push(name);
            }
        }
    }
    found
}

/// Why ck must leave an unlocked device alone, or `None` when it may go on.
/// `view` is where ck mounted it, for a lock; an unlock passes `None`, since
/// it only mounts.
fn refusal(f: &Facts, view: Option<&Path>) -> Option<String> {
    if let Some(m) = f
        .mounts
        .iter()
        .chain(&f.stacked_mounts)
        .find(|m| SYSTEM.iter().any(|s| m.as_path() == Path::new(s)))
    {
        return Some(format!(
            "it holds `{}`, so ck never touches it",
            m.display()
        ));
    }
    if f.swap {
        return Some("it holds swap, so ck never touches it".into());
    }
    if f.stacked {
        return Some(
            "something is built on it (LVM, or another mapping), so ck leaves it alone".into(),
        );
    }
    if !f.by_ck {
        return Some(
            "it was unlocked outside ck, which only locks what its own `unlock` opened: lock it where it was opened".into(),
        );
    }
    if let Some(view) = view
        && let Some(m) = f.mounts.iter().find(|m| *m != view)
    {
        return Some(format!(
            "it is also mounted at `{}`, which ck did not do: unmount that first",
            tilde(m)
        ));
    }
    None
}

/// The first bytes of `path`, enough for a LUKS header's UUID.
fn read_head(path: &Path) -> Option<Vec<u8>> {
    let mut head = vec![0; 208];
    fs::File::open(path).ok()?.read_exact(&mut head).ok()?;
    Some(head)
}

/// The UUID in a LUKS1 or LUKS2 header, which both keep at byte 168.
fn header_uuid(head: &[u8]) -> Option<String> {
    if !head.starts_with(b"LUKS\xba\xbe") {
        return None;
    }
    let field = head.get(168..208)?;
    let end = field.iter().position(|b| *b == 0).unwrap_or(field.len());
    let uuid = std::str::from_utf8(&field[..end]).ok()?;
    let ok = !uuid.is_empty() && uuid.chars().all(|c| c.is_ascii_hexdigit() || c == '-');
    ok.then(|| uuid.to_string())
}

/// udev's record for block device `name`, from its database in `/run/udev/data`.
fn udev_record(name: &str) -> Option<String> {
    let number = sys(name, "dev")?;
    fs::read_to_string(format!("/run/udev/data/b{number}")).ok()
}

/// The value of `E:<key>=` in a udev record.
fn udev_value<'a>(record: &'a str, key: &str) -> Option<&'a str> {
    record
        .lines()
        .find_map(|l| l.strip_prefix("E:")?.strip_prefix(key)?.strip_prefix('='))
}

/// The devices ck's own `unlock` opened this boot.
struct Records {
    boot: String,
    /// `(boot, uuid, loop device ck set up for it)`
    lines: Vec<(String, String, Option<String>)>,
}

impl Records {
    fn path() -> PathBuf {
        crate::state_dir().join("opened")
    }

    fn load() -> Result<Records> {
        let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        let file = Self::path();
        let text = match fs::read_to_string(&file) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(_) => bail!(
                "could not read `{}`: fix or remove it, ck will not overwrite it",
                tilde(&file)
            ),
        };
        Ok(Records {
            lines: parse_records(&text),
            boot,
        })
    }

    fn has(&self, uuid: &str) -> bool {
        !self.boot.is_empty()
            && self
                .lines
                .iter()
                .any(|(b, u, _)| *b == self.boot && u == uuid)
    }

    fn made_loop(&self, uuid: &str) -> Option<String> {
        self.lines
            .iter()
            .find(|(b, u, _)| *b == self.boot && u == uuid)
            .and_then(|(_, _, l)| l.clone())
    }

    fn add(&mut self, uuid: &str, made_loop: Option<&str>) {
        self.remove(uuid);
        self.lines.push((
            self.boot.clone(),
            uuid.to_string(),
            made_loop.map(str::to_string),
        ));
    }

    fn remove(&mut self, uuid: &str) {
        self.lines.retain(|(_, u, _)| u != uuid);
    }

    /// Writes the list back without the lines of earlier boots.
    fn save(&self) -> Result<()> {
        let body: String = self
            .lines
            .iter()
            .filter(|(b, _, _)| *b == self.boot)
            .map(|(b, u, l)| format!("{b}\t{u}\t{}\n", l.as_deref().unwrap_or("-")))
            .collect();
        crate::write_atomic(&Self::path(), body.as_bytes(), "the list of opened drives")
    }
}

fn parse_records(text: &str) -> Vec<(String, String, Option<String>)> {
    text.lines()
        .filter_map(|l| {
            let mut f = l.split('\t');
            let (boot, uuid, lp) = (f.next()?, f.next()?, f.next()?);
            let lp = (lp != "-").then(|| lp.to_string());
            Some((boot.to_string(), uuid.to_string(), lp))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opened(mounts: &[&str]) -> Facts {
        Facts {
            by_ck: true,
            stacked: false,
            swap: false,
            mounts: mounts.iter().map(PathBuf::from).collect(),
            stacked_mounts: Vec::new(),
        }
    }

    #[test]
    fn a_drive_ck_opened_and_mounted_where_it_said_may_be_locked() {
        let view = Path::new("/media/user/stick");
        assert_eq!(refusal(&opened(&["/media/user/stick"]), Some(view)), None);
    }

    #[test]
    fn a_drive_holding_a_system_folder_is_never_touched_even_if_listed_as_ours() {
        for system in SYSTEM {
            let f = opened(&[system]);
            assert!(
                refusal(&f, Some(Path::new(system))).is_some(),
                "a LUKS device mounted on `{system}` must be refused"
            );
            assert!(refusal(&f, None).is_some(), "and refused at unlock too");
        }
    }

    #[test]
    fn a_drive_unlocked_outside_ck_is_never_locked() {
        let f = Facts {
            by_ck: false,
            ..opened(&["/media/user/stick"])
        };
        assert!(refusal(&f, Some(Path::new("/media/user/stick"))).is_some());
    }

    #[test]
    fn a_drive_under_lvm_or_swap_is_never_touched() {
        let lvm = Facts {
            stacked: true,
            ..opened(&[])
        };
        let swap = Facts {
            swap: true,
            ..opened(&[])
        };
        assert!(refusal(&lvm, Some(Path::new("/media/user/x"))).is_some());
        assert!(refusal(&swap, Some(Path::new("/media/user/x"))).is_some());
    }

    #[test]
    fn a_drive_also_mounted_somewhere_ck_did_not_put_it_is_not_locked() {
        let f = opened(&["/media/user/stick", "/srv/share"]);
        assert!(refusal(&f, Some(Path::new("/media/user/stick"))).is_some());
    }

    #[test]
    fn the_uuid_is_read_from_a_luks1_or_luks2_header() {
        let mut head = vec![0u8; 208];
        head[..6].copy_from_slice(b"LUKS\xba\xbe");
        let uuid = "8a6f0c42-1b2d-4e5f-9a7b-3c4d5e6f7a8b";
        head[168..168 + uuid.len()].copy_from_slice(uuid.as_bytes());
        assert_eq!(header_uuid(&head).as_deref(), Some(uuid));

        head[0] = b'X';
        assert_eq!(header_uuid(&head), None, "no magic, no LUKS");
    }

    #[test]
    fn udev_records_give_the_filesystem_type_and_uuid() {
        let record = "S:disk/by-uuid/0000\nE:ID_FS_TYPE=crypto_LUKS\nE:ID_FS_UUID=0000\nE:ID_FS_UUID_ENC=0000\n";
        assert_eq!(udev_value(record, "ID_FS_TYPE"), Some("crypto_LUKS"));
        assert_eq!(udev_value(record, "ID_FS_UUID"), Some("0000"));
        assert_eq!(udev_value(record, "ID_FS_LABEL"), None);
    }

    #[test]
    fn the_loop_device_is_read_from_udisksctls_loop_setup_line() {
        assert_eq!(
            mapped_loop("Mapped file /example/disk as image.img as /dev/loop7.\n").as_deref(),
            Some("loop7")
        );
        assert_eq!(mapped_loop("something else"), None);
    }

    #[test]
    fn only_this_boots_opened_lines_vouch_for_a_device() {
        let r = Records {
            boot: "this".into(),
            lines: parse_records("earlier\taaaa\t-\nthis\tbbbb\tloop2\n"),
        };
        assert!(!r.has("aaaa"), "a line from before a reboot proves nothing");
        assert!(r.has("bbbb"));
        assert_eq!(r.made_loop("bbbb").as_deref(), Some("loop2"));
    }

    #[test]
    fn a_size_needs_a_unit_and_reads_it_in_binary() {
        assert_eq!(parse_size("1G"), Some(1 << 30));
        assert_eq!(parse_size("500M"), Some(500 << 20));
        assert_eq!(parse_size("4GiB"), Some(4 << 30));
        assert_eq!(
            parse_size("23423"),
            None,
            "a bare number is refused, not read as bytes"
        );
        assert_eq!(parse_size("1X"), None);
        assert!(
            parse_size("16M").unwrap() < MIN_IMAGE,
            "under the smallest image ck makes"
        );
    }
}
