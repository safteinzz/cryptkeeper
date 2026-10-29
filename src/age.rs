//! The age backend: one encrypted file, opened to a plaintext copy in memory,
//! under `$XDG_RUNTIME_DIR/cryptkeeper/age/<id>/`, with a link to that copy
//! where the file is, named without `.age`.
//!
//! Locking never loses data: the copy is encrypted to a temp file beside the
//! vault, checked, renamed over the vault, and only then deleted. An editor
//! that saves by replacing the link with a real file leaves two plaintexts,
//! and `lock` encrypts that file only when the copy matches it or is gone.

use crate::run::{self, Ran};
use crate::vault::{State, Vault, file_name};
use crate::{registry, tilde};
use anyhow::{Result, bail};
use std::fs::{self, DirBuilder, File};
use std::io::{BufRead, BufReader, Read};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const MAGIC: &[u8] = b"age-encryption.org/v1\n";
const ARMOR: &[u8] = b"-----BEGIN AGE ENCRYPTED FILE-----";
/// Stanza kinds that each name one recipient; anything else is a passphrase
/// or the random padding stanzas some implementations add.
const RECIPIENTS: [&str; 5] = [
    "X25519",
    "ssh-ed25519",
    "ssh-rsa",
    "piv-p256",
    "mlkem768x25519",
];

/// `age`, or `rage`, which takes the same flags.
fn need() -> Result<&'static str> {
    match ["age", "rage"].into_iter().find(|b| run::on_path(b)) {
        Some(b) => Ok(b),
        None => bail!(
            "`age` is not installed: install `age` with your package manager, or see https://age-encryption.org"
        ),
    }
}

pub fn is_age(path: &Path) -> bool {
    let mut head = [0u8; 34];
    let Ok(n) = File::open(path).and_then(|mut f| f.read(&mut head)) else {
        return false;
    };
    head[..n].starts_with(MAGIC) || head[..n].starts_with(ARMOR)
}

struct Header {
    /// Bytes up to and including the `--- <mac>` line.
    len: u64,
    kinds: Vec<String>,
}

impl Header {
    fn passphrase(&self) -> bool {
        self.kinds.iter().any(|k| k == "scrypt")
    }

    fn recipients(&self) -> usize {
        self.kinds
            .iter()
            .filter(|k| RECIPIENTS.contains(&k.as_str()))
            .count()
    }
}

/// The header of a binary age file, or `None` when `bytes` does not start one.
fn parse_header(bytes: &[u8]) -> Option<Header> {
    let rest = bytes.strip_prefix(MAGIC)?;
    let mut kinds = Vec::new();
    let mut at = MAGIC.len();
    for line in rest.split_inclusive(|b| *b == b'\n') {
        at += line.len();
        if !line.ends_with(b"\n") {
            return None;
        }
        if line.starts_with(b"--- ") {
            return Some(Header {
                len: at as u64,
                kinds,
            });
        }
        if let Some(stanza) = line.strip_prefix(b"-> ") {
            let kind = stanza.split(|b| *b == b' ' || *b == b'\n').next()?;
            kinds.push(String::from_utf8_lossy(kind).into_owned());
        }
    }
    None
}

fn read_header(bin: &str, v: &Vault) -> Result<Header> {
    let mut head = Vec::new();
    let read = File::open(&v.cipher).and_then(|f| f.take(1 << 16).read_to_end(&mut head));
    if read.is_err() {
        bail!("could not read `{}`", tilde(&v.cipher));
    }
    if head.starts_with(ARMOR) {
        bail!(
            "`{}` is armored (text) age, which ck does not open yet: `{bin} -d` it by hand",
            tilde(&v.cipher)
        );
    }
    match parse_header(&head) {
        Some(h) => Ok(h),
        None => bail!("`{}` does not start with an age header", tilde(&v.cipher)),
    }
}

/// How long age's binary payload is for `plain` bytes: a 16-byte nonce, then
/// 64 KiB chunks with a 16-byte tag each, and one chunk even when empty.
fn payload_len(plain: u64) -> u64 {
    let chunks = plain.div_ceil(64 * 1024).max(1);
    16 + plain + 16 * chunks
}

/// How many plaintext bytes `v`'s file holds, from its size alone: what a
/// decryption must have written, since age and rage both exit 0 having written
/// nothing when their passphrase prompt is cancelled.
fn plain_len(v: &Vault, header: &Header) -> Option<u64> {
    let payload = fs::metadata(&v.cipher)
        .ok()?
        .len()
        .checked_sub(header.len)?;
    let sealed = payload.checked_sub(16)?;
    let chunks = sealed.div_ceil(64 * 1024 + 16).max(1);
    sealed.checked_sub(16 * chunks)
}

/// The folder only this vault's copy lives in, named by a hash of its path.
fn copy_id(v: &Vault) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in v.cipher.as_os_str().as_encoded_bytes() {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{hash:016x}")
}

/// The name of `v`'s copy: its file's real name without `.age`, so every
/// name a vault is reached by shares one copy.
fn copy_name(v: &Vault) -> String {
    let name = file_name(&v.cipher);
    name.strip_suffix(".age").unwrap_or(&name).to_string()
}

/// Whether `target`, where the view links to, is the copy ck makes for `v`.
fn is_copy(v: &Vault, target: &Path) -> bool {
    let dir = target.parent();
    file_name(target) == copy_name(v)
        && dir.is_some_and(|d| file_name(d) == copy_id(v))
        && dir
            .and_then(Path::parent)
            .is_some_and(|d| d.ends_with("cryptkeeper/age"))
}

/// `$XDG_RUNTIME_DIR` resolved, refused unless it is in memory.
fn runtime_root() -> Result<PathBuf> {
    let dir = match std::env::var_os("XDG_RUNTIME_DIR").filter(|d| !d.is_empty()) {
        Some(d) => PathBuf::from(d),
        None => {
            let dir = PathBuf::from(format!("/run/user/{}", my_uid()));
            if !dir.is_dir() {
                bail!(
                    "`$XDG_RUNTIME_DIR` is not set, and ck keeps age plaintext only in memory: set it to a tmpfs folder of yours"
                );
            }
            dir
        }
    };
    let real = fs::canonicalize(&dir).unwrap_or_else(|_| dir.clone());
    match fs_type(&real) {
        Some(t) if t == "tmpfs" || t == "ramfs" => Ok(real),
        found => bail!(
            "`{}` is not in memory ({}), and ck keeps age plaintext only in memory: point `$XDG_RUNTIME_DIR` at a tmpfs",
            dir.display(),
            found.as_deref().unwrap_or("its filesystem is unknown")
        ),
    }
}

fn my_uid() -> u32 {
    fs::metadata("/proc/self")
        .map(|m| m.uid())
        .unwrap_or(u32::MAX)
}

/// `cryptkeeper/age/<id>` under `root`, each folder checked to be a real
/// folder of this user's with mode 0700, and with `make` created that way
/// where missing, so plaintext never lands where someone else can read or
/// redirect it.
fn private_dir(root: &Path, v: &Vault, make: bool) -> Result<PathBuf> {
    if make && !closed(root) {
        bail!(
            "`{}` is open to other users, so ck will not keep plaintext under it: it must be yours with mode 0700",
            tilde(root)
        );
    }
    let mut dir = root.to_path_buf();
    for part in ["cryptkeeper", "age", &copy_id(v)] {
        dir.push(part);
        if make {
            match DirBuilder::new().mode(0o700).create(&dir) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => bail!("could not create `{}` to open it in", tilde(&dir)),
            }
        }
        let private = is_private(&dir);
        if !private && make {
            bail!(
                "`{}` is not a private folder (a real folder of yours with mode 0700), so ck will not keep plaintext in it: remove it, then `ck unlock` again",
                tilde(&dir)
            );
        }
        if !private {
            bail!(
                "`{}` is not a private folder (a real folder of yours with mode 0700), so ck will not trust the plaintext in it: check nothing in it is a stranger's, `chmod 700` it, then `ck lock` again",
                tilde(&dir)
            );
        }
    }
    Ok(dir)
}

/// A real folder of this user's with mode 0700.
fn is_private(dir: &Path) -> bool {
    fs::symlink_metadata(dir)
        .is_ok_and(|m| m.file_type().is_dir() && m.uid() == my_uid() && m.mode() & 0o777 == 0o700)
}

/// A folder of this user's that nobody else may enter.
fn closed(dir: &Path) -> bool {
    fs::metadata(dir).is_ok_and(|m| m.is_dir() && m.uid() == my_uid() && m.mode() & 0o077 == 0)
}

/// Why age plaintext cannot be kept on this machine now, or `None`: what
/// `unlock` checks before it writes any, read without making anything.
pub fn runtime_problem() -> Option<String> {
    let root = match runtime_root() {
        Ok(root) => root,
        Err(e) => return Some(e.to_string()),
    };
    if !closed(&root) {
        return Some(format!(
            "`{}` is open to other users: it must be yours with mode 0700",
            tilde(&root)
        ));
    }
    ["cryptkeeper", "cryptkeeper/age"]
        .into_iter()
        .map(|rel| root.join(rel))
        .find(|d| fs::symlink_metadata(d).is_ok() && !is_private(d))
        .map(|d| {
            format!(
                "`{}` is not a private folder (a real folder of yours with mode 0700): remove it while nothing is open",
                tilde(&d)
            )
        })
}

/// `$XDG_RUNTIME_DIR` as `check` shows it.
pub fn runtime_shown() -> String {
    runtime_root().map(|r| tilde(&r)).unwrap_or_default()
}

/// The type of the filesystem holding `path`: the longest mountpoint above it.
fn fs_type(path: &Path) -> Option<String> {
    let text = fs::read_to_string("/proc/self/mounts").ok()?;
    text.lines()
        .filter_map(|l| {
            let mut f = l.split(' ');
            let point = PathBuf::from(f.nth(1)?.replace("\\040", " "));
            let kind = f.next()?;
            path.starts_with(&point)
                .then(|| (point.as_os_str().len(), kind.to_string()))
        })
        .max_by_key(|(len, _)| *len)
        .map(|(_, kind)| kind)
}

/// The copy `v` opens to, wherever `$XDG_RUNTIME_DIR` is now.
fn copy_path(v: &Vault) -> Option<PathBuf> {
    let root = runtime_root().ok()?;
    Some(
        root.join("cryptkeeper/age")
            .join(copy_id(v))
            .join(copy_name(v)),
    )
}

/// Where `v`'s plaintext is right now, read the same way by `state`,
/// `unlock` and `lock`.
enum Plain {
    None,
    /// The view is a link ck did not make.
    Foreign,
    /// The view links to ck's copy, which is gone.
    Dangling,
    /// ck's copy, with or without the view linking to it.
    Copy {
        copy: PathBuf,
        linked: bool,
    },
    /// A regular file where the view is: an editor saved over the link while
    /// `copy` is still there, or the copy was cleared and only this is left.
    OnDisk {
        copy: Option<PathBuf>,
    },
}

fn look(v: &Vault) -> Plain {
    let copy = copy_path(v).filter(|c| c.exists());
    match fs::symlink_metadata(&v.view) {
        Ok(m) if m.file_type().is_symlink() => match fs::read_link(&v.view) {
            Ok(t) if is_copy(v, &t) && t.exists() => Plain::Copy {
                copy: t,
                linked: true,
            },
            Ok(t) if is_copy(v, &t) => Plain::Dangling,
            _ => Plain::Foreign,
        },
        Ok(m) if m.is_file() => Plain::OnDisk { copy },
        _ => match copy {
            Some(copy) => Plain::Copy {
                copy,
                linked: false,
            },
            None => Plain::None,
        },
    }
}

/// Where `v`'s plaintext is while open: ck's copy, or a file at the view.
pub fn open_at(v: &Vault) -> Option<PathBuf> {
    match look(v) {
        Plain::Copy { copy, .. } => Some(copy),
        Plain::OnDisk { .. } => Some(v.view.clone()),
        _ => None,
    }
}

/// Whether the list holds `v`, which is what lets a plain file at its view
/// count as its plaintext rather than a file of the user's own.
fn is_listed(v: &Vault) -> bool {
    registry::load().is_ok_and(|all| all.iter().any(|k| k.cipher == v.cipher))
}

pub fn state(v: &Vault) -> State {
    let plain = look(v);
    if !v.cipher.exists() {
        return match plain {
            Plain::Copy { .. } | Plain::OnDisk { copy: Some(_) } => State::Open(format!(
                "`{}` is gone: put it back, then `ck lock`",
                file_name(&v.cipher)
            )),
            _ => State::Missing,
        };
    }
    match plain {
        Plain::None | Plain::Foreign => State::Locked,
        Plain::Dangling => State::Dead(
            "its copy in memory is gone (a logout or reboot clears it): `ck unlock` opens it again"
                .into(),
        ),
        Plain::Copy { copy, linked: true } => {
            State::Open(format!("plaintext in memory at `{}`", tilde(&copy)))
        }
        Plain::Copy {
            copy,
            linked: false,
        } => State::Open(format!(
            "its link is gone, the plaintext is at `{}`: `ck unlock` links it again",
            tilde(&copy)
        )),
        Plain::OnDisk { copy: Some(c) } if !view_wins(v, &c) => State::Open(format!(
            "saved over its link as a file on disk, and its copy in memory `{}` changed too: delete the one you do not want, then `ck lock`",
            tilde(&c)
        )),
        Plain::OnDisk { copy: Some(_) } => State::Open(
            "saved over its link as a file on disk: `ck lock` encrypts that file".into(),
        ),
        Plain::OnDisk { copy: None } if is_listed(v) => {
            State::Exposed("its plaintext is on disk: `ck lock` encrypts it and removes it".into())
        }
        Plain::OnDisk { copy: None } => State::Locked,
    }
}

/// The error for a vault whose `.age` file is gone while its plaintext is
/// still open.
fn gone(v: &Vault, verb: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "`{}` is gone, so ck cannot {verb} `{}`: put it back, then `ck {verb}`",
        tilde(&v.cipher),
        tilde(&v.view)
    )
}

pub fn unlock(v: &Vault, identity: Option<PathBuf>, dry: bool) -> Result<()> {
    let bin = need()?;
    if !v.cipher.exists() {
        return Err(gone(v, "unlock"));
    }
    let header = read_header(bin, v)?;
    let stored = v.identity.clone();
    let given = match identity {
        Some(id) => match fs::canonicalize(&id) {
            Ok(id) if id.is_file() => Some(id),
            _ => bail!("identity file `{}` does not exist", tilde(&id)),
        },
        None => None,
    };
    let identity = match (header.passphrase(), given.clone().or(stored.clone())) {
        (true, Some(_)) if given.is_some() => bail!(
            "`{}` opens with a passphrase, not an identity: drop `-i`",
            tilde(&v.cipher)
        ),
        (true, _) => None,
        (false, None) => bail!(
            "`{}` is encrypted to a key, not a passphrase: name its identity file with `ck unlock -i FILE`",
            tilde(&v.cipher)
        ),
        (false, id) => id,
    };
    if header.recipients() > 1 {
        bail!(
            "`{}` is encrypted to {} keys, and `ck lock` would encrypt it to one: open it with `{bin} -d` by hand",
            tilde(&v.cipher),
            header.recipients()
        );
    }
    let v = Vault {
        identity,
        ..v.clone()
    };
    match look(&v) {
        Plain::Copy { .. } | Plain::OnDisk { copy: Some(_) } => {
            return already_open(bin, &v, stored.as_deref(), given.as_deref(), dry);
        }
        Plain::Dangling => {
            if !dry && fs::remove_file(&v.view).is_err() {
                bail!("could not clear the dead link `{}`", tilde(&v.view));
            }
        }
        Plain::OnDisk { copy: None } if is_listed(&v) => bail!(
            "`{}` is open already, as a plain file on disk: `ck lock` encrypts it",
            tilde(&v.view)
        ),
        Plain::OnDisk { .. } | Plain::Foreign => bail!(
            "`{}` already exists beside `{}`: move it away, then `ck unlock`",
            tilde(&v.view),
            file_name(&v.cipher)
        ),
        Plain::None => {}
    }
    let root = runtime_root()?;
    if !dry {
        let dir = private_dir(&root, &v, true)?;
        let copy = dir.join(copy_name(&v));
        let Ok(out) = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&copy)
        else {
            bail!("could not create `{}` to open it in", tilde(&copy));
        };
        let mut cmd = Command::new(bin);
        cmd.arg("-d");
        if let Some(id) = &v.identity {
            cmd.arg("-i").arg(id);
        }
        cmd.arg(&v.cipher).stdout(out);
        let ran = run::prompting(&mut cmd);
        let whole = fs::metadata(&copy).ok().map(|m| m.len()) == plain_len(&v, &header);
        if ran != Ran::Done || !whole {
            let _ = fs::remove_file(&copy);
            let _ = fs::remove_dir(&dir);
            match ran {
                Ran::Cancelled => bail!("cancelled, so `{}` stays locked", tilde(&v.view)),
                Ran::Done => bail!(
                    "`{bin}` wrote less than `{}` holds (a cancelled prompt does that), so `{}` stays locked",
                    file_name(&v.cipher),
                    tilde(&v.view)
                ),
                Ran::Failed(_) => bail!("could not unlock `{}`", tilde(&v.view)),
            }
        }
        if std::os::unix::fs::symlink(&copy, &v.view).is_err() {
            let _ = fs::remove_file(&copy);
            let _ = fs::remove_dir(&dir);
            bail!("could not make the link `{}`", tilde(&v.view));
        }
        record_base(&copy);
        registry::remember(&v)?;
    }
    say!("unlocked: `{}`", tilde(&v.view));
    Ok(())
}

/// `unlock` of a vault whose plaintext is already open: links the view
/// again when it is gone, and keeps the identity it was opened with, since
/// `lock` encrypts to that one.
fn already_open(
    bin: &str,
    v: &Vault,
    stored: Option<&Path>,
    given: Option<&Path>,
    dry: bool,
) -> Result<()> {
    if let (Some(stored), Some(given)) = (stored, given)
        && stored != given
    {
        bail!(
            "`{}` is open already, with `{}`, and `ck lock` encrypts to that one: `ck lock` it, then `ck unlock -i {}`",
            tilde(&v.view),
            tilde(stored),
            tilde(given)
        );
    }
    if stored.is_none()
        && let Some(id) = given
        && !opens_with(bin, v, id)
    {
        bail!(
            "`{}` does not open `{}`, so ck will not lock it to that key",
            tilde(id),
            tilde(&v.cipher)
        );
    }
    let relink = match look(v) {
        Plain::Copy {
            copy,
            linked: false,
        } => Some(copy),
        _ => None,
    };
    if !dry {
        if let Some(c) = &relink {
            private_dir(&runtime_root()?, v, false)?;
            if std::os::unix::fs::symlink(c, &v.view).is_err() {
                bail!("could not make the link `{}`", tilde(&v.view));
            }
        }
        registry::remember(v)?;
    }
    match relink {
        Some(_) => say!("unlocked: `{}`", tilde(&v.view)),
        None => say!("already unlocked: `{}`", tilde(&v.view)),
    }
    Ok(())
}

/// Whether identity `id` decrypts `v`'s file, checked before ck stores it.
fn opens_with(bin: &str, v: &Vault, id: &Path) -> bool {
    let Ok(header) = read_header(bin, v) else {
        return false;
    };
    let _held = run::take_terminal();
    let child = Command::new(bin)
        .arg("-d")
        .arg("-i")
        .arg(id)
        .arg(&v.cipher)
        .stdout(Stdio::piped())
        .spawn();
    let Ok(mut child) = child else {
        return false;
    };
    // Counted, not trusted: an identity whose passphrase prompt was cancelled exits 0 too.
    let written = child
        .stdout
        .take()
        .map(|out| std::io::copy(&mut BufReader::new(out), &mut std::io::sink()).unwrap_or(0));
    child.wait().is_ok_and(|st| st.success()) && written == plain_len(v, &header)
}

pub fn lock(v: &Vault, dry: bool) -> Result<()> {
    let bin = need()?;
    let plain = look(v);
    if !v.cipher.exists() {
        return match plain {
            Plain::Copy { .. } | Plain::OnDisk { copy: Some(_) } => Err(gone(v, "lock")),
            _ => {
                say!("already locked: `{}`", tilde(&v.view));
                Ok(())
            }
        };
    }
    let header = read_header(bin, v)?;
    if !header.passphrase() && v.identity.is_none() {
        bail!(
            "ck does not know the identity `{}` opens with: `ck unlock -i FILE` it again",
            tilde(&v.cipher)
        );
    }
    // The newest plaintext, whether the view goes with it, and the copy in
    // memory to delete after.
    let (source, view_too, copy) = match plain {
        Plain::Foreign => bail!(
            "`{}` is a link ck did not make, so ck leaves it alone",
            tilde(&v.view)
        ),
        Plain::None => {
            say!("already locked: `{}`", tilde(&v.view));
            return Ok(());
        }
        Plain::OnDisk { copy: None } if !is_listed(v) => {
            say!("already locked: `{}`", tilde(&v.view));
            return Ok(());
        }
        Plain::Dangling => {
            if !dry {
                let _ = fs::remove_file(&v.view);
            }
            say!("locked: `{}`", tilde(&v.view));
            return Ok(());
        }
        Plain::Copy { copy, linked } => (copy.clone(), linked, Some(copy)),
        Plain::OnDisk { copy: Some(c) } => {
            if !view_wins(v, &c) {
                bail!(
                    "`{}` was saved over its link as a file on disk, and its copy in memory `{}` changed too since `ck unlock`, so ck will not pick one: delete the one you do not want, then `ck lock`",
                    tilde(&v.view),
                    tilde(&c)
                );
            }
            (v.view.clone(), true, Some(c))
        }
        Plain::OnDisk { copy: None } => (v.view.clone(), true, None),
    };
    if copy.is_some() {
        private_dir(&runtime_root()?, v, false)?;
    }
    if !dry {
        encrypt(bin, v, &header, &source)?;
        if view_too {
            let _ = fs::remove_file(&v.view);
        }
        if let Some(c) = copy {
            let _ = fs::remove_file(&c);
            if let Some(base) = base_path(&c) {
                let _ = fs::remove_file(base);
            }
            if let Some(dir) = c.parent() {
                let _ = fs::remove_dir(dir);
            }
        }
    }
    say!("locked: `{}`", tilde(&v.view));
    Ok(())
}

/// Whether `lock` takes the file an editor saved over the link rather than
/// `copy`: when the two match, or when `copy` is still exactly what `unlock`
/// wrote, so the file on disk is the only edit. Both changed is a choice ck
/// leaves to the user.
fn view_wins(v: &Vault, copy: &Path) -> bool {
    same_files(&v.view, copy) || untouched(copy)
}

/// Where `unlock` records what the copy looked like as it wrote it: beside
/// the copy's folder, so no copy name can collide with it.
fn base_path(copy: &Path) -> Option<PathBuf> {
    copy.parent().map(|d| d.with_extension("base"))
}

/// What changes whenever a file is written or replaced.
fn fingerprint(file: &Path) -> Option<String> {
    let m = fs::metadata(file).ok()?;
    Some(format!(
        "{} {} {} {}",
        m.ino(),
        m.len(),
        m.mtime(),
        m.mtime_nsec()
    ))
}

/// Records `copy` as `unlock` left it, so `lock` can tell it was not edited.
fn record_base(copy: &Path) {
    let (Some(base), Some(now)) = (base_path(copy), fingerprint(copy)) else {
        return;
    };
    // Without the record, `lock` only takes a file on disk that matches the copy.
    if let Ok(mut f) = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(base)
    {
        let _ = std::io::Write::write_all(&mut f, now.as_bytes());
    }
}

/// Whether `copy` is still exactly what `unlock` wrote into it.
fn untouched(copy: &Path) -> bool {
    let base = base_path(copy).and_then(|b| fs::read_to_string(b).ok());
    match (base, fingerprint(copy)) {
        (Some(base), Some(now)) => base.trim() == now,
        _ => false,
    }
}

fn same_files(a: &Path, b: &Path) -> bool {
    match (File::open(a), File::open(b)) {
        (Ok(x), Ok(y)) => same_bytes(BufReader::new(x), BufReader::new(y)),
        _ => false,
    }
}

/// Encrypts `plain` over `v.cipher` the way it was encrypted before, through
/// a temp file beside it that is checked before the rename, so a failure at
/// any step leaves both the old ciphertext and the plaintext as they were.
fn encrypt(bin: &str, v: &Vault, header: &Header, plain: &Path) -> Result<()> {
    let fail = |why: String| {
        anyhow::anyhow!(
            "could not lock `{}` ({why}), so `{}` is unchanged and the plaintext stays at `{}`: fix that, then `ck lock` again",
            tilde(&v.view),
            file_name(&v.cipher),
            tilde(plain)
        )
    };
    let before = format!("before it replaces `{}`", file_name(&v.cipher));
    let tmp = encrypted_copy(bin, v, header.passphrase(), plain, &before).map_err(fail)?;
    if let Ok(m) = fs::metadata(&v.cipher) {
        let _ = fs::set_permissions(&tmp, m.permissions());
    }
    if fs::rename(&tmp, &v.cipher).is_err() {
        let _ = fs::remove_file(&tmp);
        return Err(fail("the new file could not be saved in its place".into()));
    }
    sync_folder(&v.cipher);
    Ok(())
}

/// `plain` encrypted with a passphrase or to `v`'s identity into a temp file
/// beside `v.cipher`, decrypted again and compared byte for byte, then
/// synced; the temp file is gone again when this fails, with why. `before`
/// ends the one line ck prints ahead of asking the passphrase again, saying
/// what the check guards.
fn encrypted_copy(
    bin: &str,
    v: &Vault,
    passphrase: bool,
    plain: &Path,
    before: &str,
) -> std::result::Result<PathBuf, String> {
    let tmp = v
        .cipher
        .with_file_name(format!(".{}.ck-tmp", file_name(&v.cipher)));
    let fail = |why: String| {
        let _ = fs::remove_file(&tmp);
        Err(why)
    };
    let _ = fs::remove_file(&tmp);
    let Ok(out) = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
    else {
        return fail("its temp file could not be made".into());
    };
    let mut cmd = Command::new(bin);
    cmd.arg("-e");
    match (&v.identity, passphrase) {
        (_, true) => cmd.arg("-p"),
        (Some(id), false) => cmd.arg("-i").arg(id),
        (None, false) => return fail("no identity to encrypt to".into()),
    };
    cmd.arg(plain).stdout(out);
    // Given no passphrase, or a cancelled prompt, age and rage make one up and
    // print it once; a file locked with that is lost to whoever missed the line.
    let (ran, made_up) = run::prompting_saying(&mut cmd, "autogenerated");
    match ran {
        _ if made_up && passphrase => {
            return fail(format!(
                "`{bin}` made up a passphrase because none was typed, and ck does not lock a file with one"
            ));
        }
        Ran::Done => {}
        Ran::Cancelled => return fail("cancelled".into()),
        Ran::Failed(_) => return fail(format!("`{bin}` failed, its own lines above say why")),
    }
    if !well_formed(&tmp, plain) {
        return fail(format!("the file `{bin}` wrote did not check out"));
    }
    if passphrase {
        // The passphrase prompt answers only to the terminal, so an empty answer
        // turned into a made-up passphrase is caught only by opening the file.
        eprintln!("ck: type the passphrase once more: ck opens the new file with it {before}");
    }
    let identity = v.identity.as_deref().filter(|_| !passphrase);
    if !decrypts_to(bin, identity, &tmp, plain) {
        return fail(match passphrase {
            _ if run::interrupted() => "cancelled".into(),
            true => "it did not open with the passphrase typed to check it, so it was thrown away: type the same passphrase all three times".into(),
            false => format!("the file `{bin}` wrote did not decrypt back to the plaintext"),
        });
    }
    if File::open(&tmp).and_then(|f| f.sync_all()).is_err() {
        return fail("the new file could not be synced to disk".into());
    }
    Ok(tmp)
}

/// Syncs the folder holding `file`, so a rename or link in it survives a crash.
fn sync_folder(file: &Path) {
    if let Some(dir) = file.parent() {
        let _ = File::open(dir).and_then(|d| d.sync_all());
    }
}

/// `ck init` on an existing regular file: encrypts it into `<file>.age` with
/// a passphrase, or to `identity`'s key, checks it as `lock` does, and only
/// once the new file is in place deletes the plaintext and lists the vault.
pub fn init(file: &Path, identity: Option<PathBuf>, dry: bool) -> Result<()> {
    let bin = need()?;
    let seen = tilde(file);
    let meta = match fs::symlink_metadata(file) {
        Ok(m) => m,
        Err(_) => bail!("`{seen}` does not exist"),
    };
    if meta.file_type().is_symlink() {
        bail!("`{seen}` is a symlink: `ck init` the file it points to");
    }
    if !meta.is_file() {
        bail!("`{seen}` is not a regular file, so ck will not encrypt it");
    }
    if meta.nlink() > 1 {
        bail!(
            "`{seen}` has other hard links, so deleting it would leave its plaintext on disk under them: remove those first"
        );
    }
    let plain = crate::vault::real_parent(file);
    if let Ok(root) = runtime_root()
        && plain.starts_with(root.join("cryptkeeper"))
    {
        bail!("`{seen}` is the open copy of an age vault: `ck lock` that vault instead");
    }
    if file_name(&plain).ends_with(".age") && is_age(&plain) {
        bail!("`{seen}` is an age file already: `ck unlock` it");
    }
    let cipher = plain.with_file_name(format!("{}.age", file_name(&plain)));
    if fs::symlink_metadata(&cipher).is_ok() {
        bail!(
            "`{}` already exists: move it away, or `ck unlock` it",
            tilde(&cipher)
        );
    }
    let identity = match identity {
        Some(id) => match fs::canonicalize(&id) {
            Ok(id) if id.is_file() => Some(id),
            _ => bail!("identity file `{}` does not exist", tilde(&id)),
        },
        None => None,
    };
    let v = Vault {
        identity,
        view: plain.clone(),
        ..Vault::age(&cipher)
    };
    registry::check_storable(&v)?;
    // A list that cannot be saved to fails here, before the plaintext is gone.
    registry::load()?;
    if !dry {
        let passphrase = v.identity.is_none();
        let before = format!("before it deletes `{}`", file_name(&plain));
        let tmp = encrypted_copy(bin, &v, passphrase, &plain, &before).map_err(|why| {
            anyhow::anyhow!(
                "could not make `{}` ({why}), so `{seen}` is untouched",
                tilde(&cipher)
            )
        })?;
        let _ = fs::set_permissions(&tmp, meta.permissions());
        // A hard link fails where the name exists, so nothing put there meanwhile is replaced.
        let placed = match fs::hard_link(&tmp, &cipher) {
            Ok(()) => fs::remove_file(&tmp).is_ok(),
            Err(_) if fs::symlink_metadata(&cipher).is_err() => fs::rename(&tmp, &cipher).is_ok(),
            Err(_) => false,
        };
        if !placed {
            let _ = fs::remove_file(&tmp);
            bail!(
                "could not put `{}` in place, so `{seen}` is untouched",
                tilde(&cipher)
            );
        }
        sync_folder(&cipher);
        if fs::remove_file(&plain).is_err() {
            bail!(
                "made `{}`, but could not delete `{seen}`: delete it yourself",
                tilde(&cipher)
            );
        }
        sync_folder(&plain);
        registry::remember(&v)?;
    }
    say!(
        "made `{}` and deleted `{}`: open it with `ck unlock {}`",
        tilde(&cipher),
        file_name(&plain),
        tilde(&plain)
    );
    Ok(())
}

/// Whether `tmp` is a whole age file whose payload is the exact length age
/// writes for `plain`, read without decrypting it.
fn well_formed(tmp: &Path, plain: &Path) -> bool {
    let Ok(mut head) = File::open(tmp).map(|f| f.take(1 << 16)) else {
        return false;
    };
    let mut bytes = Vec::new();
    let Some(header) = head
        .read_to_end(&mut bytes)
        .ok()
        .and_then(|_| parse_header(&bytes))
    else {
        return false;
    };
    match (fs::metadata(tmp), fs::metadata(plain)) {
        (Ok(enc), Ok(dec)) => enc.len() == header.len + payload_len(dec.len()),
        _ => false,
    }
}

/// Whether `tmp` decrypts to exactly `plain`: with `identity` silently, or
/// without one through the passphrase prompt, so the file is proven to open
/// with what the user knows before anything is replaced or deleted.
fn decrypts_to(bin: &str, identity: Option<&Path>, tmp: &Path, plain: &Path) -> bool {
    let _held = run::take_terminal();
    let mut cmd = Command::new(bin);
    cmd.arg("-d");
    if let Some(id) = identity {
        cmd.arg("-i").arg(id);
    }
    let child = cmd
        .arg(tmp)
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .spawn();
    let Ok(mut child) = child else {
        return false;
    };
    let same = match (child.stdout.take(), File::open(plain)) {
        (Some(out), Ok(file)) => same_bytes(BufReader::new(out), BufReader::new(file)),
        _ => false,
    };
    child.wait().is_ok_and(|st| st.success()) && same
}

fn same_bytes(mut a: impl BufRead, mut b: impl BufRead) -> bool {
    loop {
        let n = match (a.fill_buf(), b.fill_buf()) {
            (Ok(x), Ok(y)) if x.is_empty() || y.is_empty() => return x.is_empty() && y.is_empty(),
            (Ok(x), Ok(y)) => {
                let n = x.len().min(y.len());
                if x[..n] != y[..n] {
                    return false;
                }
                n
            }
            _ => return false,
        };
        a.consume(n);
        b.consume(n);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSPHRASE: &[u8] =
        b"age-encryption.org/v1\n-> scrypt c2FsdA 18\nYm9keQ\n--- bWFj\n\x00payload";
    const TWO_KEYS: &[u8] = b"age-encryption.org/v1\n-> X25519 a\nYQ\n-> X25519 b\nYg\n-> 9-.x grease\n\n--- bWFj\npayload";

    #[test]
    fn the_header_ends_after_its_mac_line() {
        let h = parse_header(PASSPHRASE).unwrap();
        assert_eq!(
            &PASSPHRASE[h.len as usize..],
            b"\x00payload",
            "the payload starts right after `--- <mac>`"
        );
        assert!(h.passphrase());
        assert_eq!(h.recipients(), 0);
    }

    #[test]
    fn recipients_are_counted_without_the_padding_stanzas() {
        let h = parse_header(TWO_KEYS).unwrap();
        assert!(!h.passphrase());
        assert_eq!(h.recipients(), 2, "the grease stanza is no recipient");
    }

    #[test]
    fn a_header_cut_short_is_no_header() {
        assert!(parse_header(&PASSPHRASE[..30]).is_none());
        assert!(parse_header(b"plain text\n").is_none());
    }

    #[test]
    fn the_payload_length_counts_one_tag_per_64k_chunk() {
        assert_eq!(payload_len(0), 32, "an empty file still has one chunk");
        assert_eq!(payload_len(6), 16 + 6 + 16);
        assert_eq!(
            payload_len(65536),
            16 + 65536 + 16,
            "a full chunk is the last"
        );
        assert_eq!(payload_len(65537), 16 + 65537 + 32);
    }

    #[test]
    fn a_link_counts_as_the_copy_only_inside_cks_own_folder_for_that_vault() {
        let v = Vault::age(Path::new("/example/taxes.pdf.age"));
        let mine = Path::new("/run/user/1000/cryptkeeper/age")
            .join(copy_id(&v))
            .join("taxes.pdf");
        assert!(is_copy(&v, &mine));
        assert!(!is_copy(&v, Path::new("/example/elsewhere/taxes.pdf")));
        let other = Vault::age(Path::new("/example/other/taxes.pdf.age"));
        assert!(
            !is_copy(&other, &mine),
            "two files of the same name never share a copy"
        );
    }

    #[test]
    fn streams_compare_equal_only_byte_for_byte() {
        assert!(same_bytes(&b"abc"[..], &b"abc"[..]));
        assert!(!same_bytes(&b"abc"[..], &b"abd"[..]));
        assert!(!same_bytes(&b"abc"[..], &b"ab"[..]));
    }
}
