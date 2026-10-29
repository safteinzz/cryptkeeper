//! The promises `--help` and the README make, checked against the built `ck`.
//!
//! Every run gets an empty environment with its home, config, state and
//! runtime folders in a temp folder the test deletes, so no real vault or list
//! is ever read. Nothing here mounts. The age tests need `age` or `rage` on
//! `PATH` and a temp folder in memory, and fail saying so when either is
//! missing.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

struct Sandbox {
    root: PathBuf,
}

impl Sandbox {
    fn new(tag: &str) -> Sandbox {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("ck-cli-{tag}-{}-{stamp}", std::process::id()));
        for d in ["home/.config", "home/.local/state", "run", "work"] {
            fs::create_dir_all(root.join(d)).unwrap();
        }
        let root = fs::canonicalize(root).unwrap();
        fs::set_permissions(
            root.join("run"),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        Sandbox { root }
    }

    fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    fn work(&self) -> PathBuf {
        self.root.join("work")
    }

    fn list(&self) -> PathBuf {
        self.home().join(".config/cryptkeeper/vaults")
    }

    /// `ck <args>` in the sandbox, with `path` as its whole `PATH`.
    fn ck_with_path(&self, args: &[&str], path: &str) -> Output {
        Command::new(env!("CARGO_BIN_EXE_ck"))
            .args(args)
            .current_dir(self.work())
            .env_clear()
            .env("PATH", path)
            .env("HOME", self.home())
            .env("XDG_CONFIG_HOME", self.home().join(".config"))
            .env("XDG_STATE_HOME", self.home().join(".local/state"))
            .env("XDG_RUNTIME_DIR", self.root.join("run"))
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }

    fn ck(&self, args: &[&str]) -> Output {
        self.ck_with_path(args, "/usr/bin:/bin")
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// A folder that passes for a gocryptfs vault's encrypted half.
fn fake_gocryptfs(cipher: &Path) {
    fs::create_dir_all(cipher).unwrap();
    fs::write(
        cipher.join("gocryptfs.conf"),
        r#"{"EncryptedKey": "not-a-real-key", "Version": 2}"#,
    )
    .unwrap();
}

fn list_of(lines: &[(&Path, &Path)]) -> String {
    lines
        .iter()
        .map(|(c, v)| format!("gocryptfs\t{}\t{}\n", c.display(), v.display()))
        .collect()
}

#[test]
fn a_dry_run_forget_prints_what_forget_prints_and_changes_nothing() {
    let s = Sandbox::new("forget");
    let (a, b) = (s.work().join("a"), s.work().join("b"));
    let list = list_of(&[(&s.work().join(".a"), &a), (&s.work().join(".b"), &b)]);
    fs::create_dir_all(s.list().parent().unwrap()).unwrap();
    fs::write(s.list(), &list).unwrap();

    let dry = s.ck(&["forget", a.to_str().unwrap(), "-n"]);
    let after_dry = fs::read_to_string(s.list()).unwrap();
    let real = s.ck(&["forget", a.to_str().unwrap()]);
    let after_real = fs::read_to_string(s.list()).unwrap();

    assert!(dry.status.success() && real.status.success());
    assert_eq!(
        stdout(&dry),
        stdout(&real),
        "`-n` must print the real run's lines"
    );
    assert_eq!(after_dry, list, "`-n` changed the vault list");
    assert_eq!(
        after_real,
        list_of(&[(&s.work().join(".b"), &b)]),
        "forget should drop exactly the vault named"
    );
}

#[test]
fn clear_drops_only_the_missing_vaults() {
    let s = Sandbox::new("clear");
    let here = s.work().join(".here");
    fake_gocryptfs(&here);
    let present = (here.as_path(), s.work().join("here"));
    let gone = s.work().join(".gone");
    fs::create_dir_all(s.list().parent().unwrap()).unwrap();
    fs::write(
        s.list(),
        list_of(&[(present.0, &present.1), (&gone, &s.work().join("gone"))]),
    )
    .unwrap();

    let out = s.ck(&["clear"]);

    assert!(out.status.success(), "clear failed: {out:?}");
    assert_eq!(
        fs::read_to_string(s.list()).unwrap(),
        list_of(&[(present.0, &present.1)]),
        "clear must keep a vault whose folder is there"
    );
    assert!(
        here.join("gocryptfs.conf").exists(),
        "clear touched a vault itself"
    );
}

#[test]
fn the_list_kept_under_its_old_name_is_read_but_never_rewritten() {
    let s = Sandbox::new("migrate");
    let old = s.home().join(".config/egc/vaults");
    fs::create_dir_all(old.parent().unwrap()).unwrap();
    let (a, b) = (s.work().join("a"), s.work().join("b"));
    // The two-field lines that list wrote.
    let before = format!(
        "{}\t{}\n{}\t{}\n",
        s.work().join(".a").display(),
        a.display(),
        s.work().join(".b").display(),
        b.display()
    );
    fs::write(&old, &before).unwrap();

    // `--json`, since `ls` also lists whatever LUKS drives this machine has.
    let listed = s.ck(&["ls", "--json"]);
    let forgot = s.ck(&["forget", a.to_str().unwrap()]);

    assert!(listed.status.success() && forgot.status.success());
    assert_eq!(
        stdout(&listed).matches("\"listed\":true").count(),
        2,
        "both vaults in the old list should be listed"
    );
    assert_eq!(
        fs::read_to_string(&old).unwrap(),
        before,
        "the old list was changed"
    );
    assert_eq!(
        fs::read_to_string(s.list()).unwrap(),
        list_of(&[(&s.work().join(".b"), &b)]),
        "the change should land in the new list"
    );
}

#[test]
fn a_failure_exits_1_with_nothing_on_stdout() {
    let s = Sandbox::new("contract");
    let out = s.ck(&[]);
    assert_eq!(out.status.code(), Some(1), "no vault here is a failure");
    assert!(out.stdout.is_empty(), "an error leaked onto stdout");
    assert!(!out.stderr.is_empty(), "the error should be on stderr");
}

#[test]
fn a_plain_file_is_never_taken_for_the_vault_beside_it() {
    let s = Sandbox::new("plain");
    fake_gocryptfs(&s.work().join(".photos"));
    fs::write(s.work().join("notes.txt"), "hello").unwrap();
    let out = s.ck(&["lock", "notes.txt", "-n"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        out.stdout.is_empty(),
        "nothing should have been locked: {out:?}"
    );
}

/// The folder holding `age` or `rage` on this machine's `PATH`, and the
/// keygen beside it, or what the age tests are missing here.
fn age_tools(s: &Sandbox) -> Result<(String, PathBuf, PathBuf), String> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let found = std::env::split_paths(&path).find_map(|d| {
        ["age", "rage"].into_iter().find_map(|b| {
            let keygen = d.join(format!("{b}-keygen"));
            (d.join(b).is_file() && keygen.is_file()).then(|| (d.clone(), d.join(b), keygen))
        })
    });
    let Some((dir, bin, keygen)) = found else {
        return Err("neither `age` nor `rage` is on PATH".into());
    };
    let mounts = fs::read_to_string("/proc/self/mounts").unwrap_or_default();
    let in_memory = mounts
        .lines()
        .filter_map(|l| {
            let mut f = l.split(' ');
            Some((PathBuf::from(f.nth(1)?), f.next()?.to_string()))
        })
        .filter(|(point, _)| s.root.starts_with(point))
        .max_by_key(|(point, _)| point.as_os_str().len())
        .is_some_and(|(_, kind)| kind == "tmpfs");
    if !in_memory {
        return Err("the temp folder is not on tmpfs, where ck keeps age plaintext".into());
    }
    Ok((format!("{}:/usr/bin:/bin", dir.display()), bin, keygen))
}

/// An age file encrypted to a fresh identity, in the sandbox.
fn age_vault(s: &Sandbox, bin: &Path, keygen: &Path, body: &[u8]) -> (PathBuf, PathBuf) {
    let key = s.home().join("key.txt");
    let made = Command::new(keygen).arg("-o").arg(&key).output().unwrap();
    assert!(made.status.success(), "keygen failed: {made:?}");
    let plain = s.work().join("notes.txt");
    fs::write(&plain, body).unwrap();
    let cipher = s.work().join("notes.txt.age");
    let enc = Command::new(bin)
        .args(["-e", "-i"])
        .arg(&key)
        .arg("-o")
        .arg(&cipher)
        .arg(&plain)
        .output()
        .unwrap();
    assert!(
        enc.status.success(),
        "encrypting the fixture failed: {enc:?}"
    );
    fs::remove_file(&plain).unwrap();
    (cipher, key)
}

fn decrypt(bin: &Path, key: &Path, cipher: &Path) -> Vec<u8> {
    let out = Command::new(bin)
        .args(["-d", "-i"])
        .arg(key)
        .arg(cipher)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "the vault no longer decrypts: {out:?}"
    );
    out.stdout
}

#[test]
fn locking_an_age_file_keeps_the_edits_and_leaves_no_plaintext() {
    let s = Sandbox::new("age");
    let (path, bin, keygen) = need_age(&s);
    let (cipher, key) = age_vault(&s, &bin, &keygen, b"first draft\n");
    let view = s.work().join("notes.txt");

    let unlocked = s.ck_with_path(
        &["unlock", "notes.txt.age", "-i", key.to_str().unwrap()],
        &path,
    );
    assert!(unlocked.status.success(), "unlock failed: {unlocked:?}");
    let target = fs::read_link(&view).expect("the view should be a link to the copy");
    assert!(
        target.starts_with(s.root.join("run")),
        "the plaintext must live in `$XDG_RUNTIME_DIR`, not beside the vault"
    );
    fs::write(&view, b"first draft\nsecond thought\n").unwrap();

    let locked = s.ck_with_path(&["lock", "notes.txt"], &path);
    assert!(locked.status.success(), "lock failed: {locked:?}");
    assert_eq!(
        decrypt(&bin, &key, &cipher),
        b"first draft\nsecond thought\n"
    );
    assert!(
        fs::symlink_metadata(&view).is_err(),
        "the link outlived the lock"
    );
    assert!(!target.exists(), "the plaintext outlived the lock");
}

#[test]
fn a_lock_that_cannot_write_keeps_the_old_file_and_the_plaintext() {
    let s = Sandbox::new("agefail");
    let (path, bin, keygen) = need_age(&s);
    let (cipher, key) = age_vault(&s, &bin, &keygen, b"keep me\n");
    let before = fs::read(&cipher).unwrap();
    let unlocked = s.ck_with_path(
        &["unlock", "notes.txt.age", "-i", key.to_str().unwrap()],
        &path,
    );
    assert!(unlocked.status.success(), "unlock failed: {unlocked:?}");
    let view = s.work().join("notes.txt");
    fs::write(&view, b"keep me, edited\n").unwrap();

    let ro = std::os::unix::fs::PermissionsExt::from_mode(0o555);
    fs::set_permissions(s.work(), ro).unwrap();
    let locked = s.ck_with_path(&["lock", "notes.txt"], &path);
    let rw = std::os::unix::fs::PermissionsExt::from_mode(0o755);
    fs::set_permissions(s.work(), rw).unwrap();

    assert_eq!(
        locked.status.code(),
        Some(1),
        "a lock that could not write must fail"
    );
    assert_eq!(
        fs::read(&cipher).unwrap(),
        before,
        "the old ciphertext was touched"
    );
    assert_eq!(
        fs::read(&view).unwrap(),
        b"keep me, edited\n",
        "the plaintext must stay until a lock succeeds"
    );
}

/// The sandbox's age tools, failing the test with what is missing.
fn need_age(s: &Sandbox) -> (String, PathBuf, PathBuf) {
    age_tools(s).unwrap_or_else(|why| {
        panic!("this test needs `age` or `rage` on PATH and a tmpfs temp folder: {why}")
    })
}

#[test]
fn an_open_age_file_locks_by_any_path_that_names_it() {
    let s = Sandbox::new("agepath");
    let (path, bin, keygen) = need_age(&s);
    let (cipher, key) = age_vault(&s, &bin, &keygen, b"one\n");
    fs::create_dir(s.work().join("sub")).unwrap();
    std::os::unix::fs::symlink(s.work(), s.root.join("worklink")).unwrap();
    let key = key.to_str().unwrap();

    for name in ["../notes.txt", "../../worklink/notes.txt"] {
        let unlocked = s.ck_with_path(&["unlock", "notes.txt.age", "-i", key], &path);
        assert!(unlocked.status.success(), "unlock failed: {unlocked:?}");
        let locked = Command::new(env!("CARGO_BIN_EXE_ck"))
            .args(["lock", name])
            .current_dir(s.work().join("sub"))
            .env_clear()
            .env("PATH", &path)
            .env("HOME", s.home())
            .env("XDG_CONFIG_HOME", s.home().join(".config"))
            .env("XDG_STATE_HOME", s.home().join(".local/state"))
            .env("XDG_RUNTIME_DIR", s.root.join("run"))
            .output()
            .unwrap();
        assert!(locked.status.success(), "lock {name} failed: {locked:?}");
        assert!(
            fs::symlink_metadata(s.work().join("notes.txt")).is_err(),
            "`lock {name}` left the plaintext open"
        );
    }
    assert_eq!(
        decrypt(&bin, s.home().join("key.txt").as_path(), &cipher),
        b"one\n"
    );
}

#[test]
fn lock_never_picks_between_a_file_on_disk_and_a_different_copy_in_memory() {
    let s = Sandbox::new("agetwo");
    let (path, bin, keygen) = need_age(&s);
    let (cipher, key) = age_vault(&s, &bin, &keygen, b"start\n");
    let before = fs::read(&cipher).unwrap();
    let unlocked = s.ck_with_path(
        &["unlock", "notes.txt.age", "-i", key.to_str().unwrap()],
        &path,
    );
    assert!(unlocked.status.success(), "unlock failed: {unlocked:?}");
    let view = s.work().join("notes.txt");
    let copy = fs::read_link(&view).unwrap();
    fs::write(&copy, b"newer, in memory\n").unwrap();
    fs::remove_file(&view).unwrap();
    fs::write(&view, b"older, on disk\n").unwrap();

    let locked = s.ck_with_path(&["lock", "notes.txt"], &path);

    assert_eq!(
        locked.status.code(),
        Some(1),
        "two different plaintexts must be refused"
    );
    assert_eq!(
        fs::read(&cipher).unwrap(),
        before,
        "the ciphertext was replaced"
    );
    assert_eq!(
        fs::read(&copy).unwrap(),
        b"newer, in memory\n",
        "the copy was lost"
    );
    assert_eq!(
        fs::read(&view).unwrap(),
        b"older, on disk\n",
        "the file was lost"
    );
}

#[test]
fn a_listed_age_files_plaintext_left_on_disk_is_encrypted_by_lock() {
    let s = Sandbox::new("ageexposed");
    let (path, bin, keygen) = need_age(&s);
    let (cipher, key) = age_vault(&s, &bin, &keygen, b"start\n");
    let unlocked = s.ck_with_path(
        &["unlock", "notes.txt.age", "-i", key.to_str().unwrap()],
        &path,
    );
    assert!(unlocked.status.success(), "unlock failed: {unlocked:?}");
    let view = s.work().join("notes.txt");
    fs::remove_file(&view).unwrap();
    fs::write(&view, b"saved on disk\n").unwrap();
    // What a logout does to the copy in memory.
    fs::remove_dir_all(s.root.join("run/cryptkeeper")).unwrap();

    let locked = s.ck_with_path(&["lock", "--all"], &path);

    assert!(locked.status.success(), "lock --all failed: {locked:?}");
    assert_eq!(decrypt(&bin, &key, &cipher), b"saved on disk\n");
    assert!(!view.exists(), "the plaintext on disk outlived the lock");
}

#[test]
fn delete_takes_only_the_vault_named_never_one_found_walking_up() {
    let s = Sandbox::new("delete");
    let cipher = s.work().join(".photos");
    fake_gocryptfs(&cipher);
    fs::create_dir_all(s.work().join("photos/sub")).unwrap();

    let inside = s.ck(&[
        "delete",
        s.work().join("photos/sub").to_str().unwrap(),
        "--yes",
    ]);
    let beside = s.ck(&["delete", s.work().to_str().unwrap(), "--yes"]);
    assert!(
        !inside.status.success() && !beside.status.success(),
        "a folder in or beside a vault must not delete it"
    );
    assert!(
        cipher.join("gocryptfs.conf").exists(),
        "the vault is still there"
    );

    let asked = s.ck(&["delete", s.work().join("photos").to_str().unwrap()]);
    assert!(!asked.status.success(), "without --yes nothing is deleted");
    assert!(cipher.exists(), "without --yes the vault is still there");

    let named = s.ck(&["delete", s.work().join("photos").to_str().unwrap(), "--yes"]);
    assert!(named.status.success(), "naming the vault itself deletes it");
    assert!(!cipher.exists(), "its encrypted folder is gone");
}

#[test]
fn delete_leaves_a_folder_alone_that_only_holds_a_stray_gocryptfs_conf() {
    let s = Sandbox::new("stray-conf");
    let docs = s.work().join("docs");
    fs::create_dir_all(&docs).unwrap();
    fs::write(docs.join("thesis.txt"), "mine").unwrap();
    fs::write(docs.join("gocryptfs.conf"), "{}").unwrap();

    let out = s.ck(&["delete", docs.to_str().unwrap(), "--yes"]);
    assert!(
        !out.status.success(),
        "a folder that is not a vault must not be deleted"
    );
    assert!(
        docs.join("thesis.txt").exists(),
        "the files in it are still there"
    );
}

#[test]
fn delete_leaves_a_listed_path_alone_once_its_file_is_no_vault() {
    let s = Sandbox::new("stale-line");
    let file = s.work().join("disk.img");
    fs::write(&file, "a holiday video").unwrap();
    fs::create_dir_all(s.list().parent().unwrap()).unwrap();
    fs::write(s.list(), format!("luks\t{}\t\n", file.display())).unwrap();

    let out = s.ck(&["delete", file.to_str().unwrap(), "--yes"]);
    assert!(
        !out.status.success(),
        "a file that is no LUKS image must not be deleted"
    );
    assert!(file.exists(), "the file is still there");
}

#[test]
fn a_vault_list_kept_as_a_link_is_written_where_it_points_and_kept_private() {
    use std::os::unix::fs::PermissionsExt;
    let s = Sandbox::new("linked-list");
    let real = s.home().join("dots/vaults");
    fs::create_dir_all(real.parent().unwrap()).unwrap();
    fs::write(&real, "").unwrap();
    fs::create_dir_all(s.list().parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&real, s.list()).unwrap();
    fake_gocryptfs(&s.work().join(".photos"));

    let out = s.ck(&["add", s.work().join("photos").to_str().unwrap()]);
    assert!(
        out.status.success(),
        "add failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        fs::symlink_metadata(s.list())
            .unwrap()
            .file_type()
            .is_symlink(),
        "the link must stay a link"
    );
    let saved = fs::read_to_string(&real).unwrap();
    assert!(
        saved.contains(".photos"),
        "the file it points to holds the vault, got:\n{saved}"
    );
    let mode = fs::metadata(&real).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "the list is readable by its owner only");
}

#[test]
fn output_into_a_closed_pipe_exits_cleanly_instead_of_panicking() {
    let s = Sandbox::new("closed-pipe");
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    let out = Command::new(env!("CARGO_BIN_EXE_ck"))
        .args(["ls", "--json"])
        .current_dir(s.work())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", s.home())
        .env("XDG_CONFIG_HOME", s.home().join(".config"))
        .env("XDG_STATE_HOME", s.home().join(".local/state"))
        .env("XDG_RUNTIME_DIR", s.root.join("run"))
        .stdin(Stdio::null())
        .stdout(writer)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("panicked"), "ck panicked: {stderr}");
    assert_eq!(
        out.status.code(),
        Some(0),
        "a reader that went away is no failure"
    );
}
