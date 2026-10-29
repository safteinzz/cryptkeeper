//! cryptkeeper: one way to lock and unlock gocryptfs folders, LUKS drives and
//! age files. Binary: `ck`.
//!
//! This file is the clap `Cmd` enum, the dispatch match and the path helpers
//! every module shares; what you can run is `ck --help`, rendered from the
//! manifest, these doc comments, `WAYS` and `AFTER`.
//!
//! Every command finds its vault from where you stand or from the path it is
//! given, and shells out to the real `gocryptfs`, `udisksctl` or `age`, so
//! every vault stays usable without ck.

/// Prints one of ck's own result lines through `out::say`, so the terminal UI
/// can show it in its status line instead.
macro_rules! say {
    ($($line:tt)*) => {
        $crate::out::say(format!($($line)*))
    };
}

mod age;
mod check;
mod commands;
mod completions;
mod gocryptfs;
mod listing;
mod luks;
mod mounts;
mod out;
mod registry;
mod run;
mod scan;
mod selfcmd;
mod settings;
mod tui;
mod vault;

use anyhow::{Result, bail};
use clap::{CommandFactory, Parser, Subcommand};
use std::fs;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

/// clap's own layout with `{before-help}` moved under `Usage:`, so the shapes
/// land on top of the command list rather than on top of the screen.
const TEMPLATE: &str =
    "{about-with-newline}\n{usage-heading} {usage}\n\n{before-help}{all-args}{after-help}\n";

const WAYS: &str = "\x1b[1mWays to run it (not subcommands):\x1b[0m
  ck          on a terminal: every vault and drive to unlock and lock, `?` lists the keys
  ck | cat    piped: the vaults nearest this folder, as `ck ls` rows";

const AFTER: &str = concat!(
    "\
Kinds of vault, which `unlock` tells apart by what its path is:
  gocryptfs  a folder holding `gocryptfs.conf`, opening into `<name>` beside a `.<name>` one, else where `unlock --at` says
  luks       a LUKS drive or image file, mounted through udisks; ck locks only what it unlocked
  age        a `<name>.age` file, opening to `<name>`, a link to a copy in `$XDG_RUNTIME_DIR`

States, as `ck` and `ck ls` print them: open (unlocked), locked, dead (its open
side stopped answering, as when gocryptfs dies or a logout clears an age copy;
`ck unlock` clears it), exposed (an age file's plaintext left on disk: `ck lock`
encrypts it), missing (its encrypted side is gone, e.g. an unplugged drive).

Output is for people; `ck ls --json` and `ck check --json` print data whose field
names, kinds and state words are fixed. `ck check` says, per kind, ready, missing
(a tool to install), blocked (polkit or `$XDG_RUNTIME_DIR` stands in the way) or
unchecked (polkit could not be asked), and exits 1 unless all are ready. Errors go
to stderr as `ck: …`; exit 0 on success, 1 on failure, 2 on a usage error.
gocryptfs, udisksctl and age ask for passwords themselves, gocryptfs reading one
line from stdin when it is piped; `unlock` has no `--all`, since each asks its own.
Run `ck <command> --help` for a command's details.",
    "\n\n",
    env!("CARGO_PKG_REPOSITORY"),
    "\ncontributors: ",
    env!("CARGO_PKG_AUTHORS"),
);

/// `-V` stays a bare version string for scripts; `--version` adds the license,
/// the repository and who contributed, all from Cargo.toml.
const LONG_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    "\n",
    env!("CARGO_PKG_LICENSE"),
    "  ",
    env!("CARGO_PKG_REPOSITORY"),
    "\ncontributors: ",
    env!("CARGO_PKG_AUTHORS"),
);

#[derive(Parser)]
#[command(
    name = "cryptkeeper",
    bin_name = "ck",
    version,
    long_version = LONG_VERSION,
    about,
    help_template = TEMPLATE,
    before_help = WAYS,
    after_help = AFTER
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Open the vault you are in or beside, or the one named, asking its password  [PATH]
    ///   -t MINUTES   gocryptfs only: lock again after this long unused
    ///   -i FILE      age only: decrypt with this identity, not a passphrase
    ///   -n           say what would happen; a LUKS vault never mounted is named by its drive
    #[command(verbatim_doc_comment)]
    Unlock {
        /// A vault as `ck ls` prints it, a path in or above one, a drive (`/dev/sdb1`, `UUID=<uuid>`) or a LUKS image (default: the current folder)
        #[arg(add = completions::vaults_or_paths())]
        path: Option<PathBuf>,
        /// gocryptfs only: lock again after this many minutes with nothing using it
        #[arg(short, long, value_name = "MINUTES", value_parser = clap::value_parser!(u32).range(1..))]
        time: Option<u32>,
        /// gocryptfs only: open it into this empty folder, which ck then remembers (default: where it opened last, or `<name>` beside a `.<name>` folder)
        #[arg(long, value_name = "DIR", add = completions::dirs())]
        at: Option<PathBuf>,
        /// age only: decrypt with this identity file, and lock to its key alone (default: a passphrase, or the identity it last opened with; `lock` asks a passphrase twice, then once more to prove the new file opens with it)
        #[arg(short, long, value_name = "FILE", add = completions::files())]
        identity: Option<PathBuf>,
        /// Say what would happen, change nothing; the first unlock of a LUKS vault names its drive where the real run names the folder udisks mounts it on
        #[arg(short = 'n', long)]
        dry_run: bool,
    },
    /// Close the vault you are in or beside, or the only open one  [PATH]
    ///   -a   close every open vault
    ///   -n   say what would happen, change nothing
    #[command(verbatim_doc_comment)]
    Lock {
        /// A vault as `ck ls` prints it, a path in or above one, or a drive (default: the current folder)
        #[arg(add = completions::vaults_or_paths())]
        path: Option<PathBuf>,
        /// Close every open vault
        #[arg(short, long, conflicts_with = "path")]
        all: bool,
        /// Say what would happen, change nothing
        #[arg(short = 'n', long)]
        dry_run: bool,
    },
    /// Edit an age file in `$VISUAL` or `$EDITOR`, which must wait (`code --wait`), then lock it if it was locked  [PATH]
    ///   -i FILE   decrypt with this identity, not a passphrase
    ///   -n        say what would happen, change nothing
    #[command(verbatim_doc_comment)]
    Edit {
        /// An age vault as `ck ls` prints it, or its file; the editor must not return until the file is closed (`code --wait`, not `code`), or ck locks it while you still edit (default: the age file in or beside this folder)
        #[arg(add = completions::vaults_or_paths())]
        path: Option<PathBuf>,
        /// Decrypt with this identity file (default: a passphrase, or the identity it last opened with)
        #[arg(short, long, value_name = "FILE", add = completions::files())]
        identity: Option<PathBuf>,
        /// Say what would happen, change nothing
        #[arg(short = 'n', long)]
        dry_run: bool,
    },
    /// Open a shell in a vault with `CK_VAULT` set, then lock it if it was locked  [PATH]
    ///   -i FILE   age only: decrypt with this identity, not a passphrase
    ///   -n        say what would happen, change nothing
    #[command(verbatim_doc_comment)]
    Shell {
        /// A vault as `ck ls` prints it, a path in or above one, or a drive (default: the current folder); the shell is `$SHELL`, else `/bin/sh`, and starts in the view (the folder holding an age file's view)
        #[arg(add = completions::vaults_or_paths())]
        path: Option<PathBuf>,
        /// age only: decrypt with this identity file (default: a passphrase, or the identity it last opened with)
        #[arg(short, long, value_name = "FILE", add = completions::files())]
        identity: Option<PathBuf>,
        /// Say what would happen, change nothing
        #[arg(short = 'n', long)]
        dry_run: bool,
    },
    /// Make a vault: a new name makes a gocryptfs one, an existing file an age one (deleted, not wiped)  [NAME]
    ///   --luks PATH   a LUKS image (`--size 1G`) or drive (`--wipe`) instead, through sudo
    ///   -i FILE       age only: encrypt to this identity's key, not a passphrase
    ///   -n            say what would happen, change nothing
    #[command(verbatim_doc_comment)]
    Init {
        /// A folder name for a new gocryptfs vault (default: asked at a terminal, else the `name` setting, `vault` unless set), or an existing file to encrypt into `<file>.age`; the file is then deleted, but its blocks on disk are not wiped
        #[arg(add = completions::paths())]
        name: Option<String>,
        /// Where to make it (default: the current folder)
        #[arg(long, value_name = "PATH", add = completions::dirs())]
        dir: Option<PathBuf>,
        /// age only: encrypt to this identity file's key (default: a passphrase, asked twice, then once more to prove the new file opens with it before the file is deleted)
        #[arg(short, long, value_name = "FILE", add = completions::files())]
        identity: Option<PathBuf>,
        /// Make a LUKS vault instead, with an ext4 inside owned by you: a new image file at this path, or the drive it names (`/dev/sdb1`); cryptsetup asks the passphrase twice and once more, and sudo for your password, since only root may open it to make the filesystem
        #[arg(long, value_name = "PATH", conflicts_with_all = ["name", "dir", "identity"], add = completions::paths())]
        luks: Option<PathBuf>,
        /// With `--luks` on a new image: its size, like `500M` or `4G`
        #[arg(long, value_name = "SIZE", requires = "luks")]
        size: Option<String>,
        /// With `--luks` on a drive: format it, destroying everything on it; a drive that is mounted, in use or split into partitions is refused anyway, and cryptsetup still asks for an uppercase YES
        #[arg(long, requires = "luks")]
        wipe: bool,
        /// Say what would happen, change nothing
        #[arg(short = 'n', long)]
        dry_run: bool,
    },
    /// Put a vault in the list as it is, opening nothing: one found, or a drive ck never touches  <PATH>
    ///   -n   say what would happen, change nothing
    #[command(verbatim_doc_comment)]
    Add {
        /// A gocryptfs folder, a LUKS drive or image, or an age file; a drive ck never touches (the system disk) is listed but still never locked, changed or deleted
        #[arg(add = completions::paths())]
        path: PathBuf,
        /// Say what would happen, change nothing
        #[arg(short = 'n', long)]
        dry_run: bool,
    },
    /// Change a vault's password, through gocryptfs, cryptsetup or age  [PATH]
    ///   -n   say what would happen, change nothing
    #[command(verbatim_doc_comment)]
    Passwd {
        /// A vault as `ck ls` prints it, or a path in or above one (default: the current folder); an age file is opened with the old passphrase and locked with the new one, and one locked to an identity has none to change
        #[arg(add = completions::vaults_or_paths())]
        path: Option<PathBuf>,
        /// Say what would happen, change nothing
        #[arg(short = 'n', long)]
        dry_run: bool,
    },
    /// Save a copy of what a vault cannot open without: gocryptfs's conf, a LUKS header  [PATH]
    ///   --to FILE   save it there (default: a new file in `~/.local/share/cryptkeeper/backups`)
    ///   -n          say what would happen, change nothing
    #[command(verbatim_doc_comment)]
    Backup {
        /// A gocryptfs or LUKS vault as `ck ls` prints it, or a path in or above one (default: the current folder); an age file has no header apart from itself, so copy the `.age` file instead
        #[arg(add = completions::vaults_or_paths())]
        path: Option<PathBuf>,
        /// Where to save it; a file that exists is never overwritten (default: `$XDG_DATA_HOME/cryptkeeper/backups/<name>.gocryptfs.conf` or `.luks-header`)
        #[arg(long, value_name = "FILE", add = completions::paths())]
        to: Option<PathBuf>,
        /// Say what would happen, change nothing
        #[arg(short = 'n', long)]
        dry_run: bool,
    },
    /// Delete a locked vault for good: its encrypted folder, `.age` file or LUKS image  <PATH>
    ///   --yes   go ahead; without it ck says what it would delete and stops
    ///   -n      say what would happen, change nothing
    #[command(verbatim_doc_comment)]
    Delete {
        /// A vault as `ck ls` prints it, or its encrypted side; an open vault and a drive are refused (`ck forget` only drops one from the list)
        #[arg(add = completions::vaults_or_paths())]
        path: PathBuf,
        /// Delete it; there is no undo
        #[arg(long)]
        yes: bool,
        /// Say what would happen, change nothing
        #[arg(short = 'n', long)]
        dry_run: bool,
    },
    /// List every vault ck has made or opened, then the vaults and LUKS drives found that it has not
    ///   --json   print it as data, with the fields `ck ls --help` lists
    #[command(verbatim_doc_comment)]
    Ls {
        /// Print a JSON array instead, one object a vault or drive, with the fixed fields kind, state, name, cipher, view, where, timeout, identity, listed (false for a vault or drive found but not in the list) and note; kind and state take only the words on `ck --help`
        #[arg(long)]
        json: bool,
    },
    /// Say whether this machine can open each kind of vault, and what to install if not
    ///   --json   print it as data, with the fields kind, state, detail and fix
    #[command(verbatim_doc_comment)]
    Check {
        /// Print a JSON array instead, one object a kind, with the fixed fields kind, state, detail and fix (null when nothing needs doing)
        #[arg(long)]
        json: bool,
    },
    /// Drop vaults from `ck ls`, asking which when none are named  [VAULT]...
    ///   -n   say what would happen, change nothing
    #[command(verbatim_doc_comment)]
    Forget {
        /// A vault as `ck ls` prints it; the vault itself stays put
        #[arg(add = completions::vaults())]
        vault: Vec<String>,
        /// Say what would happen, change nothing
        #[arg(short = 'n', long)]
        dry_run: bool,
    },
    /// Drop every missing vault from `ck ls`
    ///   -n   say what would happen, change nothing
    #[command(verbatim_doc_comment)]
    Clear {
        /// Say what would happen, change nothing
        #[arg(short = 'n', long)]
        dry_run: bool,
    },
    /// Print the Tab completion script for a shell, so `source <(ck completions bash)` loads it  <SHELL>
    ///   --add   add that line to the shell's startup file, unless one there already loads it
    ///   -n      say what would happen, change nothing
    #[command(verbatim_doc_comment)]
    Completions {
        /// The shell to complete in
        shell: completions::Shell,
        /// Append the line loading the script to `~/.bashrc`, `~/.zshrc` or fish's `config.fish`, never rewriting the file
        #[arg(long)]
        add: bool,
        /// Say what would happen, change nothing
        #[arg(short = 'n', long)]
        dry_run: bool,
    },
    /// Manage cryptkeeper itself: `self update` reinstalls, `self check` looks for a newer release
    #[command(name = "self", subcommand)]
    Selfie(selfcmd::Cmd),
}

fn main() {
    // A Tab press runs `COMPLETE=<shell> ck -- …`; this answers it and exits.
    clap_complete::CompleteEnv::with_factory(Cli::command).complete();
    let cli = Cli::parse();
    let done = match cli.command {
        // Only a person at a terminal gets the UI; a pipe or a script gets the rows.
        None if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() => tui::run(),
        None => commands::status(),
        Some(Cmd::Unlock {
            path,
            time,
            at,
            identity,
            dry_run,
        }) => commands::unlock(path, time, identity, at, dry_run),
        Some(Cmd::Lock { path, all, dry_run }) => commands::lock(path, all, dry_run),
        Some(Cmd::Edit {
            path,
            identity,
            dry_run,
        }) => commands::edit(path, identity, dry_run),
        Some(Cmd::Shell {
            path,
            identity,
            dry_run,
        }) => commands::shell(path, identity, dry_run),
        Some(Cmd::Init {
            luks: Some(path),
            size,
            wipe,
            dry_run,
            ..
        }) => commands::init_luks(path, size, wipe, dry_run),
        Some(Cmd::Init {
            name,
            dir,
            identity,
            dry_run,
            ..
        }) => commands::init(name, dir, identity, dry_run),
        Some(Cmd::Passwd { path, dry_run }) => commands::passwd(path, dry_run),
        Some(Cmd::Add { path, dry_run }) => commands::add(path, dry_run),
        Some(Cmd::Delete { path, yes, dry_run }) => commands::delete(path, yes, dry_run),
        Some(Cmd::Backup { path, to, dry_run }) => commands::backup(path, to, dry_run),
        Some(Cmd::Ls { json }) => commands::ls(json),
        Some(Cmd::Check { json }) => check::run(json),
        Some(Cmd::Forget { vault, dry_run }) => commands::forget(vault, dry_run),
        Some(Cmd::Clear { dry_run }) => commands::clear(dry_run),
        Some(Cmd::Completions {
            shell,
            add,
            dry_run,
        }) => completions::run(shell, add, dry_run),
        Some(Cmd::Selfie(cmd)) => selfcmd::run(cmd),
    };
    if let Err(e) = done {
        eprintln!("ck: {e}");
        std::process::exit(1);
    }
}

fn xdg_config() -> PathBuf {
    dirs::config_dir().unwrap_or_else(|| dirs::home_dir().unwrap_or_default().join(".config"))
}

pub fn config_dir() -> PathBuf {
    xdg_config().join("cryptkeeper")
}

/// Where this tool kept its files under its old name, read only while the
/// new place has nothing.
pub fn legacy_config_dir() -> PathBuf {
    xdg_config().join("egc")
}

/// `$XDG_STATE_HOME/cryptkeeper` (usually `~/.local/state/cryptkeeper`).
pub fn state_dir() -> PathBuf {
    dirs::state_dir()
        .unwrap_or_else(|| dirs::home_dir().unwrap_or_default().join(".local/state"))
        .join("cryptkeeper")
}

/// `path` with the home folder written as `~`, for display only.
pub fn tilde(path: &Path) -> String {
    if let Some(home) = dirs::home_dir()
        && let Ok(rest) = path.strip_prefix(&home)
    {
        if rest.as_os_str().is_empty() {
            return "~".into();
        }
        return Path::new("~").join(rest).display().to_string();
    }
    path.display().to_string()
}

/// Replaces `file` with `body` through a temp file and a rename, so an
/// interrupted save never leaves half a file; `what` names it in the error.
pub fn write_atomic(file: &Path, body: &[u8], what: &str) -> Result<()> {
    let dir = file.parent().unwrap_or(Path::new("."));
    if fs::create_dir_all(dir).is_err() {
        bail!("could not create `{}` to save {what}", tilde(dir));
    }
    let tmp = file.with_extension("tmp");
    if fs::write(&tmp, body).is_err() || fs::rename(&tmp, file).is_err() {
        let _ = fs::remove_file(&tmp);
        bail!("could not write `{}` to save {what}", tilde(file));
    }
    Ok(())
}
