//! `ck self`: manage the installed binary itself.
//!
//! `self update` shells out to `cargo install cryptkeeper --force`, the crate
//! name rather than the command you type. `self check` asks the registry through
//! `cargo search`, so there is no HTTP client in the dependency tree and the
//! answer comes from the same registry `cargo install` would pull from.

use anyhow::{Result, bail};
use std::io::{self, Write};
use std::process::Command;

const CRATE: &str = env!("CARGO_PKG_NAME");

#[derive(clap::Subcommand)]
pub enum Cmd {
    /// Reinstall the latest release from crates.io
    ///   -y   skip the confirmation prompt
    ///   -n   say what would happen, change nothing
    #[command(verbatim_doc_comment)]
    Update {
        /// Skip the confirmation prompt
        #[arg(short, long)]
        yes: bool,
        /// Say what would happen, change nothing
        #[arg(short = 'n', long)]
        dry_run: bool,
    },
    /// Ask crates.io whether a newer release exists, without installing anything
    ///   exits 0 when this is the newest, 1 when one is out, 2 when it could not ask
    #[command(verbatim_doc_comment)]
    Check,
}

pub fn run(cmd: Cmd) -> Result<()> {
    match cmd {
        Cmd::Update { yes, dry_run } => update(yes, dry_run),
        Cmd::Check => check(),
    }
}

fn update(yes: bool, dry: bool) -> Result<()> {
    if !yes && !dry && !confirm() {
        println!("nothing updated");
        return Ok(());
    }
    println!("updating with `cargo install {CRATE} --force`\n");
    if dry {
        return Ok(());
    }
    match Command::new("cargo")
        .args(["install", CRATE, "--force"])
        .status()
    {
        Ok(st) if st.success() => {
            println!("\n{CRATE} is up to date");
            Ok(())
        }
        Ok(_) => bail!("`cargo install {CRATE}` failed: its own lines above say why"),
        Err(_) => bail!("`cargo` is not on your PATH: install Rust from https://rustup.rs"),
    }
}

/// Compares the installed version with the newest on crates.io, exiting 1
/// when a newer one is out and 2 when crates.io could not be asked, so a
/// script gates on the code. Nothing is downloaded or written.
fn check() -> Result<()> {
    let current = env!("CARGO_PKG_VERSION");
    let latest = match latest() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("ck: {e}");
            std::process::exit(2);
        }
    };
    if newer(&latest, current) {
        println!("{CRATE} {latest} is out, you have {current}: run `ck self update`");
        std::process::exit(1);
    } else {
        println!("{CRATE} {current} is the latest release");
    }
    Ok(())
}

/// `cargo search` prints `cryptkeeper = "X.Y.Z"    # description` for an
/// exact name match.
fn latest() -> Result<String> {
    let Ok(out) = Command::new("cargo")
        .args(["search", CRATE, "--limit", "1"])
        .output()
    else {
        bail!("`cargo` is not on your PATH: install Rust from https://rustup.rs");
    };
    if !out.status.success() {
        let said = String::from_utf8_lossy(&out.stderr);
        let said: Vec<&str> = said
            .lines()
            .filter(|l| !l.trim().is_empty())
            .take(5)
            .collect();
        bail!("could not reach crates.io:\n{}", said.join("\n"));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let prefix = format!("{CRATE} = \"");
    match text
        .lines()
        .find_map(|l| l.strip_prefix(&prefix))
        .and_then(|rest| rest.split('"').next())
    {
        Some(v) => Ok(v.to_string()),
        None => bail!("crates.io does not list `{CRATE}` yet"),
    }
}

/// Field by field, so `0.10.0` beats `0.9.9` where a string compare would not.
fn newer(a: &str, b: &str) -> bool {
    let fields = |v: &str| {
        v.split(['.', '-'])
            .map(|p| p.parse::<u64>().unwrap_or(0))
            .collect::<Vec<_>>()
    };
    fields(a) > fields(b)
}

/// Defaults to no, so a bare Enter cancels.
fn confirm() -> bool {
    eprint!("update {CRATE} to the latest release with cargo? [y/N] ");
    io::stderr().flush().ok();
    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        return false;
    }
    matches!(input.trim().to_lowercase().as_str(), "y" | "yes")
}
