//! `ck completions`: the Tab completion script, which calls back into `ck`
//! (`COMPLETE=<shell> ck -- …`) for every completion, and the one line that
//! loads it from a shell's startup file. Vault arguments complete to the
//! names in the list, read from the list alone, plus paths where one is taken.

use crate::{registry, tilde};
use anyhow::{Result, bail};
use clap_complete::engine::{
    ArgValueCompleter, CompletionCandidate, PathCompleter, ValueCompleter,
};
use clap_complete::env::{Bash, EnvCompleter, Fish, Zsh};
use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

#[derive(Clone, Copy, clap::ValueEnum)]
pub enum Shell {
    Bash,
    Zsh,
    Fish,
}

/// Prints the script for `shell`, or with `add` appends the line loading it
/// to the shell's startup file, unless a line there already does.
pub fn run(shell: Shell, add: bool, dry: bool) -> Result<()> {
    if !add {
        return print_script(shell);
    }
    let (file, line) = startup(shell);
    let text = match fs::read_to_string(&file) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(_) => bail!("could not read `{}`, so nothing was added", tilde(&file)),
    };
    let name = shell_name(shell);
    let loads = |l: &str| {
        l.contains(&format!("ck completions {name}")) || l.contains(&format!("COMPLETE={name} ck"))
    };
    if text.lines().any(loads) {
        say!("`{}` already loads them", tilde(&file));
        return Ok(());
    }
    if !dry {
        let mut body = String::new();
        if !text.is_empty() && !text.ends_with('\n') {
            body.push('\n');
        }
        body.push_str(&line);
        body.push('\n');
        let appended = file
            .parent()
            .map_or(Ok(()), fs::create_dir_all)
            .and_then(|()| fs::OpenOptions::new().create(true).append(true).open(&file))
            .and_then(|mut f| f.write_all(body.as_bytes()));
        if appended.is_err() {
            bail!("could not add to `{}`", tilde(&file));
        }
    }
    say!(
        "added `{line}` to `{}`: a new shell completes `ck`",
        tilde(&file)
    );
    Ok(())
}

fn shell_name(shell: Shell) -> &'static str {
    match shell {
        Shell::Bash => "bash",
        Shell::Zsh => "zsh",
        Shell::Fish => "fish",
    }
}

/// The startup file `shell` reads, and the line that loads the script in it.
fn startup(shell: Shell) -> (PathBuf, String) {
    let home = dirs::home_dir().unwrap_or_default();
    match shell {
        Shell::Bash => (home.join(".bashrc"), "source <(ck completions bash)".into()),
        Shell::Zsh => {
            let dir = std::env::var_os("ZDOTDIR").map_or(home, PathBuf::from);
            (dir.join(".zshrc"), "source <(ck completions zsh)".into())
        }
        Shell::Fish => (
            dirs::config_dir()
                .unwrap_or_else(|| home.join(".config"))
                .join("fish/config.fish"),
            "ck completions fish | source".into(),
        ),
    }
}

/// The same script `COMPLETE=<shell> ck` prints, calling back into this
/// binary by the name it was run as, made absolute when it was a path.
fn print_script(shell: Shell) -> Result<()> {
    let argv0 = std::env::args_os().next().unwrap_or_else(|| "ck".into());
    let mut completer = PathBuf::from(argv0);
    if completer.components().count() > 1
        && let Ok(cwd) = std::env::current_dir()
    {
        completer = cwd.join(completer);
    }
    let script: &dyn EnvCompleter = match shell {
        Shell::Bash => &Bash,
        Shell::Zsh => &Zsh,
        Shell::Fish => &Fish,
    };
    let mut out = Vec::new();
    script.write_registration(
        "COMPLETE",
        env!("CARGO_PKG_NAME"),
        "ck",
        &completer.to_string_lossy(),
        &mut out,
    )?;
    std::io::stdout().write_all(&out)?;
    Ok(())
}

/// The names `ls` prints for every listed vault that start with `current`,
/// as `~/…` and as absolute paths, from the list alone.
fn listed(current: &OsStr) -> Vec<CompletionCandidate> {
    let typed = current.to_string_lossy();
    let Ok(known) = registry::load() else {
        return Vec::new();
    };
    let mut names: Vec<(String, &'static str)> = Vec::new();
    for v in &known {
        for name in [tilde(v.name()), v.name().display().to_string()] {
            if name.starts_with(typed.as_ref()) && !names.iter().any(|(n, _)| *n == name) {
                names.push((name, v.kind.word()));
            }
        }
    }
    names
        .into_iter()
        .map(|(n, kind)| CompletionCandidate::new(n).help(Some(kind.into())))
        .collect()
}

/// Completes a vault the list holds.
pub fn vaults() -> ArgValueCompleter {
    ArgValueCompleter::new(listed)
}

/// Completes a vault the list holds, or any path.
pub fn vaults_or_paths() -> ArgValueCompleter {
    ArgValueCompleter::new(|current: &OsStr| {
        let mut found = listed(current);
        found.extend(PathCompleter::any().complete(current));
        found
    })
}

pub fn files() -> ArgValueCompleter {
    ArgValueCompleter::new(PathCompleter::file())
}

pub fn dirs() -> ArgValueCompleter {
    ArgValueCompleter::new(PathCompleter::dir())
}

pub fn paths() -> ArgValueCompleter {
    ArgValueCompleter::new(PathCompleter::any())
}
