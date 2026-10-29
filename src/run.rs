//! Running the programs ck drives: in the foreground where they ask for a
//! password, captured where only their verdict matters.

use nix::sys::signal::{SigSet, SigmaskHow, Signal, pthread_sigmask};
use nix::sys::termios::{SetArg, Termios, tcgetattr, tcsetattr};
use nix::unistd::{getpgrp, tcgetpgrp, tcsetpgrp};
use signal_hook::consts::{SIGINT, SIGQUIT};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Once};
use std::time::{Duration, Instant};

/// Set by Ctrl-C or Ctrl-\, cleared before each child starts.
static INTERRUPTED: LazyLock<Arc<AtomicBool>> = LazyLock::new(|| Arc::new(AtomicBool::new(false)));

/// Makes Ctrl-C and Ctrl-\ set a flag instead of ending ck, so a child at a
/// prompt can be cancelled and ck still cleans up after it. The signals are
/// caught, never ignored: a child inherits an ignored signal and could then
/// not be cancelled at all.
pub fn catch_interrupts() {
    static CAUGHT: Once = Once::new();
    CAUGHT.call_once(|| {
        for signal in [SIGINT, SIGQUIT] {
            let _ = signal_hook::flag::register(signal, Arc::clone(&INTERRUPTED));
        }
    });
}

/// Whether Ctrl-C was pressed since the last child started.
pub fn interrupted() -> bool {
    INTERRUPTED.load(Ordering::SeqCst)
}

#[derive(PartialEq)]
pub enum Ran {
    Done,
    Cancelled,
    /// With its exit code, `None` when it could not start or a signal ended it.
    Failed(Option<i32>),
}

/// Runs `cmd` with the terminal handed to it, so it can ask for a password.
/// Ctrl-C at that prompt reaches the whole process group, so ck catches it
/// instead of dying with the child, and the caller gets `Cancelled` to clean
/// up after. While the terminal UI runs it, its stderr is relayed and kept
/// (`out::hear`), so what it said outlives the screen it was said on.
pub fn prompting(cmd: &mut Command) -> Ran {
    if crate::out::capturing() {
        return relayed(cmd).0;
    }
    foreground(cmd)
}

/// `prompting` with nothing ever put between the child and the terminal, for
/// a program that needs a terminal on its stderr (a shell is interactive only
/// with one) or keeps that stderr after it returns (a mounted gocryptfs, which
/// a pipe nobody reads any more would block or kill).
pub fn foreground(cmd: &mut Command) -> Ran {
    let _held = take_terminal();
    verdict(cmd.status())
}

/// `prompting`, with the child's stderr relayed every time, and whether
/// `word` (lowercase) appeared in it.
pub fn prompting_saying(cmd: &mut Command, word: &str) -> (Ran, bool) {
    let (ran, heard) = relayed(cmd);
    (ran, heard.to_lowercase().contains(word))
}

/// The terminal as ck had it before a child took it, put back when dropped:
/// a password prompt killed by Ctrl-C leaves echo off, and an interactive
/// shell killed outright leaves its own process group owning the terminal,
/// which stops ck the moment it touches it.
pub struct Held {
    /// The controlling terminal, while ck's group was its foreground one.
    tty: Option<File>,
    settings: Option<Termios>,
}

/// Readies the terminal for a child that may ask on it, until the returned
/// `Held` is dropped: the terminal UI steps aside, Ctrl-C is caught and its
/// flag cleared, and the terminal's settings are kept to put back.
pub fn take_terminal() -> Held {
    crate::out::hand_over();
    catch_interrupts();
    INTERRUPTED.store(false, Ordering::SeqCst);
    // Left alone when ck runs in the background, so it never takes the
    // terminal from the shell that started it.
    let tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .ok()
        .filter(|t| tcgetpgrp(t).is_ok_and(|g| g == getpgrp()));
    let settings = tty.as_ref().and_then(|t| tcgetattr(t).ok());
    Held { tty, settings }
}

impl Drop for Held {
    fn drop(&mut self) {
        let Some(tty) = &self.tty else { return };
        // Taking the terminal back from a background group raises SIGTTOU,
        // which stops ck unless it is blocked meanwhile.
        let mut ttou = SigSet::empty();
        ttou.add(Signal::SIGTTOU);
        let mut was = SigSet::empty();
        let blocked = pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&ttou), Some(&mut was)).is_ok();
        let _ = tcsetpgrp(tty, getpgrp());
        if let Some(s) = &self.settings {
            let _ = tcsetattr(tty, SetArg::TCSANOW, s);
        }
        if blocked {
            let _ = pthread_sigmask(SigmaskHow::SIG_SETMASK, Some(&was), None);
        }
    }
}

/// Runs `cmd` with its stderr relayed to ck's as it arrives, so its prompts
/// still show, and returns what it wrote there.
fn relayed(cmd: &mut Command) -> (Ran, String) {
    let _held = take_terminal();
    let Ok(mut child) = cmd.stderr(Stdio::piped()).spawn() else {
        return (Ran::Failed(None), String::new());
    };
    let pipe = child.stderr.take();
    let relay = std::thread::spawn(move || {
        let mut heard = Vec::new();
        let Some(mut pipe) = pipe else {
            return heard;
        };
        let mut buf = [0u8; 1024];
        while let Ok(n) = pipe.read(&mut buf) {
            if n == 0 {
                break;
            }
            let mut err = std::io::stderr();
            let _ = err.write_all(&buf[..n]).and_then(|()| err.flush());
            heard.extend_from_slice(&buf[..n]);
        }
        heard
    });
    let status = child.wait();
    let heard = String::from_utf8_lossy(&relay.join().unwrap_or_default()).into_owned();
    crate::out::hear(&heard);
    (verdict(status), heard)
}

fn verdict(status: std::io::Result<ExitStatus>) -> Ran {
    match status {
        Ok(st) if st.success() => Ran::Done,
        _ if interrupted() => {
            // The child died mid-prompt, leaving the cursor after `Password:`.
            eprintln!();
            Ran::Cancelled
        }
        Ok(st) => Ran::Failed(st.code()),
        Err(_) => Ran::Failed(None),
    }
}

/// `out`'s own words for why it failed: its first five non-empty stderr
/// lines, each on a line of its own after the caller's.
pub fn said(out: &Output) -> String {
    let text = String::from_utf8_lossy(&out.stderr);
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .take(5)
        .map(|l| format!("\n{l}"))
        .collect()
}

/// What a program run by `bounded` left behind.
pub struct Bounded {
    /// `None` when a signal ended it.
    pub code: Option<i32>,
    pub stdout: String,
    /// Its stderr as `said` renders it.
    pub said: String,
}

/// Runs `cmd` with no terminal and both outputs read as it writes them, killed
/// after `limit` so a daemon that never answers cannot hang ck; `None` when it
/// could not start or ran out of time.
pub fn bounded(cmd: &mut Command, limit: Duration) -> Option<Bounded> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let reader = |pipe: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut text = Vec::new();
            if let Some(mut pipe) = pipe {
                let _ = pipe.read_to_end(&mut text);
            }
            text
        })
    };
    let out = reader(
        child
            .stdout
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );
    let err = reader(
        child
            .stderr
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if started.elapsed() < limit => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let stdout = out.join().unwrap_or_default();
    let stderr = err.join().unwrap_or_default();
    let status = status?;
    Some(Bounded {
        code: status.code(),
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        said: said(&Output {
            status,
            stdout: Vec::new(),
            stderr,
        }),
    })
}

pub fn on_path(bin: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|p| std::env::split_paths(&p).any(|d| Path::new(&d).join(bin).is_file()))
}
