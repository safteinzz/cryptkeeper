//! Where ck's own result lines go: stdout, or while the terminal UI runs an
//! action, a buffer it shows in its status line, kept with what the programs
//! it ran said and whether one of them was handed the terminal.

use std::sync::{Mutex, MutexGuard};

/// What an action run under `capture` left for the terminal UI.
#[derive(Default)]
pub struct Captured {
    /// ck's own result lines, from `say`.
    pub lines: Vec<String>,
    /// The stderr of every program ck relayed, as it was written.
    pub heard: String,
    /// Whether a program was handed the terminal, which the UI then takes back.
    pub left: bool,
}

struct Capture {
    got: Captured,
    /// Steps the UI aside; called once, before the first program that needs
    /// the terminal.
    leave: fn(),
}

static CAPTURED: Mutex<Option<Capture>> = Mutex::new(None);

fn held() -> MutexGuard<'static, Option<Capture>> {
    CAPTURED.lock().unwrap_or_else(|e| e.into_inner())
}

/// Prints `line`, or keeps it for the terminal UI while it captures.
pub fn say(line: String) {
    match held().as_mut() {
        Some(c) => c.got.lines.push(line),
        None => {
            use std::io::Write;
            let _ = writeln!(std::io::stdout(), "{line}");
        }
    }
}

/// Whether the terminal UI is running an action.
pub fn capturing() -> bool {
    held().is_some()
}

/// Called before a program that may ask on the terminal starts: while the
/// terminal UI runs an action, its screen steps aside first so the prompt
/// reaches a plain terminal; elsewhere it does nothing.
pub fn hand_over() {
    if let Some(c) = held().as_mut()
        && !c.got.left
    {
        (c.leave)();
        c.got.left = true;
    }
}

/// Keeps `text`, which a program wrote on stderr, for the terminal UI.
pub fn hear(text: &str) {
    if let Some(c) = held().as_mut() {
        c.got.heard.push_str(text);
    }
}

/// Runs `f` with every `say` kept rather than printed, calling `leave` before
/// the first program that needs the terminal, and returns what it kept.
pub fn capture<T>(leave: fn(), f: impl FnOnce() -> T) -> (T, Captured) {
    *held() = Some(Capture {
        got: Captured::default(),
        leave,
    });
    let done = f();
    let got = held().take().map(|c| c.got).unwrap_or_default();
    (done, got)
}
