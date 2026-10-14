# AGENTS.md

Working brief for an AI coding agent; people read README.md.

`easygocryptfs` is a Rust CLI, binary `egc`, that wraps `gocryptfs` so a vault is unlocked and locked from wherever you stand. It shells out to the real `gocryptfs` and `fusermount3` and never touches the ciphertext itself, so every vault stays a plain gocryptfs folder usable without egc.

## Invariants and gotchas
- The binary is bare-first: bare `egc` is the status view, and `--help` carries it as the one line under Ways to run it. The vocabulary `open`, `locked`, `dead`, `missing` is defined in `AFTER`; a new state word goes there in the same change.
- Every command that changes something takes `-n`, and a dry run prints exactly the lines the real run would: each command checks everything first, skips only the action and its registry write under `dry`, then prints. A new command keeps that shape.
- `unlock` has no `--all` on purpose, since every vault asks for its own password; `--help` says so. `lock --all` carries on past a vault that refuses and exits 1 at the end if any did.
- `forget` drops any vault from the list, missing or not: named as `ls` prints them (a leading `~/` is expanded, and the cipher path matches too), or with none named, picked by number at a prompt (numbers on stdin, empty cancels). `clear` drops every `missing` one and takes nothing; the name says it tidies leftovers, so it must never grow a way to drop a present vault.
- A vault is two siblings: a hidden `.<name>` holding `gocryptfs.conf`, and `<name>` as the mountpoint. There is no other layout and no setting for one. `vault::find` walks up from the start folder and at each level takes that folder itself when it is a cipher or a view, else its one dot child holding `gocryptfs.conf`; several is an error that names them, never a guess. A start path that does not exist still resolves when its `.<name>` sibling is a cipher, so a deleted view reopens by name.
- Bare `egc` prints `vault::nearest` as `ls` rows: every vault at the nearest level, so a folder holding several shows them all instead of failing the way `find` does for `unlock` and `lock`.
- `vault::find` only stats dot children, because a walk up through `/media` must not stat another mountpoint that might be a dead FUSE mount and hang.
- `init` runs `gocryptfs -init` without `-q`, because that is what prints the master key, the only recovery after a forgotten password, and gocryptfs shows it once. A failed or cancelled `init` removes only the folders it made itself.
- `lock` with no path falls back to the only open vault only when no vault exists anywhere above the current folder; beside several it fails and names them, like `unlock`. `vault::nearest` returns `None` for that case so the two are told apart.
- `is_mounted` counts only a `fuse.gocryptfs` mount on the view, so another filesystem mounted there never reads as the vault being open.
- Every message names a vault by its view, the folder the user knows; the cipher path appears only in `init`'s already exists error.
- `$XDG_CONFIG_HOME/egc/vaults` (usually `~/.config/egc/vaults`) holds absolute `cipher\tview` per line, so `registry::check_storable` refuses a path with a tab or newline before anything is made. A file that exists but cannot be read is an error, never an empty list, because the next save would wipe it; saves go through a temp file and a rename. A symlinked path is resolved before it is stored (`vault::nearest` resolves the parent of a view that does not exist yet), so one vault never gets two lines. `init` and `unlock` add to it; `lock` never does; `forget` and `clear` are the only things that remove lines, and neither touches a vault's folders. A vault on an unplugged drive stays listed as `missing`.
- Mounted is not open: a gocryptfs that died leaves the mount listed in `/proc/self/mounts` with every read failing, so `unlock` checks `read_dir` and clears a dead mount with `fusermount3 -u -z` before remounting. Lazy unmount is only ever used on a dead mount.
- `unlock` passes `-nosyslog` only when `/dev/log` is missing (WSL without systemd, a container): there gocryptfs's switch to syslog fails, prints five "Unix syslog delivery error" lines and then drops every later warning, a corrupt block included, while with syslog present its messages belong in the journal as before.
- `unlock -t N` (N at least 1, since gocryptfs reads 0 as never) passes `-i Nm` to gocryptfs, which unmounts only after N minutes with no activity and no open files. `ls` reads the timeout back from the gocryptfs process's `/proc/<pid>/cmdline`, so no state file exists to drift.
- egc's own prompts are `forget`'s numbers and `init`'s name, and each has an argument that skips it. `init` asks only when stdin is a terminal, because a piped stdin carries the password for gocryptfs and a name prompt would swallow it.
- Password prompts belong to gocryptfs: its stdin, stdout and stderr are inherited, and its own error lines (wrong password) print above egc's one line. Ctrl-C at that prompt hits egc too, so `run_gocryptfs` catches it with `ctrlc` and reports `Cancelled`, which is what lets `init` remove the two empty folders it made; an empty `.<name>` left by a harder kill is reused by the next `init`.
- `lock` refuses when the current folder is inside the view, since the shell's cwd alone keeps it busy. After `unlock` from inside the view, the shell still sees the empty folder underneath until `cd .`.

## Demo rig
- `demo/stage.sh` builds an empty staged home in `demo/home` (HOME and every XDG variable pointed into it, run under `env -i`); `demo/egc.tape` renders `readme-assets/egc.gif`, the one hero picture under Install. `demo/render.sh` renders it in a container (the image is `demo/Dockerfile`), so a machine needs podman or docker and nothing else: `./render.sh` builds the release binary, then gives each tape a container of its own that stages, records and tears down, with `--device /dev/fuse --cap-add SYS_ADMIN` so gocryptfs can mount, never `--privileged`. The container has no syslog, so the unlock in frame takes the `-nosyslog` path.
- The tape makes and really mounts a vault inside the stage, with the password `demo`; its master key is printed in frame and is throwaway. The tape ends with the vault locked, and `down` still unmounts anything under the stage before its guarded delete.

## Build
- `cargo build --release`, binary at `target/release/egc`.

## Layout
- `src/main.rs`: the clap `Cmd` enum, the help screen's `WAYS` and `AFTER`, dispatch, `config_dir` and `tilde`.
- `src/commands.rs`: one function per command.
- `src/vault.rs`: the on-disk shape and `find`.
- `src/registry.rs`: the vaults list.
- `src/mounts.rs`: `/proc/self/mounts`, `fusermount3`, the idle timeout.
- `src/settings.rs`: `$XDG_CONFIG_HOME/egc/settings`.
- `src/selfcmd.rs`: `self update` and `self check`, through `cargo install` and `cargo search`.
- `tests/readme.rs`: the README description block against `Cargo.toml`.

## Not built yet
- A TUI listing every vault, and unlocking at login with passwords from the Secret Service (KWallet).

## Self-repair
If anything here contradicts the code, the code wins; fix AGENTS.md in the same session you notice the drift.
