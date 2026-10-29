# cryptkeeper (`ck`)

> **Canonical:** [gitlab.com/safteinzz/cryptkeeper](https://gitlab.com/safteinzz/cryptkeeper) · **Mirror:** [github.com/safteinzz/cryptkeeper](https://github.com/safteinzz/cryptkeeper)

<!-- desc:start -->
encryption without the fuss - lock and unlock gocryptfs folders, LUKS drives and age files in one place
<!-- desc:end -->

## Install

```bash
cargo install cryptkeeper
ck self check   # is a newer release out?
ck self update  # install the latest
```

No cargo yet? Rust installs the same way on every distro: [rustup.rs](https://rustup.rs).

## It is still gocryptfs, LUKS and age

Every vault stays what it was, so its own tool opens it without ck:

```bash
gocryptfs .photos photos                 # a gocryptfs folder
udisksctl unlock -b /dev/sdb1            # a LUKS drive
age -d -o taxes.pdf taxes.pdf.age        # an age file
```

ck only works out which one you mean, and what it takes to open it.

## See every vault at once

![The vault list locking and unlocking a folder vault, then opening an encrypted file](https://gitlab.com/safteinzz/cryptkeeper/-/raw/main/readme-assets/vaults.gif)

```bash
ck                   # on a terminal: every vault and drive, and what opens here
```

Enter unlocks or locks, `s` opens a shell in a vault, and `a` adds one found
on this machine to the list without opening it. A drive ck did not open, like
the disk the system runs from, is shown but never locked.

## Open the vault you are standing in

```bash
ck unlock            # asks for the password, opens it
ck | cat             # which vault is here, and is it open?
ck lock              # closes it again
```

They walk up from the current folder to the nearest vault, so they work from
inside it or beside it, and a path picks one instead.

## Unlock a drive or a disk image

```bash
ck unlock /dev/sdb1          # asks for the passphrase, then mounts it
ck unlock ~/backup.img       # a LUKS image file
ck lock /media/you/backup    # unmounts it and closes it again
```

ck locks only what its own `unlock` opened, and never touches a drive that
holds `/` or swap.

## Keep one file encrypted

```bash
ck init taxes.pdf          # makes taxes.pdf.age, then deletes taxes.pdf
ck unlock taxes.pdf.age    # asks the passphrase, taxes.pdf appears beside it
ck lock taxes.pdf          # encrypts it again
ck edit taxes.pdf          # unlock, $EDITOR, lock, in one go
```

The plaintext is kept in memory, never on disk, and a lock that fails at any
step leaves both the old file and your edits as they were.

## Work inside a vault

```bash
ck shell ~/photos    # unlocks it, opens a shell there, locks it when you exit
```

It locks the vault afterwards only if it was locked before.

## Lock it when you walk away

```bash
ck unlock -t 100     # locks itself after 100 minutes with nothing using it
```

A file still open in the vault keeps it unlocked, so it never pulls a folder
out from under you.

## Make a vault

![The create picker, a new encrypted folder typed in with the command it runs, gocryptfs asking for its password, then the new vault listed](https://gitlab.com/safteinzz/cryptkeeper/-/raw/main/readme-assets/create.gif)

```bash
ck init photos                         # an encrypted folder: .photos opens into photos
ck init --luks ~/vault.img --size 4G   # a LUKS disk image
ck init --luks /dev/sdb1 --wipe        # a whole drive, wiping it
```

gocryptfs prints the folder's master key once: write it down, since it is the
only way back in if you forget the password.

## Change a password, keep a spare header

```bash
ck passwd ~/photos   # through gocryptfs, cryptsetup or age
ck backup ~/photos   # gocryptfs.conf or the LUKS header, saved apart
```

A vault whose header gets damaged opens only with that spare, so copy it off
the machine.

## Keep track of every vault

```bash
ck ls                     # every vault, its kind and state
ck add ~/old/vault        # list one as it is, opening nothing
ck forget ~/drive/photos  # drop one from the list, the vault stays
ck delete ~/old --yes     # delete a locked vault for good
```

A vault on an unplugged drive shows as `missing` rather than disappearing.

## Can this machine open it?

```bash
ck check             # gocryptfs, LUKS and age: ready, or what to install
```

![ck check saying gocryptfs and age are ready and LUKS is missing, with the command that installs it](https://gitlab.com/safteinzz/cryptkeeper/-/raw/main/readme-assets/check.png)

## Commands

```bash
ck lock --all                    # close every open vault
ck clear                         # drop every missing vault from the list
ck init --dir ~/drive            # make the vault somewhere else
ck unlock ~/enc --at ~/plain     # a gocryptfs folder opening somewhere else
ck unlock UUID=<uuid>            # a drive by its LUKS UUID
ck ls --json                     # every vault and drive as data
```

Every command that changes something takes `-n` to print what it would do
instead, `ck <command> --help` has the details, and `?` in `ck` lists every key.

For a script: name the vault, since `forget` and `init` ask for one otherwise,
and only the passwords prompt. `--json` prints data, and a failure exits 1.

## Tab completion

```bash
ck completions bash --add    # adds `source <(ck completions bash)` to ~/.bashrc
```

zsh and fish work the same way.

## Where it keeps things

```
~/.config/cryptkeeper/vaults         the list ck ls shows
~/.config/cryptkeeper/settings       the Settings tab: Drives through, New vault name
~/.local/state/cryptkeeper/opened    the LUKS drives ck unlocked since boot
~/.local/share/cryptkeeper/backups/  what ck backup saves
$XDG_RUNTIME_DIR/cryptkeeper/age/    the plaintext of every open age file
```

A list left in `~/.config/egc/` by this tool's old name is read until ck
writes its own.

## What it edits

`ck completions <shell> --add` appends one line to the shell's startup file,
only when no line there loads the completions yet.

## When it fails

A vault that will not lock because something uses it lists your processes
holding it, so you know what to close.

## Notes

- Over ssh, polkit asks for a password at every step, so set Drives through
  to sudo in Settings to be asked once.
- An age file opens when it is encrypted to a passphrase or to one key.
  Armored (text) age files are not opened yet.

## Compatibility

Linux, with [gocryptfs](https://github.com/rfjakob/gocryptfs#installation) and
fuse3 for folders, udisks2 or sudo and cryptsetup for LUKS drives, and
[age](https://age-encryption.org) or rage for files. It reads `/proc` and
`/sys` to see what is open, so macOS and BSD need a different implementation
first.

## License

AGPL-3.0-only
