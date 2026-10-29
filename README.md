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

Enter unlocks what is locked and locks what is open, `s` opens a shell in a
vault, and `?` lists every other key.

Vaults ck has not opened yet show at the bottom under `found on this machine`:
every gocryptfs folder, age file and LUKS image in your home, every open
gocryptfs, and every LUKS drive. `a` adds one to the list without opening it,
and Tab steps to This machine, which says what it can open.

A password prompt leaves the screen for the plain terminal and comes back
after, saying why when it failed, and a drive ck did not open is shown but
never offered a lock.

## Open the vault you are standing in

```bash
ck unlock            # asks for the password, opens it
ck | cat             # which vault is here, and is it open?
ck lock              # closes it again
```

`unlock` and `lock` walk up from the current folder to the nearest vault, so
they work from inside it, beside it, or anywhere below the folder that holds
it. A path picks one instead: `ck unlock ~/drive/photos`. Away from every
vault, `ck lock` closes the only one that is open.

Any folder holding `gocryptfs.conf` is a vault. A `.photos` one opens into
`photos` beside it; any other opens where you say once, with
`ck unlock ~/enc --at ~/plain`, and ck remembers it.

## Unlock a drive or a disk image

```bash
ck unlock /dev/sdb1          # asks for the passphrase, then mounts it
ck unlock ~/backup.img       # a LUKS image file, through a loop device
ck lock /media/you/backup    # unmounts it and closes it again
```

ck remembers a drive by its UUID, so a stick plugged into another port is the
same vault, named by where it mounts. It locks only what its own `unlock`
opened, never touches a drive holding `/` or swap, and formats one only when
`ck init --luks <drive> --wipe` says so.

Over ssh, polkit asks for a password at every step, once to unlock and once
to mount. Set Drives through to sudo in ck's Settings tab (`luks = sudo` in
`~/.config/cryptkeeper/settings`), and ck opens drives through sudo instead,
which asks once and remembers it.

`ck ls` also lists every LUKS drive plugged in that ck does not know yet, with
its label and size, and the disk the system runs from as one ck never locks.

## Keep one file encrypted

```bash
ck init taxes.pdf                        # makes taxes.pdf.age, then deletes taxes.pdf
ck unlock taxes.pdf.age                  # asks the passphrase, taxes.pdf appears beside it
ck lock taxes.pdf                        # encrypts it again, then deletes the plaintext
ck edit taxes.pdf                        # unlock, $EDITOR, lock, in one go
ck unlock notes.age -i ~/.age/key.txt    # a file encrypted to a key instead
```

The plaintext lives in memory, and `taxes.pdf` is a link to it. `lock` writes
a new encrypted file, checks it, puts it in place of the old one, and only
then deletes the plaintext, so a failure at any step keeps both.

Lock it before you log out: logging out empties that memory. An editor that
saved over the link leaves the file on disk, which `ls` shows as `exposed`
until `ck lock` encrypts it.

`init` deletes the original only once the encrypted copy checks out, but it
does not wipe the blocks it used on disk.

## Work inside a vault

```bash
ck shell ~/photos    # unlocks it, opens $SHELL there, locks it when you exit
ck edit notes.txt    # the same for one age file, in $VISUAL or $EDITOR
```

Each locks the vault afterwards only if it was locked before, and a vault you
had open stays open. The editor has to wait until you close the file, as
`code --wait` does, or ck locks it while you still edit.

## Lock it when you walk away

```bash
ck unlock -t 100     # locks itself after 100 minutes with nothing using it
```

The clock only runs while nothing is reading or writing, and a file still open
in the vault keeps it unlocked, so it never pulls a folder out from under you.
It works for gocryptfs vaults.

## Make a vault

![The create picker, a new encrypted folder typed in with the command it runs, gocryptfs asking for its password, then the new vault listed](https://gitlab.com/safteinzz/cryptkeeper/-/raw/main/readme-assets/create.gif)

```bash
ck init              # asks for a name, then makes .<name> (hidden) and <name>
ck init photos       # .photos, encrypted, and photos, where it opens
```

gocryptfs asks for the new password twice and prints the vault's master key
once: write it down, because it is the only way back in if you forget the
password.

```bash
ck init --luks ~/vault.img --size 4G   # a LUKS disk image, ext4 inside
ck init --luks /dev/sdb1 --wipe        # a whole drive, wiping it
```

cryptsetup asks for the passphrase, and sudo for your password, since only
root may open the new vault to make its filesystem. A drive that is mounted
or in use is refused.

## Change a password, keep a spare header

```bash
ck passwd ~/photos   # through gocryptfs, cryptsetup or age
ck backup ~/photos   # gocryptfs.conf or the LUKS header, saved apart
```

A vault whose header or conf gets damaged opens only with that spare, so
`ck backup` keeps one under `~/.local/share/cryptkeeper/backups`; copy it off
the machine to be safe.

## Keep track of every vault

```bash
ck ls                # every vault made or opened here, its kind and state
ck forget            # pick vaults by number to drop from that list
ck clear             # drop every missing one
ck delete ~/old --yes   # delete a locked vault for good
```

A vault on an unplugged drive shows as `missing` rather than disappearing.
`forget` and `clear` only ever drop lines from the list, never a vault itself;
`delete` is the one that removes a vault, and only a locked one.

## Can this machine open it?

```bash
ck check             # gocryptfs, LUKS and age: ready, or what to install
```

![ck check saying gocryptfs and age are ready and LUKS is missing, with the command that installs it](https://gitlab.com/safteinzz/cryptkeeper/-/raw/main/readme-assets/check.png)

It names the missing tool and the install command for your distro, and says
when polkit will ask for your password at every step, as it does over ssh;
drives still open then, and Drives through: sudo in Settings asks only once.

## Commands

```bash
ck lock --all              # close every open vault
ck forget ~/drive/photos   # drop one by name, without the prompt
ck init --dir ~/drive      # make the vault somewhere else
ck unlock UUID=<uuid>      # a drive by its LUKS UUID
ck ls --json               # every vault and drive as data
```

Every command that changes something takes `-n` to print what it would do
instead, `ck <command> --help` has the details, and `?` in `ck` lists every key.

Nothing prompts but the passwords, `forget` with no vault named, which asks
which, and `init` with no name at a terminal. gocryptfs also reads the password
as one line on a piped stdin. `ck ls --json` and `ck check --json` print data with fixed field
names, a failure exits 1, and `ck check` exits 1 unless every kind is ready.

## Tab completion

```bash
ck completions bash --add    # adds `source <(ck completions bash)` to ~/.bashrc
```

zsh and fish work the same way. Vault names complete from the list ck keeps.

## Where it keeps things

```
~/.config/cryptkeeper/vaults        the list ck ls shows, one vault per line
~/.config/cryptkeeper/settings      name = vault, the name ck init offers
~/.local/state/cryptkeeper/opened   the LUKS drives ck unlocked since boot
$XDG_RUNTIME_DIR/cryptkeeper/age/   the plaintext of every open age file
```

`$XDG_CONFIG_HOME` and `$XDG_STATE_HOME` take the place of `~/.config` and
`~/.local/state` when set. A list left in `~/.config/egc/` is read until ck
writes its own.

## What it edits

`ck completions <shell> --add` appends one line to `~/.bashrc`, `~/.zshrc` or
`~/.config/fish/config.fish`, only when no line there loads the completions
yet, and never rewrites what is already in the file.

## When it fails

A vault that will not lock because something still uses it gets a list of your
own processes holding it, with what each holds, so you know what to close.

## Notes

- A gocryptfs folder made before ck works too once it is named `.<name>`,
  which is safe while it is locked because gocryptfs never records its own
  folder's name.
- An age file opens only when it is encrypted to a passphrase or to one key,
  since `lock` encrypts it again the same way. Armored (text) age files are
  not opened yet.
- `lock` and `init` ask for an age file's passphrase three times: twice for
  the new file, and once more to open it before the old one is replaced or the
  plaintext deleted. An empty answer, which age turns into a made-up
  passphrase, fails that check, so nothing is replaced or deleted.

## Compatibility

Linux, with [gocryptfs](https://github.com/rfjakob/gocryptfs#installation) and
fuse3 for folders, udisks2 for LUKS drives, and
[age](https://age-encryption.org) or rage for files. It reads `/proc` and
`/sys` to see what is open, so macOS and BSD need a different implementation
first.

## License

AGPL-3.0-only
