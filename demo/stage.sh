#!/usr/bin/env bash
# A staged home for the README pictures. Nothing here touches your real home,
# your real vault list or your real vaults: every path is redirected into
# ./home, XDG variables included.
#
#   ./stage.sh up     build the empty staged home
#   ./stage.sh shell  a shell where `ck` is this build (what the tape records)
#   ./stage.sh down   unmount anything under the stage, then delete it
#
# The tapes make real vaults in the stage and really mount them, with the
# throwaway password `demo`, master keys and an age key that die with the stage.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

STAGE="$HERE/home"
BIN="$STAGE/.bin"
# age keeps an open file's plaintext only on tmpfs, which the stage folder is
# not, so the stage's `$XDG_RUNTIME_DIR` is a folder of its own in /dev/shm.
RUN_DIR="/dev/shm/ck-demo-stage"
CK="$HERE/../target/release/ck"

# Written by `up`, required by `down`. See the guard further down.
MARKER=".ck-demo-stage"

# The complete environment anything staged runs in. Used with `env -i`, so this
# is not "the real environment plus overrides": it is everything there is.
env_for_stage() {
  echo "HOME=$STAGE" \
       "XDG_CONFIG_HOME=$STAGE/.config" \
       "XDG_DATA_HOME=$STAGE/.local/share" \
       "XDG_STATE_HOME=$STAGE/.local/state" \
       "XDG_CACHE_HOME=$STAGE/.cache" \
       "XDG_RUNTIME_DIR=$RUN_DIR" \
       "PATH=$BIN:/usr/local/bin:/usr/bin:/bin" \
       "TERM=${TERM:-xterm-256color}" \
       "COLORTERM=truecolor" \
       "LANG=C.UTF-8"
}

up() {
  down_quiet
  [ -x "$CK" ] || { echo "stage.sh: no \`$CK\`: run \`cargo build --release\` first" >&2; exit 1; }
  mkdir -p "$STAGE"
  mkdir -p -m 700 "$RUN_DIR"
  # Stamp it before anything else, so a later `down` can prove this tree is ours.
  : > "$STAGE/$MARKER"
  echo "staged in $STAGE"
  echo
  echo "  ./stage.sh shell  a shell where ck is this build"
  echo "  ./stage.sh down   tear it all down"
}

# ---------------------------------------------------------------------------
# the teardown guard - identical in every crate's rig
# ---------------------------------------------------------------------------
# A rig is a convenience script with a recursive delete in it, run half
# attentively while thinking about something else, against a path some scenario
# may have mounted a remote filesystem onto. Both halves of that have already
# happened in this workflow: a stage path that pointed somewhere real and was
# deleted because the script trusted its own variable, and an sshfs mount inside
# a staged home torn down with `rm -rf`, which walked through the mountpoint and
# deleted the dotfiles on the machine at the far end. So the delete is proved
# rather than trusted.
refuse() { echo "REFUSING to delete $STAGE: $1" >&2; exit 1; }

assert_safe_to_delete() {
  case "$STAGE" in
    /*) ;;
    *) refuse "the stage path must be absolute" ;;
  esac
  # Resolve symlinks first: a link pointing the stage at something real must not
  # let a delete through on the strength of a harmless-looking path.
  local real
  real="$(cd "$STAGE" && pwd -P)" || refuse "cannot resolve the path"
  case "$real" in
    / | /home | /root | /usr | /etc | /var | /opt | /srv | /boot | /tmp)
      refuse "that is a system directory" ;;
  esac
  [ "$real" = "$HOME" ] && refuse "that is your home directory"
  case "$HOME/" in
    "$real"/*) refuse "your home directory is inside it" ;;
  esac
  # The real gate: only ever delete a tree this script built and stamped.
  [ -f "$real/$MARKER" ] || refuse "no \`$MARKER\` in it, so this script did not build it"
  # Unmount anything under it, longest path first, then check again: a recursive
  # delete walks straight through a mountpoint and removes the far side.
  local mp
  while read -r mp; do
    [ -n "$mp" ] || continue
    echo "unmounting $mp"
    fusermount -u "$mp" 2> /dev/null || umount "$mp" 2> /dev/null || true
  done < <(awk -v s="$real/" '$2 ~ "^"s {print length($2), $2}' /proc/mounts |
             sort -rn | cut -d' ' -f2-)
  if awk -v s="$real/" '$2 ~ "^"s {found=1} END {exit !found}' /proc/mounts; then
    refuse "something is still mounted under it; unmount it by hand and rerun"
  fi
}

down_quiet() {
  [ -d "$STAGE" ] || return 0
  assert_safe_to_delete
  # --one-file-system as a second net, in case the mount check was wrong.
  rm -rf --one-file-system "$STAGE"
  rm -rf "$RUN_DIR"
}

# ---------------------------------------------------------------------------
# the shell in frame - identical in every crate's rig
# ---------------------------------------------------------------------------
# The prompt is invented, and deliberately not the renderer's own. Sourcing a
# real ~/.bashrc paints a different picture on every machine that regenerates
# the assets, which defeats the point of keeping the rig in the repo: these
# images are a build output, and a build output that depends on whose machine
# ran it is not reproducible. A username is not a leak, but `user@host` is the
# same for everyone, and it is the same string in all six rigs so the frames
# match. Every tape sets the same theme and font for the same reason.
write_demorc() {
  cat > "$STAGE/.demorc" <<'EOF'
PS1='\[\e[38;5;114m\]user@host\[\e[0m\]:\[\e[38;5;110m\]\w\[\e[0m\]\$ '
unset PROMPT_COMMAND
HISTFILE=
clear
EOF
}

# A shell that finds this build as `ck`, so the picture shows the command you
# actually type rather than a path into target/release. It starts in the
# staged home, so the `~` in the prompt is the fixture and not your files.
open_shell() {
  [ -f "$STAGE/$MARKER" ] || { echo "stage.sh: no stage: run \`./stage.sh up\` first" >&2; exit 1; }
  mkdir -p "$BIN"
  ln -sf "$(cd "$(dirname "$CK")" && pwd)/ck" "$BIN/ck"
  write_demorc
  (cd "$STAGE" && env -i $(env_for_stage) \
    bash --noprofile --rcfile "$STAGE/.demorc" -i)
}

case "${1:-up}" in
  up)    up ;;
  shell) open_shell ;;
  down)  down_quiet; echo "torn down" ;;
  *)     echo "usage: $0 [up|shell|down]" >&2; exit 2 ;;
esac
