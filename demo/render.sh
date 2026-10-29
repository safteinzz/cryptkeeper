#!/usr/bin/env bash
# Render the README pictures in a container, so a machine needs podman or docker
# and nothing else: no vhs, no ttyd, no gocryptfs, no font, and the same frames
# on every machine that runs it.
#
#   ./render.sh              every tape
#   ./render.sh vaults       one tape
#
# Each tape stages its own home (`./stage.sh up`) in a container of its own,
# which tears the stage down once the tape is recorded.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

ENGINE="$(command -v podman || command -v docker || true)"
[ -n "$ENGINE" ] || { echo "render.sh needs podman or docker" >&2; exit 1; }
IMAGE=localhost/cryptkeeper-render

TAPES=("$@")
[ ${#TAPES[@]} -gt 0 ] || TAPES=(vaults create check)

(cd .. && cargo build --release)
# The Dockerfile is the whole build context: nothing in this folder is copied in.
"$ENGINE" build -q -t "$IMAGE" - < Dockerfile > /dev/null

# Run as this user, not root: the images it writes stay yours, and the staged
# shell's prompt ends in `$` as it does on a machine rendering without a
# container, rather than root's `#`.
if [ "$(basename "$ENGINE")" = docker ]; then
  USER_ARGS=(--user "$(id -u):$(id -g)" -e HOME=/tmp)
else
  USER_ARGS=(--userns=keep-id -e HOME=/tmp)
fi

# No network: the vaults are files and folders inside the stage. gocryptfs needs /dev/fuse
# and SYS_ADMIN to mount inside the container, which is all of `--privileged`
# the tape uses.
for t in "${TAPES[@]}"; do
  echo "── $t.tape"
  "$ENGINE" run --rm --network none "${USER_ARGS[@]}" \
    --device /dev/fuse --cap-add SYS_ADMIN \
    -v "$(cd .. && pwd):/work/cryptkeeper:Z" -w /work/cryptkeeper/demo \
    --entrypoint bash "$IMAGE" \
    -c "vhs $t.tape > /dev/null; s=\$?; ./stage.sh down > /dev/null; exit \$s"
done
echo "done: see ../readme-assets/"
