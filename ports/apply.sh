#!/usr/bin/env bash
# LACUNA -- apply one port to a clean checkout of its upstream zkVM.
#
#   usage: ./apply.sh <zkvm> <path-to-upstream-checkout>
#   e.g.:  ./apply.sh nexus ~/src/nexus-zkvm
#
# The checkout MUST be at the revision in ports/<zkvm>/UPSTREAM_REV. Each port is
# (a) a set of NEW files copied in verbatim and (b) one patch against tracked files.
# Every hook is additive and default-OFF: with no LACUNA_* environment variable set,
# the tree behaves exactly as upstream.
set -euo pipefail
VM=${1:?usage: apply.sh <zkvm> <upstream-checkout>}
DST=${2:?usage: apply.sh <zkvm> <upstream-checkout>}
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$VM"
[ -d "$SRC" ] || { echo "no such port: $VM (have: $(ls -d "$(dirname "$SRC")"/*/ | xargs -n1 basename | tr '\n' ' '))" >&2; exit 1; }
git -C "$DST" rev-parse --git-dir >/dev/null 2>&1 || { echo "$DST is not a git checkout" >&2; exit 1; }

WANT=$(cat "$SRC/UPSTREAM_REV")
HAVE=$(git -C "$DST" rev-parse HEAD)
if [ "$WANT" != "$HAVE" ]; then
  echo "WARNING: $DST is at $HAVE but this port was built against $WANT" >&2
  echo "         the patch will probably not apply; check out $WANT first." >&2
fi

if [ -d "$SRC/new" ]; then
  echo "== copying new files"
  ( cd "$SRC/new" && find . -type f -print0 ) | while IFS= read -r -d '' f; do
    install -D -m 0644 "$SRC/new/$f" "$DST/$f"
    echo "   + $f"
  done
else
  echo "== no new files for this port"
fi

echo "== applying vendor patch"
git -C "$DST" apply --verbose "$SRC/vendor.patch"
echo "== done. Build and run per $SRC/README.md"
