#!/usr/bin/env bash
# Build one deployment from a copy of this repository and run it, leaving the working tree untouched.
#
#   scripts/try.sh deploy/examples/door.toml
#
# Needs the pinned cancho compiler on PATH and Python 3 (docs/examples.html). Stop it with Ctrl-C.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
file="$(cd "$(dirname "${1:?usage: scripts/try.sh DEPLOYMENT.toml}")" && pwd)/$(basename "$1")"
flags=()
[ -n "${CANCHO_IGNORE_REV:-}" ] && flags+=(--ignore-compiler-rev)   # local testing only

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
git -C "$root" ls-files -z | (cd "$root" && xargs -0 cp --parents -t "$work")
cd "$work"
python3 scripts/generate.py "$file"
cancho build "${flags[@]}" >/dev/null
echo "gateway built from $1; listening, one JSON line per request below (Ctrl-C stops it)" >&2
build/gateway
