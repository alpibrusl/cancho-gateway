#!/usr/bin/env bash
# Build the release assets into dist/ (docs/release.md). Needs the pinned cancho compiler on PATH and Python 3.
#
#   scripts/release.sh
#
# dist/ gets, for the demo deployment (deploy/demo.toml):
#   cancho-gateway-demo-linux-x86_64             the binary (config compiled in)
#   cancho-gateway-demo.authority.json           what the compiler says that binary may do
#   cancho-gateway-src.tar.gz                    the sources, generator and example deployments, to build your own
#   SHA256SUMS
# It builds from a clean `git archive` of HEAD, so a dirty working tree cannot leak into a release.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
flags=()
[ -n "${CANCHO_IGNORE_REV:-}" ] && flags+=(--ignore-compiler-rev)   # local testing only; CI never sets it

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/src" "$root/dist"
git -C "$root" archive HEAD | tar -x -C "$work/src"

(
  cd "$work/src"
  python3 scripts/generate.py deploy/demo.toml
  cancho build "${flags[@]}"
  # The demo binary's own authority must equal the recorded report: a deployment that widened it fails here, not in a release.
  python3 scripts/authority.py --check
)

out="$root/dist"
cp "$work/src/build/gateway" "$out/cancho-gateway-demo-linux-x86_64"
python3 - "$root" "$work/src" "$out" <<'PY'
import json, pathlib, sys
root, src, out = map(pathlib.Path, sys.argv[1:])
# authority.py --check (above) has just proved this file is what the compiler derives for the demo build.
recorded = json.loads((src / "manifests" / "gateway.authority.json").read_text())
(out / "cancho-gateway-demo.authority.json").write_text(json.dumps(recorded, indent=2, sort_keys=True) + "\n")
PY
tar -C "$work/src" --exclude=build --exclude=dist -czf "$out/cancho-gateway-src.tar.gz" .
(cd "$out" && sha256sum cancho-gateway-demo-linux-x86_64 cancho-gateway-demo.authority.json cancho-gateway-src.tar.gz > SHA256SUMS)
echo "release assets:"; ls -l "$out"
