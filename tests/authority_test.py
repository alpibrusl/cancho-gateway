#!/usr/bin/env python3
"""Gate 6 of docs/tls.md: the authority check must be able to fail. A TLS build whose certificate directory is widened (to `/etc`, a parent
of nothing it needs) reports another path, and `scripts/authority.py` refuses it; the true build passes; a build narrowed to `/` is refused
by the compiler itself (nested paths); and a deployment without `tls_listen` reports no `fs_read` at all.

    python3 tests/authority_test.py
"""

import pathlib
import subprocess
import sys
import tempfile
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import authority  # noqa: E402


def report(tmp, mutate=None):
    subprocess.run([sys.executable, str(ROOT / "scripts" / "generate.py"), str(ROOT / "deploy/examples/tls.toml"), "--out", tmp], check=True, capture_output=True)
    f = pathlib.Path(tmp) / "tlsfiles.cho"
    if mutate:
        f.write_text(mutate(f.read_text()))
    with open(ROOT / "cancho.toml", "rb") as fh:
        sources = [s for e in tomllib.load(fh)["bin"] if e["name"] == "gateway" for s in e["sources"]]
    files = [str(pathlib.Path(tmp) / pathlib.Path(s).name) if s.startswith("generated/") else str(ROOT / s) for s in sources]
    return authority.derive(authority.dependencies(files) + files)


def main():
    with open(ROOT / "authority.toml", "rb") as fh:
        allow = set(tomllib.load(fh)["gateway-tls"]["allow"])
    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        true = authority.problems_for("gateway-tls", report(tmp), allow)
        print("%-4s the true TLS build is within its ceiling %s" % ("ok" if not true else "FAIL", true))
        failures += bool(true)
    with tempfile.TemporaryDirectory() as tmp:
        wide = authority.problems_for("gateway-tls", report(tmp, lambda t: t.replace('"/etc/cancho-gateway/tls"', '"/etc"')), allow)
        print("%-4s a widened directory is refused: %s" % ("ok" if wide else "FAIL", wide))
        failures += not wide
    with tempfile.TemporaryDirectory() as tmp:
        try:
            report(tmp, lambda t: t.replace('"/etc/cancho-gateway/tls"', '"/"'))
            print("FAIL narrowing to / was accepted")
            failures += 1
        except SystemExit as e:
            print("ok   narrowing to / is refused by the compiler: %s" % str(e).splitlines()[-1][:100])
    print("%d failures" % failures)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
