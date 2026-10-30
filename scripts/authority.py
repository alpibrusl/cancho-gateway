#!/usr/bin/env python3
"""The authority gate (docs/design.md section 3): derive, record, and hold to the ceiling.

    python3 scripts/authority.py            # regenerate manifests/gateway.authority.json, then check
    python3 scripts/authority.py --check    # change nothing; exit 1 on drift or a breach

A derived label must be in authority.toml; the report may be unbounded only by what the ceiling names; no foreign symbol; and no label
named in FORBIDDEN, whatever the ceiling says. The compiler is $CANCHO, or `cancho` on PATH.
"""

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
FORBIDDEN = {"ffi", "fs_write", "file_write", "dir_write"}
# The deployment that turns TLS on is derived as well (docs/tls.md section 4): its generated modules replace the example's, and the report must
# name exactly the two filesystem paths the program reads, never `fs_read("")`.
PROFILES = [("gateway-tls", "gateway", "deploy/examples/tls.toml")]


def dependencies(sources):
    """The packages `cancho build` fetched (the TLS engine and what it requires), for a program that imports them."""
    if not any(s.endswith("src/tlsio.cho") for s in sources):
        return []
    found = sorted(str(p) for p in (ROOT / "build" / "deps").glob("*.cho"))
    if not found:
        sys.exit("build/deps is empty: run `cancho build` once first")
    return found


def derive(files):
    out = subprocess.run([os.environ.get("CANCHO", "cancho"), "authority", *files, "--std", "--output", "json"],
                         capture_output=True, text=True)
    if out.returncode != 0:
        sys.exit("cancho authority failed:\n" + out.stdout + out.stderr)
    return json.loads(out.stdout)


def label_text(label):
    if label["argument"] is None:
        return label["name"]
    return '%s("%s")' % (label["name"], label["argument"])


def problems_for(name, report, allowed):
    problems = []
    # `bounded` is false while a network is held without a literal narrowing (the compiler's report since net-bounds): the gateway listens and
    # connects where its deployment says, so `net_in("")` and `net_out("")` are in the ceiling (docs/design.md section 2.1). What may make the
    # report unbounded is exactly what the ceiling names.
    for item in report.get("unbounded_by", []):
        if item not in allowed:
            problems.append("%s: unbounded by %s, which the ceiling does not allow" % (name, item))
    if not report.get("bounded", False) and not report.get("unbounded_by"):
        problems.append("%s: bounded is false and nothing says why" % name)
    if report.get("foreign_symbols"):
        problems.append("%s: foreign symbols %s" % (name, report["foreign_symbols"]))
    for label in report["labels"]:
        text = label_text(label)
        if label["name"] in FORBIDDEN:
            problems.append("%s: %s is forbidden to the gateway" % (name, text))
        elif text not in allowed:
            problems.append("%s: %s is not within the ceiling in authority.toml" % (name, text))
    return problems


def main():
    check = "--check" in sys.argv[1:]
    with open(ROOT / "cancho.toml", "rb") as f:
        project = tomllib.load(f)
    with open(ROOT / "authority.toml", "rb") as f:
        ceilings = tomllib.load(f)
    failures = []
    derive_cached = {}
    for entry in project.get("bin", []):
        name = entry["name"]
        if name not in ceilings:
            failures.append("%s: no ceiling in authority.toml" % name)
            continue
        sources = [str(ROOT / s) for s in entry["sources"]]
        report = derive(dependencies(sources) + sources)
        record = ROOT / "manifests" / ("%s.authority.json" % name)
        text = json.dumps(report, indent=2) + "\n"
        if check:
            if not record.exists() or record.read_text() != text:
                failures.append("%s: %s is not the compiler's report" % (name, record.relative_to(ROOT)))
        else:
            record.parent.mkdir(exist_ok=True)
            record.write_text(text)
        derive_cached[name] = report
        failures.extend(problems_for(name, report, set(ceilings[name].get("allow", []))))
        print("%-8s %s" % (name, ", ".join(label_text(l) for l in report["labels"])))
    bins = {e["name"]: e for e in project.get("bin", [])}
    for name, base, deployment in PROFILES:
        if name not in ceilings:
            failures.append("%s: no ceiling in authority.toml" % name)
            continue
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run([sys.executable, str(ROOT / "scripts" / "generate.py"), str(ROOT / deployment), "--out", tmp], check=True)
            sources = [str(pathlib.Path(tmp) / pathlib.Path(s).name) if s.startswith("generated/") else str(ROOT / s) for s in bins[base]["sources"]]
            report = derive(dependencies(sources) + sources)
        record = ROOT / "manifests" / ("%s.authority.json" % name)
        text = json.dumps(report, indent=2) + "\n"
        if check:
            if not record.exists() or record.read_text() != text:
                failures.append("%s: %s is not the compiler's report" % (name, record.relative_to(ROOT)))
        else:
            record.write_text(text)
        failures.extend(problems_for(name, report, set(ceilings[name].get("allow", []))))
        reads = sorted(label_text(l) for l in report["labels"] if l["name"] == "fs_read")
        if len(reads) != 2 or any(r == 'fs_read("")' for r in reads):
            failures.append("%s: the filesystem authority must be exactly two named paths, found %s" % (name, reads))
        print("%-8s %s" % (name, ", ".join(label_text(l) for l in report["labels"])))
    plain = [label_text(l) for l in derive_cached.get("gateway", {}).get("labels", [])]
    if any(t.startswith("fs_read") for t in plain):
        failures.append("gateway: a deployment without tls_listen must report no fs_read, found %s" % plain)
    for p in failures:
        print("FAIL " + p)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
