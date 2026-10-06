#!/usr/bin/env python3
"""The authority gate (docs/design.md section 3): derive, record, and hold to the ceiling.

    python3 scripts/authority.py            # regenerate manifests/gateway.authority.json, then check
    python3 scripts/authority.py --check    # change nothing; exit 1 on drift or a breach

A derived label must be in authority.toml; `bounded` must be true; no foreign symbol; and no label
named in FORBIDDEN, whatever the ceiling says. The compiler is $LEX_SYS, or `lex-sys` on PATH.
"""

import json
import os
import pathlib
import subprocess
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
FORBIDDEN = {"ffi", "fs_read", "fs_write", "file_read", "file_write", "dir_read", "dir_write"}


def derive(files):
    out = subprocess.run([os.environ.get("LEX_SYS", "lex-sys"), "authority", *files, "--std", "--output", "json"],
                         capture_output=True, text=True)
    if out.returncode != 0:
        sys.exit("lex-sys authority failed:\n" + out.stdout + out.stderr)
    return json.loads(out.stdout)


def label_text(label):
    if label["argument"] is None:
        return label["name"]
    return '%s("%s")' % (label["name"], label["argument"])


def problems_for(name, report, allowed):
    problems = []
    if not report.get("bounded", False):
        problems.append("%s: bounded is false" % name)
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
    with open(ROOT / "lex-sys.toml", "rb") as f:
        project = tomllib.load(f)
    with open(ROOT / "authority.toml", "rb") as f:
        ceilings = tomllib.load(f)
    failures = []
    for entry in project.get("bin", []):
        name = entry["name"]
        if name not in ceilings:
            failures.append("%s: no ceiling in authority.toml" % name)
            continue
        report = derive([str(ROOT / s) for s in entry["sources"]])
        record = ROOT / "manifests" / ("%s.authority.json" % name)
        text = json.dumps(report, indent=2) + "\n"
        if check:
            if not record.exists() or record.read_text() != text:
                failures.append("%s: %s is not the compiler's report" % (name, record.relative_to(ROOT)))
        else:
            record.parent.mkdir(exist_ok=True)
            record.write_text(text)
        failures.extend(problems_for(name, report, set(ceilings[name].get("allow", []))))
        print("%-8s %s" % (name, ", ".join(label_text(l) for l in report["labels"])))
    for p in failures:
        print("FAIL " + p)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
