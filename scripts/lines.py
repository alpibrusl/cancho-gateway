#!/usr/bin/env python3
"""No source file over 2,000 lines (the repo rule; split by concern, never raise the ceiling)."""

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
CEILING = 2000
SUFFIXES = {".cho", ".py", ".sh", ".toml", ".yml"}
SKIP = {".git", "build"}


def main():
    over = []
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file() or path.suffix not in SUFFIXES or SKIP & set(path.relative_to(ROOT).parts):
            continue
        n = len(path.read_text().splitlines())
        if n > CEILING:
            over.append((path.relative_to(ROOT), n))
    for path, n in over:
        print("FAIL %s has %d lines (ceiling %d)" % (path, n, CEILING))
    return 1 if over else 0


if __name__ == "__main__":
    sys.exit(main())
