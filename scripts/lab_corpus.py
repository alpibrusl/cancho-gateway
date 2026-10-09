#!/usr/bin/env python3
"""The refusal lab's corpus (docs/lab-corpus.json): every case of the smuggling corpus, with the verdict the
gateway's own framing judge gave it, produced by build/framing_probe at the pinned compiler.

    python3 scripts/lab_corpus.py          # regenerate docs/lab-corpus.json
    python3 scripts/lab_corpus.py --check # change nothing; exit 1 if the committed file is stale

The lab page (docs/lab.html) judges the visitor's bytes in the browser and proves it agrees with this file on
every load; the file is the bridge between the binary and the page. The three head-limit cases (16384 bytes of
padding) are left out: the page constructs them itself, and the hex would be 32 KB of the same letter.

`headers` is the probe's capacity for the case (the gateway's own limit is 64, `limit.headers`): the lab must
judge each recorded case at its recorded capacity, and a visitor's input at 64.
"""
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "lab-corpus.json"
DROP = {"head-at-limit", "head-over-limit", "no-blank-line-over-limit"}


def cases():
    sys.path.insert(0, str(ROOT / "tests" / "smuggling"))
    from corpus import CASES
    return CASES


def main():
    probe = ROOT / "build" / "framing_probe"
    if not probe.exists():
        sys.exit("lab_corpus.py: build/framing_probe is missing: run `cancho build` first")
    out = []
    for cid, request, headers, must, status, source in cases():
        if cid in DROP:
            continue
        got = subprocess.run([str(probe), str(headers), request.hex(), "gateway"],
                             capture_output=True, text=True, timeout=10)
        if got.returncode not in (0, 1):
            sys.exit("lab_corpus.py: %s trapped (exit %d)" % (cid, got.returncode))
        words = got.stdout.strip().split()
        entry = {"id": cid, "hex": request.hex(), "headers": headers}
        if words[0] == "accept":
            entry["outcome"] = "accept"
            if must != "accept":
                sys.exit("lab_corpus.py: %s must be %s, the probe accepts it" % (cid, must))
        elif words[0] == "more":
            entry["outcome"] = "more"
            if must != "more":
                sys.exit("lab_corpus.py: %s must be %s, the probe wants more" % (cid, must))
        elif words[0] == "refuse":
            entry["outcome"] = "refuse"
            entry["rule"] = words[1]
            entry["status"] = int(words[2])
            if must != "refuse" or (status is not None and status != entry["status"]):
                sys.exit("lab_corpus.py: %s disagrees with the corpus: %s" % (cid, words))
        else:
            sys.exit("lab_corpus.py: %s: the probe answered %r" % (cid, got.stdout))
        out.append(entry)
    text = json.dumps(out, separators=(",", ":")) + "\n"
    if "--check" in sys.argv[1:]:
        if not OUT.exists() or OUT.read_text() != text:
            print("stale: docs/lab-corpus.json is not what the probe answers")
            return 1
        print("docs/lab-corpus.json is what the probe answers")
        return 0
    OUT.write_text(text)
    print("wrote docs/lab-corpus.json: %d cases" % len(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
