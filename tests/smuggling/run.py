#!/usr/bin/env python3
"""Run the smuggling corpus through build/framing_probe (std.http.parse alone) and report the gaps.

    python3 tests/smuggling/run.py            # std.http alone: every case, exit 1 on any disagreement
    python3 tests/smuggling/run.py --chunked  # chunked bodies: corpus under six deliveries, then 1,500 fuzzed bodies
    python3 tests/smuggling/run.py --prefixes # every proper prefix of each case, delivered split at any byte
    python3 tests/smuggling/run.py --fuzz N   # N mutated heads: no trap, accepted heads self-contained
    python3 tests/smuggling/run.py --gateway  # gateway.framing.judge: must agree on every case, with the status
    python3 tests/smuggling/run.py --gaps     # only the disagreements

A gap is a case the gateway must handle one way and std.http handles the other. docs/framing.md records the table.
"""

import pathlib
import random
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from corpus import CASES  # noqa: E402
from chunked_corpus import CASES as CHUNKED  # noqa: E402

CODES = {1: "incomplete", 2: "request_line", 3: "method", 4: "target", 5: "version", 6: "header", 7: "too_many",
         8: "length", 9: "fold", 10: "too_large", 11: "encoding", 12: "host"}


def probe(request, headers, gateway):
    cmd = [str(ROOT / "build" / "framing_probe"), str(headers), request.hex()] + (["gateway"] if gateway else [])
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    if out.returncode not in (0, 1):
        return "TRAP exit %d" % out.returncode
    return out.stdout.strip()


def judge(must, status, got, gateway):
    words = got.split()
    kind = words[:1]
    if got.startswith("TRAP") or kind not in (["accept"], ["refuse"], ["more"]):
        return "BROKEN"
    if must == "more":
        return "ok" if kind == ["more"] or (not gateway and words[:2] == ["refuse", "1"]) else "GAP"
    if must == "accept":
        return "ok" if kind == ["accept"] else "GAP (refuses a request the gateway must serve)"
    if kind != ["refuse"]:
        return "GAP (accepts a request the gateway must refuse)"
    if gateway and (int(words[2]) != status):
        return "WRONG STATUS (%s, want %d)" % (words[2], status)
    return "ok"


def prefixes():
    """Delivery split at every byte: every proper prefix of an accepted head is `more` (never an accept, never a
    refusal), and the whole is accepted. A refused head's prefixes may refuse early, never accept."""
    bad = 0
    checked = 0
    for cid, request, headers, must, status, source in CASES:
        if len(request) > 400:
            continue
        whole = probe(request, headers, True).split()
        # Prefixes past the head are a head plus part of its body: legitimately accepted.
        end = int(whole[1]) if whole[:1] == ["accept"] else len(request)
        for n in range(end):
            got = probe(request[:n], headers, True).split()[:1]
            checked += 1
            if must == "accept" and got != ["more"]:
                print("FAIL %s: prefix of %d bytes is %s, want more" % (cid, n, got))
                bad += 1
            if must != "accept" and got == ["accept"]:
                print("FAIL %s: prefix of %d bytes is accepted" % (cid, n))
                bad += 1
    print("%d prefixes checked, %d failures" % (checked, bad))
    return bad


def fuzz(count):
    """Mutate corpus heads at random (flip, insert, delete, splice, truncate); nothing may trap, and whatever is
    accepted must be self-contained: the head alone is accepted the same way and no shorter prefix is."""
    rng = random.Random(3)
    seeds = [c[1] for c in CASES if len(c[1]) <= 400]
    bad = accepted = 0
    for _ in range(count):
        data = bytearray(rng.choice(seeds))
        for _ in range(rng.randint(1, 4)):
            op = rng.randrange(5)
            at = rng.randrange(len(data) + 1)
            if op == 0 and data:
                data[min(at, len(data) - 1)] = rng.randrange(256)
            elif op == 1:
                data.insert(at, rng.choice(b"\r\n :\x00\t,;" + bytes([rng.randrange(256)])))
            elif op == 2 and data:
                del data[min(at, len(data) - 1)]
            elif op == 3:
                data[at:at] = rng.choice(seeds)[: rng.randrange(40)]
            else:
                del data[at:]
        got = probe(bytes(data), 8, True)
        words = got.split()
        if got.startswith("TRAP") or words[:1] not in (["accept"], ["refuse"], ["more"]):
            print("FAIL trap or broken answer %r for %r" % (got, bytes(data)))
            bad += 1
        elif words[0] == "accept":
            accepted += 1
            head = bytes(data)[: int(words[1])]
            if probe(head, 8, True).split()[:2] != words[:2]:
                print("FAIL accepted head is not self-contained: %r" % bytes(data))
                bad += 1
            for n in range(len(head)):
                if probe(head[:n], 8, True).split()[:1] == ["accept"]:
                    print("FAIL a shorter prefix (%d) of an accepted head is accepted: %r" % (n, head))
                    bad += 1
                    break
    print("%d fuzzed heads, %d accepted, %d failures" % (count, accepted, bad))
    return bad


def chunk_probe(body, max_body, piece):
    out = subprocess.run([str(ROOT / "build" / "framing_probe"), "1", body.hex(), "chunked:%d:%d" % (max_body, piece)],
                         capture_output=True, text=True, timeout=10)
    if out.returncode not in (0, 1):
        return "TRAP exit %d" % out.returncode
    return out.stdout.strip()


def chunked_cases():
    """The chunked corpus, delivered whole and then split into pieces of 1, 2, 3, 5 and 7 bytes: the answer must be the
    expected one and identical for every split."""
    bad = checked = 0
    for cid, body, max_body, outcome, want, counted, source in CHUNKED:
        answers = {}
        for piece in (0, 1, 2, 3, 5, 7):
            answers[piece] = chunk_probe(body, max_body, piece)
            checked += 1
        if outcome == "refuse":
            expect = "refuse %s" % want
            ok = all(a.startswith(expect) for a in answers.values())
        else:
            expect = "%s %d %d" % (outcome, want, counted)
            ok = all(a == expect for a in answers.values())
        if not ok:
            bad += 1
            print("FAIL %-28s want %-34s got %s" % (cid, expect, answers))
    print("%d chunked cases x 6 deliveries = %d runs, %d failures" % (len(CHUNKED), checked, bad))
    return bad


def chunked_fuzz(count):
    """Mutated chunked bodies, delivered whole and split: nothing traps, and every delivery agrees."""
    rng = random.Random(5)
    seeds = [c[1] for c in CHUNKED if len(c[1]) <= 200] + [b"3\r\nabc\r\n0\r\n\r\n", b"1\r\nx\r\n1\r\ny\r\n0\r\n\r\n"]
    bad = done = 0
    for _ in range(count):
        data = bytearray(rng.choice(seeds))
        for _ in range(rng.randint(1, 3)):
            op = rng.randrange(4)
            at = rng.randrange(len(data) + 1)
            if op == 0 and data:
                data[min(at, len(data) - 1)] = rng.choice(b"0123456789abcdefABCDEF;\r\n \t-x" + bytes([rng.randrange(256)]))
            elif op == 1:
                data.insert(at, rng.choice(b"0123456789abcdef;\r\n \t" + bytes([rng.randrange(256)])))
            elif op == 2 and data:
                del data[min(at, len(data) - 1)]
            else:
                del data[at:]
        whole = chunk_probe(bytes(data), 64, 0)
        if whole.startswith("TRAP") or whole.split()[:1] not in (["done"], ["more"], ["refuse"]):
            print("FAIL trap or broken answer %r for %r" % (whole, bytes(data)))
            bad += 1
            continue
        done += whole.startswith("done")
        for piece in (1, 3):
            got = chunk_probe(bytes(data), 64, piece)
            if got != whole:
                print("FAIL split delivery differs for %r: whole %r, pieces of %d %r" % (bytes(data), whole, piece, got))
                bad += 1
                break
    print("%d fuzzed chunked bodies, %d complete, %d failures" % (count, done, bad))
    return bad


def main():
    if "--chunked" in sys.argv[1:]:
        return 1 if (chunked_cases() + chunked_fuzz(1500)) else 0
    if "--prefixes" in sys.argv[1:]:
        return 1 if prefixes() else 0
    if "--fuzz" in sys.argv[1:]:
        return 1 if fuzz(int(sys.argv[sys.argv.index("--fuzz") + 1])) else 0
    only_gaps = "--gaps" in sys.argv[1:]
    gateway = "--gateway" in sys.argv[1:]
    bad = 0
    for cid, request, headers, must, status, source in CASES:
        got = probe(request, headers, gateway)
        verdict = judge(must, status, got, gateway)
        if verdict != "ok":
            bad += 1
        if not only_gaps or verdict != "ok":
            print("%-30s must %-6s %s: %-44s %s" % (cid, must, "gateway" if gateway else "std.http", got, verdict))
    print("%d cases, %d disagreements (%s)" % (len(CASES), bad, "gateway.framing" if gateway else "std.http alone"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
