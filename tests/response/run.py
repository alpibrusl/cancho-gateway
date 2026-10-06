#!/usr/bin/env python3
"""The upstream-response corpus (task #6, docs/pool.md section 2) through build/response_probe.

    python3 tests/response/run.py            # the corpus, the split-delivery property, 1,500 seeded mutations

Each case: (id, bytes, head_request, expected line prefix, source). `head <length> <status> <version> <mode> <cl> <reusable>
<interim>`: mode 0 none, 1 Content-Length, 2 chunked, 3 until close. Sources are RFC 9112 sections; the llhttp and nginx test
suites have not been consulted.
"""

import pathlib
import random
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
OK = b"HTTP/1.1 200 OK\r\n"
C = []


def case(cid, data, expect, source, head_request=False):
    if "{L}" in expect:
        expect = expect.replace("{L}", str(data.index(b"\r\n\r\n") + 4))
    C.append((cid, data, head_request, expect, source))


case("content-length", OK + b"Content-Length: 5\r\n\r\nhello", "head {L} 200 11 1 5 1 0", "RFC 9112 6.3")
case("chunked", OK + b"Transfer-Encoding: chunked\r\n\r\n", "head {L} 200 11 2 -1 1 0", "RFC 9112 6.1")
case("chunked-case", OK + b"Transfer-Encoding: Chunked\r\n\r\n", "head {L} 200 11 2 -1 1 0", "RFC 9112 7 (names are case-insensitive)")
case("until-close", OK + b"\r\n", "head {L} 200 11 3 -1 0 0", "RFC 9112 6.3 item 8")
case("zero-length", OK + b"Content-Length: 0\r\n\r\n", "head {L} 200 11 0 0 1 0", "RFC 9112 6.3")
case("no-body-204", b"HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\n", "head {L} 204 11 0 5 1 0", "RFC 9112 6.3 item 1")
case("no-body-304", b"HTTP/1.1 304 Not Modified\r\n\r\n", "head {L} 304 11 0 -1 1 0", "RFC 9112 6.3 item 1")
case("head-response", OK + b"Content-Length: 5\r\n\r\n", "head {L} 200 11 0 5 1 0", "RFC 9112 6.3 item 2", head_request=True)
case("interim-100", b"HTTP/1.1 100 Continue\r\n\r\n", "head {L} 100 11 0 -1 1 1", "RFC 9110 15.2")
case("interim-103", b"HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n", "head {L} 103 11 0 -1 1 1", "RFC 9110 15.2")
case("connection-close", OK + b"Content-Length: 1\r\nConnection: close\r\n\r\n", "head {L} 200 11 1 1 0 0", "RFC 9112 9.6")
case("connection-close-in-list", OK + b"Content-Length: 1\r\nConnection: Keep-Alive, Close\r\n\r\n", "head {L} 200 11 1 1 0 0", "RFC 9110 7.6.1")
case("http10-plain", b"HTTP/1.0 200 OK\r\nContent-Length: 1\r\n\r\n", "head {L} 200 10 1 1 0 0", "RFC 9112 9.3 (1.0 closes unless keep-alive)")
case("http10-keep-alive", b"HTTP/1.0 200 OK\r\nContent-Length: 1\r\nConnection: keep-alive\r\n\r\n", "head {L} 200 10 1 1 1 0", "RFC 9112 9.3")
case("empty-reason", b"HTTP/1.1 200 \r\nContent-Length: 0\r\n\r\n", "head {L} 200 11 0 0 1 0", "RFC 9112 4 (the SP stays, the reason may be empty)")
case("reason-with-tab", b"HTTP/1.1 200 O\tK\r\nContent-Length: 0\r\n\r\n", "head {L} 200 11 0 0 1 0", "RFC 9112 4")
case("value-with-ows", OK + b"Content-Length:   5   \r\n\r\n", "head {L} 200 11 1 5 1 0", "RFC 9112 5 (OWS)")
for cid, data, expect, source in [
    ("cl-and-te", OK + b"Content-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n", "refuse response.two-lengths 502", "RFC 9112 6.3 item 3"),
    ("te-and-cl", OK + b"Transfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n", "refuse response.two-lengths 502", "RFC 9112 6.3 item 3"),
    ("cl-twice-same", OK + b"Content-Length: 5\r\nContent-Length: 5\r\n\r\n", "refuse response.length 502", "one framing, no tolerance"),
    ("cl-twice-differ", OK + b"Content-Length: 5\r\nContent-Length: 6\r\n\r\n", "refuse response.length 502", "RFC 9112 6.3 item 5"),
    ("cl-list", OK + b"Content-Length: 5, 5\r\n\r\n", "refuse response.length 502", "RFC 9112 6.3"),
    ("cl-letters", OK + b"Content-Length: abc\r\n\r\n", "refuse response.length 502", "RFC 9112 6.2"),
    ("cl-sign", OK + b"Content-Length: +5\r\n\r\n", "refuse response.length 502", "RFC 9112 6.2"),
    ("cl-empty", OK + b"Content-Length:\r\n\r\n", "refuse response.length 502", "RFC 9112 6.2"),
    ("cl-overflow", OK + b"Content-Length: 99999999999999999999\r\n\r\n", "refuse response.length 502", "overflow"),
    ("te-gzip", OK + b"Transfer-Encoding: gzip\r\n\r\n", "refuse response.transfer-encoding 502", "RFC 9112 6.1"),
    ("te-gzip-chunked", OK + b"Transfer-Encoding: gzip, chunked\r\n\r\n", "refuse response.transfer-encoding 502", "only a lone chunked is spoken"),
    ("te-twice", OK + b"Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n", "refuse response.transfer-encoding 502", "Kettle 2019"),
    ("te-xchunked", OK + b"Transfer-Encoding: xchunked\r\n\r\n", "refuse response.transfer-encoding 502", "Kettle 2019"),
    ("status-line-no-space", b"HTTP/1.1 200\r\nContent-Length: 0\r\n\r\n", "refuse response.status-line 502", "RFC 9112 4"),
    ("status-two-digits", b"HTTP/1.1 20 OK\r\n\r\n", "refuse response.status-line 502", "RFC 9112 4"),
    ("status-letters", b"HTTP/1.1 2x0 OK\r\n\r\n", "refuse response.status-line 502", "RFC 9112 4"),
    ("status-99", b"HTTP/1.1 099 No\r\n\r\n", "refuse response.status 502", "RFC 9110 15"),
    ("status-101", b"HTTP/1.1 101 Switching\r\n\r\n", "refuse response.status 502", "Upgrade is not spoken"),
    ("version-2", b"HTTP/2.0 200 OK\r\n\r\n", "refuse response.version 502", "RFC 9112 2.3"),
    ("version-0.9", b"HTTP/0.9 200 OK\r\n\r\n", "refuse response.version 502", "RFC 9112 2.3"),
    ("not-http", b"ICY 200 OK\r\n\r\n", "refuse response.status-line 502", "RFC 9112 4"),
    ("lowercase-http", b"http/1.1 200 OK\r\n\r\n", "refuse response.status-line 502", "RFC 9112 2.3 (case-sensitive)"),
    ("bare-lf", b"HTTP/1.1 200 OK\nContent-Length: 0\n\n", "more", "RFC 9112 2.2 (no CRLFCRLF: never complete)"),
    ("bare-cr-value", OK + b"X: a\rb\r\n\r\n", "refuse response.header 502", "RFC 9112 2.2"),
    ("nul-in-value", OK + b"X: a\x00b\r\n\r\n", "refuse response.header 502", "RFC 9110 5.5"),
    ("del-in-value", OK + b"X: a\x7fb\r\n\r\n", "refuse response.header 502", "RFC 9110 5.5"),
    ("nul-in-reason", b"HTTP/1.1 200 O\x00K\r\n\r\n", "refuse response.status-line 502", "RFC 9112 4"),
    ("space-before-colon", OK + b"Content-Length : 5\r\n\r\n", "refuse response.header 502", "RFC 9112 5.1"),
    ("empty-name", OK + b": x\r\n\r\n", "refuse response.header 502", "RFC 9110 5.1"),
    ("no-colon", OK + b"Junk\r\n\r\n", "refuse response.header 502", "RFC 9112 5"),
    ("obs-fold", OK + b"X: a\r\n b\r\n\r\n", "refuse response.fold 502", "RFC 9112 5.2"),
    ("leading-space-header", OK + b" X: a\r\n\r\n", "refuse response.fold 502", "RFC 9112 5.2"),
    ("incomplete", OK + b"Content-Length: 5\r\n", "more", "arrives in pieces"),
    ("incomplete-empty", b"", "more", "nothing yet"),
    ("too-large", OK + b"X: " + b"a" * 16400, "refuse response.head-too-large 502", "bounded memory"),
]:
    case(cid, data, expect, source)
body_len = lambda total: OK + b"X: " + b"a" * (total - len(OK) - 3 - 4) + b"\r\n\r\n"
case("head-at-limit", body_len(16384), "head {L} 200 11 3 -1 0 0", "bounded memory: exactly 16384 bytes")
case("head-over-limit", body_len(16385), "refuse response.head-too-large 502", "bounded memory: 16385 bytes")
many = OK + b"".join(b"H%d: v\r\n" % i for i in range(65)) + b"\r\n"
case("too-many-headers", many, "refuse response.header 502", "the table holds 64 headers")


def probe(data, head_request=False):
    out = subprocess.run([str(ROOT / "build" / "response_probe"), "1" if head_request else "0", data.hex()],
                         capture_output=True, text=True, timeout=10)
    return "TRAP exit %d" % out.returncode if out.returncode not in (0, 1) else out.stdout.strip()


def main():
    bad = 0
    for cid, data, head_request, expect, source in C:
        got = probe(data, head_request)
        if not got.startswith(expect):
            bad += 1
            print("FAIL %-28s want %-40s got %s" % (cid, expect, got))
    print("%d cases, %d failures" % (len(C), bad))
    # Split delivery: every proper prefix of an accepted head is `more`.
    checked = 0
    for cid, data, head_request, expect, source in C:
        if expect.startswith("head "):
            length = int(expect.split()[1])
            for n in range(0, length, 1 if length < 400 else 211):
                checked += 1
                got = probe(data[:n], head_request)
                if got != "more":
                    bad += 1
                    print("FAIL %s: a prefix of %d bytes is %r, want more" % (cid, n, got))
    print("%d proper prefixes checked" % checked)
    # Seeded mutations: no trap; an accepted head is self-contained.
    rng = random.Random(6)
    seeds = [c[1] for c in C if len(c[1]) < 400]
    fuzzed = accepted = 0
    for _ in range(1500):
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
        got = probe(bytes(data))
        fuzzed += 1
        if got.startswith("TRAP") or got.split()[:1] not in (["head"], ["more"], ["refuse"]):
            bad += 1
            print("FAIL trap or broken answer %r for %r" % (got, bytes(data)))
        elif got.startswith("head"):
            accepted += 1
            length = int(got.split()[1])
            if probe(bytes(data)[:length]) != got:
                bad += 1
                print("FAIL an accepted head is not self-contained: %r" % bytes(data))
            elif any(probe(bytes(data)[:k]).startswith("head") for k in range(0, length, max(1, length // 12))):
                bad += 1
                print("FAIL a shorter prefix of an accepted head is accepted: %r" % bytes(data))
    print("%d fuzzed heads, %d accepted, %d failures in all" % (fuzzed, accepted, bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
