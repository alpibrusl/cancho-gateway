#!/usr/bin/env python3
"""Differential test of route selection: src/route.ls against tests/route_ref.py over generated tables and requests.

    python3 tests/route_test.py [TABLES] [REQUESTS]    # defaults: 12 tables, 400 requests each

For each seeded random deployment: scripts/generate.py validates it and writes the modules, the probe is built from them,
and every request's answer must equal the reference's. The requests are drawn from the table's own hosts and prefixes with
boundary, case, port, dot-segment, percent-escape, control-byte and unknown-method variants.
"""

import os
import pathlib
import random
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))
import generate  # noqa: E402
import route_ref  # noqa: E402

LEX = os.environ.get("LEX_SYS", "lex-sys")
METHODS = generate.METHODS
SEGMENTS = ["a", "api", "static", "v1", "x", "a.b", "..", ".", "api2"]


def random_deployment(rng):
    hosts = [None, None, "a.example", "b.example", "api.example.com", "10.0.0.7"]
    lines = ["listen = 8080", ""]
    for n in range(rng.randint(1, 4)):
        lines += ["[[upstream]]", 'name = "u%d"' % n, 'addr = "10.1.%d.1:%d"' % (n, 9000 + n), ""]
    for _ in range(rng.randint(1, 14)):
        prefix = "/" + "/".join(rng.choice(SEGMENTS[:7]) for _ in range(rng.randint(0, 3)))
        lines += ["[[route]]", 'upstream = "u%d"' % rng.randrange(1, 2)]
        lines += ['path_prefix = "%s"' % prefix]
        host = rng.choice(hosts)
        if host:
            lines += ['host = "%s"' % host]
        if rng.random() < 0.5:
            lines += ["methods = [%s]" % ", ".join('"%s"' % m for m in rng.sample(METHODS, rng.randint(1, 4)))]
        lines += ["max_body = %d" % rng.choice([0, 10, 1000, 1 << 20, 1 << 30]), ""]
    return "\n".join(lines)


def valid_deployment(rng):
    """A random deployment the generator accepts (it refuses ties; the draw is repeated until there are none)."""
    while True:
        text = random_deployment(rng).replace('upstream = "u1"', 'upstream = "u0"')
        with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as f:
            f.write(text)
        try:
            listen, ups, routes, _ = generate.load(f.name)
            return f.name, ups, routes
        except generate.Refusal:
            os.unlink(f.name)


def requests(rng, routes, count):
    named = [r["host"] for r in routes if r["host"]]
    junk_hosts = ["OTHER.example", "a.example:80", "A.EXAMPLE", "", "bad host", "a.example:", "[::1]", "x" * 254, "a_b.example",
                  "b.example:123456"]
    prefixes = [r["prefix"] for r in routes]
    out = []
    for _ in range(count):
        base = rng.choice(prefixes)
        if rng.random() < 0.6:
            # a clean request that exercises selection: the table's own hosts and prefixes, boundary tails, known methods
            tail = rng.choice(["", "", "/", "/x", "/x/y", "x", "x/y"])
            path = base.rstrip("/") + tail if base != "/" or tail.startswith("/") or not tail else "/" + tail
            host = rng.choice(named + ["other.example"] + [h.upper() + ":8080" for h in named])
            method = rng.choice(METHODS)
        else:
            tail = rng.choice(["", "/", "/x", "x", "/..", "/../x", "/./x", "//x", "/%2e", "/%2E%2e/x", "/%2f", "/%5C", "/%41",
                               "/%4", "/%zz", "%", "/a b", "/\x01", "/\x7f", "/\\x", "/\xff", "?", "/x?y"])
            path = rng.choice([base + tail, tail or "/", "", "x", "/" + rng.choice(SEGMENTS)])
            host = rng.choice(named + junk_hosts + ["other.example"])
            method = rng.choice(METHODS + ["get", "FETCH", "", "CONNECT", "TRACE"])
        out.append((host.encode(), method.encode(), path.encode("latin-1")))
    return out


def probe(binary, batch):
    args = [binary] + ["%s:%s:%s" % (h.hex(), m.hex(), p.hex()) for h, m, p in batch]
    out = subprocess.run(args, capture_output=True, text=True, timeout=60)
    if out.returncode != 0:
        raise SystemExit("probe exited %d: %s" % (out.returncode, out.stderr[:200]))
    return out.stdout.splitlines()


def expected(routes, h, m, p):
    ans = route_ref.select(routes, h, m, p)
    return "route %d %d %d" % (ans[1], ans[2], ans[3]) if ans[0] == "route" else "refuse %s %d" % (ans[1], ans[2])


# Fixed cases against deploy/example.toml, with literal expectations (not derived from the reference): the host picks the
# route set, the longest prefix wins on a segment boundary, a method the best prefix does not allow falls to a shorter one.
FIXED = [
    ("api.example.com", "GET", "/x", "route 0 0 1048576"),
    ("API.Example.COM:8443", "DELETE", "/anything", "route 0 0 1048576"),
    ("api.example.com", "GET", "/static/a", "route 0 0 1048576"),
    ("other.example", "GET", "/static/a", "route 1 1 0"),
    ("other.example", "HEAD", "/static", "route 1 1 0"),
    ("other.example", "POST", "/static/a", "route 2 1 1048576"),
    ("other.example", "GET", "/staticx", "route 2 1 1048576"),
    ("other.example", "GET", "/", "route 2 1 1048576"),
    ("other.example", "FETCH", "/", "refuse route.method 405"),
    ("other.example", "GET", "/a/../b", "refuse route.path 400"),
    ("other.example", "GET", "/a/%2e%2E/b", "refuse route.path 400"),
    ("other.example", "GET", "/a%2Fb", "refuse route.path 400"),
    ("other.example", "GET", "/a//b", "refuse route.path 400"),
    ("other.example", "GET", "", "refuse route.path 400"),
    ("other.example", "GET", "*", "refuse route.path 400"),
    ("", "GET", "/", "refuse route.host 400"),
    ("other.example:99999x", "GET", "/", "refuse route.host 400"),
    ("[::1]", "GET", "/", "refuse route.host 400"),
]


def fixed():
    binary = ROOT / "build" / "route_probe"
    batch = [(h.encode(), m.encode(), p.encode()) for h, m, p, _ in FIXED]
    got = probe(str(binary), batch)
    bad = 0
    for (h, m, p, want), g in zip(FIXED, got):
        if g != want:
            bad += 1
            print("FAIL fixed %r %s %r: got %r, want %r" % (h, m, p, g, want))
    print("%d fixed cases, %d failures" % (len(FIXED), bad))
    return bad


def main():
    if "--fixed" in sys.argv[1:]:
        return 1 if fixed() else 0
    tables = int(sys.argv[1]) if len(sys.argv) > 1 else 12
    per = int(sys.argv[2]) if len(sys.argv) > 2 else 400
    rng = random.Random(4)
    failures = total = hits = 0
    for t in range(tables):
        deploy, ups, routes = valid_deployment(rng)
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run([sys.executable, str(ROOT / "scripts" / "generate.py"), deploy, "--out", tmp], check=True)
            binary = os.path.join(tmp, "probe")
            built = subprocess.run([LEX, "build", "--std", os.path.join(tmp, "routes.ls"), str(ROOT / "src" / "route.ls"),
                                    str(ROOT / "src" / "route_probe.ls"), "-o", binary], capture_output=True, text=True)
            if built.returncode != 0:
                raise SystemExit("build failed: " + built.stderr[:300])
            batch = requests(rng, routes, per)
            got = probe(binary, batch)
            for (h, m, p), g in zip(batch, got):
                want = expected(routes, h, m, p)
                total += 1
                hits += want.startswith("route")
                if g != want:
                    failures += 1
                    print("FAIL table %d: host %r method %r path %r: got %r, want %r" % (t, h, m, p, g, want))
                    if failures > 20:
                        raise SystemExit(1)
            if len(got) != len(batch):
                failures += 1
                print("FAIL table %d: %d answers for %d requests" % (t, len(got), len(batch)))
        os.unlink(deploy)
    print("%d tables, %d requests (%d routed, %d refused), %d failures" % (tables, total, hits, total - hits, failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
