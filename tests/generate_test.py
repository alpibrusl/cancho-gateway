#!/usr/bin/env python3
"""Table tests of scripts/generate.py: the prefix rule, and one refusal per rule tag."""

import json
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import generate  # noqa: E402

PREFIX = [
    (["10.0.1.5:9000"], "10.0.1.5:9000"),                       # one upstream: exact
    (["10.0.1.5:9000", "10.0.1.6:9000"], "10.0.1."),
    (["10.0.1.5:9000", "10.0.1.50:9000"], "10.0.1."),           # shares '10.0.1.5', which would over-admit
    (["10.0.1.5:9000", "10.0.1.5:9001"], "10.0.1.5:"),   # cut at the colon
    (["10.0.1.5:9000", "192.168.0.1:9000"], ""),                # nothing shared: reported, not hidden
    (["a.internal:80", "b.internal:80"], ""),
    (["api.internal:80", "api.internal:81"], "api.internal:"),
]

UP = 'listen = 80\n[[upstream]]\nname = "a"\naddr = "10.0.0.1:1"\n'
R = '[[route]]\nupstream = "a"\n'

# (rule, line the refusal must name or None, deployment text)
REFUSALS = [
    ("config.listen", 1, 'listen = 0\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.listen", 1, 'listen = "80"\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.listen", 1, 'listen = true\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.upstream", 1, "listen = 80\n"),
    ("config.upstream", 4, 'listen = 80\n[[upstream]]\nname="a"\naddr="10.0.0.1"\n'),
    ("config.upstream", 4, 'listen = 80\n[[upstream]]\nname="a"\naddr="10.0.0.1:70000"\n'),
    ("config.upstream", 3, 'listen = 80\n[[upstream]]\nname="A"\naddr="10.0.0.1:1"\n'),
    ("config.upstream", 4, 'listen = 80\n[[upstream]]\nname="a"\naddr="evil\\"host:1"\n'),
    ("config.duplicate", 6, 'listen = 80\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n[[upstream]]\nname="a"\naddr="10.0.0.2:1"\n'),
    ("config.duplicate", 7, 'listen = 80\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n[[upstream]]\nname="b"\naddr="10.0.0.1:1"\n'),
    ("config.count", None, "listen = 80\n" + "".join('[[upstream]]\nname="u%d"\naddr="10.0.%d.%d:1"\n' % (i, i // 250, i % 250 + 1) for i in range(257))),
    ("config.read", 1, "listen = [unterminated\n"),
    ("config.timeout", 2, 'listen = 80\nheader_timeout_ms = 5\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.timeout", 2, 'listen = 80\nconnect_timeout_ms = "5s"\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.timeout", 2, 'listen = 80\ntotal_timeout_ms = 600001\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.timeout", 3, 'listen = 80\nheader_timeout_ms = 5000\ntotal_timeout_ms = 1000\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    # --- routes, with the line they must name
    ("config.unknown-key", 7, UP + R + 'path_pref = "/"\n'),
    ("config.unknown-key", 2, 'listen = 80\nlisten_port = 1\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.unknown-key", 3, 'listen = 80\n[[upstream]]\naddress = "10.0.0.1:1"\nname = "a"\n'),
    ("config.route", 7, UP + R + 'path_prefix = "api"\n'),
    ("config.route", 7, UP + R + 'path_prefix = "/api/"\n'),
    ("config.route", 7, UP + R + 'path_prefix = "/a//b"\n'),
    ("config.route", 7, UP + R + 'path_prefix = "/a/../b"\n'),
    ("config.route", 7, UP + R + 'path_prefix = "/a%2fb"\n'),
    ("config.route", 7, UP + R + 'path_prefix = "/a b"\n'),
    ("config.route", 7, UP + R + 'path_prefix = "/a\\\\b"\n'),
    ("config.route", 5, UP + R),
    ("config.route", 8, UP + R + 'path_prefix = "/"\nhost = "Example.com"\n'),
    ("config.route", 8, UP + R + 'path_prefix = "/"\nhost = "example.com:80"\n'),
    ("config.route", 8, UP + R + 'path_prefix = "/"\nmethods = ["GET", "FETCH"]\n'),
    ("config.route", 8, UP + R + 'path_prefix = "/"\nmethods = []\n'),
    ("config.route", 8, UP + R + 'path_prefix = "/"\nmethods = ["GET", "GET"]\n'),
    ("config.route", 8, UP + R + 'path_prefix = "/"\nmax_body = -1\n'),
    ("config.route", 8, UP + R + 'path_prefix = "/"\nmax_body = 1073741825\n'),
    ("config.route-upstream", 7, UP + '[[route]]\npath_prefix = "/"\nupstream = "b"\n'),
    ("config.route-conflict", 10, UP + R + 'path_prefix = "/x"\n' + R + 'path_prefix = "/x"\n'),
    ("config.route-conflict", 11, UP + R + 'path_prefix = "/x"\nmethods = ["GET", "POST"]\n' + R + 'path_prefix = "/x"\nmethods = ["POST"]\n'),
    ("config.routes", None, UP + "".join('[[route]]\nupstream = "a"\npath_prefix = "/r%d"\n' % i for i in range(257))),
]

# Accepted: a host-specific route beside a host-less one on the same prefix, and the same prefix with disjoint methods.
ACCEPTED = [
    UP + R + 'path_prefix = "/"\nhost = "a.example"\n' + R + 'path_prefix = "/"\n',
    UP + R + 'path_prefix = "/x"\nmethods = ["GET"]\n' + R + 'path_prefix = "/x"\nmethods = ["POST"]\n',
    UP + R + 'path_prefix = "/x"\nhost = "a.example"\n' + R + 'path_prefix = "/x"\nhost = "b.example"\n',
]


def run(text, *extra):
    with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as f:
        f.write(text)
    out = subprocess.run([sys.executable, str(ROOT / "scripts" / "generate.py"), f.name, "--explain", *extra],
                         capture_output=True, text=True)
    pathlib.Path(f.name).unlink()
    return out


def main():
    failures = 0
    for addrs, want in PREFIX:
        got = generate.intended_prefix(addrs)
        if got != want:
            print("FAIL prefix %s: got %r, want %r" % (addrs, got, want))
            failures += 1
    for rule, line, text in REFUSALS:
        out = run(text)
        try:
            answer = json.loads(out.stderr)
        except ValueError:
            answer = {}
        if out.returncode != 2 or answer.get("rule") != rule or (line is not None and answer.get("line") != line):
            print("FAIL refusal %s at line %s: exit %d, %r" % (rule, line, out.returncode, out.stderr.strip()[:140]))
            failures += 1
    for text in ACCEPTED:
        out = run(text)
        if out.returncode != 0:
            print("FAIL accepted deployment refused: %r" % out.stderr.strip()[:140])
            failures += 1
    # The hint for a misspelt key, and byte-stable refusal output (the same file, twice).
    with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as f:
        f.write(UP + R + 'path_pref = "/"\n')
    cmd = [sys.executable, str(ROOT / "scripts" / "generate.py"), f.name, "--explain"]
    first, second = (subprocess.run(cmd, capture_output=True, text=True).stderr for _ in range(2))
    pathlib.Path(f.name).unlink()
    if json.loads(first).get("hint") != "did you mean 'path_prefix'?" or first != second:
        print("FAIL the hint for a misspelt key, or the refusal is not byte-stable: %r" % first.strip())
        failures += 1
    print("%d prefix cases, %d refusal cases, %d accepted, %d failures" % (len(PREFIX), len(REFUSALS), len(ACCEPTED), failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
