#!/usr/bin/env python3
"""Table tests of scripts/generate.py: the prefix rule, and one refusal per rule tag."""

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

REFUSALS = [
    ("config.listen", 'listen = 0\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.listen", 'listen = "80"\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.listen", 'listen = true\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n'),
    ("config.upstream", "listen = 80\n"),
    ("config.upstream", 'listen = 80\n[[upstream]]\nname="a"\naddr="10.0.0.1"\n'),
    ("config.upstream", 'listen = 80\n[[upstream]]\nname="a"\naddr="10.0.0.1:70000"\n'),
    ("config.upstream", 'listen = 80\n[[upstream]]\nname="A"\naddr="10.0.0.1:1"\n'),
    ("config.upstream", 'listen = 80\n[[upstream]]\nname="a"\naddr="evil\\"host:1"\n'),
    ("config.duplicate", 'listen = 80\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n[[upstream]]\nname="a"\naddr="10.0.0.2:1"\n'),
    ("config.duplicate", 'listen = 80\n[[upstream]]\nname="a"\naddr="10.0.0.1:1"\n[[upstream]]\nname="b"\naddr="10.0.0.1:1"\n'),
    ("config.count", "listen = 80\n" + "".join('[[upstream]]\nname="u%d"\naddr="10.0.%d.%d:1"\n' % (i, i // 250, i % 250 + 1) for i in range(257))),
    ("config.read", "listen = [unterminated\n"),
]


def main():
    failures = 0
    for addrs, want in PREFIX:
        got = generate.intended_prefix(addrs)
        if got != want:
            print("FAIL prefix %s: got %r, want %r" % (addrs, got, want))
            failures += 1
    for rule, text in REFUSALS:
        with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as f:
            f.write(text)
        out = subprocess.run([sys.executable, str(ROOT / "scripts" / "generate.py"), f.name, "--explain"],
                             capture_output=True, text=True)
        pathlib.Path(f.name).unlink()
        if out.returncode != 2 or ('"rule":"%s"' % rule) not in out.stderr:
            print("FAIL refusal %s: exit %d, stderr %r" % (rule, out.returncode, out.stderr.strip()[:120]))
            failures += 1
    print("%d prefix cases, %d refusal cases, %d failures" % (len(PREFIX), len(REFUSALS), failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
