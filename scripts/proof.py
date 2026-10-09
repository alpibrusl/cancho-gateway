#!/usr/bin/env python3
"""The report tables on the proof page (docs/proof.html), spliced from the recorded authority reports
(manifests/*.authority.json) so the page cannot claim a bound the compiler did not derive, and cannot drift
from the ceiling a person reviews (authority.toml).

    python3 scripts/proof.py          # splice the tables into docs/proof.html
    python3 scripts/proof.py --check # change nothing; exit 1 if the page is stale

The fragment is everything between the two markers; the rest of the page is written by hand, like the
benchmark tables scripts/figures.py writes into docs/evidence.html.
"""
import html
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PAGE = ROOT / "docs" / "proof.html"
MANIFESTS = ROOT / "manifests"
BEGIN, END = "<!-- report:begin -->", "<!-- report:end -->"

# What a derived label means, in the words of docs/design.md section 3. A label the compiler derives but this
# table does not name is a build failure here: the page must explain every capability it reports.
MEANINGS = {
    "args": "the command line, for <code>--version</code>",
    "clock": "the clock, for deadlines (never logged as a timestamp)",
    "conn_accept": "accepting connections on the listening sockets",
    "conn_read": "reading from an open connection",
    "conn_write": "writing to an open connection",
    "dir_read": "reading a directory (the certificate directory, through a handle)",
    "file_read": "reading a file through a directory handle",
    "heap": "the heap: every slab is sized at start",
    "io_write": "standard output: the access log (and standard error)",
    "err_write": "standard error",
    "net_in(\"\")": "listening: the network bound is shared with connecting and <strong>not narrowed</strong>",
    "net_out(\"\")": "connecting: the upstream set is enforced in code and tested, not proved by the compiler",
    "poll": "the poller: one thread, one loop",
    "fs_read(\"/dev/urandom\")": "random bytes for TLS handshakes, exactly this device",
    "fs_read(\"/etc/cancho-gateway/tls\")": "the certificate directory compiled into the binary, exactly this path",
}
NEVER = ["ffi", "fs_write", "file_write", "dir_write", "exec", "fork"]


def label_text(label):
    if label["argument"] is None:
        return label["name"]
    return '%s("%s")' % (label["name"], label["argument"])


def load(name):
    return json.loads((MANIFESTS / ("%s.authority.json" % name)).read_text())


def row(label):
    text = label_text(label)
    meaning = MEANINGS.get(text)
    if meaning is None:
        sys.exit("proof.py: no meaning written for %s; the page must explain every derived label" % text)
    cls = "good" if label["bounded"] else "bad"
    bounded = "bounded" if label["bounded"] else "UNBOUNDED"
    return ('      <tr><th><code>%s</code></th><td>%s</td><td class="%s">%s</td></tr>'
            % (html.escape(text), meaning, cls, bounded))


def table(name, title, note):
    report = load(name)
    if not report.get("bounded", False):
        sys.exit("proof.py: %s is not bounded; the page refuses to show it" % name)
    if report.get("foreign_symbols"):
        sys.exit("proof.py: %s derives foreign symbols; the page refuses to show it" % name)
    labels = report["labels"]
    return [
        '  <div class="fitwrap"><table class="fit">',
        "    <thead><tr><th>%s &middot; <code>%s.authority.json</code></th><td>what it means</td><td>the compiler says</td></tr></thead>"
        % (html.escape(title), name),
        "    <tbody>",
    ] + [row(l) for l in labels] + [
        "    </tbody>",
        "  </table></div>",
        '  <p class="note">%s</p>' % html.escape(note),
    ]


def fragment():
    plain, tls = load("gateway"), load("gateway-tls")
    stats = [
        ('<div><b>0</b><span>files written, ever: <code>fs_write</code>, <code>file_write</code>, <code>dir_write</code> are not capabilities the binary has</span></div>'),
        ('<div><b>0</b><span>foreign calls: <code>ffi</code> is released at start; no C, no <code>unsafe</code></span></div>'),
        ('<div><b>%s</b><span>pure functions the compiler counted in the gateway, of every function it has</span></div>' % format(len(plain["pure"]), ",")),
        ('<div><b>2</b><span>paths the TLS build reads: <code>/dev/urandom</code> and the certificate directory; the build without <code>tls_listen</code> reads none</span></div>'),
    ]
    parts = ['  <div class="stats">'] + stats + ["  </div>"]
    parts += table("gateway", "The gateway, a build without TLS",
                   "The ceiling a person reviews is [gateway] in authority.toml; what the compiler derives may be smaller, never larger. This table is the derived set.")
    parts += table("gateway-tls", "The same program, built for deploy/examples/tls.toml",
                   "Exactly two named paths are added, and scripts/authority.py fails on any other fs_read. The generated modules replace the example's, so this is the TLS deployment's own report.")
    parts.append("  <p>Never in any build: <code>" + "</code>, <code>".join(NEVER) + "</code>. A change to either report fails CI before it fails a reader.")
    return "\n".join(parts) + "\n"


def splice(page, fragment_text):
    i, j = page.index(BEGIN) + len(BEGIN), page.index(END)
    return page[:i] + "\n" + fragment_text + page[j:]


def main():
    page = PAGE.read_text()
    if BEGIN not in page or END not in page:
        sys.exit("proof.py: docs/proof.html lacks the splice markers")
    spliced = splice(page, fragment())
    if "--check" in sys.argv[1:]:
        if spliced != page:
            print("stale: docs/proof.html (report tables)")
            return 1
        print("the proof page's report tables are current")
        return 0
    PAGE.write_text(spliced)
    print("wrote the report tables into docs/proof.html")
    return 0


if __name__ == "__main__":
    sys.exit(main())
