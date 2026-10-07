#!/usr/bin/env python3
"""The site's links (docs/*.html): every in-page anchor, every relative file and every link into this repository's own tree must exist.

    python3 scripts/check_site.py          # exit 1 and list the broken links

Links to other repositories and to the web are not fetched (CI has no business depending on them).
"""

import html.parser
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
RELEASE = "https://github.com/alpibrusl/cancho-gateway/releases/latest/download/"
REPO = re.compile(r"^https://github\.com/alpibrusl/cancho-gateway/(?:blob|tree)/main/?(.*)$")


class Page(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids, self.links = set(), []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if "id" in a:
            self.ids.add(a["id"])
        for key in ("href", "src"):
            if key in a and a[key]:
                self.links.append(a[key])


def parse(path):
    p = Page()
    p.feed(path.read_text())
    return p


def main():
    pages = {p.name: parse(p) for p in sorted(DOCS.glob("*.html"))}
    bad = []
    for name, page in pages.items():
        for link in page.links:
            if link.startswith(RELEASE) and link[len(RELEASE):] not in (ROOT / "scripts" / "release.sh").read_text():
                bad.append("%s: %s (release.sh builds no asset of that name)" % (name, link))
            if link.startswith(("http://", "https://", "mailto:")):
                m = REPO.match(link.split("#")[0])
                if m and not (ROOT / m.group(1)).exists():
                    bad.append("%s: %s (no such path in the repository)" % (name, link))
                continue
            target, _, anchor = link.partition("#")
            if not target:
                if anchor and anchor not in page.ids and anchor != "top":
                    bad.append("%s: #%s (no such id)" % (name, anchor))
                continue
            if not (DOCS / target).exists():
                bad.append("%s: %s (no such file in docs/)" % (name, link))
            elif anchor and target in pages and anchor not in pages[target].ids:
                bad.append("%s: %s (no such id in %s)" % (name, link, target))
    for b in bad:
        print("BROKEN " + b)
    print("%d pages, %d links checked, %d broken" % (len(pages), sum(len(p.links) for p in pages.values()), len(bad)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
