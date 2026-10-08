#!/usr/bin/env python3
"""The site's links (docs/*.html): every in-page anchor, every relative file and every link into this repository's own tree must exist.

    python3 scripts/check_site.py          # exit 1 and list the broken links

Links to other repositories and to the web are not fetched (CI has no business depending on them).
"""

import html
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


def check_examples(bad):
    """Every deployment shown on the examples page is the file in deploy/examples/, line for line, so the page cannot drift from what runs."""
    page = (DOCS / "examples.html").read_text()
    for f in sorted((ROOT / "deploy" / "examples").glob("*.toml")):
        body = "\n".join(l for l in f.read_text().splitlines() if not l.startswith("# Used by"))
        if html.escape(body, quote=False) not in page:
            bad.append("examples.html: the deployment shown for %s is not the file's content" % f.name)


def check_seo(bad):
    """What a search engine reads: one title and description of a useful length, a canonical URL that is the page's own, one h1, social tags, valid
    JSON-LD, and a sitemap that lists every page."""
    import json
    base = "https://alpibrusl.github.io/cancho-gateway/"
    names = sorted(p.name for p in DOCS.glob("*.html"))
    for name in names:
        s = (DOCS / name).read_text()
        title = re.findall(r"<title>(.*?)</title>", s, re.S)
        desc = re.findall(r'<meta name="description" content="(.*?)"', s)
        canon = re.findall(r'<link rel="canonical" href="(.*?)"', s)
        if len(title) != 1 or not 20 <= len(html.unescape(title[0])) <= 65:
            bad.append("%s: one <title> of 20 to 65 characters" % name)
        if len(desc) != 1 or not 70 <= len(html.unescape(desc[0])) <= 165:
            bad.append("%s: one description of 70 to 165 characters" % name)
        want = base + ("" if name == "index.html" else name)
        if canon != [want]:
            bad.append("%s: canonical must be %s" % (name, want))
        if re.findall(r'<meta property="og:url" content="(.*?)"', s) != [want]:
            bad.append("%s: og:url must equal the canonical" % name)
        for tag in ("og:title", "og:description", "og:image"):
            if 'property="%s"' % tag not in s:
                bad.append("%s: missing %s" % (name, tag))
        for tag in ("twitter:card", "twitter:title", "twitter:description", "twitter:image"):
            if 'name="%s"' % tag not in s:
                bad.append("%s: missing %s" % (name, tag))
        if s.count("<h1") != 1:
            bad.append("%s: exactly one h1" % name)
        for block in re.findall(r'<script type="application/ld\+json">(.*?)</script>', s, re.S):
            try:
                json.loads(block)
            except ValueError as e:
                bad.append("%s: JSON-LD does not parse: %s" % (name, e))
        if "application/ld+json" not in s:
            bad.append("%s: no JSON-LD" % name)
    sitemap = (DOCS / "sitemap.xml").read_text() if (DOCS / "sitemap.xml").exists() else ""
    for name in names:
        if "<loc>%s</loc>" % (base + ("" if name == "index.html" else name)) not in sitemap:
            bad.append("sitemap.xml lacks %s" % name)
    if "Sitemap: " + base + "sitemap.xml" not in ((DOCS / "robots.txt").read_text() if (DOCS / "robots.txt").exists() else ""):
        bad.append("robots.txt must name the sitemap")


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
    check_examples(bad)
    check_seo(bad)
    for b in bad:
        print("BROKEN " + b)
    print("%d pages, %d links checked, %d broken" % (len(pages), sum(len(p.links) for p in pages.values()), len(bad)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
