#!/usr/bin/env python3
"""The site's data figures, drawn from the recorded benchmark results (bench/results/*.json) so that a number on the page is a number in a file.

    python3 scripts/figures.py          # write docs/figures/bench.svg and memory.svg, and the benchmark tables inside docs/evidence.html
    python3 scripts/figures.py --check  # exit 1 if the committed figures or tables differ from what the results give

Each SVG is self-contained (its own colours, light and dark), because it is shown with <img>.
"""

import json
import pathlib
import statistics
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
RESULTS = ROOT / "bench" / "results"
CELLS = [("C1", "keep-alive, 64 connections"), ("C1b", "keep-alive, 8 connections"), ("C2", "Connection: close"), ("C3", "64 KiB response"), ("C4", "16 KiB POST")]

STYLE = """<style>
.t{fill:#14171c;font:600 13px system-ui,sans-serif}.s{fill:#5b6573;font:12px system-ui,sans-serif}.v{fill:#14171c;font:600 12px system-ui,sans-serif}.v,.s{paint-order:stroke;stroke:#fbfbfc;stroke-width:4px;stroke-linejoin:round}
.a{fill:#265e8d}.b{fill:#a89f8f}.ref{stroke:#5b6573;stroke-width:1.4;stroke-dasharray:4 3}.tick{stroke:#14171c;stroke-width:2}.grid{stroke:#e1e4ea;stroke-width:1}
@media (prefers-color-scheme:dark){.v,.s{stroke:#0d1217}.t,.v{fill:#e8eaee}.s{fill:#9ba5b3}.a{fill:#6fa3d6}.b{fill:#8c8576}.ref{stroke:#9ba5b3}.tick{stroke:#e8eaee}.grid{stroke:#232932}}
</style>"""


def ratios(path, key, other, cell):
    """Per-round ratios key / other for one cell, from one results file (the rounds are interleaved, so they are paired)."""
    data = json.loads(path.read_text())["cells"][cell]
    a = {r["run"]: r["rps"] for r in data[key]}
    b = {r["run"]: r["rps"] for r in data[other]}
    return statistics.median(a[i] / b[i] for i in a)


def bench_svg():
    first, second = RESULTS / "2026-10-06.json", RESULTS / "2026-10-07.json"
    x0, scale, row = 210, 190, 74
    lines = ['<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 700 %d" role="img" aria-label="Throughput of cancho-gateway divided by nginx and by HAProxy in five benchmark cells, from two runs: it is above nginx only with Connection: close, and below HAProxy except there.">' % (60 + row * len(CELLS)), STYLE]
    lines.append('<text class="t" x="0" y="18">cancho-gateway ÷ the other proxy, requests per second</text>')
    lines.append('<text class="s" x="0" y="36">bar: second run, 2026-10-07 · tick: first run, 2026-10-06 · right of the dashed line, the gateway is faster</text>')
    ref = x0 + scale
    for i in range(1, 12):
        gx = x0 + scale * i * 0.2
        lines.append('<line class="grid" x1="%.1f" y1="48" x2="%.1f" y2="%d"/>' % (gx, gx, 48 + row * len(CELLS) - 6))
    lines.append('<line class="ref" x1="%d" y1="46" x2="%d" y2="%d"/>' % (ref, ref, 52 + row * len(CELLS) - 10))
    for n, (cell, label) in enumerate(CELLS):
        y = 56 + n * row
        lines.append('<text class="t" x="0" y="%d">%s</text><text class="s" x="0" y="%d">%s</text>' % (y + 14, cell, y + 30, label))
        for k, (other, cls, name) in enumerate((("nginx", "a", "nginx"), ("haproxy", "b", "HAProxy"))):
            r2 = ratios(second, "lexsys", other, cell)
            r1 = ratios(first, "lexsys", other, cell)
            by = y + k * 26
            lines.append('<rect class="%s" x="%d" y="%d" width="%.1f" height="18" rx="3"/>' % (cls, x0, by, scale * r2))
            lines.append('<line class="tick" x1="%.1f" y1="%d" x2="%.1f" y2="%d"/>' % (x0 + scale * r1, by - 3, x0 + scale * r1, by + 21))
            lines.append('<text class="v" x="%.1f" y="%d">%.2f</text><text class="s" x="%.1f" y="%d">÷ %s</text>' % (x0 + scale * max(r1, r2) + 8, by + 14, r2, x0 + scale * max(r1, r2) + 46, by + 14, name))
    lines.append("</svg>")
    return "\n".join(lines) + "\n"


def memory_svg():
    mem = json.loads((RESULTS / "2026-10-07.json").read_text())["memory"]
    order = [("lexsys", "cancho-gateway"), ("nginx", "nginx"), ("haproxy", "HAProxy"), ("caddy", "Caddy"), ("envoy", "Envoy"), ("traefik", "Traefik"), ("kong", "Kong")]
    top = max(mem[k]["after_kib"] for k, _ in order) / 1024
    x0, scale, row = 120, 360, 30
    lines = ['<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 560 %d" role="img" aria-label="Resident memory with 100 idle connections: cancho-gateway 1.9 MiB, nginx 11.8, HAProxy 14.9, Caddy 33, Envoy 59, Traefik 83, Kong 156.">' % (48 + row * len(order)), STYLE]
    lines.append('<text class="t" x="0" y="18">Resident memory with 100 idle connections, MiB</text>')
    for i, (k, name) in enumerate(order):
        mib = mem[k]["after_kib"] / 1024
        y = 32 + i * row
        w = max(3.0, scale * mib / top)
        lines.append('<text class="%s" x="0" y="%d">%s</text>' % ("t" if k == "lexsys" else "s", y + 15, name))
        lines.append('<rect class="%s" x="%d" y="%d" width="%.1f" height="20" rx="3"/>' % ("a" if k == "lexsys" else "b", x0, y, w))
        lines.append('<text class="v" x="%.1f" y="%d">%.1f</text>' % (x0 + w + 8, y + 15, mib))
    lines.append("</svg>")
    return "\n".join(lines) + "\n"


NAMES = [("lexsys", "cancho-gateway", True), ("lexsys-base", "cancho-gateway before the syscall change", False), ("nginx", "nginx 1.24", False), ("haproxy", "HAProxy 2.8", False),
         ("envoy", "Envoy 1.39", False), ("caddy", "Caddy 2.6", False), ("traefik", "Traefik 3.6", False), ("kong", "Kong 3.9", False)]
CELL_NAMES = CELLS + [("C5", "100 ms upstream, 64 connections (the ideal is 640 requests/s)")]


def bench_html():
    """The benchmark tables of docs/evidence.html, from the second run's results: every figure there is a figure in the file."""
    data = json.loads((RESULTS / "2026-10-07.json").read_text())
    out = []
    for cell, label in CELL_NAMES:
        out.append('<h3 id="%s">%s: %s</h3>' % (cell, cell, label))
        out.append('<div class="fitwrap"><table class="fit num"><thead><tr><th>proxy</th><th>requests/s, median (min&ndash;max)</th><th>p50 ms</th><th>p99 ms</th><th>proxy CPU</th></tr></thead><tbody>')
        for key, name, us in NAMES:
            runs = data["cells"][cell][key]
            rps = [r["rps"] for r in runs]
            out.append('<tr%s><th>%s</th><td class="n">%s (%s&ndash;%s)</td><td class="n">%.2f</td><td class="n">%.2f</td><td class="n">%d%%</td></tr>' % (
                ' class="us"' if us else "", name, format(round(statistics.median(rps)), ","), format(round(min(rps)), ","), format(round(max(rps)), ","),
                statistics.median(r["p50"] for r in runs), statistics.median(r["p99"] for r in runs), round(100 * statistics.median(r["proxy_cpu"] for r in runs))))
        out.append("</tbody></table></div>")
    out.append('<h3 id="oha">C1 again, open loop: 6,000 requests/s, oha with latency correction</h3>')
    out.append('<div class="fitwrap"><table class="fit num"><thead><tr><th>proxy</th><th>p50 ms</th><th>p99 ms, median (min&ndash;max)</th></tr></thead><tbody>')
    for key, name, us in NAMES:
        runs = data["cells"]["C1-oha"][key]
        p99 = [r["p99"] for r in runs]
        out.append('<tr%s><th>%s</th><td class="n">%.2f</td><td class="n">%.2f (%.2f&ndash;%.2f)</td></tr>' % (' class="us"' if us else "", name, statistics.median(r["p50"] for r in runs), statistics.median(p99), min(p99), max(p99)))
    out.append("</tbody></table></div>")
    out.append('<h3 id="memory">C6: resident memory, before and with 100 idle connections</h3>')
    out.append('<div class="fitwrap"><table class="fit num"><thead><tr><th>proxy</th><th>MiB before</th><th>MiB with 100 idle connections</th></tr></thead><tbody>')
    for key, name, us in NAMES:
        if key == "lexsys-base":
            continue
        m = data["memory"][key]
        out.append('<tr%s><th>%s</th><td class="n">%.1f</td><td class="n">%.1f</td></tr>' % (' class="us"' if us else "", name, m["before_kib"] / 1024, m["after_kib"] / 1024))
    out.append("</tbody></table></div>")
    return "\n".join(out) + "\n"


def splice(html, fragment):
    a, b = "<!-- bench:begin -->", "<!-- bench:end -->"
    i, j = html.index(a) + len(a), html.index(b)
    return html[:i] + "\n" + fragment + html[j:]


def main():
    out = {"bench.svg": bench_svg(), "memory.svg": memory_svg()}
    target = ROOT / "docs" / "figures"
    page = ROOT / "docs" / "evidence.html"
    spliced = splice(page.read_text(), bench_html()) if page.exists() else None
    if "--check" in sys.argv[1:]:
        stale = [n for n, t in out.items() if not (target / n).exists() or (target / n).read_text() != t]
        if spliced is not None and spliced != page.read_text():
            stale.append("evidence.html (benchmark tables)")
        print("stale: " + ", ".join(stale) if stale else "figures are current")
        return 1 if stale else 0
    target.mkdir(exist_ok=True)
    for n, t in out.items():
        (target / n).write_text(t)
        print("wrote docs/figures/" + n)
    if spliced is not None:
        page.write_text(spliced)
        print("wrote the benchmark tables into docs/evidence.html")
    return 0


if __name__ == "__main__":
    sys.exit(main())
