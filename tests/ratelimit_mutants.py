#!/usr/bin/env python3
"""Mutants of the rate limiter (docs/ratelimit.md section 10, gate 6): copy the tree, apply one single edit, run the tests that should notice it.

    python3 tests/ratelimit_mutants.py [-j N] [ID ...]      # all mutants, or the named ones; N at a time (default 2)

A mutant is KILLED when a test fails, SURVIVED when none does (every test is then run, to be sure), INVALID when the edited tree does not build (the edit is
then wrong, not the tests). The output is the table section 12 of the document records. Needs `build/deps` filled by one `cancho build`.
"""

import concurrent.futures
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
LEX = os.environ.get("CANCHO", "cancho")

# (id, file, old text (exactly once), new text, how it is killed first: "unit" runs `cancho test`, "gen" the generator tests, or a list of e2e test names (the whole
# suite follows if those pass), and what the edit breaks)
M = []


def m(ident, path, old, new, kill, what):
    M.append((ident, path, old, new, kill, what))


R = "src/ratelimit.cho"
# ---- the arithmetic
m("a01", R, "    if gained >= cap - have {\n        return cap;\n    }\n    return have + gained;", "    return have + gained;", "unit", "the refill is not capped at the burst")
m("a02", R, "    if elapsed > max_elapsed() {\n        elapsed = max_elapsed();\n    }", "", "unit", "a huge elapsed time is not cut (the product overflows)")
m("a03", R, "    if now > last {\n        if last < 0 {", "    if true {\n        if last < 0 {", "unit", "a clock that goes back gains negative time")
m("a04", R, "    if have >= cap {\n        return cap;\n    }\n    var elapsed", "    var elapsed", "unit", "a damaged bucket above its capacity is kept")
m("a05", R, "    let ms = (deficit + r - 1) / r;\n    let secs", "    let ms = deficit / r;\n    let secs", "unit", "the milliseconds of a wait are rounded down")
m("a06", R, "    let secs = (ms + 999) / 1000;\n    if secs < 1 {\n        return 1;", "    let secs = ms / 1000;\n    if secs < 1 {\n        return 1;", "unit", "the seconds of a wait are rounded down")
m("a07", R, "    if secs < 1 {\n        return 1;\n    }\n    return secs;", "    return secs;", "unit", "a wait can be 0 seconds")
m("a08", R, "    if units >= per_ms {\n        table[at + 1] = units - per_ms;", "    if units > per_ms {\n        table[at + 1] = units - per_ms;", "unit", "a bucket holding exactly one token is refused")
m("a09", R, "        table[at + 1] = units - per_ms;\n        return 0;", "        table[at + 1] = units;\n        return 0;", "unit", "a request costs nothing")
m("a10", R, "    table[at + 2] = now;\n    if units >= per_ms {", "    if units >= per_ms {", "unit", "the clock of a bucket is never brought up to date")
m("a11", R, "    var deficit = per_ms - units;\n    if deficit < 1 {\n        deficit = 1;\n    }", "    var deficit = per_ms - units;", "unit", "a deficit of 0 or less is not clamped")
# ---- the table
m("t01", R, "refill(table[at + 1], table[at + 2], now, rate, per_ms, burst) >= cap {", "false {", "unit", "a bucket that has refilled is never taken over")
m("t02", R, "        if table[at] == 0 || refill(", "        if refill(", "unit", "an empty bucket is not free")
m("t03", R, "            table[at + 1] = cap;\n            table[at + 2] = now;\n            return spend", "            table[at + 1] = 0;\n            table[at + 2] = now;\n            return spend", "unit", "a new key starts with an empty bucket")
m("t04", R, "        if table[at] == fp {\n            return spend", "        if table[at] == fp + 1 {\n            return spend", "unit", "a key never finds its own bucket")
m("t05", R, "    return hash1(key) * 2147483648 + hash2(key) + 1;", "    return hash1(key) * 2147483648 + hash2(key);", "unit", "a fingerprint can be 0, the mark of an empty bucket")
m("t06", R, "    if secs > max_retry() {\n        secs = max_retry();\n    }", "", "unit", "the wait for a full table is not cut at a day")
m("t07", R, "        if i == 0 || ms < soonest {", "        if i == 0 || ms > soonest {", "unit", "a full table names the longest wait, not the shortest")
m("t08", R, "    if base < 0 || buckets < 1 || base + buckets > len(table) / bucket_ints() {", "    if base < 0 || buckets < 1 {", "unit", "a table that does not fit is read")
m("t09", R, "    if buckets < ways() {\n        return 1;\n    }", "", "unit", "a route of one bucket has a set of four")
m("t10", R, "    return (hash1(key) + hash2(key)) % 2147483647 % sets;", "    return hash1(key) % sets / 2 * 2;", "unit", "half the sets are never used")
m("t11", R, "        h = (h * 48271 + int_of(key[i]) + 1) % 2147483647;", "        h = (h * 48271 + int_of(key[i]) + 1) % 2147483647 % 1000003;", "unit", "the first hash has too few values")
m("t12", R, "        let at = first + i * bucket_ints();\n        if table[at] == fp {", "        let at = first + i * bucket_ints() + 3;\n        if table[at] == fp {", "unit", "a lookup reads the next bucket")
# ---- the key
m("k01", R, "        let last = int_of(spec[2]) == 'l';", "        let last = int_of(spec[2]) == 'f';", "unit", "the first and last forwarded-for elements are swapped")
m("k02", R, "        if count_named(src, table, name) != 1 {", "        if count_named(src, table, name) < 1 {", "unit", "a repeated header is keyed on its first value")
m("k03", R, "            if int_of(value[i]) == ',' && (last || cut < 0) {", "            if int_of(value[i]) == ',' && (cut < 0) {", "unit", "the last element is cut at the first comma")
m("k04", R, "        if is_lower(http.header_name(src, table, i), name) && (last || found < 0) {", "        if is_lower(http.header_name(src, table, i), name) && (found < 0) {", "unit", "the last forwarded-for header is the first")
m("k05", R, "        return bytes.trim(value[cut + 1..len(value)]);", "        return value[cut + 1..len(value)];", "unit", "the last element keeps its spaces")
m("k06", R, "    if int_of(spec[0]) == 'h' {", "    if int_of(spec[0]) == 'q' {", "unit", "a header key is the absent key")
m("k07", R, "    if len(spec) < 3 {\n        return src[0..0];\n    }", "", "unit", "a short spec is read past its end")
m("k08", R, "    if len(a) != len(lower) {\n        return false;\n    }\n    var i = 0;\n    while i < len(a) {\n        if bytes.to_lower(int_of(a[i])) != int_of(lower[i]) {", "    var i = 0;\n    while i < len(lower) {\n        if bytes.to_lower(int_of(a[i])) != int_of(lower[i]) {", "unit", "a header whose name extends the key's is the key")
# ---- the proxy, the refusal, the counters: end to end
P = "src/proxy.cho"
m("p01", P, "    if rate_limited(tab, core, k, sel, view, tb, now) {", "    if false && rate_limited(tab, core, k, sel, view, tb, now) {", ["over_the_limit_is_a_429_with_a_retry_after_and_the_upstream_never_sees_it"], "the limit is never applied")
m("p02", P, "    st[p + shared.ws_mode()] = 0;\n    if verdict > 0 {", "    if verdict > 0 {", ["an_upgrade_is_limited_and_a_limited_upgrade_takes_no_tunnel_place"], "a limited upgrade keeps its place among the tunnels")
m("p03", P, '        refuse(tab, core, k, 429, "limit.rate", now);', '        refuse(tab, core, k, 429, "limit.rate-table", now);', ["over_the_limit_is_a_429_with_a_retry_after_and_the_upstream_never_sees_it"], "a spent bucket is reported as a full table")
m("p04", P, "        st[p + shared.retry_after()] = verdict;", "        st[p + shared.retry_after()] = 0;", ["over_the_limit_is_a_429_with_a_retry_after_and_the_upstream_never_sees_it"], "limit.rate carries no Retry-After")
m("p05", P, "    if route.rate(sel) == 0 {\n        return false;", "    if false {\n        return false;", ["under_the_limit_everything_passes"], "a route with no limit is limited")
m("p06", P, "        metrics.rate_refused(contents(core.stats), sel, false);", "", ["the_counters_agree_with_what_the_clients_were_told"], "limit.rate is not counted")
m("p07", P, "        st[p + shared.retry_after()] = 0 - verdict;", "        st[p + shared.retry_after()] = 0;", ["a_full_table_refuses_a_new_key_and_still_serves_an_old_one"], "limit.rate-table carries no Retry-After")
m("p08", P, "route.rate_base(sel), route.rate_buckets(sel), ratelimit.key(view, tb, route.rate_key(sel)), route.rate(sel)", "0, route.rate_buckets(sel), ratelimit.key(view, tb, route.rate_key(sel)), route.rate(sel)", ["a_limit_on_one_route_does_not_touch_another", "two_header_keys_are_limited_independently"], "every route uses the first buckets of the table")
m("p09", P, "ratelimit.key(view, tb, route.rate_key(sel)), route.rate(sel)", "\"\", route.rate(sel)", ["two_header_keys_are_limited_independently"], "every request has the absent key")
m("p10", P, "route.rate_per_ms(sel), route.rate_burst(sel), now);", "route.rate_per_ms(sel), route.rate_burst(sel), 0);", ["a_burst_then_a_refill_after_the_wait_it_named"], "the clock is not passed")
m("q01", "src/problem.cho", "    if retry > 0 {\n        k = out.put(out, k, \"\\r\\nRetry-After: \");", "    if retry >= 0 {\n        k = out.put(out, k, \"\\r\\nRetry-After: \");", "unit", "every response carries a Retry-After")
m("q02", "src/problem.cho", '        return "Too Many Requests";', '        return "Error";', "unit", "a 429 has no reason")
m("n01", "src/metrics.cho", "        if table_full {\n            at = at + 1;\n        }", "", "unit-or-e2e", "a full table is counted as a spent bucket")
m("n02", "src/metrics.cho", "        var at = route_index * route_block() + 23;", "        var at = route_index * route_block() + 22;", "unit-or-e2e", "the counter overwrites the sum of the durations")
m("n03", "src/route.cho", "return number(bytes.field(blob[at..line_end(blob, at)], 9, 16));", "return number(bytes.field(blob[at..line_end(blob, at)], 9, 15));", ["a_limit_on_one_route_does_not_touch_another", "two_header_keys_are_limited_independently"], "a route's tables begin at its bucket count")
m("n04", "src/route.cho", "return number(bytes.field(blob[at..line_end(blob, at)], 9, 13));", "return number(bytes.field(blob[at..line_end(blob, at)], 9, 11));", ["a_burst_then_a_refill_after_the_wait_it_named"], "the burst is the rate")
# ---- the generator
G = "scripts/generate.py"
m("g01", G, 'if key.startswith("h:") and key[2:] in RATE_REFUSED_HEADERS:', "if False:", "gen", "a limit may be keyed on Host or Content-Length")
m("g02", G, 'if (key.startswith("x:") or key.startswith("h:") and key[2:] in RATE_CLAIM_HEADERS) and not trust:', "if False:", "gen", "a limit may be keyed on a forwarding claim the route does not believe")
m("g03", G, "or buckets % 4:", ":", "gen", "a table of 6 buckets is accepted")
m("g04", G, "        if base > BUCKETS_TOTAL:", "        if base >= BUCKETS_TOTAL:", "gen", "a deployment of exactly 65,536 buckets is refused")
m("g05", G, 'key = "h:" + spec[7:].lower()', 'key = "h:" + spec[7:]', "gen", "header names are not lowercased")
m("g06", G, '        if "rate_buckets" in r:\n            bad(', "        if False:\n            bad(", "gen", "rate_buckets is accepted with a route key")
m("g07", G, "if not m or int(m.group(1)) > RATE_MAX:", "if not m:", "gen", "a rate of 1,000,001 a second is accepted")
m("g08", G, "if not isinstance(burst, int) or isinstance(burst, bool) or not 1 <= burst <= BURST_MAX:", "if not isinstance(burst, int) or not 1 <= burst <= BURST_MAX:", "gen", "a boolean is a burst")
m("g09", G, "        for key in (\"rate_burst\", \"rate_key\", \"rate_buckets\"):\n            if key in r:", "        for key in (\"rate_burst\", \"rate_key\"):\n            if key in r:", "gen", "rate_buckets without rate_limit is accepted")
m("g10", G, "        r[\"base\"] = base\n        base += r[\"buckets\"]", "        r[\"base\"] = 0\n        base += r[\"buckets\"]", "gen", "every route's table begins at bucket 0")


def tree(tmp):
    for name in ("src", "scripts", "tests", "generated", "deploy"):
        shutil.copytree(ROOT / name, tmp / name, ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copy(ROOT / "cancho.toml", tmp / "cancho.toml")
    (tmp / "build").mkdir()
    shutil.copytree(ROOT / "build" / "deps", tmp / "build" / "deps")


def failing(output):
    return re.findall(r"^FAIL +(\S+)", output, re.M)


def run_mutant(mutant):
    ident, path, old, new, kill, what = mutant
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="rlmut"))
    try:
        tree(tmp)
        text = (tmp / path).read_text()
        if text.count(old) != 1:
            return ident, what, "INVALID", "the old text occurs %d times in %s" % (text.count(old), path)
        (tmp / path).write_text(text.replace(old, new))
        env = dict(os.environ, RL_TREE=str(tmp))
        if kill == "unit":
            attempts = [("unit", None), ("e2e", None)]
        elif kill == "unit-or-e2e":
            attempts = [("unit", None), ("e2e", None)]
        elif kill == "gen":
            attempts = [("gen", None)]
        else:
            attempts = [("e2e", kill), ("e2e", None)]
        for how, names in attempts:
            if how == "unit":
                r = subprocess.run([LEX, "test"], cwd=tmp, capture_output=True, text=True, env=env, timeout=900)
                out = r.stdout + r.stderr
                if "error:" in out and "test result" not in out:
                    return ident, what, "INVALID", out.strip().splitlines()[-1][:160]
                if r.returncode != 0:
                    names_ = re.findall(r"^test (test_\S+) \.\.\. FAILED", out, re.M)
                    return ident, what, "KILLED", "cancho test: " + (", ".join(names_[:3]) or "a build or run failure")
            elif how == "gen":
                r = subprocess.run([sys.executable, str(tmp / "tests" / "generate_test.py")], cwd=tmp, capture_output=True, text=True, env=env, timeout=600)
                if r.returncode != 0:
                    return ident, what, "KILLED", "generate_test: " + "; ".join(l[:90] for l in r.stdout.splitlines() if l.startswith("FAIL"))[:200]
            else:
                r = subprocess.run([sys.executable, str(ROOT / "tests" / "ratelimit_test.py")] + (names or []), cwd=ROOT, capture_output=True, text=True, env=env, timeout=1500)
                out = r.stdout + r.stderr
                if "build failed" in out:
                    return ident, what, "INVALID", out.strip().splitlines()[-1][:200]
                if r.returncode != 0:
                    return ident, what, "KILLED", ("e2e: " + ", ".join(failing(out)[:3])) if failing(out) else "e2e: " + out.strip().splitlines()[-1][:120]
        return ident, what, "SURVIVED", "no test failed, the whole suite included"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    args = sys.argv[1:]
    jobs = 2
    if args[:1] == ["-j"]:
        jobs, args = int(args[1]), args[2:]
    chosen = [x for x in M if not args or x[0] in args]
    with concurrent.futures.ThreadPoolExecutor(jobs) as pool:
        results = list(pool.map(run_mutant, chosen))
    width = max(len(r[1]) for r in results)
    for ident, what, verdict, detail in results:
        print("%-4s %-8s %-*s  %s" % (ident, verdict, width, what, detail))
    killed = sum(1 for r in results if r[2] == "KILLED")
    print("%d mutants: %d killed, %d survived, %d invalid" % (len(results), killed, sum(1 for r in results if r[2] == "SURVIVED"), sum(1 for r in results if r[2] == "INVALID")))
    return 0 if all(r[2] == "KILLED" for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
