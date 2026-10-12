#!/usr/bin/env python3
"""Mutants of the rate limiter (docs/ratelimit.md section 10, gate 6, and section 13.4, gate 16): copy the tree, apply one single edit, run the tests that should notice it.

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

# (id, file, old text (exactly once), new text, how it is killed first: "unit" runs `cancho test`, "gen" the generator tests, a list of e2e test names (the whole
# suite follows if those pass), or ("proxy", [test names]) for tests/proxy_test.py, and what the edit breaks)
M = []


def m(ident, path, old, new, kill, what):
    M.append((ident, path, old, new, kill, what))


R = "src/ratelimit.cho"
# ---- the arithmetic
m("a01", R, "    if gained >= cap - have {\n        return cap;\n    }\n    return have + gained;", "    return have + gained;", "unit", "the refill is not capped at the burst")
m("a02", R, "    if elapsed > max_elapsed() {\n        elapsed = max_elapsed();\n    }", "", "unit", "a huge elapsed time is not cut (the product overflows)")
m("a03", R, "    if now > last {\n        if last < 0 {", "    if true {\n        if last < 0 {", "unit", "a clock that goes back gains negative time")
m("a05", R, "    let ms = (deficit + r - 1) / r;\n", "    let ms = deficit / r;\n", "unit", "the milliseconds of a wait are rounded down")
m("a06", R, "    return (ms + 999) / 1000;\n}\n\n// Two polynomial", "    return ms / 1000;\n}\n\n// Two polynomial", "unit", "the seconds of a wait are rounded down")
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
m("p02", P, "    st[p + shared.ws_mode()] = 0;\n    if verdict > ratelimit.route_offset() {", "    if verdict > ratelimit.route_offset() {", ["an_upgrade_is_limited_and_a_limited_upgrade_takes_no_tunnel_place"], "a limited upgrade keeps its place among the tunnels")
m("p03", P, '        refuse(tab, core, k, 429, "limit.rate", now);', '        refuse(tab, core, k, 429, "limit.rate-table", now);', ["over_the_limit_is_a_429_with_a_retry_after_and_the_upstream_never_sees_it"], "a spent bucket is reported as a full table")
m("p04", P, "        st[p + shared.retry_after()] = verdict;", "        st[p + shared.retry_after()] = 0;", ["over_the_limit_is_a_429_with_a_retry_after_and_the_upstream_never_sees_it"], "limit.rate carries no Retry-After")
m("p05", P, "    if route.rate(sel) == 0 {\n        return false;", "    if false {\n        return false;", ["under_the_limit_everything_passes"], "a route with no limit is limited")
m("p06", P, "        metrics.rate_refused(contents(core.stats), sel, false);", "", ["the_counters_agree_with_what_the_clients_were_told"], "limit.rate is not counted")
m("p07", P, "        st[p + shared.retry_after()] = 0 - verdict;", "        st[p + shared.retry_after()] = 0;", ["a_full_table_refuses_a_new_key_and_still_serves_an_old_one"], "limit.rate-table carries no Retry-After")
m("p08", P, "route.rate_base(sel), route.rate_buckets(sel), element, route.rate(sel)", "0, route.rate_buckets(sel), element, route.rate(sel)", ["a_limit_on_one_route_does_not_touch_another", "two_header_keys_are_limited_independently"], "every route uses the first buckets of the table")
m("p09", P, "        let element = ratelimit.key(view, tb, route.rate_key(sel));", "        let element = \"\";", ["two_header_keys_are_limited_independently"], "every request has the absent key")
m("p10", P, "element, route.rate(sel), route.rate_per_ms(sel), route.rate_burst(sel), route.rate_ceiling_at(sel), route.rate_ceiling(sel), route.rate_ceiling_per_ms(sel), route.rate_ceiling_burst(sel), now);",
  "element, route.rate(sel), route.rate_per_ms(sel), route.rate_burst(sel), route.rate_ceiling_at(sel), route.rate_ceiling(sel), route.rate_ceiling_per_ms(sel), route.rate_ceiling_burst(sel), 0);", ["a_burst_then_a_refill_after_the_wait_it_named"], "the clock is not passed")
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
m("g09", G, "        for key in (\"rate_burst\", \"rate_key\", \"rate_buckets\", \"rate_route_limit\", \"rate_route_burst\", \"rate_xff_prefix\"):\n            if key in r:", "        for key in (\"rate_burst\", \"rate_key\", \"rate_route_limit\", \"rate_route_burst\", \"rate_xff_prefix\"):\n            if key in r:", "gen", "rate_buckets without rate_limit is accepted")
m("g10", G, "        r[\"base\"] = base\n        base += r[\"buckets\"]", "        r[\"base\"] = 0\n        base += r[\"buckets\"]", "gen", "every route's table begins at bucket 0")


# ======== slice 2 (docs/ratelimit.md section 13): the route-wide ceiling, the IPv6 key, the generator's new rules, the half-open trial
# ---- the ceiling's verdict (src/ratelimit.cho)
m("c01", R, "    if verdict != 0 || c_rate < 1 {\n        return verdict;\n    }", "    if c_rate < 1 {\n        return verdict;\n    }", "unit", "a request its own key refused asks the ceiling too, and may be admitted by it")
m("c02", R, "    let wait = admit(table, ceil_at, 1, \"\", c_rate, c_per_ms, c_burst, now);\n    if wait == 0 {\n        return 0;\n    }", "    let wait = admit(table, ceil_at, 1, \"\", c_rate, c_per_ms, c_burst, now);\n    if wait == 0 {\n        return verdict;\n    }\n    if verdict != 0 {\n        return verdict;\n    }", "unit", "a request its own key refused spends a token of the ceiling")
m("c03", R, "    return route_offset() + wait;\n}", "    return wait;\n}", "unit", "the ceiling's refusal looks like the key's own")
m("c04", R, "let wait = admit(table, ceil_at, 1, \"\", c_rate, c_per_ms, c_burst, now);", "let wait = admit(table, ceil_at, 1, \"\", rate, per_ms, burst, now);", "unit", "the ceiling is limited at the key's rate and burst")
m("c05", R, "let wait = admit(table, ceil_at, 1, \"\", c_rate, c_per_ms, c_burst, now);", "let wait = admit(table, ceil_at, 1, \"\", c_rate, c_per_ms, c_rate, now);", "unit", "the ceiling's burst is its rate")
m("c06", R, "let wait = admit(table, ceil_at, 1, \"\", c_rate, c_per_ms, c_burst, now);", "let wait = admit(table, ceil_at, 1, key, c_rate, c_per_ms, c_burst, now);", "unit", "the ceiling is a bucket of the key, not of the route")
m("c07", R, "pub fn route_offset() -> [] int {\n    return 1000000;", "pub fn route_offset() -> [] int {\n    return 100;", "unit", "the ceiling's verdicts overlap the key's")
m("c08", R, "    return route_offset() + wait;\n}", "    return route_offset() + 1;\n}", "unit", "the ceiling's refusal names no wait")
m("c09", R, "    if verdict != 0 || c_rate < 1 {", "    if verdict != 0 || c_rate < 0 {", "unit", "a ceiling of 0 is a ceiling")
m("c10", R, "    if ceil_at >= len(table) / bucket_ints() {\n        return route_offset() + 1;\n    }", "", "unit", "a ceiling far outside the table is read (the sum overflows)")
m("c11", R, "    if wait < 0 {\n        return route_offset() + 1;\n    }", "", "unit", "a ceiling outside the table is admitted")
m("c12", R, "    if wait == 0 {\n        return 0;\n    }", "    if wait <= 0 {\n        return 0;\n    }", "unit", "a ceiling outside the table is admitted (the table's refusal is taken for a token)")
# ---- the ceiling in the loop and the record
m("e01", P, "element, route.rate(sel), route.rate_per_ms(sel), route.rate_burst(sel), route.rate_ceiling_at(sel), route.rate_ceiling(sel),", "element, route.rate(sel), route.rate_per_ms(sel), route.rate_burst(sel), route.rate_ceiling_at(sel), 0,", ["forty_distinct_keys_against_a_ceiling_of_five_admit_exactly_five"], "the ceiling is never applied")
m("e02", P, "        metrics.rate_route_refused(contents(core.stats), sel);", "        metrics.rate_refused(contents(core.stats), sel, false);", ["forty_distinct_keys_against_a_ceiling_of_five_admit_exactly_five"], "a ceiling refusal is counted as the key's")
m("e03", P, "        metrics.rate_route_refused(contents(core.stats), sel);\n", "", ["forty_distinct_keys_against_a_ceiling_of_five_admit_exactly_five"], "a ceiling refusal is not counted")
m("e04", P, "        refuse(tab, core, k, 429, \"limit.rate-route\", now);", "        refuse(tab, core, k, 429, \"limit.rate\", now);", ["forty_distinct_keys_against_a_ceiling_of_five_admit_exactly_five"], "a ceiling refusal carries the key's rule")
m("e05", P, "        st[p + shared.retry_after()] = verdict - ratelimit.route_offset();", "        st[p + shared.retry_after()] = 0;", ["forty_distinct_keys_against_a_ceiling_of_five_admit_exactly_five"], "a ceiling refusal carries no Retry-After")
m("e06", P, "        st[p + shared.retry_after()] = verdict - ratelimit.route_offset();", "        st[p + shared.retry_after()] = verdict;", ["forty_distinct_keys_against_a_ceiling_of_five_admit_exactly_five"], "a ceiling refusal's Retry-After keeps the offset")
m("e07", P, "    st[p + shared.ws_mode()] = 0;\n    if verdict > ratelimit.route_offset() {", "    if verdict > ratelimit.route_offset() {", ["a_limited_upgrade_by_the_ceiling_takes_no_tunnel_place"], "an upgrade the ceiling refused keeps its place among the tunnels")
m("e08", "src/route.cho", "return number(bytes.field(blob[at..line_end(blob, at)], 9, 30));", "return number(bytes.field(blob[at..line_end(blob, at)], 9, 16));", ["forty_distinct_keys_against_a_ceiling_of_five_admit_exactly_five", "a_key_refused_by_its_own_bucket_takes_nothing_from_the_ceiling"], "the ceiling is the first bucket of the route's table")
m("e09", "src/route.cho", "return number(bytes.field(blob[at..line_end(blob, at)], 9, 29));", "return number(bytes.field(blob[at..line_end(blob, at)], 9, 27));", ["a_key_refused_by_its_own_bucket_takes_nothing_from_the_ceiling"], "the ceiling's burst is its rate")
m("e10", "src/route.cho", "return number(bytes.field(blob[at..line_end(blob, at)], 9, 28));", "return number(bytes.field(blob[at..line_end(blob, at)], 9, 29));", ["the_ceilings_retry_after_is_a_wait_that_works"], "the ceiling's period is its burst")
m("n05", "src/metrics.cho", "        let at = route_index * route_block() + 40;", "        let at = route_index * route_block() + 39;", "unit-or-e2e", "the ceiling's counter overwrites a token counter")
m("n06", "src/metrics.cho", '        k = jnum(out, k, "rate_route_limited", stats[base + 40]);', '        k = jnum(out, k, "rate_route_limited", stats[base + 24]);', "unit-or-e2e", "the JSON shows the table's counter for the ceiling's")
m("n07", "src/metrics.cho", '        k = sample(out, k, "rate_route_limited_total", "", "route", route.name(i), stats[i * route_block() + 40]);', '        k = sample(out, k, "rate_route_limited_total", "", "route", route.name(i), stats[i * route_block() + 23]);', "unit-or-e2e", "Prometheus shows the key's counter for the ceiling's")
m("q03", "src/metrics.cho", "        bytes = bytes + 1836 + 316 + 130 + 850 + 112 + 42 * len(route.name(i));", "        bytes = bytes + 1836 + 316 + 130 + 850 + 42 * len(route.name(i));", "unit-or-e2e", "the scrape buffer is sized without the ceiling's counter")
# ---- the IPv6 key (src/ipkey.cho): the unit test and its vectors, from Python's ipaddress
I = "src/ipkey.cho"
m("v01", I, "        if keep < 8 {\n            var unit = 1;", "        if keep < 7 {\n            var unit = 1;", "unit", "the bit before the prefix's end is not cut")
m("v02", I, "        var keep = bits - m * 8;", "        var keep = bits - m * 8 + 1;", "unit", "the prefix is one bit too long")
m("v03", I, "        var keep = bits - m * 8;\n        if keep < 0 {\n            keep = 0;\n        }", "        var keep = bits - m * 8;", "unit", "a byte past the prefix keeps a negative number of bits")
m("v04", I, "    return int_of(buf[at + 10]) == 255 && int_of(buf[at + 11]) == 255;", "    return false;", "unit", "an IPv4-mapped address is aggregated like any other")
m("v05", I, "    return int_of(buf[at + 10]) == 255 && int_of(buf[at + 11]) == 255;", "    return int_of(buf[at + 10]) == 255;", "unit", "::ff:xx is taken for IPv4-mapped")
m("v06", I, "    while i < 10 {\n        if int_of(buf[at + i]) != 0 {", "    while i < 9 {\n        if int_of(buf[at + i]) != 0 {", "unit", "a nonzero ninth byte is taken for IPv4-mapped")
m("v07", I, "            if j - i > 4 || n >= 8 {", "            if j - i > 5 || n >= 8 {", "unit", "a group of five digits is an address")
m("v08", I, "            if j - i > 4 || n >= 8 {", "            if j - i > 4 {", "unit", "a ninth group is written past the address")
m("v09", I, "                if gap >= 0 {\n                    return false;\n                }\n                gap = n;", "                gap = n;", "unit", "a second :: is an address")
m("v10", I, "                i = i + 1;\n                if i >= len(t) {\n                    return false;\n                }", "                i = i + 1;", "unit", "a trailing single colon is an address")
m("v11", I, "            if digits > 0 && octet == 0 {", "            if false {", "unit", "a dotted quad may have leading zeros")
m("v12", I, "            if digits > 3 || octet > 255 {", "            if digits > 3 || octet > 256 {", "unit", "an octet may be 256")
m("v13", I, "            if j != len(t) || n > 6 {", "            if n > 6 {", "unit", "a dotted quad need not be last")
m("v14", I, "            if int_of(elem[close + 1]) != ':' || digits < 1 || digits > 5 {", "            if int_of(elem[close + 1]) != ':' || digits < 1 || digits > 6 {", "unit", "a port may have six digits")
m("v15", I, "            if int_of(elem[close + 1]) != ':' || digits < 1 || digits > 5 {", "            if digits < 1 || digits > 5 {", "unit", "anything may follow the bracket")
m("v16", I, "    if len(elem) < 2 || len(elem) > element_max() || len(buf) < scratch_len() {", "    if len(elem) < 2 || len(elem) > element_max() {", "unit", "a scratch that is too small is written")
m("v17", I, "    if len(t) < 2 || len(t) > literal_max() || at < 0 || at + 16 > len(buf) {", "    if len(t) < 2 || at < 0 || at + 16 > len(buf) {", "unit", "a literal of any length is read")
m("v18", I, "        if int_of(t[1]) != ':' {\n            return false;\n        }\n        gap = 0;", "        gap = 0;", "unit", "a leading single colon is an address")
m("v19", I, "    if gap < 0 {\n        return n == 8;\n    }", "    if gap < 0 {\n        return n >= 7;\n    }", "unit", "seven groups are an address")
m("v20", I, "    if n > 7 {\n        return false;\n    }\n    // The groups after", "    // The groups after", "unit", "a :: that stands for no group is an address")
m("v21", I, "        buf[at + 15 - m] = buf[at + gap * 2 + tail - 1 - m];", "        buf[at + 15 - m] = buf[at + gap * 2 + tail - m];", "unit", "the groups after :: are moved one byte off")
m("v22", I, "    var bits = prefix;\n    if bits < 1 {\n        bits = 128;\n    }", "    var bits = prefix;", "unit", "a prefix below 1 overflows (or aggregates everything)")
m("v23", I, "            v = bv / unit * unit;", "            v = bv / unit;", "unit", "the masked byte is shifted, not cut")
m("v24", I, "    if int_of(elem[0]) == '[' {", "    if int_of(elem[0]) == '(' {", "unit", "brackets are not understood")
m("v25", I, "            k = out.put_int(buf, k, int_of(buf[at + 12 + m]));", "            k = out.put_int(buf, k, int_of(buf[at + 11 + m]));", "unit", "the IPv4 address of a mapped one is read one byte off")
m("v26", I, "        k = out.put_hex(buf, k, v, 2);", "        k = out.put_hex(buf, k, v, 1);", "unit", "the key is not padded: 0x0a and 0xa0 are one key")
# ---- the IPv6 key in the loop
m("w01", P, "        if route.rate_xff_prefix(sel) > 0 {", "        if false {", ["an_ipv6_host_rotating_inside_its_prefix_is_one_bucket"], "the prefix is never applied")
m("w02", P, "aggregated = ipkey.aggregate(element, route.rate_xff_prefix(sel), scratch);", "aggregated = ipkey.aggregate(element, 64, scratch);", ["a_prefix_of_128_tells_every_address_apart_and_a_prefix_of_48_aggregates_more"], "every route aggregates on /64")
m("w03", P, "route.rate_buckets(sel), scratch[0..aggregated], route.rate(sel)", "route.rate_buckets(sel), element, route.rate(sel)", ["an_ipv6_host_rotating_inside_its_prefix_is_one_bucket"], "the aggregated key is computed and not used")
m("w04", P, "        if aggregated > 0 {\n            verdict", "        if aggregated >= 0 {\n            verdict", ["what_is_not_an_ipv6_literal_is_keyed_on_its_text_as_before", "ipv4_is_keyed_as_before_and_an_ipv4_mapped_address_is_the_ipv4_address"], "an element that is not a literal has the empty key")
m("w05", "src/route.cho", "return number(bytes.field(blob[at..line_end(blob, at)], 9, 31));", "return number(bytes.field(blob[at..line_end(blob, at)], 9, 30));", ["an_ipv6_host_rotating_inside_its_prefix_is_one_bucket"], "the prefix is read from the ceiling's bucket")
# ---- the generator's rules 9 to 14
m("h01", G, "if not cm or int(cm.group(1)) > RATE_MAX:", "if not cm:", "gen", "a ceiling of 1,000,001 a second is accepted")
m("h02", G, "if not isinstance(c_burst, int) or isinstance(c_burst, bool) or not 1 <= c_burst <= BURST_MAX:", "if not isinstance(c_burst, int) or not 1 <= c_burst <= BURST_MAX:", "gen", "a boolean is a ceiling's burst")
m("h03", G, "    elif \"rate_route_burst\" in r:\n        bad(", "    elif False:\n        bad(", "gen", "rate_route_burst is accepted without rate_route_limit")
m("h04", G, "        if key == \"r\":\n            bad('rate_route_limit has no meaning", "        if False:\n            bad('rate_route_limit has no meaning", "gen", "a route key may have a ceiling")
m("h05", G, "or not XFF_PREFIX_RANGE[0] <= prefix <= XFF_PREFIX_RANGE[1]:", "or not 0 <= prefix <= XFF_PREFIX_RANGE[1]:", "gen", "a prefix of 0 is accepted")
m("h06", G, "or not XFF_PREFIX_RANGE[0] <= prefix <= XFF_PREFIX_RANGE[1]:", "or not XFF_PREFIX_RANGE[0] <= prefix <= 129:", "gen", "a prefix of 129 is accepted")
m("h07", G, "    elif \"rate_xff_prefix\" in r:\n        bad(", "    elif False:\n        bad(", "gen", "a prefix is accepted with a key that is not an address")
m("h08", G, "            r[\"c_at\"] = base\n            base += 1\n", "            r[\"c_at\"] = base\n", "gen", "the ceiling's bucket is not counted in the table")
m("h09", G, "            r[\"c_at\"] = base\n", "            r[\"c_at\"] = r[\"base\"]\n", "gen", "the ceiling is the first bucket of its route")
m("h10", G, "prefix = r.get(\"rate_xff_prefix\", XFF_PREFIX)", "prefix = r.get(\"rate_xff_prefix\", 128)", "gen", "the default prefix is 128")
m("h11", G, "if not isinstance(prefix, int) or isinstance(prefix, bool) or not XFF_PREFIX_RANGE[0]", "if not isinstance(prefix, int) or not XFF_PREFIX_RANGE[0]", "gen", "a boolean is a prefix")
# ---- the circuit's half-open trial (src/proxy.cho): tests/proxy_test.py
T = "the_half_open_trial_has_one_life_from_open_to_closed"
m("x01", P, "        h[b + 1] = now + shared.circuit_open_ms();", "        h[b + 1] = now + shared.circuit_open_ms() / 4;", ("proxy", [T]), "a reopened circuit stays open for a quarter of a period")
m("x02", P, "    if h[b + 2] != 0 && now < h[b + 2] {\n        return 2;\n    }\n", "", ("proxy", [T]), "a trial in flight does not hold the others back")
m("x03", P, "    h[b] = 0;\n    h[b + 1] = 0;\n    h[b + 2] = 0;", "    h[b] = 0;\n    h[b + 2] = 0;", ("proxy", [T]), "a trial's success leaves the circuit half open")
m("x04", P, "    h[b] = 0;\n    h[b + 1] = 0;\n    h[b + 2] = 0;", "    h[b + 1] = 0;\n    h[b + 2] = 0;", ("proxy", [T]), "a trial's success does not forget the failures")
m("x05", P, "        h[b + 1] = now + shared.circuit_open_ms();", "        h[b + 1] = h[b + 1];", ("proxy", [T]), "a failed trial does not reopen the circuit")
m("x06", P, "    if now < h[b + 1] {\n        return 2;\n    }\n", "", ("proxy", [T]), "an open circuit admits everything")
m("x07", P, "    h[b + 2] = now + shared.connect_ms() + shared.upstream_ms();\n    return 1;", "    return 1;", ("proxy", [T]), "the trial is never recorded as in flight")
m("x08", P, "        h[b + 1] = now + shared.circuit_open_ms();\n        h[b + 2] = 0;", "        h[b + 1] = now + shared.circuit_open_ms();", ("proxy", [T]), "a failed trial is never replaced by another")
m("x09", P, "    if h[b] >= shared.circuit_threshold() {\n        h[b + 1] = now + shared.circuit_open_ms();", "    if h[b] > shared.circuit_threshold() {\n        h[b + 1] = now + shared.circuit_open_ms();", ("proxy", [T]), "the circuit opens one failure late")


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
        elif isinstance(kill, tuple):
            attempts = [("proxy", kill[1])]
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
            elif how == "proxy":
                r = subprocess.run([sys.executable, str(tmp / "tests" / "proxy_test.py")] + names, cwd=tmp, capture_output=True, text=True, env=env, timeout=900)
                out = r.stdout + r.stderr
                if "build failed" in out or "error:" in out and "tests," not in out:
                    return ident, what, "INVALID", out.strip().splitlines()[-1][:200]
                if r.returncode != 0:
                    return ident, what, "KILLED", ("proxy_test: " + ", ".join(failing(out)[:3])) if failing(out) else "proxy_test: " + out.strip().splitlines()[-1][:120]
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
