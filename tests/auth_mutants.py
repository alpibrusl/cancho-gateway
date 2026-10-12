#!/usr/bin/env python3
"""Mutants of authentication (docs/auth.md section 10, gate 5): copy the tree, apply one single edit, run the tests that should notice it.

    python3 tests/auth_mutants.py [-j N] [ID ...]      # all mutants, or the named ones; N at a time (default 2)

A mutant is KILLED when a test fails, SURVIVED when none does (every test is then run, to be sure), INVALID when the edited tree does not build (the edit is
then wrong, not the tests). The output is the table section 12 of the document records. Needs `build/deps` filled by one `cancho build`.

An edit is one (old, new) pair, or a list of pairs when one idea needs two places (moving a call). A mutant listed as EQUIVALENT is expected to SURVIVE, and the document says why
no test could kill it.
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

# (id, file, edit, how it is killed first: "unit" runs `cancho test`, "gen" the generator tests, or a list of e2e test names (the whole suite follows if those pass), what the edit breaks)
M = []
EQUIVALENT = set()


def m(ident, path, edit, *rest):
    if isinstance(edit, str):
        old, (new, kill, what) = edit, rest
        M.append((ident, path, [(old, new)], kill, what))
    else:
        kill, what = rest
        M.append((ident, path, edit, kill, what))


A = "src/auth.cho"
# ---- the parsing
m("a01", A, "    if found > 1 {\n        return 2;\n    }", "    if found > 2 {\n        return 2;\n    }", "unit", "a header twice is accepted")
m("a02", A, "    if found == 0 {\n        return 1;\n    }", "    if found == 0 {\n        return 2;\n    }", "unit", "a missing header is malformed")
m("a03", A, "    return credential_ok_cap(cred, max_credential());", "    return credential_ok_cap(cred, max_credential() + 1);", "unit", "a credential of 257 bytes is accepted")
m("a04", A, "    if len(cred) < 1 || len(cred) > cap {", "    if len(cred) > cap {", "unit", "an empty credential is accepted")
m("a05", A, " || c == '_' || c == '~' || c == '+' || c == '/' || c == '=';", " || c == '_' || c == '~' || c == '+' || c == '/';", "unit", "'=' is outside the alphabet")
m("a06", A, " || c == '_' || c == '~' || c == '+' || c == '/' || c == '=';", " || c == '_' || c == '~' || c == '+' || c == '/' || c == '=' || c == ' ';", "unit", "a space is inside the alphabet")
m("a07", A, 'is_lower(value[0..6], "bearer")', 'bytes.equal(value[0..6], "bearer")', "unit", "the scheme is case-sensitive")
m("a08", A, " || int_of(value[6]) != ' ' {", " {", "unit", "any byte may follow the scheme")
m("a09", A, "    if len(value) < 7 ||", "    if len(value) < 6 ||", "unit", "the scheme alone is read past its end")
m("a10", A, "    if !bearer {\n        return value;\n    }", "    if true {\n        return value;\n    }", "unit", "a Bearer token is the whole value")
m("a12", A, "    return credential_of(http.header_value(src, table, at), is_lower(name, \"authorization\"));", "    return credential_of(http.header_value(src, table, at), true);", "unit", "every header is read as a Bearer token")
m("a13", A, "    if is_lower(http.header_name(src, table, i), name) {\n            found = found + 1;", "    if bytes.equal(http.header_name(src, table, i), name) {\n            found = found + 1;", "unit", "a header name is case-sensitive")
# ---- the comparison
m("c01", A, "        return '0' + v;\n    }\n    return 'a' + v - 10;", "        return '0' + v;\n    }\n    return 'A' + v - 10;", "unit", "the digest is written in uppercase")
m("c02", A, "    while i < hex_len() {\n        diff =", "    while i < hex_len() - 1 {\n        diff =", "unit", "the last digit of a digest is not compared")
m("c03", A, "    var diff = 0;\n    var i = 0;", "    var diff = 0;\n    var i = 1;", "unit", "the first digit of a digest is not compared")
m("c04", A, "        diff = diff | int_of(hex[i]) ^ int_of(blob[from + i]);", "        diff = int_of(hex[i]) ^ int_of(blob[from + i]);", "unit", "only the last digit decides")
m("c05", A, "    return (255 - diff) / 255;", "    return (256 - diff) / 255;", "unit", "a digit one bit off is a match")
m("c06", A, "found = found + (index + 1) * same_digest(hex, blob, tab + 1);", "found = found + index * same_digest(hex, blob, tab + 1);", "unit", "the first key is index 0, which means none")
m("c07", A, "found = found + (index + 1) * same_digest(hex, blob, tab + 1);", "found = found + (index + 1) * same_digest(hex, blob, tab);", "unit", "the digest is read from the tab")
m("c08", A, "    if from < 0 || from + hex_len() > len(blob) {\n        return 0;\n    }", "", "unit", "a digest past the table's end is read")
m("c09", A, "found = found + (index + 1) * same_digest(hex, blob, tab + 1);", "found = (index + 1) * same_digest(hex, blob, tab + 1);", "unit", "only the last key can be found")
m("c10", A, "        crypto.sha256(cred, digest);", "        crypto.sha256(cred[0..len(cred) / 2], digest);", "unit", "half the credential is hashed")
m("c11", A, "            return bytes.field(blob[at..end], 9, 1);", "            return bytes.field(blob[at..end], 9, 2);", "unit", "a key is named by its digest")
m("c12", A, "        if n == index {\n            return bytes.field", "        if n == index + 1 {\n            return bytes.field", "unit", "a key is named by its neighbour")
# ---- equivalent to the eye of a functional test: they change timing, never an answer (docs/auth.md section 4.3)
m("e01", A, "    while i < hex_len() {\n        diff =", "    while i < hex_len() && diff == 0 {\n        diff =", "unit", "a digest comparison stops at its first difference")
m("e02", A, "        while at < len(blob) {\n            let end = line_end(blob, at);\n            // The digest follows", "        while at < len(blob) && found == 0 {\n            let end = line_end(blob, at);\n            // The digest follows", "unit", "the keys after a match are not compared")
EQUIVALENT |= {"e01", "e02", "p16"}
m("k01", A, "        return true;\n    }\n    var v = 0;", "        return false;\n    }\n    var v = 0;", "unit", "a route that allows every key allows none")
m("k02", A, "            if any && v == index {", "            if any && v == index + 1 {", "unit", "a route's list is shifted by one")
m("k03", A, "        } else if bytes.is_digit(int_of(keys[i])) && v < 1000 {", "        } else if bytes.is_digit(int_of(keys[i])) {", "unit", "a huge number in a list overflows")
m("k04", A, "    if rule >= 1 && rule <= 3 {\n        return 401;", "    if rule >= 1 && rule <= 4 {\n        return 401;", "unit", "a forbidden key is a 401")
m("k05", A, '        return "auth.invalid";', '        return "auth.malformed";', "unit", "an unknown key is called malformed")
# ---- the refusal and the counters
Q = "src/problem.cho"
m("q01", Q, "    if status == 401 && len(challenge) > 0 {", "    if status >= 401 && len(challenge) > 0 {", "unit", "a 403 carries a challenge")
m("q02", Q, '        } else if bytes.equal(rule, "auth.invalid") {', '        } else if bytes.equal(rule, "auth.missing") {', "unit", "an unknown key is told its credential was not asked for")
m("q03", Q, '        if bytes.equal(rule, "auth.malformed") {', '        if bytes.equal(rule, "auth.missing") {', "unit", "a malformed credential is told it was missing")
m("q04", Q, '    if status == 401 {\n        return "Unauthorized";', '    if status == 401 {\n        return "Error";', "unit", "a 401 has no reason")
N = "src/metrics.cho"
m("n01", N, "        let at = route_index * route_block() + 24 + rule;", "        let at = route_index * route_block() + 25 + rule;", "unit", "the counters are one slot too far")
m("n02", N, "    if route_index >= 0 && route_index < routes() && rule >= 1 && rule <= 4 {", "    if route_index >= 0 && route_index < routes() && rule >= 1 && rule <= 5 {", "unit", "a fifth kind is written past the counters")
m("n03", N, '        k = jnum(out, k, "malformed", stats[base + 26]);', '        k = jnum(out, k, "malformed", stats[base + 25]);', "unit", "malformed shows the missing count")
F = "src/forward.cho"
m("f01", F, "        if copy && is(name, strip) {", '        if copy && is(name, "authorization") {', "unit", "the header stripped is always Authorization")
S = "src/shared.cho"
m("l01", S, "        identity = auth.identity(st[p + auth_slot()]);", "        identity = auth.identity(st[p + auth_slot()] + 1);", ["the_log_names_the_identity_last_and_never_the_key", "a_valid_key_the_route_does_not_allow_is_a_403"], "the log names the next key")
m("l02", S, "    if st[p + auth_slot()] > 0 {\n        identity", "    if false {\n        identity", ["the_log_names_the_identity_last_and_never_the_key", "a_valid_key_the_route_does_not_allow_is_a_403"], "the log never names the caller")
# ---- the proxy: end to end
P = "src/proxy.cho"
m("p01", P, "    if unauthenticated(tab, core, k, sel, view, tb, now) {\n        return 0;\n    }\n    if route.websocket(sel)", "    if false && unauthenticated(tab, core, k, sel, view, tb, now) {\n        return 0;\n    }\n    if route.websocket(sel)", ["each_bad_credential_is_refused_with_its_status_its_rule_and_its_challenge"], "authentication is never applied")
m("p02", P, [("    if unauthenticated(tab, core, k, sel, view, tb, now) {\n        return 0;\n    }\n    if route.websocket(sel)", "    if route.websocket(sel)"),
             ("    if rate_limited(tab, core, k, sel, view, tb, now) {\n        return 0;\n    }", "    if rate_limited(tab, core, k, sel, view, tb, now) || unauthenticated(tab, core, k, sel, view, tb, now) {\n        return 0;\n    }")], ["authentication_comes_before_the_rate_limiter_and_the_identity_is_its_key"], "authentication comes after the rate limiter")
m("p03", P, [("    if unauthenticated(tab, core, k, sel, view, tb, now) {\n        return 0;\n    }\n    if route.websocket(sel)", "    if route.websocket(sel)"),
             ("    let max_body = route.max_body(sel);\n    if http.is_chunked(tb) {", "    if unauthenticated(tab, core, k, sel, view, tb, now) {\n        return 0;\n    }\n    let max_body = route.max_body(sel);\n    if http.is_chunked(tb) {")], ["a_websocket_upgrade_is_authenticated_and_a_refused_one_takes_no_tunnel_place"], "a refused upgrade keeps its place among the tunnels")
m("p04", P, "            st[p + shared.auth_slot()] = found;\n", "", ["authentication_comes_before_the_rate_limiter_and_the_identity_is_its_key"], "the caller is not remembered")
m("p05", P, "            if !auth.allowed(route.auth_keys(sel), found - 1) {", "            if false {", ["a_valid_key_the_route_does_not_allow_is_a_403"], "a key is allowed on every route")
m("p06", P, "            if !auth.allowed(route.auth_keys(sel), found - 1) {", "            if !auth.allowed(route.auth_keys(sel), 0) {", ["a_valid_key_the_route_does_not_allow_is_a_403"], "only the first key is ever allowed")
m("p07", P, "            strip = route.auth_header(st[p + 31] - 1);", '            strip = "";', ["a_valid_key_passes_and_the_credential_is_not_forwarded"], "the credential is forwarded")
m("p08", P, " && route.auth_forward(st[p + 31] - 1) == 0 {", " {", ["auth_forward_keeps_the_credential"], "the credential is never forwarded")
m("p09", P, "st[p + 23] % 2 == 1, st[p + tlsio.f_mode()] != 0, shared.meta_get(core, k, 4, 0), strip);\n        } else {", 'st[p + 23] % 2 == 1, st[p + tlsio.f_mode()] != 0, shared.meta_get(core, k, 4, 0), "");\n        } else {', ["a_websocket_upgrade_is_authenticated_and_a_refused_one_takes_no_tunnel_place"], "the credential reaches a WebSocket upstream")
m("p10", P, "    metrics.auth_refused(contents(core.stats), sel, rule);", "    metrics.auth_refused(contents(core.stats), sel, 1);", ["the_counters_agree_with_what_the_clients_were_told"], "every refusal is counted as missing")
m("p11", P, "    metrics.auth_refused(contents(core.stats), sel, rule);\n", "", ["the_counters_agree_with_what_the_clients_were_told"], "a refusal is not counted")
m("p12", P, "        challenge = route.auth_challenge(st[p + 31] - 1);", '        challenge = "";', ["each_bad_credential_is_refused_with_its_status_its_rule_and_its_challenge"], "a 401 invites no credential")
m("p13", P, "        let cred = auth.credential(view, tb, header);", '        let cred = auth.credential(view, tb, "authorization");', ["a_valid_key_passes_and_the_credential_is_not_forwarded"], "the credential is always read from Authorization")
m("p14", P, "    var rule = auth.parse_cap(view, tb, header, cap);", '    var rule = auth.parse_cap(view, tb, "authorization", cap);', ["each_bad_credential_is_refused_with_its_status_its_rule_and_its_challenge"], "the credential is always parsed from Authorization")
m("p15", P, "auth.identity(st[p + shared.auth_slot()]), route.rate(sel)", 'auth.key_name(0 - 1), route.rate(sel)', ["authentication_comes_before_the_rate_limiter_and_the_identity_is_its_key"], "every caller shares the bucket of the empty key")
m("p16", P, "auth.identity(st[p + shared.auth_slot()]), route.rate(sel)", "auth.identity(st[p + shared.auth_slot()] + 1), route.rate(sel)", ["authentication_comes_before_the_rate_limiter_and_the_identity_is_its_key"], "every caller spends its neighbour's bucket")
m("p17", P, "            if found == 0 {\n                rule = 3;", "            if found < 0 {\n                rule = 3;", ["each_bad_credential_is_refused_with_its_status_its_rule_and_its_challenge"], "an unknown key is admitted as no one")
m("p18", P, "    refuse(tab, core, k, auth.status(rule), auth.tag(rule), now);", "    refuse(tab, core, k, 401, auth.tag(rule), now);", ["a_valid_key_the_route_does_not_allow_is_a_403"], "a forbidden key is a 401")
# ---- the generator
G = "scripts/generate.py"
m("g01", G, 'KEY_DIGEST = re.compile(r"[0-9a-f]{64}")', 'KEY_DIGEST = re.compile(r"[0-9a-fA-F]{64}")', "gen", "an uppercase digest is accepted")
m("g02", G, '        if any(digest == d for _, d in api_keys):', "        if False:", "gen", "two names may share a digest")
m("g03", G, "MAX_KEYS = 64", "MAX_KEYS = 65", "gen", "65 keys are accepted")
m("g04", G, "    if auth_routes and listen != 0 and not plain_ok:", "    if False:", "gen", "a key may cross a plain listener without the flag")
m("g05", G, '"auth_header": lower,', '"auth_header": header,', "gen", "the header name is not lowercased")
m("g06", G, '",".join(str(key_names.index(n)) for n in allowed)', '",".join(str(key_names.index(n) + 1) for n in allowed)', "gen", "a route's key list is shifted by one")
m("g07", G, "AUTH_REFUSED_HEADERS = RATE_REFUSED_HEADERS + RATE_CLAIM_HEADERS + [", "AUTH_REFUSED_HEADERS = RATE_REFUSED_HEADERS + [", "gen", "a forwarding claim may carry a key")
m("g08", G, '    if api_keys and not any(r["auth"] & 1 for r in routes):', "    if False:", "gen", "keys that protect nothing are compiled in")
m("g09", G, '    if key == "a" and identities is None:', "    if False:", "gen", "the identity is a rate key on a route without one")
m("g10", G, 'KEY_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,31}")', 'KEY_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}")', "gen", "a key name may be in uppercase")
m("g11", G, '    if not isinstance(forward, bool):', "    if False:", "gen", "auth_forward may be a string")
m("g12", G, '        if any(kname == n for n, _ in api_keys):', "        if False:", "gen", "two keys may share a name")
m("g13", G, '    if "auth_allow_plain" in doc and (not auth_routes or listen == 0):', '    if "auth_allow_plain" in doc and (not auth_routes):', "gen", "the flag is accepted without a plain listener")
m("g14", G, '        challenge = \'ApiKey realm="cancho-gateway", header="%s"\' % lower', "        challenge = 'Bearer realm=\"cancho-gateway\"'", "gen", "a route that reads X-Api-Key invites a Bearer token")
m("g15", G, '"%s\\t%s\\n" % k for k in api_keys', '"%s\\t%s\\n" % (k[0], k[1].upper()) for k in api_keys', "gen", "the digests are compiled in uppercase")
m("g17", G, "        if crowded:", "        if False:", "gen", "more identities than a set of four buckets can hold are accepted")
m("g18", G, "            slot = 0 if sets < 2 else (h1 + h2) % 2147483647 % sets", "            slot = 0 if sets < 2 else h1 % sets", "gen", "the set is chosen by another hash than the gateway's")
m("g16", G, '        if auth["auth"] & 1 and not api_keys:', "        if False:", "gen", "a route nobody can enter is accepted")
M_ = "scripts/mkkey.py"
m("s01", M_, '    return "ck_" + base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")', '    return "ck_" + base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()', "gen", "a key ends in '='")
m("s02", M_, '    print("key for %s (shown once; the gateway cannot show it again): %s" % (names[0], key), file=sys.stderr)', '    print("key for %s (shown once; the gateway cannot show it again): %s" % (names[0], key))', "gen", "the key goes to standard output, where a redirect would put it in the file")
m("s03", M_, "hashlib.sha256(key.encode()).hexdigest()", "hashlib.sha256(key.encode()).hexdigest().upper()", "gen", "the digest is written in uppercase")
m("s04", M_, "secrets.token_bytes(32)", "secrets.token_bytes(8)", "gen", "a key of 64 bits")


def tree(tmp):
    for name in ("src", "scripts", "tests", "generated", "deploy"):
        shutil.copytree(ROOT / name, tmp / name, ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copy(ROOT / "cancho.toml", tmp / "cancho.toml")
    (tmp / "build").mkdir()
    shutil.copytree(ROOT / "build" / "deps", tmp / "build" / "deps")


def failing(output):
    return re.findall(r"^FAIL +(\S+)", output, re.M)


def run_mutant(mutant):
    ident, path, edits, kill, what = mutant
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="authmut"))
    try:
        tree(tmp)
        text = (tmp / path).read_text()
        for old, new in edits:
            if text.count(old) != 1:
                return ident, what, "INVALID", "the old text occurs %d times in %s" % (text.count(old), path)
            text = text.replace(old, new)
        (tmp / path).write_text(text)
        env = dict(os.environ, AUTH_TREE=str(tmp), RL_TREE=str(tmp))
        if kill == "unit":
            attempts = [("unit", None), ("gen", None), ("e2e", None)]
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
                r = subprocess.run([sys.executable, str(ROOT / "tests" / "auth_test.py")] + (names or []), cwd=ROOT, capture_output=True, text=True, env=env, timeout=1500)
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
    survived = [r[0] for r in results if r[2] == "SURVIVED"]
    print("%d mutants: %d killed, %d survived (%s), %d invalid" % (len(results), killed, len(survived), ", ".join(survived), sum(1 for r in results if r[2] == "INVALID")))
    return 0 if all(r[2] == "KILLED" or r[0] in EQUIVALENT and r[2] == "SURVIVED" for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
