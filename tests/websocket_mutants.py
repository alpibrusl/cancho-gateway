#!/usr/bin/env python3
"""Mutants of the WebSocket code (docs/websocket.md section 12, gate 8): copy the tree, apply one single edit, run the tests that should notice it.

    python3 tests/websocket_mutants.py [-j N] [ID ...]      # all mutants, or the named ones; N at a time (default 2)

A mutant is KILLED when a test fails, SURVIVED when none does (every test is then run, to be sure), INVALID when the edited tree does not build (the edit is
then wrong, not the tests). The output is the table section 13 of the document records. Needs `build/deps` filled by one `cancho build`.
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


# ---- the handshake checks (src/websocket.cho), judged request by request
m("w01", "src/websocket.cho", 'if !bytes.equal(http.method(src, table), "GET") {', "if false {", "unit", "the method is not checked")
m("w02", "src/websocket.cho", "if http.version(table) != 11 {", "if false {", "unit", "HTTP/1.0 is admitted")
m("w03", "src/websocket.cho", 'if count_named(src, table, count, "upgrade") != 1 || !is(value_of(src, table, first_named(', 'if count_named(src, table, count, "upgrade") < 1 || !is(value_of(src, table, first_named(', "unit", "two Upgrade headers are admitted")
m("w04", "src/websocket.cho", '!is(value_of(src, table, first_named(src, table, count, "upgrade")), "websocket")', "false", "unit", "any Upgrade protocol is admitted")
m("w05", "src/websocket.cho", "} else if !loose && !is(tok, \"keep-alive\") {", "} else if false {", "unit", "any other Connection token is admitted")
m("w06", "src/websocket.cho", 'if count_named(src, table, count, "connection") != 1 || !connection_upgrade(value_of(src, table, conn), false) {', 'if !connection_upgrade(value_of(src, table, conn), false) {', "unit", "two Connection headers are admitted")
m("w07", "src/websocket.cho", 'if count_named(src, table, count, "content-length") > 0 || count_named(src, table, count, "transfer-encoding") > 0 {\n        return 0 - 4;', 'if count_named(src, table, count, "transfer-encoding") > 0 {\n        return 0 - 4;', "unit", "a Content-Length (even 0) is admitted")
m("w08", "src/websocket.cho", 'if count_named(src, table, count, "content-length") > 0 || count_named(src, table, count, "transfer-encoding") > 0 {\n        return 0 - 4;', 'if count_named(src, table, count, "content-length") > 0 {\n        return 0 - 4;', "unit", "a Transfer-Encoding is admitted")
m("w09", "src/websocket.cho", "if len(src) > http.body_start(table) {", "if false {", "unit", "bytes pipelined behind the head are admitted")
m("w10", "src/websocket.cho", '!bytes.equal(value_of(src, table, version), "13")', "false", "unit", "any version is admitted")
m("w11", "src/websocket.cho", 'count_named(src, table, count, "sec-websocket-version") != 1 ||', "", "unit", "two version headers are admitted")
m("w12", "src/websocket.cho", "return c == 'A' || c == 'Q' || c == 'g' || c == 'w';", "return true;", "unit", "a non-canonical key is admitted")
m("w13", "src/websocket.cho", "if int_of(v[22]) != '=' || int_of(v[23]) != '=' {", "if false {", "unit", "a key without its padding is admitted")
m("w14", "src/websocket.cho", "if len(v) != 24 {", "if len(v) < 22 {", "unit", "a key of the wrong length is admitted")
m("w15", "src/websocket.cho", "if entries(protocols) > 0 && mask == 0 {", "if false {", "unit", "a client that offers none of the route's subprotocols is admitted")
m("w16", "src/websocket.cho", "if entries(protocols) == 0 && sp >= 0 {\n        return 0 - 8;\n    }\n    let origin", "if false {\n        return 0 - 8;\n    }\n    let origin", "unit", "a subprotocol is admitted on a route that serves none")
m("w17", "src/websocket.cho", "if items > max_offered() {", "if items > 1000 {", "unit", "a list of 17 subprotocols is admitted")
m("w18", "src/websocket.cho", "if origin >= 0 && !csv_has(origins, value_of(src, table, origin)) {", "if false {", "unit", "every Origin is admitted")
m("w19", "src/websocket.cho", 'if count_named(src, table, count, "origin") > 1 {', 'if count_named(src, table, count, "origin") > 2 {', "unit", "two Origin headers are admitted")
m("w20", "src/websocket.cho", "mask = mask | 1 << j - 1;", "mask = mask | 1;", "unit", "the offered mask names the first subprotocol only")
# ---- the upstream's 101
m("r01", "src/websocket.cho", "!bytes.equal(value_of(src, table, acc), expected)", "false", "unit", "the accept value is not compared")
m("r02", "src/websocket.cho", "!bytes.equal(value_of(src, table, acc), expected)", "!bytes.equal(value_of(src, table, acc)[0..27], expected[0..27])", "unit", "the accept value is compared on a prefix")
m("r03", "src/websocket.cho", 'if count_named(src, table, count, "sec-websocket-accept") != 1 ||', 'if count_named(src, table, count, "sec-websocket-accept") < 1 ||', "unit", "two accept headers are admitted")
m("r04", "src/websocket.cho", 'if count_named(src, table, count, "upgrade") != 1 || !is(value_of(src, table, up), "websocket") {', 'if false {', "unit", "a 101 without Upgrade: websocket is admitted")
m("r05", "src/websocket.cho", 'if count_named(src, table, count, "connection") != 1 || !connection_upgrade(value_of(src, table, conn), true) {', 'if false {', "unit", "a 101 without Connection: Upgrade is admitted")
m("r06", "src/websocket.cho", 'if count_named(src, table, count, "content-length") > 0 || count_named(src, table, count, "transfer-encoding") > 0 {\n        return 0 - 11;', 'if false {\n        return 0 - 11;', "unit", "a 101 with a body header is admitted")
m("r07", "src/websocket.cho", "if bytes.equal(bytes.field(protocols, ',', j), chosen) && mask / (1 << j - 1) % 2 == 1 {", "if bytes.equal(bytes.field(protocols, ',', j), chosen) {", "unit", "a subprotocol the client did not offer is admitted")
m("r08", "src/websocket.cho", "if sp < 0 {\n            return 0 - 13;\n        }", "if false {\n            return 0 - 13;\n        }", "unit", "no subprotocol is admitted where the route requires one")
m("r09", "src/websocket.cho", "if entries(protocols) == 0 && sp >= 0 {\n        return 0 - 13;\n    }\n    if entries(protocols) > 0 {", "if false {\n        return 0 - 13;\n    }\n    if entries(protocols) > 0 {", "unit", "a subprotocol is admitted where the route serves none")
m("r10", "src/websocket.cho", 'if count_named(src, table, count, "sec-websocket-extensions") > 0 {', "if false {", "unit", "an unsolicited extension is admitted")
m("r11", "src/websocket.cho", 'return "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";', 'return "258EAFA5-E914-47DA-95CA-C5AB0DC85B12";', "unit", "the GUID is wrong")
m("r12", "src/sha1.cho", "k = 0x5a827999;", "k = 0x5a82799a;", "unit", "a SHA-1 round constant is wrong")
m("r13", "src/sha1.cho", "f = wb & wc | wb & wd | wc & wd;", "f = wb & wc | wb & wd;", "unit", "SHA-1's majority function is wrong")
m("r14", "src/b64.cho", "a[62] = byte_of('+');", "a[62] = byte_of('-');", "unit", "the base64 alphabet is wrong")
m("r15", "src/websocket.cho", 'k = out.put(out, k, "\\r\\nVia: 1.1 cancho-gateway\\r\\nX-Request-Id: ");', 'k = out.put(out, k, "\\r\\nServer: upstream\\r\\nVia: 1.1 cancho-gateway\\r\\nX-Request-Id: ");', "unit", "the 101 head carries a field nobody checked")
# ---- the other modules
m("f01", "src/forward.cho", 'if copy && upgrade && is(name, "sec-websocket-extensions") {', 'if copy && false && is(name, "sec-websocket-extensions") {', "unit", "Sec-WebSocket-Extensions is forwarded")
m("f02", "src/forward.cho", 'k = out.put(out, k, "Connection: Upgrade\\r\\nUpgrade: websocket\\r\\n");', 'k = out.put(out, k, "Connection: close\\r\\n");', "unit", "the upstream is not told it is an upgrade")
m("f03", "src/response.cho", "if code < 100 || code == 101 && !upgrade {", "if code < 100 {", "unit", "a 101 is accepted for every request")
m("f04", "src/problem.cho", 'k = out.put(out, k, "\\r\\nSec-WebSocket-Version: 13");', 'k = out.put(out, k, "");', "unit", "a 426 does not name the version")
m("f05", "src/accesslog.cho", ",\\\"upgrade\\\":\\\"websocket\\\"", ",\\\"upgrade\\\":\\\"websock\\\"", "unit", "the log's upgrade value is wrong")
m("f06", "src/route.cho", "return number(bytes.field(blob[at..line_end(blob, at)], 9, 8));", "return number(bytes.field(blob[at..line_end(blob, at)], 9, 7));", ["handshake_selects_the_subprotocol_and_the_head_has_only_checked_fields"], "the route's websocket column is read from the wrong place")
# ---- the proxy (src/proxy.cho, src/shared.cho): end to end
m("p01", "src/proxy.cho", "if route.websocket(sel) == 1 && websocket.asks_upgrade(view, tb) {", "if route.websocket(sel) == 2 && websocket.asks_upgrade(view, tb) {", ["handshake_selects_the_subprotocol_and_the_head_has_only_checked_fields", "refusals_before_the_dial_each_have_their_tag_and_never_reach_the_upstream", "a_route_without_websocket_ignores_the_upgrade"], "no route is a websocket route")
m("p02", "src/proxy.cho", "if shared.tunnels(core, false) >= deploy.ws_max_tunnels() {", "if shared.tunnels(core, false) > deploy.ws_max_tunnels() {", ["the_limit_refuses_the_fourth_and_frees_with_a_close"], "the limit is off by one")
m("p03", "src/proxy.cho", "if shared.tunnels(core, false) >= deploy.ws_max_tunnels() {", "if shared.tunnels(core, false) >= 1000 {", ["the_limit_refuses_the_fourth_and_frees_with_a_close", "a_hundred_and_twenty_tunnels_at_once_and_the_next_is_refused"], "the limit is not applied")
m("p04", "src/proxy.cho", "        st[p + 16] = 0;\n        st[p + 17] = 1;\n    }\n    st[p + 3] = 1;", "        st[p + 16] = 0;\n    }\n    st[p + 3] = 1;", ["a_tunnel_connection_is_never_pooled"], "an upgrade may take a pooled connection")
m("p05", "src/proxy.cho", "if st[pc + shared.ws_mode()] == 1 {\n                    r = response.parse_upgrade(view, tb);", "if st[pc + shared.ws_mode()] == 7 {\n                    r = response.parse_upgrade(view, tb);", ["handshake_selects_the_subprotocol_and_the_head_has_only_checked_fields"], "a 101 is never accepted")
m("p06", "src/proxy.cho", "    if verdict < 0 {\n        health_fail(tab, core, st[pu + 11], now);", "    if false {\n        health_fail(tab, core, st[pu + 11], now);", ["the_upstreams_refusals_of_the_upgrade_each_have_their_tag"], "the upstream's 101 is not checked")
m("p07", "src/proxy.cho", "    if verdict < 0 {\n        health_fail(tab, core, st[pu + 11], now);\n        refuse(", "    if verdict < 0 {\n        refuse(", ["the_circuit_counts_a_bad_101_and_closes_on_a_good_one"], "a bad 101 is not a failure of the upstream")
m("p08", "src/proxy.cho", "    health_ok(core, st[pu + 11]);\n    let n = websocket.upgrade_response", "    let n = websocket.upgrade_response", ["the_circuit_counts_a_bad_101_and_closes_on_a_good_one"], "a good 101 is not a success of the upstream")
m("p09", "src/proxy.cho", "            st[pc + 27] = st[pc + 27] + take;\n            st[pc + 7] = now + deploy.ws_idle_ms();", "            st[pc + 27] = st[pc + 27] + take;", ["traffic_from_the_upstream_alone_keeps_a_tunnel_open"], "the idle timer is not reset by the upstream's bytes")
m("p10", "src/proxy.cho", "            st[p + 28] = st[p + 28] + take;\n            st[p + 7] = now + deploy.ws_idle_ms();", "            st[p + 28] = st[p + 28] + take;", ["traffic_from_the_client_alone_keeps_a_tunnel_open"], "the idle timer is not reset by the client's bytes")
m("p11", "src/proxy.cho", "    st[pc + 12] = now + deploy.ws_lifetime_ms();", "    st[pc + 12] = 0;", ["a_busy_tunnel_is_closed_at_the_lifetime"], "the lifetime is not applied")
m("p12", "src/proxy.cho", "            if st[p + 12] != 0 && now >= st[p + 12] {\n                shared.meta_put(core, k, 68, 40, 1, websocket.tag(websocket.lifetime_rule()));", "            if false {\n                shared.meta_put(core, k, 68, 40, 1, websocket.tag(websocket.lifetime_rule()));", ["a_busy_tunnel_is_closed_at_the_lifetime"], "the sweep does not close at the lifetime")
m("p13", "src/proxy.cho", "            } else if st[p + 7] != 0 && now >= st[p + 7] {\n                shared.meta_put(core, k, 68, 40, 1, websocket.tag(websocket.idle_rule()));", "            } else if false {\n                shared.meta_put(core, k, 68, 40, 1, websocket.tag(websocket.idle_rule()));", ["an_idle_tunnel_is_closed_at_the_idle_time"], "the sweep does not close an idle tunnel")
m("p14", "src/proxy.cho", "        var take = st[pu + 4];\n        let room = shared.pend_size() - st[pc + 5];\n        if take > room {\n            take = room;\n        }", "        var take = st[pu + 4];\n        let room = shared.pend_size() - st[pc + 5];", ["a_client_that_reads_late_gets_eight_mebibytes_intact_with_the_queues_bounded"], "the client's queue room is not respected (downstream)")
m("p15", "src/proxy.cho", "        var take = st[p + 4];\n        let room = shared.pend_size() - st[pu + 5];\n        if take > room {\n            take = room;\n        }", "        var take = st[p + 4];\n        let room = shared.pend_size() - st[pu + 5];", ["an_upstream_that_reads_late_receives_thirty_two_mebibytes_intact"], "the upstream's queue room is not respected (upstream)")
m("p16", "src/proxy.cho", "    if st[p + 14] == 1 && st[p + 4] == 0 && st[pu + 5] == 0 {\n        shared.drop_session(tab, core, k);", "    if false {\n        shared.drop_session(tab, core, k);", ["the_client_closing_ends_the_upstream_connection_and_frees_the_slots"], "a client that closed leaves the tunnel up")
m("p17", "src/proxy.cho", "    if st[pu + 14] == 1 && st[pu + 4] == 0 {\n        st[pc + 8] = 1;", "    if false {\n        st[pc + 8] = 1;", ["the_upstream_closing_ends_the_client_side"], "an upstream that closed leaves the tunnel up")
m("p19", "src/proxy.cho", "if readiness % 2 == 1 && (st[p + 3] == 0 || st[p + 3] == 3 && st[p + 10] == 0 || st[p + 3] == 6) {", "if readiness % 2 == 1 && (st[p + 3] == 0 || st[p + 3] == 3 && st[p + 10] == 0) {", ["text_binary_ping_and_close_frames_go_both_ways"], "a tunnel's client is never read")
m("p20", "src/proxy.cho", "    if st[p + 16] >= 1 {\n        shared.drop_session(tab, core, client);", "    if st[p + 16] == 1 {\n        shared.drop_session(tab, core, client);", ["an_upstream_that_resets_mid_tunnel_ends_the_session"], "a write to a lost upstream is answered as if it were an HTTP exchange")
m("p21", "src/proxy.cho", "        websocket.accept_for(view, tb, m[at..at + 28]);\n        st[p + shared.ws_mode()] = 1;\n        st[p + shared.ws_mask()] = w;", "        websocket.accept_for(view, tb, m[at..at + 28]);\n        st[p + shared.ws_mode()] = 1;\n        st[p + shared.ws_mask()] = 0;", ["handshake_selects_the_subprotocol_and_the_head_has_only_checked_fields"], "the offered mask is lost")
m("p22", "src/proxy.cho", "        if st[p + shared.ws_mode()] == 1 {\n            m = forward.rewrite_upgrade(", "        if st[p + shared.ws_mode()] == 7 {\n            m = forward.rewrite_upgrade(", ["the_upstream_is_sent_the_checked_request_and_no_extensions"], "the upstream is sent the ordinary rewrite")
m("p23", "src/proxy.cho", "    metrics.ws_opened(contents(core.stats));\n", "", ["metrics_count_the_tunnel_and_return_to_zero"], "the tunnel counter does not count")
m("p24", "src/proxy.cho", "    st[pc + 3] = 6;\n", "    st[pc + 3] = 3;\n", ["text_binary_ping_and_close_frames_go_both_ways"], "the client stays in the request phase (not a tunnel)")
m("p25", "src/shared.cho", "st[p + tlsio.f_mode()] != 0, st[p + ws_mode()] == 2);", "st[p + tlsio.f_mode()] != 0, false);", ["the_access_log_line_of_a_tunnel"], "the log line has no upgrade key")
m("p26", "src/shared.cho", "pub fn ws_accept_at() -> [] int {\n    return 252;", "pub fn ws_accept_at() -> [] int {\n    return 250;", ["a_long_path_is_logged_whole_beside_the_accept_value"], "the accept value overlaps the path in the meta area")
m("p27", "src/adminloop.cho", "g[metrics.ws_gauge()] = shared.tunnels(core, true);", "g[metrics.ws_gauge()] = 0;", ["metrics_count_the_tunnel_and_return_to_zero"], "the active gauge is not filled")
m("p28", "src/shared.cho", "if st[p] == 1 && st[p + 1] == 1 && (st[p + ws_mode()] == 2 || st[p + ws_mode()] == 1 && !open) {", "if st[p] == 1 && st[p + 1] == 1 && st[p + ws_mode()] == 2 {", ["upgrades_still_waiting_for_their_101_hold_a_place"], "an upgrade in progress holds no place")
m("p29", "src/proxy.cho", "                tunnel_up(tab, core, k, now);\n            } else {\n                pump_request(tab, core, k, now);", "                pump_request(tab, core, k, now);\n            } else {\n                pump_request(tab, core, k, now);", ["text_binary_ping_and_close_frames_go_both_ways"], "read_client does not call tunnel_up (pump_request dispatches there too: expected equivalent)")
m("p30", "src/proxy.cho", "|| st[p + 3] == 6 && st[p + 4] < shared.buf_size() && st[p + 14] == 0 {\n                let before = st[p + tlsio.f_prog()];", "{\n                let before = st[p + tlsio.f_prog()];", ["one_mebibyte_each_way_over_tls", "eight_mebibytes_to_a_late_reader_over_tls", "a_wss_handshake_and_every_frame_type"], "the TLS turn does not read a tunnel's client again")
m("p31", "src/proxy.cho", "|| st[p + 3] == 6 && st[p + 4] < shared.buf_size() && st[p + 14] == 0 {\n            want = want + 1;", "{\n            want = want + 1;", ["text_binary_ping_and_close_frames_go_both_ways"], "a tunnel's client is not watched for reading")
# ---- the generator
m("g01", "scripts/generate.py", 'if ws and not mask & 1:', "if False:", "gen", "a websocket route may exclude GET")
m("g02", "scripts/generate.py", 'ORIGIN = re.compile(r"[a-z][a-z0-9+.-]*://[a-z0-9.-]+(:[0-9]{1,5})?")', 'ORIGIN = re.compile(r"[a-z][a-z0-9+.-]*://[a-z0-9.-]+(:[0-9]{1,5})?/?")', "gen", "an origin with a trailing slash is accepted")
m("g03", "scripts/generate.py", "if ws_keys and not any(r[\"ws\"] for r in routes):", "if False:", "gen", "ws_* keys are accepted without a websocket route")
m("g04", "scripts/generate.py", "WS_TUNNELS_RANGE = 64, (1, 127)", "WS_TUNNELS_RANGE = 64, (1, 500)", "gen", "more tunnels than the table holds")



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
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="wsmut"))
    try:
        tree(tmp)
        text = (tmp / path).read_text()
        if text.count(old) != 1:
            return ident, what, "INVALID", "the old text occurs %d times in %s" % (text.count(old), path)
        (tmp / path).write_text(text.replace(old, new))
        env = dict(os.environ, WS_TREE=str(tmp))
        if kill == "unit":
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
                r = subprocess.run([sys.executable, str(ROOT / "tests" / "websocket_test.py")] + (names or []), cwd=ROOT, capture_output=True, text=True, env=env, timeout=1500)
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
