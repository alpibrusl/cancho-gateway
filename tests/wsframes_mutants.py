#!/usr/bin/env python3
"""Mutants of the WebSocket frame code (docs/websocket-frames.md section 13, gate 9): copy the tree, apply one single edit, run the tests that should notice it.

    python3 tests/wsframes_mutants.py [-j N] [ID ...]      # all mutants, or the named ones; N at a time (default 2)

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


F = "src/wsframe.cho"
P = "src/proxy.cho"
# ---- the parser (unit tests first)
m("a01", F, "if b0 / 16 % 8 != 0 {", "if false {", "unit", "reserved bits are admitted")
m("a02", F, "if op > 2 && op < 8 || op > 10 {", "if op > 10 {", "unit", "opcodes 3 to 7 are admitted")
m("a03", F, "if op > 2 && op < 8 || op > 10 {", "if op > 2 && op < 8 {", "unit", "opcodes 11 to 15 are admitted")
m("a04", F, "if op >= 8 && fin == 0 {", "if false {", "unit", "a fragmented control frame is admitted")
m("a05", F, "if op >= 8 && l7 > 125 {", "if false {", "unit", "a control frame over 125 bytes is admitted")
m("a06", F, "if op == 8 && l7 == 1 {", "if false {", "unit", "a Close of one byte is admitted")
m("a07", F, "if b1 / 128 != want_mask {", "if false {", "unit", "the mask bit is not checked")
m("a08", F, "if length < 126 {", "if length < 0 {", "unit", "a 16-bit length under 126 is admitted")
m("a09", F, "if length < 65536 {", "if length < 0 {", "unit", "a 64-bit length under 65536 is admitted")
m("a10", F, "if int_of(data[at + 2]) >= 128 {", "if int_of(data[at + 2]) >= 256 {", "unit", "a 64-bit length with the top bit set is admitted")
m("a11", F, "if op == 0 && ws[b + 6] == 0 {", "if false {", "unit", "a continuation with no message is admitted")
m("a12", F, "if op > 0 && op < 8 && ws[b + 6] != 0 {", "if false {", "unit", "a new data frame inside a message is admitted")
m("a13", F, "if ws[b + 13] == 1 {\n                    return viol(ws, b, 9, at, 1);", "if false {\n                    return viol(ws, b, 9, at, 1);", "unit", "a frame after a Close is admitted")
m("a14", F, "if op < 8 && length > maxmsg - ws[b + 7] {", "if false {", "unit", "the message limit is not applied")
m("a15", F, "ws[b + 7] = ws[b + 7] + length;", "ws[b + 7] = 0;", "unit", "the limit counts one fragment, not the message")
m("a16", F, "if op < 8 && length > maxmsg - ws[b + 7] {", "if op < 8 && length >= maxmsg - ws[b + 7] {", "unit", "the limit is off by one")
m("a17", F, "if take > 0 && (uon == 1 || op == 8) {", "if take > 0 && (op == 8) {", "unit", "UTF-8 is not validated")
m("a18", F, "} else if c < 194 {", "} else if c < 192 {", "unit", "overlong two-byte forms (C0, C1) are admitted")
m("a19", F, "lo = 160;", "lo = 128;", "unit", "an overlong three-byte form (E0 80..9F) is admitted")
m("a20", F, "hi = 159;", "hi = 191;", "unit", "a surrogate (ED A0..BF) is admitted")
m("a21", F, "lo = 144;", "lo = 128;", "unit", "an overlong four-byte form (F0 80..8F) is admitted")
m("a22", F, "hi = 143;", "hi = 191;", "unit", "a value above U+10FFFF (F4 90..) is admitted")
m("a23", F, "} else if c == 244 {", "} else if c >= 244 {", "unit", "lead bytes F5 to FF are admitted")
m("a24", F, "if uon == 1 && ws[b + 3] == 1 && ws[b + 8] != 0 {", "if false {", "unit", "a message may end inside a character")
m("a25", F, "if op == 8 && done_before + i < 2 {", "if false {", "unit", "a Close frame's code is not read")
m("a26", F, "if int_of(data[1]) == 136 {", "if int_of(data[1]) == 999 {", "unit", "the gateway's Pong is never recognised")
m("a27", F, "if got != v >> 8 * (7 - j) & 255 {", "if false {", "unit", "any Pong of 8 bytes is taken for the gateway's")
m("a28", F, "        } else {\n            if stop {\n                return at;\n            }", "        } else {\n            if false {\n                return at;\n            }", "unit", "stop does not stop at a boundary")
m("a29", F, "if avail < 2 + ext {\n                    return at;", "if avail < 2 {\n                    return at;", "unit", "a length is read before it is all there")
m("a30", F, "if ws[b + 12] >= 2 {\n                        ws[b + 15] = ws[b + 11];", "if false {\n                        ws[b + 15] = ws[b + 11];", "unit", "a Close with a code is reported as 1005")
m("a31", F, "if rule == 10 {\n        return 1009;", "if rule == 10 {\n        return 1002;", "unit", "too big is answered 1002")
m("a32", F, "to_client = 1011;", "to_client = 1002;", "unit", "a client whose upstream broke the rules is told 1002")
m("a33", F, "if ws[dir_base(0) + 13] == 1 {\n        ws[5] = 2;", "if false {\n        ws[5] = 2;", "unit", "a second Close is sent in a direction that has carried one")
m("a34", F, "if ws[12] > since {\n        since = ws[12];", "if false {\n        since = ws[12];", "unit", "the pong deadline ignores what the client sent since")
m("a35", F, "return ping_ms > 0 && ws[0] == 0 && ws[9] == 0 && now >= ws[12] + ping_ms;", "return ping_ms > 0 && ws[0] == 0 && now >= ws[12] + ping_ms;", "unit", "a second Ping is sent while one is outstanding")
m("a36", F, "if at_boundary == 1 {\n        // What was answered ends at a frame boundary, whatever the frame in hand had begun to do to the state.\n        ws[b] = 0;", "if at_boundary == 7 {\n        // What was answered ends at a frame boundary, whatever the frame in hand had begun to do to the state.\n        ws[b] = 0;", ["every_violation_by_the_client_is_closed_with_its_code_and_stays_off_the_upstream"], "a violation leaves the parser inside the frame it refused")
# ---- the tunnel

m("c01", P, "let m = wsframe.put_close_masked(pd[qb + st[pt + 5]..qb + st[pt + 5] + wsframe.close_masked_len()], w[code_at]);", "let m = wsframe.put_close(pd[qb + st[pt + 5]..qb + st[pt + 5] + wsframe.close_len()], w[code_at]);", ["every_violation_by_the_client_is_closed_with_its_code_and_stays_off_the_upstream"], "the Close toward the upstream is unmasked")
m("c02", P, "var stop = cs == 1;", "var stop = false;", ["a_close_from_the_lifetime_waits_for_the_frame_the_upstream_is_sending"], "a close does not wait for the frame boundary")
m("c03", P, "            if ev == 0 && w[b] == 0 {\n                // At a frame boundary", "            if ev == 0 {\n                // At a frame boundary", ["the_ping_waits_for_the_end_of_a_frame_in_flight"], "a Ping or Close is placed inside a frame in flight")
m("c04", P, "                w[9] = 0;\n                st[pc + 7] = now + deploy.ws_idle_ms();\n                moving = st[ps + 4] > 0;", "                moving = st[ps + 4] > 0;", ["a_client_that_answers_stays_past_the_idle_time_and_the_upstream_never_sees_the_pings"], "the gateway's Pong is not taken and does not reset the idle timer")
m("c05", P, "                st[ps + 4] = st[ps + 4] - 14;\n                w[9] = 0;", "                w[9] = 0;", ["a_client_that_answers_stays_past_the_idle_time_and_the_upstream_never_sees_the_pings"], "the gateway's Pong is forwarded as well")
m("c06", P, "                st[pc + 7] = now + deploy.ws_idle_ms();\n                moving = st[ps + 4] > 0;\n            } else if ev == 0", "                moving = st[ps + 4] > 0;\n            } else if ev == 0", ["a_client_that_answers_stays_past_the_idle_time_and_the_upstream_never_sees_the_pings"], "a Pong does not reset the idle timer")
m("c07", P, "contents(core.wsf)[ws_at(k) + wsframe.t_heard()] = now;", "", ["a_client_that_is_sending_is_not_pinged_and_one_that_ignores_pings_while_sending_is_not_closed"], "the client is never heard (its clock)")
m("c08", P, "} else if wsframe.pong_expired(wk, now, deploy.ws_pong_ms()) {", "} else if false {", ["a_client_that_does_not_answer_is_closed_at_the_pong_deadline"], "an unanswered Ping is never noticed")
m("c09", P, "} else if wsframe.ping_due(wk, now, deploy.ws_ping_ms()) {\n                tunnel_run(tab, core, k, 1, now);", "} else if false {\n                tunnel_run(tab, core, k, 1, now);", ["a_client_that_does_not_answer_is_closed_at_the_pong_deadline"], "a silent client is never Pinged")
m("c10", P, "                if cs != 1 {\n                    tunnel_mark(core, client, w[b + 15], dir, now);", "                if false {\n                    tunnel_mark(core, client, w[b + 15], dir, now);", ["every_violation_by_the_client_is_closed_with_its_code_and_stays_off_the_upstream"], "a violation does not close the tunnel")
m("c11", P, "                if w[8] == 0 {\n                    w[8] = w[b + 15];\n                }", "", ["a_close_from_either_peer_is_passed_through_and_answered"], "the first Close's code is not kept")
m("c12", P, "                if cs == 0 {\n                    w[0] = 2;\n                    w[1] = now + deploy.ws_close_ms();", "                if false {\n                    w[0] = 2;\n                    w[1] = now + deploy.ws_close_ms();", ["a_peer_that_never_answers_a_close_is_closed_at_the_wait"], "a peer's Close starts no wait for the answer")
m("c13", P, "shared.meta_put(core, client, 68, 40, 1, wsframe.tag(wsframe.rule_truncated()));", "", ["truncated_frames_then_the_end_of_the_stream"], "a truncated frame has no tag")
m("c14", P, "if st[ps + 14] == 1 && w[0] == 1 && (st[ps + 4] == 0 || w[sent_at] != 0) {", "if st[ps + 14] == 1 && w[0] == 1 {", ["a_close_from_the_lifetime_waits_for_the_frame_the_upstream_is_sending"], "a side's end while closing discards what it had not delivered")
m("c15", P, "w[wsframe.dir_base(0) + wsframe.d_offender()] == 1 && st[pc + 3] == 6", "false && st[pc + 3] == 6", ["a_client_that_is_still_sending_when_it_is_refused_still_gets_its_close"], "a client that broke a rule does not linger")
m("c16", P, "        metrics.ws_messages(contents(core.stats), w[14]);", "", ["the_counters"], "messages are not counted")
m("c17", P, "                    metrics.ws_pinged(contents(core.stats));", "", ["a_client_that_does_not_answer_is_closed_at_the_pong_deadline"], "Pings are not counted")
m("c18", P, "    if cause == wsframe.rule_pong_timeout() {\n        metrics.ws_pong_timeout(contents(core.stats));\n    }", "", ["a_client_that_does_not_answer_is_closed_at_the_pong_deadline"], "unanswered Pings are not counted")
m("c19", "src/shared.cho", "            metrics.ws_closed(contents(core.stats), ws_close);", "", ["the_counters"], "the close codes are not counted")
m("c20", P, "                if now >= wk[1] {", "                if false {", ["a_peer_that_never_answers_a_close_is_closed_at_the_wait"], "the close wait has no end")
m("c21", P, "let maxmsg = route.ws_max_message(st[pc + 31] - 1);", "let maxmsg = 268435456;", ["a_message_of_exactly_the_limit_passes_and_one_byte_more_does_not"], "the route's message limit is not read")
m("c22", "src/route.cho", "return number(bytes.field(blob[at..line_end(blob, at)], 9, 26));", "return number(bytes.field(blob[at..line_end(blob, at)], 9, 25));", ["a_message_of_exactly_the_limit_passes_and_one_byte_more_does_not"], "the message limit is read from the wrong column")
m("c23", P, "                st[pc + 7] = now + deploy.ws_idle_ms();\n                if flush(tab, core, dst, now) == 1 {", "                if flush(tab, core, dst, now) == 1 {", ["a_client_that_is_sending_is_not_pinged_and_one_that_ignores_pings_while_sending_is_not_closed"], "forwarded bytes do not reset the idle timer")
m("c25", "src/accesslog.cho", "    if ws_close > 0 {\n        k = put_number(out, k, \"ws_close\", ws_close);", "    if false {\n        k = put_number(out, k, \"ws_close\", ws_close);", "unit", "the log has no ws_close")
m("c26", P, "        if w[0] == 1 {\n            not_ok(core, pc);\n        } else if w[0] == 2 {", "        if w[0] == 1 {\n        } else if w[0] == 2 {", ["a_close_from_the_lifetime_waits_for_the_frame_the_client_is_sending"], "a close by the gateway is logged as ok once the peers end the connection")
m("c27", P, "if w[0] == 1 && w[wsframe.dir_base(0) + wsframe.d_offender()]", "if w[0] == 2 && w[wsframe.dir_base(0) + wsframe.d_offender()]", ["every_violation_by_the_client_is_closed_with_its_code_and_stays_off_the_upstream"], "a violation's lingering is never reached (no end of the closing)")
m("g01", "scripts/generate.py", "WS_MESSAGE, WS_MESSAGE_RANGE = 1 << 20, (1024, 1 << 28)", "WS_MESSAGE, WS_MESSAGE_RANGE = 1 << 20, (1024, 1 << 40)", "gen", "a message limit past its bound")
m("g02", "scripts/generate.py", 'if "ws_pong_ms" in doc and ping == 0:', "if False:", "gen", "ws_pong_ms is accepted without ws_ping_ms")
m("g03", "scripts/generate.py", 'if "ws_max_message_bytes" in r and not ws:', "if False:", "gen", "ws_max_message_bytes is accepted on a route that is not a websocket route")
m("g04", "scripts/generate.py", "WS_PING_RANGE = (1000, 86400000)", "WS_PING_RANGE = (1, 86400000)", "gen", "a keepalive Ping every millisecond is accepted")


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
                r = subprocess.run([sys.executable, str(ROOT / "tests" / "wsframes_test.py")] + (names or []), cwd=ROOT, capture_output=True, text=True, env=env, timeout=1500)
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
