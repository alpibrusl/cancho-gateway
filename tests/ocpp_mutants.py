#!/usr/bin/env python3
"""Mutants of the OCPP-J validation (docs/ocpp.md section 9, gate 6): copy the tree, apply one single edit, run the tests that should notice it.

    python3 tests/ocpp_mutants.py [-j N] [ID ...]      # all mutants, or the named ones; N at a time (default 2)

A mutant is KILLED when a test fails, SURVIVED when none does (every test is then run, to be sure), INVALID when the edited tree does not build (the edit is
then wrong, not the tests). The output is the table section 11 of the document records. Needs `build/deps` filled by one `cancho build`.
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


O = "src/ocppframe.cho"
F = "src/wsframe.cho"
P = "src/proxy.cho"
V = "src/wsvalidate.cho"
B = "src/wsbind.cho"
G = "scripts/generate.py"
MET = "src/metrics.cho"
# ---- the recogniser (unit tests first)
m("o01", O, "    if ws[o + 2] >= 32 {\n        return 25;", "    if ws[o + 2] >= 33 {\n        return 25;", "unit", "nesting may go one level past the bound")
m("o02", O, "    if ws[o + 2] >= 32 {\n        return 25;", "    if ws[o + 2] >= 31 {\n        return 25;", "unit", "nesting is refused one level early")
m("o03", O, "    ws[o + 1] = ws[o + 1] / 2;\n", "", "unit", "a closed container is not popped from the stack")
m("o04", O, "        ws[o + 1] = ws[o + 1] * 2 + 1;", "        ws[o + 1] = ws[o + 1] * 2;", "unit", "an object is pushed as an array")
m("o05", O, "    if c == 125 && obj == 1 || c == 93 && obj == 0 {", "    if c == 125 || c == 93 {", "unit", "a container is closed by the wrong bracket")
m("o06", O, "    if c == 45 {\n        ws[o] = 15;", "    if c == 46 {\n        ws[o] = 15;", "unit", "a negative number is refused")
m("o07", O, "        if digit(c) {\n            return 18;\n        }\n        return number_end(ws, o, c);\n    }\n    if p == 17 {", "        return number_end(ws, o, c);\n    }\n    if p == 17 {", "unit", "a number with a leading zero is admitted")
m("o08", O, "        if digit(c) {\n            ws[o] = 19;\n            return 0;\n        }\n        return 18;", "        ws[o] = 19;\n        return 0;", "unit", "a decimal point need not be followed by a digit")
m("o09", O, "        if c == 43 || c == 45 {\n            ws[o] = 21;", "        if c == 43 {\n            ws[o] = 21;", "unit", "an exponent may not have a minus sign")
m("o10", O, "    if p == 21 {\n        if digit(c) {\n            ws[o] = 22;\n            return 0;\n        }\n        return 18;", "    if p == 21 {\n        ws[o] = 22;\n        return 0;", "unit", "an exponent's sign need not be followed by a digit")
m("o11", O, "        if digit(c) {\n            ws[o] = 22;\n            return 0;\n        }\n        return 18;\n    }\n    if p == 21", "        if digit(c) {\n            ws[o] = 22;\n            return 0;\n        }\n        return number_end(ws, o, c);\n    }\n    if p == 21", "unit", "an `e` need not be followed by digits")
m("o12", O, "c == 98 || c == 102 || c == 110 || c == 114 || c == 116 {", "c == 98 || c == 102 || c == 110 || c == 114 {", "unit", "the escape \\t is refused")
m("o13", O, "            ws[o + 3] = 4;\n            ws[o] = 14;", "            ws[o + 3] = 3;\n            ws[o] = 14;", "unit", "a \\u escape needs three hex digits")
m("o14", O, "digit(c) || c >= 65 && c <= 70 || c >= 97 && c <= 102 {", "digit(c) || c >= 65 && c <= 90 || c >= 97 && c <= 102 {", "unit", "G to Z are hex digits")
m("o15", O, "p == 28 && c == 115", "p == 28 && c == 116", "unit", "`false` is spelt wrongly")
m("o16", O, " || p == 32 && c == 108 {\n        ws[o] = done(ws, o);", " {\n        ws[o] = done(ws, o);", "unit", "`null` never ends")
m("o17", O, "ws[o + 5] == 1 && ws[o + 3] > 36 ||", "ws[o + 5] == 1 && ws[o + 3] > 37 ||", "unit", "an id may have 37 characters")
m("o18", O, "ws[o + 5] != 1 && ws[o + 3] > 64 {", "ws[o + 5] != 1 && ws[o + 3] > 65 {", "unit", "an action may have 65 characters")
m("o19", O, "if c < 32 || c > 126 || c == 92 {", "if c < 32 || c > 127 || c == 92 {", "unit", "DEL is a character of an id")
m("o20", O, "if c < 32 || c > 126 || c == 92 {", "if c < 31 || c > 126 || c == 92 {", "unit", "a control character is a character of an id")
m("o21", O, "if c < 32 || c > 126 || c == 92 {", "if c < 32 || c > 126 {", "unit", "a backslash is a character of an id")
m("o22", O, "        if ws[o + 5] != 1 && !(c >= 48", "        if false && !(c >= 48", "unit", "an action may hold any printable character")
m("o23", O, "            if ws[o + 3] == 0 {\n                return string_rule(ws, o);\n            }\n", "", "unit", "an id or action may be empty")
m("o24", O, "        } else if ws[o + 4] == 3 {\n            last = 2;", "        } else if ws[o + 4] == 3 {\n            last = 3;", "unit", "a CALLRESULT has four elements")
m("o25", O, "        } else {\n            last = 4;", "        } else {\n            last = 3;", "unit", "a CALLERROR has four elements")
m("o26", O, "            if ws[o + 5] >= last {\n                return 20;", "            if ws[o + 5] > last {\n                return 20;", "unit", "a comma after the last element is admitted")
m("o27", O, "            if ws[o + 5] < last {\n                return 20;\n            }\n            ws[o] = 4;", "            ws[o] = 4;", "unit", "a message may close before its last element")
m("o28", O, "if c == 50 || c == 51 || c == 52 {", "if c == 50 || c == 51 || c == 52 || c == 53 {", "unit", "message type 5 is admitted")
m("o29", O, "        if c == 93 {\n            return 20;\n        }\n        return 19;", "        return 19;", "unit", "a message of one element is not an arity error")
m("o30", O, "    if c == 93 {\n        return 20;\n    }\n    if idx == 1", "    if idx == 1", "unit", "a missing element is not an arity error")
m("o31", O, "    if idx == 3 && ty == 4 {", "    if idx == 3 && ty == 99 {", "unit", "a CALLERROR's description is taken for its details")
m("o32", O, "    if idx == 1 || idx == 2 && ty != 3 {", "    if idx == 1 || idx == 2 {", "unit", "a CALLRESULT's payload is read as a string")
m("o33", O, "    if ws[o + 2] == 0 {\n        return 3;\n    }\n    return 11;", "    return 11;", "unit", "the top level is never left")
m("o34", O, "    if p == 4 {\n        if space(c) {\n            return 0;\n        }\n        return 18;", "    if p == 4 {\n        return 0;", "unit", "bytes after the closing bracket are admitted")
m("o35", O, "    if p == 0 {\n        if space(c) {\n            return 0;\n        }\n", "    if p == 0 {\n", "unit", "white space before the message is refused")
m("o36", O, "return c == 32 || c == 9 || c == 10 || c == 13;", "return c == 32 || c == 9 || c == 10;", "unit", "a carriage return is not white space")
m("o37", O, "        if c < 32 {\n            return 18;\n        }\n        return 0;\n    }\n    if p == 5 {", "        return 0;\n    }\n    if p == 5 {", "unit", "a control character is admitted in a string")
m("o38", O, "                ws[o + 6] = 0;\n                ws[o] = 10;", "                ws[o + 6] = 0;\n                ws[o] = 11;", "unit", "a member's name needs no colon")
m("o39", O, "        if c == 58 {\n            ws[o] = 6;", "        if c == 44 {\n            ws[o] = 6;", "unit", "a colon is a comma")
m("o40", O, "    if p == 9 {\n        if space(c) {\n            return 0;\n        }\n", "    if p == 9 {\n        if space(c) {\n            return 0;\n        }\n        if c == 125 {\n            return close(ws, o);\n        }\n", "unit", "an object may end with a comma")
m("o41", O, "    if p == 6 {\n        if space(c) {\n            return 0;\n        }\n", "    if p == 6 {\n        if space(c) {\n            return 0;\n        }\n        if c == 93 {\n            return close(ws, o);\n        }\n", "unit", "an array may end with a comma")
m("o42", O, "    ws[o + 2] = ws[o + 2] + 1;\n    if c == 123 {", "    if c == 123 {", "unit", "the depth is never counted")
m("o43", O, "        if c == 34 {\n            if ws[o + 3] == 0 {\n                return string_rule(ws, o);\n            }\n            ws[o] = 3;", "        if c == 34 {\n            if ws[o + 3] == 0 {\n                return string_rule(ws, o);\n            }\n            ws[o] = 11;", "unit", "an id is followed by an item separator, not an element separator")
m("o44", O, "            ws[o + 5] = ws[o + 5] + 1;\n            ws[o] = 1;", "            ws[o] = 1;", "unit", "the element index never advances")
# ---- the parser's wiring
m("w01", F, "                    if von != 0 {\n                        let vrule", "                    if false {\n                        let vrule", 'unit', 'the recogniser is never stepped')
m("w02", F, "if von != 0 && ws[b + 3] == 1 {", "if false {", 'unit', 'a message may end before the grammar does')
m("w03", F, "if von != 0 && ws[b + 3] == 1 {", "if von != 0 {", 'unit', 'every fragment must be a whole message')
m("w04", F, "                if op == 2 {\n                    let vbin", "                if false {\n                    let vbin", 'unit', 'a binary message is admitted on an OCPP route')
m("w05", F, "                    wsvalidate.begin(ws, b + 20, wsvalidate.kind(ws, b + 20));\n", "", 'unit', 'a message begins where the last one ended')
m("w06", F, "                von = wsvalidate.kind(ws, b + 20);", "                von = 0;", 'unit', 'no direction is validated')
m("w07", F, "            var von = 0;\n            if uon == 1 {\n                von = wsvalidate.kind(ws, b + 20);\n            }", "            var von = wsvalidate.kind(ws, b + 20);", 'unit', 'control frames are read as OCPP')
m("w08", V, "    if rule == 17 || rule == 25 {\n        return 1008;", "    if rule == 17 || rule == 26 {\n        return 1008;", 'unit', 'nesting is answered 1007')
m("w09", V, "    if rule >= 18 && rule <= 24 {\n        return 1007;\n    }\n", "", 'unit', 'a malformed message is answered 1002')
m("w10", V, 'return "ws.ocpp-code";', 'return "ws.ocpp-codes";', 'unit', 'a tag is misspelt')
m("w11", V, "    if rule >= 17 && rule <= 25 {\n        return 1;", "    if rule >= 18 && rule <= 25 {\n        return 1;", ['the_counters_and_the_refusal_tags'], 'a binary refusal is not counted as an OCPP one')
m("w12", F, "    wsvalidate.set_kind(ws, dir_base(1) + 20, kind);\n", "", 'unit', "the upstream's messages are not validated")
m("w13", F, "    wsvalidate.set_kind(ws, dir_base(0) + 20, kind);\n", "", 'unit', "the client's messages are not validated")
# ---- the tunnel
m("p01", B, "    if route.ws_ocpp(index) > 0 {", "    if false {", ['every_refusal_by_the_client_is_closed_with_its_code_and_stays_off_the_upstream'], 'no tunnel is validated')
m("p02", B, "    if route.ws_ocpp(index) > 0 {", "    if true {", ['a_route_without_ws_ocpp_forwards_what_slice_two_did'], 'every tunnel is validated')
m("p03", B, "        metrics.ws_ocpp_violation(stats);\n", "", ['the_counters_and_the_refusal_tags'], 'violations are not counted')
m("p04", "src/route.cho", "return number(bytes.field(blob[at..line_end(blob, at)], 9, 32));", "return number(bytes.field(blob[at..line_end(blob, at)], 9, 31));", ["a_route_without_ws_ocpp_forwards_what_slice_two_did"], "the version mask is read from the wrong column")
# ---- the metrics
m("t01", MET, "    stats[ws_base() + 12] = stats[ws_base() + 12] + 1;", "    stats[ws_base() + 12] = stats[ws_base() + 12] + 2;", "unit", "a violation is counted twice")
m("t02", MET, 'k = jnum(out, k, "ocpp_violations", stats[ws_base() + 12]);', 'k = jnum(out, k, "ocpp_violation", stats[ws_base() + 12]);', "unit", "the JSON key is misspelt")
m("t03", MET, 'k = plain(out, k, "ws_ocpp_violations_total", stats[ws_base() + 12]);', 'k = plain(out, k, "ws_ocpp_violations_total", stats[ws_base() + 11]);', "unit", "Prometheus shows another counter")
# ---- the generator
m("g01", G, 'if sorted(protocols) != sorted("ocpp" + v for v in want):', "if False:", "gen", "ws_ocpp is accepted with other subprotocols")
m("g02", G, 'not all(isinstance(v, str) and v in OCPP_VERSIONS for v in want)', 'not all(isinstance(v, str) for v in want)', "gen", "an unknown version is accepted")
m("g03", G, "not 1 <= len(want) <= len(OCPP_VERSIONS)", "not 0 <= len(want) <= len(OCPP_VERSIONS)", "gen", "an empty list of versions is accepted")
m("g04", G, '"ws_ocpp": ocpp, **rate', '"ws_ocpp": 0, **rate', "gen", "the table never switches validation on")
m("g05", G, 'OCPP_VERSIONS = {"1.6": 1, "2.0.1": 2}', 'OCPP_VERSIONS = {"1.6": 1, "2.0.1": 1}', "gen", "the two versions have the same bit")
m("g06", G, '    ocpp = sum(OCPP_VERSIONS[v] for v in want)', '    ocpp = 1', "gen", "the mask of a route is always 1")

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
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="ocppmut"))
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
                r = subprocess.run([sys.executable, str(ROOT / "tests" / "ocpp_test.py")] + (names or []), cwd=ROOT, capture_output=True, text=True, env=env, timeout=1500)
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
