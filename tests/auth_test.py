#!/usr/bin/env python3
"""Authentication end to end (docs/auth.md section 10, gate 3): a built gateway, a recording upstream, and clients that count what they were told.

    python3 tests/auth_test.py [test_name ...]            # all tests, or the named ones
    AUTH_TREE=/path/to/copy python3 tests/auth_test.py ...   # build the gateway from another copy of the tree (tests/auth_mutants.py)

One gateway is built from loose files, as tests/ratelimit_test.py does (it is that file's `Gateway`): plain, TLS and WebSocket listeners and an admin one, three
API keys, and a route for each way a credential can be asked for. Needs `build/deps` filled by one `cancho build`, and `openssl` for the TLS certificates.
"""

import hashlib
import json
import os
import pathlib
import re
import sys
import tempfile
import time
import traceback

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
os.environ.setdefault("RL_TREE", os.environ.get("AUTH_TREE", ""))
if not os.environ["RL_TREE"]:
    del os.environ["RL_TREE"]
import proxy_test as pt  # noqa: E402
import ratelimit_test as rt  # noqa: E402
import websocket_test as wt  # noqa: E402
from ratelimit_test import get, rule_of, seen  # noqa: E402

# Made here, never read from a file: the gateway is given their digests.
KEYS = {"alice": "ck_test_alice_" + "A" * 29, "bob": "ck_test_bob-" + "B" * 31, "carol": "ck_test.carol~" + "C" * 29}
WRONG = "ck_test_alice_" + "A" * 28 + "B"


def digest(key):
    return hashlib.sha256(key.encode()).hexdigest()


TOP = "auth_allow_plain = true\n"
ROUTES = "".join('\n[[api_key]]\nname = "%s"\nsha256 = "%s"\n' % (n, digest(k)) for n, k in KEYS.items()) + """
[[route]]
name = "open"
path_prefix = "/open"
upstream = "up"

[[route]]
name = "bearer"
path_prefix = "/b"
upstream = "up"
auth = "api-key"

[[route]]
name = "hdr"
path_prefix = "/h"
upstream = "up"
auth = "api-key"
auth_header = "X-Api-Key"

[[route]]
name = "fwd"
path_prefix = "/f"
upstream = "up"
auth = "api-key"
auth_header = "X-Api-Key"
auth_forward = true

[[route]]
name = "subset"
path_prefix = "/s"
upstream = "up"
auth = "api-key"
auth_keys = ["alice", "carol"]

[[route]]
name = "lim"
path_prefix = "/lim"
upstream = "up"
auth = "api-key"
rate_limit = "1/h"
rate_burst = 2
rate_key = "auth"
rate_buckets = 4

[[route]]
name = "hdrlim"
path_prefix = "/hl"
upstream = "up"
auth = "api-key"
auth_header = "X-Api-Key"
rate_limit = "1/h"
rate_burst = 1
rate_key = "auth"
rate_buckets = 4

[[route]]
name = "wsa"
path_prefix = "/wsa"
upstream = "ws"
websocket = true
auth = "api-key"

[[route]]
name = "wso"
path_prefix = "/wso"
upstream = "ws"
websocket = true
"""

BEARER = 'Bearer realm="cancho-gateway"'
APIKEY = 'ApiKey realm="cancho-gateway", header="x-api-key"'
ID = re.compile(rb"[0-9a-f]+-[0-9a-f]+-[0-9a-f]{8}")


def bearer(name):
    return "Authorization: Bearer " + KEYS[name]


def key_header(name):
    return "X-Api-Key: " + KEYS[name]


def masked(raw):
    return ID.sub(b"ID", raw)


def head_of(up, path):
    """The recorded request head the upstream got for this path, as {lowercase name: [values]}."""
    with up.lock:
        for h in up.heads:
            if h.split(b" ")[1].decode() == path:
                return pt.heads_of(h), h
    raise AssertionError("the upstream never saw %s" % path)


class Main:
    def a_valid_key_passes_and_the_credential_is_not_forwarded(gw, up, ws):
        for n, name in enumerate(KEYS):
            s, h, b, _ = get(gw, "/b/ok%d" % n, [bearer(name)])
            assert s == 200 and b == b"ok", (name, s)
            heads, raw = head_of(up, "/b/ok%d" % n)
            assert "authorization" not in heads, heads
            assert KEYS[name].encode() not in raw, raw
            assert heads["via"] == ["1.1 cancho-gateway"] and "x-request-id" in heads, heads
        # The same for a route that reads a header of its own, and the other headers go through.
        s, h, b, _ = get(gw, "/h/ok", [key_header("bob"), "X-Other: kept"])
        assert s == 200
        heads, raw = head_of(up, "/h/ok")
        assert "x-api-key" not in heads and heads["x-other"] == ["kept"] and KEYS["bob"].encode() not in raw, heads
        # A client's own Authorization on a route that reads X-Api-Key is the upstream's business: forwarded as before.
        s, *_ = get(gw, "/h/own", [key_header("bob"), "Authorization: Basic dXNlcjpwYXNz"])
        assert s == 200
        heads, raw = head_of(up, "/h/own")
        assert heads["authorization"] == ["Basic dXNlcjpwYXNz"] and "x-api-key" not in heads, heads
        # A name in another case is the same header.
        s, *_ = get(gw, "/h/case", ["x-API-key: " + KEYS["alice"]])
        assert s == 200 and "x-api-key" not in head_of(up, "/h/case")[0]

    def auth_forward_keeps_the_credential(gw, up, ws):
        s, *_ = get(gw, "/f/kept", [key_header("carol")])
        assert s == 200
        heads, _ = head_of(up, "/f/kept")
        assert heads["x-api-key"] == [KEYS["carol"]], heads
        assert get(gw, "/f/no")[0] == 401

    def routes_without_auth_are_unaffected(gw, up, ws):
        n0 = len(gw.lines())
        for i, extra in enumerate(([], ["Authorization: Basic Zm9v"], ["Authorization: Bearer nonsense"], ["Authorization: Bearer a", "Authorization: Bearer b"], ["X-Api-Key: x"])):
            s, h, b, _ = get(gw, "/open/%d" % i, extra)
            assert s == 200 and b == b"ok", (i, s)
            heads, _ = head_of(up, "/open/%d" % i)
            assert heads.get("authorization", []) == [e.split(": ", 1)[1] for e in extra if e.startswith("Authorization")], (i, heads)
            e = gw.find(n0, path="/open/%d" % i)
            assert e["status"] == 200 and "identity" not in e, e

    def each_bad_credential_is_refused_with_its_status_its_rule_and_its_challenge(gw, up, ws):
        cases = [
            ("a missing header", [], 401, "auth.missing", BEARER),
            ("an empty header", ["Authorization:"], 401, "auth.malformed", BEARER + ', error="invalid_request"'),
            ("blanks only", ["Authorization:    "], 401, "auth.malformed", BEARER + ', error="invalid_request"'),
            ("Basic", ["Authorization: Basic dXNlcjpwYXNz"], 401, "auth.malformed", BEARER + ', error="invalid_request"'),
            ("the scheme alone", ["Authorization: Bearer"], 401, "auth.malformed", BEARER + ', error="invalid_request"'),
            ("the scheme and a space", ["Authorization: Bearer "], 401, "auth.malformed", BEARER + ', error="invalid_request"'),
            ("no scheme", ["Authorization: " + KEYS["alice"]], 401, "auth.malformed", BEARER + ', error="invalid_request"'),
            ("two spaces", ["Authorization: Bearer  " + KEYS["alice"]], 401, "auth.malformed", BEARER + ', error="invalid_request"'),
            ("a tab", ["Authorization: Bearer\t" + KEYS["alice"]], 401, "auth.malformed", BEARER + ', error="invalid_request"'),
            ("a space inside", ["Authorization: Bearer ck_test alice"], 401, "auth.malformed", BEARER + ', error="invalid_request"'),
            ("a quote", ['Authorization: Bearer "%s"' % KEYS["alice"]], 401, "auth.malformed", BEARER + ', error="invalid_request"'),
            ("a comma", ["Authorization: Bearer %s,x" % KEYS["alice"]], 401, "auth.malformed", BEARER + ', error="invalid_request"'),
            ("the header twice, the same good key", [bearer("alice"), bearer("alice")], 401, "auth.malformed", BEARER + ', error="invalid_request"'),
            ("the header twice, a good key and a bad one", [bearer("alice"), "authorization: Bearer nope"], 401, "auth.malformed", BEARER + ', error="invalid_request"'),
            ("a credential of 257 bytes", ["Authorization: Bearer " + "k" * 257], 401, "auth.malformed", BEARER + ', error="invalid_request"'),
            ("a credential of 5,000 bytes", ["Authorization: Bearer " + "k" * 5000], 401, "auth.malformed", BEARER + ', error="invalid_request"'),
            ("an unknown key", ["Authorization: Bearer ck_test_unknown"], 401, "auth.invalid", BEARER + ', error="invalid_token"'),
            ("a wrong key (one character changed)", ["Authorization: Bearer " + WRONG], 401, "auth.invalid", BEARER + ', error="invalid_token"'),
            ("a prefix of a key", ["Authorization: Bearer " + KEYS["alice"][:-1]], 401, "auth.invalid", BEARER + ', error="invalid_token"'),
            ("a key and one more character", ["Authorization: Bearer " + KEYS["alice"] + "x"], 401, "auth.invalid", BEARER + ', error="invalid_token"'),
            ("a key in another case", ["Authorization: Bearer " + KEYS["alice"].upper()], 401, "auth.invalid", BEARER + ', error="invalid_token"'),
            ("a credential of 256 bytes that is no key", ["Authorization: Bearer " + "k" * 256], 401, "auth.invalid", BEARER + ', error="invalid_token"'),
        ]
        n0 = len(gw.lines())
        for i, (what, headers, status, rule, challenge) in enumerate(cases):
            path = "/b/refused%d" % i
            s, h, b, raw = get(gw, path, headers)
            assert s == status and rule_of(b) == rule, (what, s, b)
            assert h["www-authenticate"] == challenge, (what, h)
            assert h["content-type"] == "application/problem+json" and h["connection"] == "close", (what, h)
            body = json.loads(b)
            assert body["status"] == 401 and body["title"] == "Unauthorized" and body["request_id"] == h["x-request-id"], (what, body)
            assert raw.index(b"Content-Length") < raw.index(b"WWW-Authenticate") < raw.index(b"X-Request-Id"), (what, raw[:300])
            for credential in (KEYS["alice"], digest(KEYS["alice"])):
                assert credential.encode() not in raw, (what, "the refusal echoes a credential")
            assert seen(up, path) == 0, (what, "the upstream saw a refused request")
            e = gw.find(n0, path=path)
            assert e["status"] == 401 and e["rule"] == rule and e["outcome"] == "refused" and e["route"] == "bearer" and "identity" not in e, (what, e)
        # The same through the other source: a header of its own, and a challenge that says which.
        for what, headers, rule, challenge in (("missing", [], "auth.missing", APIKEY), ("empty", ["X-Api-Key:"], "auth.malformed", APIKEY + ', error="invalid_request"'),
                                               ("twice", [key_header("bob"), key_header("bob")], "auth.malformed", APIKEY + ', error="invalid_request"'),
                                               ("with a scheme", ["X-Api-Key: Bearer " + KEYS["bob"]], "auth.malformed", APIKEY + ', error="invalid_request"'),
                                               ("oversized", ["X-Api-Key: " + "z" * 257], "auth.malformed", APIKEY + ', error="invalid_request"'),
                                               ("wrong", ["X-Api-Key: " + WRONG], "auth.invalid", APIKEY + ', error="invalid_token"'),
                                               ("the wrong header (Authorization on a route that reads X-Api-Key)", [bearer("alice")], "auth.missing", APIKEY)):
            s, h, b, _ = get(gw, "/h/refused", headers)
            assert s == 401 and rule_of(b) == rule and h["www-authenticate"] == challenge, (what, s, h, b)
        assert seen(up, "/h/refused") == 0

    def a_scheme_in_any_case_and_a_header_in_any_case_are_accepted(gw, up, ws):
        for i, line in enumerate(("authorization: bearer " + KEYS["alice"], "AUTHORIZATION: BEARER " + KEYS["alice"], "Authorization:   Bearer " + KEYS["alice"] + "  \t")):
            assert get(gw, "/b/case%d" % i, [line])[0] == 200, line

    def an_unknown_key_and_a_wrong_key_get_the_same_response(gw, up, ws):
        # Only the request id differs: nothing in the answer says whether a key exists, how much of it was right or which check failed.
        answers = []
        for credential in ("ck_test_unknown", WRONG, KEYS["alice"][:-1], KEYS["bob"] + "0", "k" * 256, "x"):
            s, h, b, raw = get(gw, "/b/same", ["Authorization: Bearer " + credential])
            assert s == 401, (credential, s)
            answers.append(masked(raw))
        assert len(set(answers)) == 1, [a[:200] for a in answers]
        # And the same holds for the other source.
        answers = [masked(get(gw, "/h/same", ["X-Api-Key: " + c])[3]) for c in ("ck_test_unknown", WRONG, KEYS["bob"][:-1])]
        assert len(set(answers)) == 1

    def a_valid_key_the_route_does_not_allow_is_a_403(gw, up, ws):
        n0 = len(gw.lines())
        s, h, b, raw = get(gw, "/s/denied", [bearer("bob")])
        assert s == 403 and rule_of(b) == "auth.forbidden", (s, b)
        assert "www-authenticate" not in h and json.loads(b)["title"] == "Forbidden", h
        assert seen(up, "/s/denied") == 0
        assert get(gw, "/s/alice", [bearer("alice")])[0] == 200
        assert get(gw, "/s/carol", [bearer("carol")])[0] == 200
        # The 403 is the answer to an authenticated key, so the log names it; an invalid credential on the same route is still a 401.
        e = gw.find(n0, path="/s/denied")
        assert e["status"] == 403 and e["rule"] == "auth.forbidden" and e["identity"] == "bob", e
        s, h, b, _ = get(gw, "/s/nokey", ["Authorization: Bearer " + WRONG])
        assert s == 401 and rule_of(b) == "auth.invalid", (s, b)

    def authentication_comes_before_the_rate_limiter_and_the_identity_is_its_key(gw, up, ws):
        n0 = len(gw.lines())
        m0 = gw.route_metrics("lim")
        # A flood of bad credentials: refused as such, each, and not one of them spends a token.
        for i in range(25):
            what = (["Authorization: Bearer ck_test_flood%d" % i], [], ["Authorization: Basic eA=="], ["Authorization: Bearer " + WRONG])[i % 4]
            s, h, b, _ = get(gw, "/lim/flood%d" % i, what)
            assert s == 401 and rule_of(b).startswith("auth."), (i, s, b)
        m1 = gw.route_metrics("lim")
        assert m1["rate_limited"] == m0["rate_limited"] and m1["rate_table_full"] == m0["rate_table_full"], (m0, m1)
        assert sum(m1["auth_refused"].values()) == sum(m0["auth_refused"].values()) + 25, (m0, m1)
        # The burst is 2 a key: alice has all of hers after the flood, and so do the others, independently.
        assert [get(gw, "/lim/a%d" % i, [bearer("alice")])[0] for i in range(3)] == [200, 200, 429]
        assert [get(gw, "/lim/b%d" % i, [bearer("bob")])[0] for i in range(3)] == [200, 200, 429]
        assert get(gw, "/lim/c0", [bearer("carol")])[0] == 200
        s, h, b, _ = get(gw, "/lim/a9", [bearer("alice")])
        assert s == 429 and rule_of(b) == "limit.rate" and h["retry-after"] == "3600", (s, h)
        # Only the keys' own spending is limited: a bad credential is still a 401, not a 429, with alice's bucket empty.
        s, h, b, _ = get(gw, "/lim/bad", ["Authorization: Bearer " + WRONG])
        assert s == 401 and "retry-after" not in h, (s, h)
        assert seen(up, "/lim/") == 5, seen(up, "/lim/")
        m2 = gw.route_metrics("lim")
        assert m2["rate_limited"] == m0["rate_limited"] + 3 and m2["rate_table_full"] == m0["rate_table_full"], (m0, m2)
        e = gw.find(n0, path="/lim/a9")
        assert e["status"] == 429 and e["rule"] == "limit.rate" and e["identity"] == "alice", e
        # The same spelling of the key in another header is the same identity: the bucket is the name's, not the string's.
        assert get(gw, "/hl/x", [key_header("carol")])[0] == 200
        assert get(gw, "/hl/y", [key_header("carol")])[0] == 429
        assert get(gw, "/hl/z", [key_header("alice")])[0] == 200

    def a_websocket_upgrade_is_authenticated_and_a_refused_one_takes_no_tunnel_place(gw, up, ws):
        n0 = len(gw.lines())
        # Six upgrades that are refused and still lingering must not fill the two places the deployment allows.
        socks = []
        for i, extra in enumerate(([], ["Authorization: Bearer " + WRONG], ["Authorization: Basic eA=="], [], ["Authorization: Bearer " + WRONG], [])):
            raw, _ = wt.request_bytes("/wsa/r%d" % i, protocols=(), extra=extra)
            s = wt.open_socket(gw)
            s.sendall(raw)
            socks.append(s)
        got = []
        for s in socks:
            head, _ = wt.read_head(s)
            got.append(wt.parse_head(head)[0])
        assert got == [401] * 6, got
        a = wt.connect_ws(gw, "/wsa/a", protocols=(), extra=[bearer("alice")])
        b = wt.connect_ws(gw, "/wsa/b", protocols=(), extra=[bearer("bob")])
        a.text("hello")
        assert a.expect(1) == b"hello"
        for s in socks:
            s.close()
        a.close()
        b.close()
        # The credential does not reach the upstream, and the refused upgrades never did.
        assert seen(ws, "/wsa/r") == 0
        with ws.lock:
            heads = [h for h in ws.heads if h.split(b" ")[1].startswith(b"/wsa/")]
        assert len(heads) == 2 and all(b"authorization" not in h.lower() and KEYS["alice"].encode() not in h for h in heads), heads
        e = gw.find(n0, path="/wsa/a", wait=8)
        assert e["status"] == 101 and e["upgrade"] == "websocket" and e["identity"] == "alice" and list(e)[-1] == "identity", e
        e = gw.find(n0, path="/wsa/r0")
        assert e["status"] == 401 and e["rule"] == "auth.missing" and "identity" not in e and "upgrade" not in e, e
        # A route that does not authenticate is untouched, with or without a credential.
        o = wt.connect_ws(gw, "/wso/a", protocols=())
        o.close()

    def the_same_over_tls(gw, up, ws):
        n0 = len(gw.lines())
        s, h, b, _ = get(gw, "/b/tls-ok", [bearer("bob")], tls=True)
        assert s == 200 and b == b"ok"
        assert "authorization" not in head_of(up, "/b/tls-ok")[0]
        s, h, b, _ = get(gw, "/b/tls-none", [], tls=True)
        assert s == 401 and rule_of(b) == "auth.missing" and h["www-authenticate"] == BEARER, (s, h)
        s, h, b, _ = get(gw, "/b/tls-bad", ["Authorization: Bearer " + WRONG], tls=True)
        assert s == 401 and rule_of(b) == "auth.invalid", (s, b)
        s, h, b, _ = get(gw, "/s/tls-denied", [bearer("bob")], tls=True)
        assert s == 403 and rule_of(b) == "auth.forbidden"
        e = gw.find(n0, path="/b/tls-ok")
        assert e["tls"] is True and e["identity"] == "bob" and list(e)[-2:] == ["tls", "identity"], e
        # The plain and the TLS listener answer a bad credential in the same bytes but for the id.
        plain = masked(get(gw, "/b/tls-bad", ["Authorization: Bearer " + WRONG])[3])
        tls = masked(get(gw, "/b/tls-bad", ["Authorization: Bearer " + WRONG], tls=True)[3])
        assert plain == tls

    def the_log_names_the_identity_last_and_never_the_key(gw, up, ws):
        lines = gw.lines()
        authed = [l for l in lines if "identity" in l]
        assert authed and all(list(l)[-1] == "identity" for l in authed), authed[:2]
        assert {l["identity"] for l in authed} <= set(KEYS)
        plain = next(l for l in lines if l.get("route") == "open")
        shape = ["t", "id", "method", "path", "route", "upstream", "status", "rule", "outcome", "ms", "upstream_ms", "bytes_in", "bytes_out"]
        assert list(plain) == shape, list(plain)
        ok = next(l for l in authed if l["outcome"] == "ok")
        assert list(ok) == shape + ["identity"], list(ok)
        # Nowhere in anything the gateway wrote: not a key, not a digest.
        with gw.lock:
            everything = b"".join(gw.log)
        for name, key in KEYS.items():
            assert key.encode() not in everything and digest(key).encode() not in everything, name

    def the_binary_holds_digests_and_no_key(gw, up, ws):
        binary = (gw.tmp / "gateway").read_bytes()
        for name, key in KEYS.items():
            assert key.encode() not in binary, "the binary holds the key of %s" % name
            assert digest(key).encode() in binary, "the binary does not hold the digest of %s" % name
        assert WRONG.encode() not in binary

    def the_counters_agree_with_what_the_clients_were_told(gw, up, ws):
        lines = gw.lines()
        kinds = {"auth.missing": "missing", "auth.malformed": "malformed", "auth.invalid": "invalid", "auth.forbidden": "forbidden"}
        total = {k: 0 for k in kinds}
        for name in ("open", "bearer", "hdr", "fwd", "subset", "lim", "hdrlim", "wsa", "wso"):
            m = gw.route_metrics(name)
            for rule, kind in kinds.items():
                mine = [l for l in lines if l.get("route") == name and l.get("rule") == rule]
                assert m["auth_refused"][kind] == len(mine), (name, kind, m["auth_refused"][kind], len(mine))
                total[rule] += len(mine)
        assert list(gw.route_metrics("bearer")["auth_refused"]) == ["missing", "malformed", "invalid", "forbidden"]
        assert list(gw.route_metrics("bearer"))[-3:] == ["rate_limited", "rate_table_full", "auth_refused"]
        assert gw.route_metrics("open")["auth_refused"] == {"missing": 0, "malformed": 0, "invalid": 0, "forbidden": 0}
        m = gw.metrics()
        for rule, n in total.items():
            assert m["refusals"].get(rule, 0) == n and n > 0, (rule, m["refusals"].get(rule), n)
        prom = gw.admin_get("/metrics?format=prometheus").decode()
        assert "# TYPE cancho_gateway_auth_refused_total counter" in prom
        for name in ("bearer", "subset"):
            for kind in ("missing", "malformed", "invalid", "forbidden"):
                assert 'cancho_gateway_auth_refused_total{route="%s",kind="%s"} %d' % (name, kind, gw.route_metrics(name)["auth_refused"][kind]) in prom, (name, kind)

    def a_refusal_leaves_nothing_behind(gw, up, ws):
        time.sleep(0.8)
        m = gw.metrics()
        assert m["sessions_active"] <= 1 and m["ws"]["tunnels_active"] == 0, m["sessions_active"]
        assert gw.alive()
        # And a request still goes through after all of it.
        assert get(gw, "/b/last", [bearer("carol")])[0] == 200


def main():
    wanted = sys.argv[1:]
    todo = [n for n in vars(Main) if not n.startswith("_") and (not wanted or n in wanted)]
    unknown = [w for w in wanted if w not in todo]
    if unknown:
        print("no such test: %s" % ", ".join(unknown))
        return 2
    failures = 0
    with tempfile.TemporaryDirectory() as t1:
        up = pt.Upstream(pt.free_port())
        ws = wt.WsUpstream(pt.free_port())
        gw = rt.Gateway(t1, up.port, ws.port, ROUTES, top=TOP)
        try:
            for name in todo:
                t0 = time.time()
                try:
                    getattr(Main, name)(gw, up, ws)
                    if not gw.alive():
                        raise AssertionError("the gateway died")
                    print("ok    %-90s %.1fs" % (name, time.time() - t0))
                except (AssertionError, OSError, EOFError, KeyError, IndexError, ValueError, StopIteration) as e:
                    failures += 1
                    print("FAIL  %-90s %s: %s (line %d)" % (name, type(e).__name__, e, traceback.extract_tb(e.__traceback__)[-1].lineno))
                    if not gw.alive():
                        print("      the gateway died: exit %s %s" % (gw.proc.returncode, gw.proc.stderr.read()[:300]))
                        break
        finally:
            gw.stop()
    print("%d tests, %d failures" % (len(todo), failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
