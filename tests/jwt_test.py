#!/usr/bin/env python3
"""JWT verification end to end (docs/jwt.md section 11, gate 3): a built gateway, a recording upstream, tokens made in memory and clients that count what they were told.

    python3 tests/jwt_test.py [test_name ...]            # all tests, or the named ones
    JWT_TREE=/path/to/copy python3 tests/jwt_test.py ...   # build the gateway from another copy of the tree (tests/jwt_mutants.py)

One gateway is built from loose files, as tests/auth_test.py does: plain, TLS and WebSocket listeners and an admin one, two public keys made here (fresh seeds every run, never written to
a file: the gateway is given the public halves), and a route for each thing a token can be asked to be. Tokens are signed by scripts/jwtkit.py (pure Python, RFC 8032). The clock cannot be
injected into the built gateway, so the leeway is tested with margins of at least two seconds each side of the boundary (the exact boundaries are tests/jwt_test.cho's).
Needs `build/deps` filled by one `cancho build`, and `openssl` for the TLS certificates.
"""

import hashlib
import hmac
import json
import os
import pathlib
import re
import secrets
import sys
import tempfile
import time
import traceback

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
os.environ.setdefault("RL_TREE", os.environ.get("JWT_TREE", ""))
if not os.environ["RL_TREE"]:
    del os.environ["RL_TREE"]
import jwtkit  # noqa: E402
import proxy_test as pt  # noqa: E402
import ratelimit_test as rt  # noqa: E402
import websocket_test as wt  # noqa: E402
from ratelimit_test import get, rule_of, seen  # noqa: E402

# Made here, never read from a file. The gateway is given the public halves. SEED3 signs what no route trusts.
SEED1, SEED2, SEED3 = (secrets.token_bytes(32) for _ in range(3))
PK1, PK2 = jwtkit.b64u(jwtkit.public_key(SEED1)), jwtkit.b64u(jwtkit.public_key(SEED2))
ISS = "https://iss.example"
ALICE = "ck_test_alice_" + "A" * 29
DOTTED = "ck.a.b"          # an API key with two dots: on a route that also takes tokens it is read as one (docs/jwt.md section 12.1)


def digest(key):
    return hashlib.sha256(key.encode()).hexdigest()


TOP = "auth_allow_plain = true\n"
ROUTES = """
[[jwt_key]]
name = "k1"
public_key = "%s"

[[jwt_key]]
name = "k2"
public_key = "%s"

[[api_key]]
name = "alice"
sha256 = "%s"

[[api_key]]
name = "dotted"
sha256 = "%s"
""" % (PK1, PK2, digest(ALICE), digest(DOTTED)) + """
[[route]]
name = "open"
path_prefix = "/open"
upstream = "up"

[[route]]
name = "jwt"
path_prefix = "/j"
upstream = "up"
auth = "jwt"
jwt_aud = "api"
jwt_iss = "https://iss.example"

[[route]]
name = "solo"
path_prefix = "/j1"
upstream = "up"
auth = "jwt"
jwt_keys = ["k1"]
jwt_aud = "api"

[[route]]
name = "aud2"
path_prefix = "/a2"
upstream = "up"
auth = "jwt"
jwt_aud = "other"
jwt_iss = "https://iss.example"

[[route]]
name = "lee"
path_prefix = "/lee"
upstream = "up"
auth = "jwt"
jwt_aud = "api"
jwt_leeway = 5

[[route]]
name = "fwd"
path_prefix = "/f"
upstream = "up"
auth = "jwt"
auth_forward = true

[[route]]
name = "noaud"
path_prefix = "/na"
upstream = "up"
auth = "jwt"

[[route]]
name = "both"
path_prefix = "/both"
upstream = "up"
auth = ["api-key", "jwt"]
jwt_aud = "api"

[[route]]
name = "apionly"
path_prefix = "/ao"
upstream = "up"
auth = "api-key"

[[route]]
name = "lim"
path_prefix = "/lim"
upstream = "up"
auth = "jwt"
jwt_aud = "api"
jwt_iss = "https://iss.example"
rate_limit = "1/h"
rate_burst = 2

[[route]]
name = "wsa"
path_prefix = "/wsa"
upstream = "ws"
websocket = true
auth = "jwt"
jwt_aud = "api"

[[route]]
name = "wso"
path_prefix = "/wso"
upstream = "ws"
websocket = true
"""

BEARER = 'Bearer realm="cancho-gateway"'
INVALID_TOKEN = BEARER + ', error="invalid_token"'
INVALID_REQUEST = BEARER + ', error="invalid_request"'
ID = re.compile(rb"[0-9a-f]+-[0-9a-f]+-[0-9a-f]{8}")
KINDS = ["malformed", "alg", "header", "kid", "claims", "expired", "not_yet_valid", "audience", "issuer", "clock", "signature"]
TAGS = ["jwt." + k for k in ("malformed", "alg", "header", "kid", "claims", "expired", "nbf", "aud", "iss", "clock", "signature")]


def masked(raw):
    return ID.sub(b"ID", raw)


def head_of(up, path):
    with up.lock:
        for h in up.heads:
            if h.split(b" ")[1].decode() == path:
                return pt.heads_of(h), h
    raise AssertionError("the upstream never saw %s" % path)


def now():
    return int(time.time())


def claims(**kw):
    c = {"exp": now() + 300, "iss": ISS, "aud": "api", "sub": "alice"}
    c.update(kw)
    return {k: v for k, v in c.items() if v is not None}


def header(**kw):
    h = {"alg": "EdDSA", "typ": "JWT", "kid": "k1"}
    h.update(kw)
    return {k: v for k, v in h.items() if v is not None}


def tok(h=None, p=None, seed=SEED1, **raw):
    return jwtkit.compact(header() if h is None else h, claims() if p is None else p, seed, **raw)


def auth(token):
    return "Authorization: Bearer " + token


def b64j(obj):
    return jwtkit.b64u(json.dumps(obj, separators=(",", ":")).encode())


def parts(t):
    return t.split(".")


def hs256_confusion():
    """The classic attack: an HS256 token whose HMAC key is the deployment's public key."""
    hh = b64j({"alg": "HS256", "typ": "JWT", "kid": "k1"})
    pp = b64j(claims())
    sig = hmac.new(jwtkit.public_key(SEED1), (hh + "." + pp).encode(), hashlib.sha256).digest()
    return hh + "." + pp + "." + jwtkit.b64u(sig)


def causes():
    """(what, token, the rule the log must say): every way a token on /j can be refused for its content."""
    good = tok()
    h, p, s = parts(good)
    flipped = s[:20] + ("B" if s[20] != "B" else "C") + s[21:]
    t = now()
    return [
        ("expired", tok(p=claims(exp=t - 30)), "jwt.expired"),
        ("not yet valid", tok(p=claims(nbf=t + 600)), "jwt.nbf"),
        ("wrong audience", tok(p=claims(aud="other")), "jwt.aud"),
        ("no audience", tok(p=claims(aud=None)), "jwt.aud"),
        ("wrong issuer", tok(p=claims(iss="https://evil.example")), "jwt.iss"),
        ("wrong signature", h + "." + p + "." + flipped, "jwt.signature"),
        ("signed by a key no route trusts, with a trusted kid", tok(seed=SEED3), "jwt.signature"),
        ("alg none, unsigned", jwtkit.b64u(b'{"alg":"none","kid":"k1"}') + "." + p + ".", "jwt.alg"),
        ("alg none, with a signature", tok(h=header(alg="none")), "jwt.alg"),
        ("alg HS256 signed with the public key as the secret", hs256_confusion(), "jwt.alg"),
        ("alg RS256", tok(h=header(alg="RS256")), "jwt.alg"),
        ("alg in the wrong case", tok(h=header(alg="eddsa")), "jwt.alg"),
        ("payload tampered after signing", h + "." + b64j(claims(exp=now() + 99999)) + "." + s, "jwt.signature"),
        ("header tampered after signing", b64j(header(kid="k2")) + "." + p + "." + s, "jwt.signature"),
        ("duplicate claims", tok(raw_payload=b'{"exp":%d,"aud":"api","iss":"%s","exp":1}' % (now() + 300, ISS.encode())), "jwt.malformed"),
        ("duplicate header members", tok(raw_header=b'{"alg":"none","alg":"EdDSA","kid":"k1"}'), "jwt.malformed"),
        ("oversize payload", tok(p=claims(pad="x" * 1500)), "jwt.malformed"),
        ("oversize token", tok(p=claims(pad="x" * 1500)) + "A" * 1000, "jwt.malformed"),
        ("malformed base64url (+)", h + "." + p[:5] + "+" + p[6:] + "." + s, "jwt.malformed"),
        ("padding", h + "=." + p + "." + s, "jwt.malformed"),
        ("one dot", h + "." + p + s, "jwt.malformed"),
        ("three dots", good + ".AAAA", "jwt.malformed"),
        ("no dots", "not-a-token", "jwt.malformed"),
        ("empty signature", h + "." + p + ".", "jwt.malformed"),
        ("a signature of the wrong length", h + "." + p + "." + s[:-4], "jwt.malformed"),
        ("a payload that is not JSON", tok(raw_payload=b"hello"), "jwt.malformed"),
        ("a payload that is an array", tok(raw_payload=b"[1]"), "jwt.malformed"),
        ("no exp", tok(p=claims(exp=None)), "jwt.claims"),
        ("exp as a float", tok(raw_payload=b'{"exp":%d.0,"aud":"api","iss":"%s"}' % (now() + 300, ISS.encode())), "jwt.claims"),
        ("exp as a string", tok(p=claims(exp=str(now() + 300))), "jwt.claims"),
        ("an unknown kid", tok(h=header(kid="nobody")), "jwt.kid"),
        ("no kid on a route with two keys", tok(h=header(kid=None)), "jwt.kid"),
        ("crit", tok(h=header(crit=["exp"])), "jwt.header"),
        ("a typ that is not JWT", tok(h=header(typ="at+jwt")), "jwt.header"),
    ]


class Main:
    def a_valid_token_passes_and_the_credential_is_not_forwarded(gw, up, ws):
        n0 = len(gw.lines())
        for i, (kid, seed) in enumerate((("k1", SEED1), ("k2", SEED2))):
            t = tok(h=header(kid=kid), seed=seed)
            s, h, b, _ = get(gw, "/j/ok%d" % i, [auth(t)])
            assert s == 200 and b == b"ok", (kid, s, b)
            heads, raw = head_of(up, "/j/ok%d" % i)
            assert "authorization" not in heads and t.encode() not in raw and heads["via"] == ["1.1 cancho-gateway"], heads
            e = gw.find(n0, path="/j/ok%d" % i)
            assert e["status"] == 200 and e["identity"] == kid and list(e)[-1] == "identity" and e["route"] == "jwt", e
        # A token with no kid on a route that has exactly one key (the key is not a choice), the typ in another case, an audience array, whitespace in the payload.
        assert get(gw, "/j1/nokid", [auth(tok(h=header(kid=None)))])[0] == 200
        assert get(gw, "/j/typ", [auth(tok(h=header(typ="jwt")))])[0] == 200
        assert get(gw, "/j/audarray", [auth(tok(p=claims(aud=["x", "api", "y"])))])[0] == 200
        assert get(gw, "/j/ignored", [auth(tok(h=header(jku="https://evil.example/jwks", jwk={"kty": "OKP"})))])[0] == 200
        # A scheme and a header name in any case are accepted, as for API keys.
        assert get(gw, "/j/case", ["authorization: bearer " + tok()])[0] == 200

    def auth_forward_keeps_the_token(gw, up, ws):
        t = tok()
        s, *_ = get(gw, "/f/kept", [auth(t)])
        assert s == 200
        heads, _ = head_of(up, "/f/kept")
        assert heads["authorization"] == ["Bearer " + t], heads
        assert get(gw, "/f/no")[0] == 401

    def routes_without_auth_are_unaffected(gw, up, ws):
        n0 = len(gw.lines())
        for i, extra in enumerate(([], ["Authorization: Bearer " + tok()], ["Authorization: Bearer a.b.c"], ["Authorization: Basic Zm9v"])):
            s, h, b, _ = get(gw, "/open/%d" % i, extra)
            assert s == 200 and b == b"ok", (i, s)
            heads, _ = head_of(up, "/open/%d" % i)
            assert heads.get("authorization", []) == [e.split(": ", 1)[1] for e in extra], (i, heads)
            e = gw.find(n0, path="/open/%d" % i)
            assert e["status"] == 200 and "identity" not in e, e

    def every_invalid_token_is_refused_with_the_same_response_and_its_own_tag_in_the_log(gw, up, ws):
        n0 = len(gw.lines())
        answers = {}
        for i, (what, token, tag) in enumerate(causes()):
            path = "/j/bad%d" % i
            s, h, b, raw = get(gw, path, [auth(token)])
            assert s == 401, (what, s, b)
            assert rule_of(b) == "auth.invalid" and h["www-authenticate"] == INVALID_TOKEN, (what, h, b)
            assert h["content-type"] == "application/problem+json" and h["connection"] == "close", (what, h)
            body = json.loads(b)
            assert body["status"] == 401 and body["title"] == "Unauthorized" and body["request_id"] == h["x-request-id"], (what, body)
            assert raw.index(b"Content-Length") < raw.index(b"WWW-Authenticate") < raw.index(b"X-Request-Id"), (what, raw[:300])
            assert token.encode() not in raw and parts(tok())[2].encode() not in raw, (what, "the refusal echoes the token")
            assert seen(up, path) == 0, (what, "the upstream saw a refused request")
            answers[what] = masked(raw)
            e = gw.find(n0, path=path)
            assert e["status"] == 401 and e["rule"] == tag and e["outcome"] == "refused" and e["route"] == "jwt" and "identity" not in e, (what, e["rule"], tag)
        # One answer, byte for byte but for the request id: nothing says which check failed.
        assert len(set(answers.values())) == 1, {w: a[:160] for w, a in answers.items()}
        assert len(answers) >= 30

    def a_credential_that_is_not_a_token_at_all_is_the_requests_fault_not_the_tokens(gw, up, ws):
        # Syntax of the header (RFC 6750 2.1), as for API keys: its own tag and challenge, decided before any token is looked at.
        for what, headers, rule, challenge in (
                ("no header", [], "auth.missing", BEARER),
                ("empty", ["Authorization:"], "auth.malformed", INVALID_REQUEST),
                ("Basic", ["Authorization: Basic dXNlcjpwYXNz"], "auth.malformed", INVALID_REQUEST),
                ("twice", [auth(tok()), auth(tok())], "auth.malformed", INVALID_REQUEST),
                ("a space inside", ["Authorization: Bearer a b.c.d"], "auth.malformed", INVALID_REQUEST),
                ("a quote", ['Authorization: Bearer "x.y.z"'], "auth.malformed", INVALID_REQUEST),
                ("two spaces", ["Authorization: Bearer  " + tok()], "auth.malformed", INVALID_REQUEST)):
            s, h, b, _ = get(gw, "/j/hdr", headers)
            assert s == 401 and rule_of(b) == rule and h["www-authenticate"] == challenge, (what, s, h, b)
        assert seen(up, "/j/hdr") == 0

    def a_token_valid_for_one_route_is_refused_on_a_route_with_another_audience(gw, up, ws):
        n0 = len(gw.lines())
        t = tok()
        assert get(gw, "/j/aud", [auth(t)])[0] == 200
        s, h, b, _ = get(gw, "/a2/aud", [auth(t)])
        assert s == 401 and rule_of(b) == "auth.invalid" and gw.find(n0, path="/a2/aud")["rule"] == "jwt.aud"
        # A token for both audiences, and one for the other route's audience.
        both = tok(p=claims(aud=["api", "other"]))
        assert get(gw, "/j/aud2", [auth(both)])[0] == 200 and get(gw, "/a2/aud2", [auth(both)])[0] == 200
        other = tok(p=claims(aud="other"))
        assert get(gw, "/a2/aud3", [auth(other)])[0] == 200 and get(gw, "/j/aud3", [auth(other)])[0] == 401
        # A route that configures no audience and no issuer accepts any.
        assert get(gw, "/na/any", [auth(tok(p=claims(aud="whatever", iss="whoever")))])[0] == 200
        assert get(gw, "/na/none", [auth(tok(p=claims(aud=None, iss=None)))])[0] == 200
        # A token for an issuer the route did not configure.
        assert get(gw, "/a2/iss", [auth(tok(p=claims(aud="other", iss="https://evil.example")))])[0] == 401

    def a_route_only_accepts_the_keys_it_allows(gw, up, ws):
        n0 = len(gw.lines())
        assert get(gw, "/j1/k1", [auth(tok(h=header(kid="k1")))])[0] == 200
        s, h, b, _ = get(gw, "/j1/k2", [auth(tok(h=header(kid="k2"), seed=SEED2))])
        assert s == 401 and rule_of(b) == "auth.invalid" and gw.find(n0, path="/j1/k2")["rule"] == "jwt.kid"

    def the_leeway_is_a_margin_on_exp_and_nbf_and_nothing_else(gw, up, ws):
        t = now()
        # /j has no leeway: a second or two past exp is expired, a second or two before it is not; nbf the same the other way round.
        assert get(gw, "/j/e1", [auth(tok(p=claims(exp=t + 3)))])[0] == 200
        assert get(gw, "/j/e2", [auth(tok(p=claims(exp=t - 2)))])[0] == 401
        assert get(gw, "/j/n1", [auth(tok(p=claims(nbf=t - 2)))])[0] == 200
        assert get(gw, "/j/n2", [auth(tok(p=claims(nbf=t + 3)))])[0] == 401
        # /lee has 5 seconds: exp two seconds past and nbf three seconds ahead are inside it, eight and nine outside.
        assert get(gw, "/lee/e1", [auth(tok(p=claims(exp=t - 2)))])[0] == 200
        assert get(gw, "/lee/e2", [auth(tok(p=claims(exp=t - 8)))])[0] == 401
        assert get(gw, "/lee/n1", [auth(tok(p=claims(nbf=t + 3)))])[0] == 200
        assert get(gw, "/lee/n2", [auth(tok(p=claims(nbf=t + 9)))])[0] == 401
        # The leeway extends exp and nbf and no other claim: a wrong audience is wrong however lenient the clock.
        assert get(gw, "/lee/aud", [auth(tok(p=claims(aud="other")))])[0] == 401

    def authentication_comes_before_the_rate_limiter(gw, up, ws):
        m0 = gw.route_metrics("lim")
        n0 = len(gw.lines())
        # A flood of bad tokens is refused as such, each, and not one spends a token of the route's bucket (burst 2).
        for i, (what, token, tag) in enumerate(causes()):
            s, h, b, _ = get(gw, "/lim/flood%d" % i, [auth(token)])
            assert s == 401 and rule_of(b) == "auth.invalid", (what, s, b)
        m1 = gw.route_metrics("lim")
        assert m1["rate_limited"] == m0["rate_limited"] and m1["rate_table_full"] == m0["rate_table_full"], (m0, m1)
        assert sum(m1["jwt_refused"].values()) == sum(m0["jwt_refused"].values()) + len(causes()), (m0, m1)
        # The bucket is whole afterwards: two good tokens go in and the third is the limiter's.
        assert [get(gw, "/lim/g%d" % i, [auth(tok())])[0] for i in range(3)] == [200, 200, 429]
        s, h, b, _ = get(gw, "/lim/bad", [auth(tok(p=claims(aud="other")))])
        assert s == 401 and "retry-after" not in h, (s, h)
        assert seen(up, "/lim/") == 2

    def a_websocket_upgrade_is_authenticated_and_a_refused_one_takes_no_tunnel_place(gw, up, ws):
        n0 = len(gw.lines())
        socks = []
        for i, extra in enumerate(([], [auth(tok(p=claims(exp=now() - 30)))], [auth("a.b.c")], ["Authorization: Basic eA=="], [auth(tok(seed=SEED3))], [])):
            raw, _ = wt.request_bytes("/wsa/r%d" % i, protocols=(), extra=extra)
            s = wt.open_socket(gw)
            s.sendall(raw)
            socks.append(s)
        got = []
        for s in socks:
            head, _ = wt.read_head(s)
            got.append(wt.parse_head(head)[0])
        assert got == [401] * 6, got
        t = tok()
        a = wt.connect_ws(gw, "/wsa/a", protocols=(), extra=[auth(t)])
        b = wt.connect_ws(gw, "/wsa/b", protocols=(), extra=[auth(tok(h=header(kid="k2"), seed=SEED2))])
        a.text("hello")
        assert a.expect(1) == b"hello"
        for s in socks:
            s.close()
        a.close()
        b.close()
        assert seen(ws, "/wsa/r") == 0
        with ws.lock:
            heads = [h for h in ws.heads if h.split(b" ")[1].startswith(b"/wsa/")]
        assert len(heads) == 2 and all(b"authorization" not in h.lower() and t.encode() not in h for h in heads), heads
        e = gw.find(n0, path="/wsa/a", wait=8)
        assert e["status"] == 101 and e["upgrade"] == "websocket" and e["identity"] == "k1" and list(e)[-1] == "identity", e
        e = gw.find(n0, path="/wsa/r1")
        assert e["status"] == 401 and e["rule"] == "jwt.expired" and "identity" not in e and "upgrade" not in e, e
        wt.connect_ws(gw, "/wso/a", protocols=()).close()

    def the_same_over_tls(gw, up, ws):
        n0 = len(gw.lines())
        t = tok(h=header(kid="k2"), seed=SEED2)
        s, h, b, _ = get(gw, "/j/tls-ok", [auth(t)], tls=True)
        assert s == 200 and b == b"ok"
        assert "authorization" not in head_of(up, "/j/tls-ok")[0]
        s, h, b, _ = get(gw, "/j/tls-none", [], tls=True)
        assert s == 401 and rule_of(b) == "auth.missing" and h["www-authenticate"] == BEARER, (s, h)
        bad = tok(p=claims(exp=now() - 30))
        s, h, b, _ = get(gw, "/j/tls-bad", [auth(bad)], tls=True)
        assert s == 401 and rule_of(b) == "auth.invalid" and h["www-authenticate"] == INVALID_TOKEN, (s, b)
        e = gw.find(n0, path="/j/tls-ok")
        assert e["tls"] is True and e["identity"] == "k2" and list(e)[-2:] == ["tls", "identity"], e
        assert gw.find(n0, path="/j/tls-bad")["rule"] == "jwt.expired"
        plain = masked(get(gw, "/j/tls-bad", [auth(bad)])[3])
        over_tls = masked(get(gw, "/j/tls-bad", [auth(bad)], tls=True)[3])
        assert plain == over_tls

    def a_route_that_takes_both_kinds_decides_by_the_shape_and_never_falls_back(gw, up, ws):
        n0 = len(gw.lines())
        # An API key and a token each work.
        assert get(gw, "/both/key", ["Authorization: Bearer " + ALICE])[0] == 200
        assert get(gw, "/both/jwt", [auth(tok())])[0] == 200
        e = gw.find(n0, path="/both/key")
        assert e["identity"] == "alice", e
        e = gw.find(n0, path="/both/jwt")
        assert e["identity"] == "k1", e
        for path in ("/both/key", "/both/jwt"):
            heads, raw = head_of(up, path)
            assert "authorization" not in heads, heads
        # A wrong key is the key's refusal (auth.invalid, from the API-key path); a bad token is the token's (jwt.*), the same answer on the wire.
        s, h, b, raw_key = get(gw, "/both/badkey", ["Authorization: Bearer ck_test_unknown"])
        assert s == 401 and rule_of(b) == "auth.invalid" and h["www-authenticate"] == INVALID_TOKEN
        assert gw.find(n0, path="/both/badkey")["rule"] == "auth.invalid"
        s, h, b, raw_tok = get(gw, "/both/badtok", [auth(tok(p=claims(exp=now() - 30)))])
        assert s == 401 and rule_of(b) == "auth.invalid" and h["www-authenticate"] == INVALID_TOKEN
        assert gw.find(n0, path="/both/badtok")["rule"] == "jwt.expired"
        assert masked(raw_key) == masked(raw_tok)
        # No downgrade: a credential with two dots is a token and only a token. An API key that has two dots works on a route that takes keys alone and not on one that also takes tokens.
        assert get(gw, "/ao/dotted", ["Authorization: Bearer " + DOTTED])[0] == 200
        s, h, b, _ = get(gw, "/both/dotted", ["Authorization: Bearer " + DOTTED])
        assert s == 401 and gw.find(n0, path="/both/dotted")["rule"] == "jwt.malformed", (s, b)
        # And the other way: a token on a route that takes keys alone is a key that does not exist (the dots are in the alphabet), never a token.
        s, h, b, _ = get(gw, "/ao/token", [auth(tok())])
        assert s == 401 and gw.find(n0, path="/ao/token")["rule"] == "auth.invalid", (s, b)
        # A credential of 257 bytes with no dots is an oversized key, as ever; with two dots it is a token and `jwt.malformed`.
        s, h, b, _ = get(gw, "/both/long", ["Authorization: Bearer " + "k" * 257])
        assert s == 401 and rule_of(b) == "auth.malformed" and h["www-authenticate"] == INVALID_REQUEST, (s, h)
        s, h, b, _ = get(gw, "/both/long2", ["Authorization: Bearer " + "k" * 120 + "." + "k" * 120 + "." + "k" * 100])
        assert s == 401 and rule_of(b) == "auth.invalid" and gw.find(n0, path="/both/long2")["rule"] == "jwt.malformed"
        # A route that takes tokens alone, given an API key: not a token.
        s, h, b, _ = get(gw, "/j/key", ["Authorization: Bearer " + ALICE])
        assert s == 401 and gw.find(n0, path="/j/key")["rule"] == "jwt.malformed"

    def the_log_names_the_verifying_key_last_and_never_the_token(gw, up, ws):
        lines = gw.lines()
        authed = [l for l in lines if "identity" in l]
        assert authed and all(list(l)[-1] == "identity" for l in authed), authed[:2]
        assert {l["identity"] for l in authed} <= {"k1", "k2", "alice", "dotted"}
        plain = next(l for l in lines if l.get("route") == "open")
        shape = ["t", "id", "method", "path", "route", "upstream", "status", "rule", "outcome", "ms", "upstream_ms", "bytes_in", "bytes_out"]
        assert list(plain) == shape, list(plain)
        with gw.lock:
            everything = b"".join(gw.log)
        assert b"eyJ" not in everything, "a token (or a piece of one) is in the log"
        for part in (PK1, PK2):
            assert part.encode() not in everything

    def the_binary_holds_public_keys_and_no_seed(gw, up, ws):
        binary = (gw.tmp / "gateway").read_bytes()
        for seed, pk in ((SEED1, PK1), (SEED2, PK2)):
            assert pk.encode() in binary, "the binary does not hold a public key"
            assert seed not in binary and seed.hex().encode() not in binary and jwtkit.b64u(seed).encode() not in binary, "the binary holds a seed"
        assert jwtkit.b64u(SEED3).encode() not in binary

    def the_counters_agree_with_what_the_clients_were_told(gw, up, ws):
        lines = gw.lines()
        total = {k: 0 for k in TAGS}
        for name in ("open", "jwt", "solo", "aud2", "lee", "fwd", "noaud", "both", "apionly", "lim", "wsa", "wso"):
            m = gw.route_metrics(name)
            assert list(m["jwt_refused"]) == KINDS, list(m["jwt_refused"])
            for kind, tag in zip(KINDS, TAGS):
                mine = [l for l in lines if l.get("route") == name and l.get("rule") == tag]
                assert m["jwt_refused"][kind] == len(mine), (name, kind, m["jwt_refused"][kind], len(mine))
                total[tag] += len(mine)
        assert gw.route_metrics("open")["jwt_refused"] == {k: 0 for k in KINDS}
        m = gw.metrics()
        for tag, n in total.items():
            assert m["refusals"].get(tag, 0) == n, (tag, m["refusals"].get(tag), n)
        assert all(total[t] > 0 for t in TAGS if t != "jwt.clock"), total
        assert total["jwt.clock"] == 0
        prom = gw.admin_get("/metrics?format=prometheus").decode()
        assert "# TYPE cancho_gateway_jwt_refused_total counter" in prom
        for name in ("jwt", "lim", "both"):
            for kind in KINDS:
                assert 'cancho_gateway_jwt_refused_total{route="%s",kind="%s"} %d' % (name, kind, gw.route_metrics(name)["jwt_refused"][kind]) in prom, (name, kind)
        # Every token refusal was a 401 `auth.invalid` to the client, and slice 1's counter of that rule does not count them (its `invalid` is the API keys').
        assert gw.route_metrics("jwt")["auth_refused"]["invalid"] == 0

    def a_refusal_leaves_nothing_behind(gw, up, ws):
        time.sleep(0.8)
        m = gw.metrics()
        assert m["sessions_active"] <= 1 and m["ws"]["tunnels_active"] == 0, m["sessions_active"]
        assert gw.alive()
        assert get(gw, "/j/last", [auth(tok())])[0] == 200


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
                    print("ok    %-96s %.1fs" % (name, time.time() - t0))
                except (AssertionError, OSError, EOFError, KeyError, IndexError, ValueError, StopIteration) as e:
                    failures += 1
                    print("FAIL  %-96s %s: %s (line %d)" % (name, type(e).__name__, e, traceback.extract_tb(e.__traceback__)[-1].lineno))
                    if not gw.alive():
                        print("      the gateway died: exit %s %s" % (gw.proc.returncode, gw.proc.stderr.read()[:300]))
                        break
        finally:
            gw.stop()
    print("%d tests, %d failures" % (len(todo), failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
