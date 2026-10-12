#!/usr/bin/env python3
"""A differential check of the verifier against an independent implementation (docs/jwt.md section 11, gate 5).

    python3 tests/jwt_differential.py [N] [SEED]    # N tokens (default 1500), a fixed random seed (default 8037)

A corpus of tokens is made with Python's `cryptography` (OpenSSL) as the signer: valid tokens of every shape the rules allow, and every kind of corruption of them (a flipped character,
another alphabet, a repeated member, a float where an integer is wanted, a deep claim, ...), some re-signed so that the claims logic is what decides, some not. Each is sent to a built
gateway, and what it answered (the status and the rule tag in its access log) is compared with `reference()` below: the rules of docs/jwt.md written again from the document, in Python,
with `json` for the syntax and OpenSSL for the signature. Any disagreement is printed and fails the run. Needs `cryptography`; without it the corpus is signed with scripts/jwtkit.py and
the run says so (the signing is then not independent: the verification by the gateway still is).
"""
import base64
import hashlib
import json
import os
import pathlib
import random
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
import jwt_test as jt  # noqa: E402
import jwtkit  # noqa: E402
import proxy_test as pt  # noqa: E402
import ratelimit_test as rt  # noqa: E402
import websocket_test as wt  # noqa: E402

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    OPENSSL = True
except ImportError:
    OPENSSL = False

ALPHABET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
LIMITS = {"token": 2048, "header_seg": 256, "payload_seg": 1366, "header": 192, "payload": 1024, "depth": 4, "members": 64, "name": 64}
MAX_TIME = 253402300799
AUD, ISS = "api", "https://iss.example"


# ---- the reference: docs/jwt.md again, in Python ----

def b64_strict(text):
    """The bytes of a base64url segment, or None: alphabet only, length not 1 mod 4, canonical (one spelling per byte string)."""
    if len(text) % 4 == 1 or not set(text) <= ALPHABET:
        return None
    raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    return raw if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() == text else None


def depth(value):
    if isinstance(value, dict):
        return 1 + max([depth(v) for v in value.values()] + [0])
    if isinstance(value, list):
        return 1 + max([depth(v) for v in value] + [0])
    return 0


def has_surrogate(value):
    if isinstance(value, str):
        return any(0xD800 <= ord(c) <= 0xDFFF for c in value)
    if isinstance(value, dict):
        return any(has_surrogate(k) or has_surrogate(v) for k, v in value.items())
    if isinstance(value, list):
        return any(has_surrogate(v) for v in value)
    return False


def parse_object(raw, limit):
    """The JSON object `raw` is, or None: strict syntax, at most `limit` bytes, a root object, nesting, members, names, no repeated name."""
    if len(raw) > limit:
        return None

    def pairs(items):
        keys = [k for k, _ in items]
        if len(set(keys)) != len(keys):
            raise ValueError("repeated name")
        return dict(items)

    def refuse(constant):
        raise ValueError(constant)

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=refuse)
    except (ValueError, RecursionError):
        return None
    if not isinstance(value, dict) or depth(value) > LIMITS["depth"] - 0 or len(value) > LIMITS["members"] or any(len(k.encode()) > LIMITS["name"] for k in value) or has_surrogate(value):
        return None
    return value


def is_time(v):
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= MAX_TIME


def reference(token, keys, allowed, aud, iss, leeway, now_s):
    """(accepted key name or None, rule tag or None)."""
    if len(token) > LIMITS["token"] or token.count(".") != 2:
        return None, "jwt.malformed"
    hseg, pseg, sseg = token.split(".")
    if not hseg or not pseg or len(hseg) > LIMITS["header_seg"] or len(pseg) > LIMITS["payload_seg"]:
        return None, "jwt.malformed"
    hraw = b64_strict(hseg)
    header = parse_object(hraw, LIMITS["header"]) if hraw is not None else None
    if header is None:
        return None, "jwt.malformed"
    if header.get("alg") != "EdDSA" or not isinstance(header.get("alg"), str):
        return None, "jwt.alg"
    if "crit" in header:
        return None, "jwt.header"
    if "typ" in header and not (isinstance(header["typ"], str) and header["typ"].lower() == "jwt" and header["typ"].isascii()):
        return None, "jwt.header"
    names = [k for k in keys if k in allowed]
    kid = header.get("kid", None)
    if "kid" in header:
        pick = kid if isinstance(kid, str) and kid in names else None
    else:
        pick = names[0] if len(names) == 1 else None
    if pick is None:
        return None, "jwt.kid"
    if len(sseg) != 86 or b64_strict(sseg) is None:
        return None, "jwt.malformed"
    praw = b64_strict(pseg)
    payload = parse_object(praw, LIMITS["payload"]) if praw is not None else None
    if payload is None:
        return None, "jwt.malformed"
    exp, nbf, iat = payload.get("exp"), payload.get("nbf"), payload.get("iat")
    if "exp" not in payload or not is_time(exp) or ("nbf" in payload and not is_time(nbf)) or ("iat" in payload and not is_time(iat)):
        return None, "jwt.claims"
    if now_s >= exp + leeway:
        return None, "jwt.expired"
    if "nbf" in payload and now_s + leeway < nbf:
        return None, "jwt.nbf"
    if iss and payload.get("iss") != iss:
        return None, "jwt.iss"
    if aud:
        a = payload.get("aud")
        ok = a == aud if isinstance(a, str) else isinstance(a, list) and len(a) <= 16 and all(isinstance(x, str) for x in a) and aud in a
        if not ok:
            return None, "jwt.aud"
    msg = (hseg + "." + pseg).encode()
    sig = base64.urlsafe_b64decode(sseg + "==")
    public = keys[pick]
    try:
        if OPENSSL:
            Ed25519PublicKey.from_public_bytes(public).verify(sig, msg)
        elif not jwtkit.verify(public, msg, sig):
            raise ValueError("signature")
    except (InvalidSignature, ValueError):
        return None, "jwt.signature"
    return pick, None


# ---- the corpus ----

class Signer:
    def __init__(self, seed):
        self.seed = seed
        self.private = Ed25519PrivateKey.from_private_bytes(seed) if OPENSSL else None
        self.public = jwtkit.public_key(seed)

    def sign(self, msg):
        return self.private.sign(msg) if OPENSSL else jwtkit.sign(self.seed, msg)


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def jbytes(obj):
    return json.dumps(obj, separators=(",", ":")).encode()


def make(signer, hdr, pay, raw_h=None, raw_p=None):
    h, p = b64(raw_h if raw_h is not None else jbytes(hdr)), b64(raw_p if raw_p is not None else jbytes(pay))
    return h + "." + p + "." + b64(signer.sign((h + "." + p).encode()))


def corpus(rng, signers, n, t):
    """Yield (what, token): valid tokens with one change at a time, and sometimes two."""
    names = list(signers)

    def base_header():
        return {"alg": "EdDSA", "typ": "JWT", "kid": rng.choice(names)}

    def base_payload():
        return {"exp": t + rng.choice([60, 300, 3600, 10 ** 6]), "iss": ISS, "aud": AUD, "sub": "u%d" % rng.randrange(1000)}

    header_edits = [
        ("alg none", lambda h: h.update(alg="none")), ("alg HS256", lambda h: h.update(alg="HS256")), ("alg lower", lambda h: h.update(alg="eddsa")), ("alg number", lambda h: h.update(alg=5)),
        ("alg missing", lambda h: h.pop("alg")), ("alg array", lambda h: h.update(alg=["EdDSA"])), ("crit", lambda h: h.update(crit=["b64"])), ("crit empty", lambda h: h.update(crit=[])),
        ("typ other", lambda h: h.update(typ="at+jwt")), ("typ lower", lambda h: h.update(typ="jwt")), ("typ mixed", lambda h: h.update(typ="JwT")), ("typ number", lambda h: h.update(typ=3)),
        ("typ missing", lambda h: h.pop("typ")), ("kid unknown", lambda h: h.update(kid="zz")), ("kid missing", lambda h: h.pop("kid")), ("kid number", lambda h: h.update(kid=1)),
        ("kid null", lambda h: h.update(kid=None)), ("kid case", lambda h: h.update(kid=h["kid"].upper())), ("kid empty", lambda h: h.update(kid="")),
        ("jku", lambda h: h.update(jku="https://evil.example/k")), ("jwk", lambda h: h.update(jwk={"kty": "OKP", "crv": "Ed25519", "x": "AAAA"})), ("cty", lambda h: h.update(cty="JWT")),
        ("x5c", lambda h: h.update(x5c=["MIIB"])), ("deep header", lambda h: h.update(a={"b": {"c": {"d": 1}}})), ("nested ok", lambda h: h.update(a={"b": [1]})), ("big header", lambda h: h.update(pad="x" * rng.choice([100, 150, 200]))),
    ]
    payload_edits = [
        ("exp past", lambda p: p.update(exp=t - rng.choice([1, 2, 10, 100]))), ("exp now", lambda p: p.update(exp=t)), ("exp missing", lambda p: p.pop("exp")), ("exp float", lambda p: p.update(exp=float(t + 100))),
        ("exp string", lambda p: p.update(exp=str(t + 100))), ("exp null", lambda p: p.update(exp=None)), ("exp true", lambda p: p.update(exp=True)), ("exp negative", lambda p: p.update(exp=-5)),
        ("exp huge", lambda p: p.update(exp=2 ** 70)), ("exp max", lambda p: p.update(exp=MAX_TIME)), ("exp over", lambda p: p.update(exp=MAX_TIME + 1)), ("exp array", lambda p: p.update(exp=[t + 100])),
        ("nbf future", lambda p: p.update(nbf=t + rng.choice([5, 50, 5000]))), ("nbf past", lambda p: p.update(nbf=t - rng.choice([1, 50]))), ("nbf string", lambda p: p.update(nbf="1")),
        ("nbf float", lambda p: p.update(nbf=1.5)), ("iat future", lambda p: p.update(iat=t + 10 ** 5)), ("iat string", lambda p: p.update(iat="x")), ("iat ok", lambda p: p.update(iat=t - 5)),
        ("aud other", lambda p: p.update(aud="other")), ("aud missing", lambda p: p.pop("aud")), ("aud array ok", lambda p: p.update(aud=["x", AUD, "y"])), ("aud array bad", lambda p: p.update(aud=["x", "y"])),
        ("aud array number", lambda p: p.update(aud=[AUD, 1])), ("aud 16", lambda p: p.update(aud=["x%d" % i for i in range(15)] + [AUD])), ("aud 17", lambda p: p.update(aud=["x%d" % i for i in range(16)] + [AUD])),
        ("aud number", lambda p: p.update(aud=1)), ("aud case", lambda p: p.update(aud="API")), ("aud prefix", lambda p: p.update(aud="ap")), ("aud object", lambda p: p.update(aud={"x": AUD})),
        ("iss other", lambda p: p.update(iss="https://evil.example")), ("iss missing", lambda p: p.pop("iss")), ("iss array", lambda p: p.update(iss=[ISS])), ("iss null", lambda p: p.update(iss=None)),
        ("deep claim ok", lambda p: p.update(a={"b": [[1]]})), ("deep claim bad", lambda p: p.update(a={"b": [[[1]]]})), ("many members ok", lambda p: p.update({"c%d" % i: i for i in range(58)})),
        ("many members bad", lambda p: p.update({"c%d" % i: i for i in range(61)})), ("name 64", lambda p: p.update({"n" * 64: 1})), ("name 65", lambda p: p.update({"n" * 65: 1})),
        ("big payload", lambda p: p.update(pad="x" * rng.choice([800, 900, 1100]))), ("unicode", lambda p: p.update(sub="é中\U0001f600")), ("empty claims value", lambda p: p.update(sub="")),
    ]
    raw_payloads = [
        ("dup exp", lambda: b'{"exp":%d,"aud":"api","iss":"%s","exp":1}' % (t + 100, ISS.encode())),
        ("dup exp escaped", lambda: b'{"exp":%d,"aud":"api","iss":"%s","\\u0065xp":2}' % (t + 100, ISS.encode())),
        ("dup aud", lambda: b'{"exp":%d,"aud":"api","aud":"x","iss":"%s"}' % (t + 100, ISS.encode())),
        ("dup nested", lambda: b'{"exp":%d,"aud":"api","iss":"%s","a":{"x":1,"x":2}}' % (t + 100, ISS.encode())),
        ("escaped aud", lambda: b'{"exp":%d,"aud":"\\u0061pi","iss":"%s"}' % (t + 100, ISS.encode())),
        ("exp exponent", lambda: b'{"exp":1.8e9,"aud":"api","iss":"%s"}' % ISS.encode()), ("exp minus zero", lambda: b'{"exp":-0,"aud":"api","iss":"%s"}' % ISS.encode()),
        ("exp leading zero", lambda: b'{"exp":0%d,"aud":"api","iss":"%s"}' % (t + 100, ISS.encode())), ("exp plus", lambda: b'{"exp":+%d,"aud":"api","iss":"%s"}' % (t + 100, ISS.encode())),
        ("trailing comma", lambda: b'{"exp":%d,"aud":"api","iss":"%s",}' % (t + 100, ISS.encode())), ("NaN", lambda: b'{"exp":%d,"aud":"api","iss":"%s","x":NaN}' % (t + 100, ISS.encode())),
        ("Infinity", lambda: b'{"exp":%d,"aud":"api","iss":"%s","x":Infinity}' % (t + 100, ISS.encode())), ("comment", lambda: b'{"exp":%d,"aud":"api","iss":"%s"}//x' % (t + 100, ISS.encode())),
        ("trailing data", lambda: b'{"exp":%d,"aud":"api","iss":"%s"} 1' % (t + 100, ISS.encode())), ("bom", lambda: b'\xef\xbb\xbf{"exp":%d,"aud":"api","iss":"%s"}' % (t + 100, ISS.encode())),
        ("lone surrogate", lambda: b'{"exp":%d,"aud":"api","iss":"%s","x":"\\ud800"}' % (t + 100, ISS.encode())), ("pair surrogate", lambda: b'{"exp":%d,"aud":"api","iss":"%s","x":"\\ud83d\\ude00"}' % (t + 100, ISS.encode())),
        ("bad utf8", lambda: b'{"exp":%d,"aud":"api","iss":"%s","x":"\xff"}' % (t + 100, ISS.encode())), ("control char", lambda: b'{"exp":%d,"aud":"api","iss":"%s","x":"a\nb"}' % (t + 100, ISS.encode())),
        ("bad escape", lambda: b'{"exp":%d,"aud":"api","iss":"%s","x":"\\q"}' % (t + 100, ISS.encode())), ("whitespace", lambda: b' \r\n\t{ "exp" : %d , "aud":"api","iss":"%s" } \n' % (t + 100, ISS.encode())),
        ("array root", lambda: b"[1,2]"), ("string root", lambda: b'"x"'), ("null root", lambda: b"null"), ("empty", lambda: b""), ("not json", lambda: b"hello"),
        ("single quotes", lambda: b"{'exp':1}"), ("unquoted", lambda: b"{exp:1}"), ("deep 20", lambda: b'{"exp":%d,"aud":"api","iss":"%s","a":' % (t + 100, ISS.encode()) + b"[" * 20 + b"]" * 20 + b"}"),
    ]
    raw_headers = [
        ("hdr dup alg", lambda k: b'{"alg":"none","alg":"EdDSA","kid":"%s"}' % k), ("hdr dup alg 2", lambda k: b'{"alg":"EdDSA","alg":"none","kid":"%s"}' % k),
        ("hdr dup kid", lambda k: b'{"alg":"EdDSA","kid":"%s","kid":"zz"}' % k), ("hdr array", lambda k: b'["EdDSA"]'), ("hdr empty obj", lambda k: b"{}"), ("hdr syntax", lambda k: b'{"alg":"EdDSA",}'),
        ("hdr trailing", lambda k: b'{"alg":"EdDSA","kid":"%s"} x' % k), ("hdr escaped alg", lambda k: b'{"alg":"Ed\\u0044SA","kid":"%s"}' % k), ("hdr escaped kid", lambda k: b'{"alg":"EdDSA","kid":"\\u006b%s"}' % k[1:]),
        ("hdr bad utf8", lambda k: b'{"alg":"EdDSA","kid":"%s","x":"\xc3("}' % k),
    ]

    def good(kid=None):
        h, p = base_header(), base_payload()
        if kid:
            h["kid"] = kid
        return h, p

    for i in range(n):
        kind = rng.randrange(10)
        kid_name = rng.choice(names)
        h, p = good(kid_name)
        signer = signers[h["kid"]] if h["kid"] in signers else signers[kid_name]
        if kind == 0:
            yield "valid", make(signer, h, p)
        elif kind in (1, 2):
            what, edit = rng.choice(header_edits)
            edit(h)
            yield what, make(signers.get(h.get("kid"), signer) if isinstance(h.get("kid"), str) else signer, h, p)
        elif kind in (3, 4):
            what, edit = rng.choice(payload_edits)
            edit(p)
            yield what, make(signer, h, p)
        elif kind == 5:
            what, raw = rng.choice(raw_payloads)
            yield what, make(signer, h, p, raw_p=raw())
        elif kind == 6:
            what, raw = rng.choice(raw_headers)
            yield what, make(signer, h, p, raw_h=raw(kid_name.encode()))
        elif kind == 7:
            # a valid token, then corrupted as text
            tok = make(signer, h, p)
            seg = rng.randrange(3)
            parts = tok.split(".")
            s = parts[seg]
            op = rng.randrange(8)
            at = rng.randrange(len(s))
            alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            if op == 0:
                s = s[:at] + rng.choice([c for c in alpha if c != s[at]]) + s[at + 1:]
            elif op == 1:
                s = s[:at] + rng.choice("+/=. ") + s[at + 1:]
            elif op == 2:
                s = s[:at]
            elif op == 3:
                s = s + rng.choice(["A", "AA", "AAA", "=", "==", "AAAA"])
            elif op == 4:
                s = s[:at] + s[at + 1:]
            elif op == 5:
                s = s.replace("-", "+").replace("_", "/") + "=" * (-len(s) % 4)
            elif op == 6:
                s = ""
            else:
                s = s[:at] + s[at] + s[at:]
            parts[seg] = s
            yield "text corruption %d of segment %d" % (op, seg), ".".join(parts)
        elif kind == 8:
            tok = make(signer, h, p)
            op = rng.randrange(6)
            parts = tok.split(".")
            if op == 0:
                yield "segments swapped", ".".join([parts[1], parts[0], parts[2]])
            elif op == 1:
                yield "a fourth segment", tok + "." + parts[2]
            elif op == 2:
                yield "no dots", "".join(parts)
            elif op == 3:
                yield "one dot", parts[0] + "." + parts[1] + parts[2]
            elif op == 4:
                yield "signature of another message", parts[0] + "." + make(signer, h, base_payload()).split(".")[1] + "." + parts[2]
            else:
                yield "token doubled", tok + tok
        else:
            # the signature by a key the route does not trust, under a trusted kid; or a signature with a changed S
            other = Signer(os.urandom(32)) if OPENSSL else Signer(bytes(rng.randrange(256) for _ in range(32)))
            if rng.randrange(2):
                yield "signed by another key", make(other, h, p)
            else:
                tok = make(signer, h, p)
                hh, pp, ss = tok.split(".")
                raw = bytearray(base64.urlsafe_b64decode(ss + "=="))
                raw[rng.randrange(64)] ^= 1 << rng.randrange(8)
                yield "a bit of the signature changed", hh + "." + pp + "." + b64(bytes(raw))


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 1500
    seed = int(sys.argv[2]) if len(sys.argv) > 2 else 8037
    rng = random.Random(seed)
    signers = {"k1": Signer(jt.SEED1), "k2": Signer(jt.SEED2)}
    keys = {name: s.public for name, s in signers.items()}
    print("signer: %s" % ("cryptography (OpenSSL)" if OPENSSL else "scripts/jwtkit.py (cryptography is not installed: the signing is not independent)"))
    disagreements, counts = [], {}
    with tempfile.TemporaryDirectory() as tmp:
        up = pt.Upstream(pt.free_port())
        ws = wt.WsUpstream(pt.free_port())
        gw = rt.Gateway(tmp, up.port, ws.port, jt.ROUTES, top=jt.TOP)
        try:
            t = int(time.time())
            sent = []
            for i, (what, token) in enumerate(corpus(rng, signers, n, t)):
                path = "/j/d%d" % i
                try:
                    token.encode("ascii")
                except UnicodeEncodeError:
                    continue
                if not set(token) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~+/="):
                    continue            # outside the header's alphabet: refused as auth.malformed before any token is read; the unit test and the end-to-end test have those
                s, h, b, _ = jt.get(gw, path, ["Authorization: Bearer " + token])
                sent.append((i, what, token, path, s))
            time.sleep(0.5)
            log = {l["path"]: l for l in gw.lines() if "path" in l}
            now_s = int(time.time())
            for i, what, token, path, status in sent:
                accepted, tag = reference(token, keys, set(keys), AUD, ISS, 0, int(log[path]["t"] / 1000) if False else now_s)
                line = log[path]
                got = (line.get("identity") if status == 200 else None, None if status == 200 else line["rule"])
                want = (accepted, tag)
                counts[tag or "accepted"] = counts.get(tag or "accepted", 0) + 1
                if status not in (200, 401) or got != want:
                    # A token that was valid when it was made and at the edge of its lifetime when it was judged may legitimately differ by the seconds the run took: the reference is
                    # evaluated again at the time of the gateway's own log line before a difference is reported.
                    when = int(line["t"] / 1000)
                    accepted2, tag2 = reference(token, keys, set(keys), AUD, ISS, 0, when)
                    if (accepted2, tag2) != got:
                        disagreements.append((what, token[:90], got, want, (accepted2, tag2)))
        finally:
            gw.stop()
    print("%d tokens sent; outcomes: %s" % (len(sent), ", ".join("%s %d" % kv for kv in sorted(counts.items()))))
    for d in disagreements[:30]:
        print("DISAGREE %-30s %s gateway %s reference %s (at the log time: %s)" % d)
    print("%d disagreements" % len(disagreements))
    return 1 if disagreements else 0


if __name__ == "__main__":
    sys.exit(main())
