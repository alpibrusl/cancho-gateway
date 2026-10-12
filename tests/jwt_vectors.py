"""The vectors of tests/jwt_test.cho, written as cancho source (tests/jwt_vectors.cho) so that the unit test needs no tool to make its tokens (docs/jwt.md section 11).

    python3 tests/jwt_vectors.py            # rewrite tests/jwt_vectors.cho
    python3 tests/jwt_vectors.py --check    # fail if it is not what this script writes

The keys are **test keys**: the seeds are `bytes(range(32))` and `bytes(range(1, 33))`, public by construction, and a token signed with them proves nothing anywhere. Every token is made
by `scripts/jwtkit.py` (pure Python, RFC 8032) and the signing is checked against OpenSSL in tests/jwt_test.py where `cryptography` is installed.
"""
import hashlib
import hmac
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))
import jwtkit  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "jwt_vectors.cho")

NOW = 1800000000
SEED1 = bytes(range(32))
SEED2 = bytes(range(1, 33))
PK1 = jwtkit.b64u(jwtkit.public_key(SEED1))
PK2 = jwtkit.b64u(jwtkit.public_key(SEED2))
EXP = NOW + 100
GOOD_H = {"alg": "EdDSA", "typ": "JWT", "kid": "k1"}
GOOD_P = {"exp": EXP, "iss": "https://iss.example", "aud": "api", "sub": "alice"}


def tok(header=None, payload=None, seed=SEED1, **raw):
    return jwtkit.compact(GOOD_H if header is None else header, GOOD_P if payload is None else payload, seed, **raw)


def with_(d, **kw):
    e = dict(d)
    e.update(kw)
    return e


def without(d, *names):
    return {k: v for k, v in d.items() if k not in names}


def flip(s, at):
    """`s` with the character at `at` replaced by another character of the base64url alphabet."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    c = s[at]
    return s[:at] + alphabet[(alphabet.index(c) + 1) % 64] + s[at + 1:]


def parts(t):
    return t.split(".")


def vectors():
    v = {}
    good = tok()
    h, p, s = parts(good)
    v["ok"] = good
    v["ok_k2"] = tok(with_(GOOD_H, kid="k2"), seed=SEED2)
    v["ok_nokid"] = tok(without(GOOD_H, "kid"))
    v["ok_notyp"] = tok(without(GOOD_H, "typ"))
    v["ok_typ_lower"] = tok(with_(GOOD_H, typ="jwt"))
    v["ok_kid_escaped"] = tok(raw_header=b'{"alg":"EdDSA","kid":"k\\u0031"}')
    v["ok_ignored_members"] = tok(with_(GOOD_H, jku="https://evil.example/jwks", jwk={"kty": "OKP"}, cty="x", x5c=["a"]))
    v["ok_aud_array"] = tok(payload=with_(GOOD_P, aud=["other", "api", "more"]))
    v["ok_aud_array16"] = tok(payload=with_(GOOD_P, aud=["x%d" % i for i in range(15)] + ["api"]))
    v["ok_depth4"] = tok(payload=with_(GOOD_P, a={"b": [[1]]}))
    v["ok_members64"] = tok(payload=dict(list(GOOD_P.items()) + [("c%02d" % i, i) for i in range(60)]))
    v["ok_name64"] = tok(payload=with_(GOOD_P, **{"n" * 64: 1}))
    v["ok_nbf"] = tok(payload=with_(GOOD_P, nbf=NOW + 50, iat=NOW))
    v["ok_exp_max"] = tok(payload={"exp": 253402300799})
    v["ok_exp_noaud"] = tok(payload={"exp": EXP})
    v["ok_whitespace"] = tok(raw_payload=b' \n{ "exp" : %d , "aud":"api" , "iss" : "https://iss.example" }\t' % EXP)
    v["ok_unicode"] = tok(payload=with_(GOOD_P, sub="é中\U0001f600"))
    # signature and structure
    v["bad_sig_flip"] = h + "." + p + "." + flip(s, 10)
    v["bad_sig_other_key"] = tok(seed=SEED2)
    v["bad_sig_tampered_payload"] = h + "." + jwtkit.b64u(json.dumps(with_(GOOD_P, exp=EXP + 1000), separators=(",", ":")).encode()) + "." + s
    v["bad_sig_tampered_header"] = jwtkit.b64u(json.dumps(with_(GOOD_H, kid="k2"), separators=(",", ":")).encode()) + "." + p + "." + s
    v["bad_sig_noncanonical"] = h + "." + p + "." + s[:-1] + "B"
    v["bad_sig_short"] = h + "." + p + "." + s[:-1]
    v["bad_sig_long"] = h + "." + p + "." + s + "A"
    v["bad_sig_empty"] = h + "." + p + "."
    v["bad_sig_zero"] = h + "." + p + "." + "A" * 86
    # S not below the group order L: 2^255 - 1 as the low 32 bytes of the signature after a valid R
    r_enc = jwtkit.unb64u(s)[:32]
    big_s = (jwtkit.Q + 5).to_bytes(32, "little")
    v["bad_sig_s_ge_l"] = h + "." + p + "." + jwtkit.b64u(r_enc + big_s)
    # the identity-point signature that a small-order key would accept for any message (the key is not configured; this is for the verifier's own refusal of it)
    v["bad_sig_identity"] = h + "." + p + "." + jwtkit.b64u(bytes([1]) + bytes(31) + bytes(32))
    v["bad_dots0"] = h + p + s
    v["bad_dots1"] = h + "." + p + s
    v["bad_dots3"] = good + ".AAAA"
    v["bad_dots4_jwe"] = ".".join([h, "", "AAAA", "AAAA", "AAAA"])
    v["bad_empty_header"] = "." + p + "." + s
    v["bad_empty_payload"] = h + ".." + s
    v["bad_leading_dot"] = "." + good
    v["bad_trailing_dot"] = good + "."
    v["bad_padding"] = h + "=." + p + "." + s
    v["bad_plus"] = h + "." + p[:5] + "+" + p[6:] + "." + s
    v["bad_slash"] = h + "." + p[:5] + "/" + p[6:] + "." + s
    v["bad_space"] = h + "." + p[:5] + " " + p[6:] + "." + s
    v["bad_len1mod4"] = h + "." + p + "A" * ((1 - len(p)) % 4) + "." + s
    v["bad_high_byte"] = good.replace(".", ".é", 1)
    v["bad_nul"] = good[:20] + "\x00" + good[21:]
    # alg
    for name, alg in (("none", "none"), ("none_upper", "NONE"), ("hs256", "HS256"), ("rs256", "RS256"), ("eddsa_lower", "eddsa"), ("eddsa_space", "EdDSA "), ("es256", "ES256"), ("empty", ""), ("ed25519", "Ed25519")):
        v["bad_alg_" + name] = tok(with_(GOOD_H, alg=alg))
    v["bad_alg_missing"] = tok(without(GOOD_H, "alg"))
    v["bad_alg_number"] = tok(with_(GOOD_H, alg=1))
    v["bad_alg_array"] = tok(with_(GOOD_H, alg=["EdDSA"]))
    v["bad_alg_null"] = tok(with_(GOOD_H, alg=None))
    # the classic confusion attack: HS256, the public key (raw bytes, then its text) as the HMAC secret
    hh = jwtkit.b64u(json.dumps({"alg": "HS256", "typ": "JWT", "kid": "k1"}, separators=(",", ":")).encode())
    si = (hh + "." + p).encode()
    v["bad_confusion_raw"] = hh + "." + p + "." + jwtkit.b64u(hmac.new(jwtkit.public_key(SEED1), si, hashlib.sha256).digest())
    v["bad_confusion_text"] = hh + "." + p + "." + jwtkit.b64u(hmac.new(PK1.encode(), si, hashlib.sha256).digest())
    v["bad_alg_none_unsigned"] = jwtkit.b64u(b'{"alg":"none","kid":"k1"}') + "." + p + "."
    # header
    v["bad_crit"] = tok(with_(GOOD_H, crit=["exp"]))
    v["bad_crit_empty"] = tok(with_(GOOD_H, crit=[]))
    v["bad_crit_null"] = tok(with_(GOOD_H, crit=None))
    v["bad_typ_atjwt"] = tok(with_(GOOD_H, typ="at+jwt"))
    v["bad_typ_number"] = tok(with_(GOOD_H, typ=1))
    v["bad_typ_escaped"] = tok(raw_header=b'{"alg":"EdDSA","typ":"\\u004aWT","kid":"k1"}')
    v["bad_kid_unknown"] = tok(with_(GOOD_H, kid="nobody"))
    v["bad_kid_number"] = tok(with_(GOOD_H, kid=1))
    v["bad_kid_empty"] = tok(with_(GOOD_H, kid=""))
    v["bad_kid_case"] = tok(with_(GOOD_H, kid="K1"))
    v["bad_kid_long"] = tok(with_(GOOD_H, kid="k" * 90))
    v["bad_header_array"] = tok(raw_header=b'["EdDSA"]')
    v["bad_header_string"] = tok(raw_header=b'"EdDSA"')
    v["bad_header_dup_alg"] = tok(raw_header=b'{"alg":"none","alg":"EdDSA","kid":"k1"}')
    v["bad_header_dup_alg2"] = tok(raw_header=b'{"alg":"EdDSA","alg":"none","kid":"k1"}')
    v["bad_header_dup_kid"] = tok(raw_header=b'{"alg":"EdDSA","kid":"k1","kid":"k2"}')
    v["bad_header_syntax"] = tok(raw_header=b'{"alg":"EdDSA",}')
    v["bad_header_empty_object_noalg"] = tok(raw_header=b"{}")
    v["bad_header_trailing"] = tok(raw_header=b'{"alg":"EdDSA","kid":"k1"} x')
    v["bad_header_big"] = tok(with_(GOOD_H, pad="x" * 200))
    v["bad_header_utf8"] = tok(raw_header=b'{"alg":"EdDSA","kid":"k1","x":"\xff"}')
    # payload
    v["bad_exp_missing"] = tok(payload=without(GOOD_P, "exp"))
    v["bad_exp_float"] = tok(raw_payload=b'{"exp":%d.0}' % EXP)
    v["bad_exp_exponent"] = tok(raw_payload=b'{"exp":1.8e9}')
    v["bad_exp_string"] = tok(payload=with_(GOOD_P, exp=str(EXP)))
    v["bad_exp_negative"] = tok(payload=with_(GOOD_P, exp=-1))
    v["bad_exp_negzero_float"] = tok(raw_payload=b'{"exp":-0.0}')
    v["bad_exp_huge"] = tok(raw_payload=b'{"exp":92233720368547758070}')
    v["bad_exp_over"] = tok(payload={"exp": 253402300800})
    v["bad_exp_null"] = tok(payload=with_(GOOD_P, exp=None))
    v["bad_exp_bool"] = tok(payload=with_(GOOD_P, exp=True))
    v["bad_exp_array"] = tok(payload=with_(GOOD_P, exp=[EXP]))
    v["bad_nbf_float"] = tok(payload=with_(GOOD_P, nbf=1.5))
    v["bad_nbf_string"] = tok(payload=with_(GOOD_P, nbf="0"))
    v["bad_iat_string"] = tok(payload=with_(GOOD_P, iat="now"))
    v["bad_iat_float"] = tok(payload=with_(GOOD_P, iat=1.0))
    v["bad_payload_array"] = tok(raw_payload=b"[1]")
    v["bad_payload_string"] = tok(raw_payload=b'"x"')
    v["bad_payload_number"] = tok(raw_payload=b"1")
    v["bad_payload_empty_object"] = tok(raw_payload=b"{}")
    v["bad_payload_syntax"] = tok(raw_payload=b'{"exp":%d,}' % EXP)
    v["bad_payload_nonjson"] = tok(raw_payload=b"hello world")
    v["bad_payload_trailing"] = tok(raw_payload=b'{"exp":%d} {}' % EXP)
    v["bad_payload_comment"] = tok(raw_payload=b'{"exp":%d /* x */}' % EXP)
    v["bad_payload_nan"] = tok(raw_payload=b'{"exp":NaN}')
    v["bad_payload_single_quotes"] = tok(raw_payload=b"{'exp':%d}" % EXP)
    v["bad_payload_leading_zero"] = tok(raw_payload=b'{"exp":0%d}' % EXP)
    v["bad_payload_utf8"] = tok(raw_payload=b'{"exp":%d,"x":"\xc3("}' % EXP)
    v["bad_dup_exp"] = tok(raw_payload=b'{"exp":%d,"exp":1}' % EXP)
    v["bad_dup_exp_first_bad"] = tok(raw_payload=b'{"exp":1,"exp":%d}' % EXP)
    v["bad_dup_exp_escaped"] = tok(raw_payload=b'{"exp":%d,"\\u0065xp":1}' % EXP)
    v["bad_dup_aud"] = tok(raw_payload=b'{"exp":%d,"aud":"api","aud":"other"}' % EXP)
    v["bad_dup_other"] = tok(raw_payload=b'{"exp":%d,"x":1,"x":2}' % EXP)
    v["bad_dup_nested"] = tok(raw_payload=b'{"exp":%d,"aud":"api","iss":"https://iss.example","a":{"x":1,"x":2}}' % EXP)
    v["bad_dup_nested_escaped"] = tok(raw_payload=b'{"exp":%d,"aud":"api","iss":"https://iss.example","a":[{"y":1},{"x":1,"\\u0078":2}]}' % EXP)
    v["ok_same_name_in_two_objects"] = tok(raw_payload=b'{"exp":%d,"aud":"api","iss":"https://iss.example","a":{"x":1},"b":{"x":2}}' % EXP)
    v["bad_nested_members65"] = tok(payload=with_(GOOD_P, a={"m%02d" % i: i for i in range(65)}))
    v["ok_nested_members64"] = tok(payload=with_(GOOD_P, a={"m%02d" % i: i for i in range(64)}))
    v["bad_depth5"] = tok(payload=with_(GOOD_P, a={"b": [[[1]]]}))
    v["bad_depth_deep"] = tok(raw_payload=b'{"exp":%d,"a":' % EXP + b"[" * 300 + b"]" * 300 + b"}")
    v["bad_members65"] = tok(payload=dict(list(GOOD_P.items()) + [("c%02d" % i, i) for i in range(61)]))
    v["bad_name65"] = tok(payload=with_(GOOD_P, **{"n" * 65: 1}))
    v["bad_aud_array17"] = tok(payload=with_(GOOD_P, aud=["x%d" % i for i in range(16)] + ["api"]))
    v["bad_aud_array_number"] = tok(payload=with_(GOOD_P, aud=["api", 1]))
    v["bad_aud_number"] = tok(payload=with_(GOOD_P, aud=1))
    v["bad_aud_other"] = tok(payload=with_(GOOD_P, aud="other"))
    v["bad_aud_prefix"] = tok(payload=with_(GOOD_P, aud="api2"))
    v["bad_aud_case"] = tok(payload=with_(GOOD_P, aud="API"))
    v["bad_aud_missing"] = tok(payload=without(GOOD_P, "aud"))
    v["bad_iss_other"] = tok(payload=with_(GOOD_P, iss="https://evil.example"))
    v["bad_iss_missing"] = tok(payload=without(GOOD_P, "iss"))
    v["bad_iss_array"] = tok(payload=with_(GOOD_P, iss=["https://iss.example"]))
    v["bad_payload_big"] = tok(payload=with_(GOOD_P, pad="x" * 1100))
    v["bad_token_big"] = tok(payload=with_(GOOD_P, pad="x" * 1000)) + "A" * 1000
    return v


def b64_cases():
    """(text, expected bytes as hex or None if the text must be refused)."""
    import random
    rng = random.Random(8037)
    cases = []
    for n in range(0, 70):
        b = bytes(rng.randrange(256) for _ in range(n))
        cases.append((jwtkit.b64u(b), b.hex()))
    for n in (190, 191, 192, 193, 255, 256):
        b = bytes(rng.randrange(256) for _ in range(n))
        cases.append((jwtkit.b64u(b), b.hex()))
    for text in ("A", "AAAAA", "AAAAAAAAA", "AB", "AC", "AAB", "AAC", "QQ==", "QQ=", "QQ", "Q", "+/+/", "-_-_", "AA AA", "AA\nAA", "AAAé", "AAAA\x00", "====", "=", "AAAA=", "A===", "ab/d", "ab+d", "QQ.", " QQ"):
        cases.append((text, None if not (len(text) % 4 != 1 and all(c.isascii() and (c.isalnum() or c in "-_") for c in text) and _canonical(text)) else jwtkit.unb64u(text).hex()))
    return cases


def _canonical(text):
    try:
        b = jwtkit.unb64u(text)
    except Exception:
        return False
    return jwtkit.b64u(b) == text


def lit(s):
    """A cancho string literal for the text `s`. The literal takes only \\n \\r \\t \\\\ \\" and \\0 as escapes; any other character is written as itself (UTF-8)."""
    escapes = {'"': '\\"', "\\": "\\\\", "\n": "\\n", "\r": "\\r", "\t": "\\t", "\0": "\\0"}
    out = []
    for ch in s:
        if ch in escapes:
            out.append(escapes[ch])
        elif ord(ch) < 0x20 or ord(ch) == 0x7f:
            raise ValueError("no escape for %r" % ch)
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def render():
    lines = ["edition 5;", "", "module gateway.jwt_vectors;", "", "// GENERATED by tests/jwt_vectors.py: the tokens of tests/jwt_test.cho. Test keys only (seeds bytes(range(32)) and bytes(range(1, 33)), public by construction). Do not edit.", ""]
    lines += ["pub fn now() -> [] int {", "    return %d;" % NOW, "}", ""]
    lines += ["pub fn exp() -> [] int {", "    return %d;" % EXP, "}", ""]
    lines += ["pub fn keys() -> [] &static [byte] {", "    return %s;" % lit("k1\t%s\nk2\t%s\n" % (PK1, PK2)), "}", ""]
    for name, token in vectors().items():
        lines += ["pub fn v_%s() -> [] &static [byte] {" % name, "    return %s;" % lit(token), "}", ""]
    cases = b64_cases()
    lines += ["pub fn b64_count() -> [] int {", "    return %d;" % len(cases), "}", ""]
    for fname, pick in (("b64_text", lambda c: c[0]), ("b64_want", lambda c: "ok:" + c[1] if c[1] is not None else "no")):
        lines += ["pub fn %s(i: int) -> [] &static [byte] {" % fname]
        for i, c in enumerate(cases):
            lines += ["    if i == %d {" % i, "        return %s;" % lit(pick(c)), "    }"]
        lines += ['    return "";', "}", ""]
    return "\n".join(lines)


if __name__ == "__main__":
    text = render()
    if "--check" in sys.argv:
        if not os.path.exists(OUT) or open(OUT).read() != text:
            print("tests/jwt_vectors.cho is not what tests/jwt_vectors.py writes")
            sys.exit(1)
        print("tests/jwt_vectors.cho is current (%d tokens)" % len(vectors()))
    else:
        open(OUT, "w").write(text)
        print("wrote tests/jwt_vectors.cho: %d tokens, %d base64url cases" % (len(vectors()), len(b64_cases())))
