"""Ed25519 and compact JWS in pure Python, from RFC 8032 section 6 and RFC 7515 (docs/jwt.md).

Used by `scripts/generate.py` (to refuse a public key that is not a point of the curve or is of small order), by `scripts/mkjwt.py` (to make keys and tokens) and by the tests (to make tokens
in memory). Standard library only, so it runs wherever the generator does. It is slow (milliseconds to tens of milliseconds a signature) and **not constant time**: it signs test tokens, it
is not for production secrets. The differential tests check it against OpenSSL (`cryptography`) where that is installed.
"""
import base64
import hashlib
import json

P = 2 ** 255 - 19
Q = 2 ** 252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
I = pow(2, (P - 1) // 4, P)


def _inv(x):
    return pow(x, P - 2, P)


def _recover_x(y, sign):
    """RFC 8032 5.1.3: the x of the point with this y and sign bit, or None if there is none."""
    if y >= P:
        return None
    x2 = (y * y - 1) * _inv(D * y * y + 1) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * I % P
    if (x * x - x2) % P != 0:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


_GY = 4 * _inv(5) % P
_GX = _recover_x(_GY, 0)
G = (_GX, _GY, 1, _GX * _GY % P)
IDENTITY = (0, 1, 1, 0)


def add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % P
    b = (p[1] + p[0]) * (q[1] + q[0]) % P
    c = 2 * p[3] * q[3] * D % P
    d = 2 * p[2] * q[2] % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def mul(s, p):
    r = IDENTITY
    while s > 0:
        if s & 1:
            r = add(r, p)
        p = add(p, p)
        s >>= 1
    return r


def equal(p, q):
    return (p[0] * q[2] - q[0] * p[2]) % P == 0 and (p[1] * q[2] - q[1] * p[2]) % P == 0


def compress(p):
    zi = _inv(p[2])
    x, y = p[0] * zi % P, p[1] * zi % P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def decompress(s):
    """The point a 32-byte encoding names, or None (y out of range, or no square root)."""
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % P)


def small_order(p):
    """True for the eight points whose order divides 8: a key like that verifies a signature for every message."""
    return equal(mul(8, p), IDENTITY)


def _h(m):
    return int.from_bytes(hashlib.sha512(m).digest(), "little")


def _expand(seed):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_key(seed):
    a, _ = _expand(seed)
    return compress(mul(a, G))


def sign(seed, msg):
    a, prefix = _expand(seed)
    pk = compress(mul(a, G))
    r = _h(prefix + msg) % Q
    rs = compress(mul(r, G))
    k = _h(rs + pk + msg) % Q
    return rs + int.to_bytes((r + k * a) % Q, 32, "little")


def verify(pk, msg, sig):
    """RFC 8032 5.1.7, for the differential tests (not used by the gateway)."""
    if len(pk) != 32 or len(sig) != 64:
        return False
    a = decompress(pk)
    r = decompress(sig[:32])
    s = int.from_bytes(sig[32:], "little")
    if a is None or r is None or s >= Q:
        return False
    k = _h(sig[:32] + pk + msg) % Q
    return equal(mul(s, G), add(r, mul(k, a)))


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def unb64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def compact(header, payload, seed, *, raw_header=None, raw_payload=None):
    """A compact JWS signed with `seed` (Ed25519). `header` and `payload` are dicts, or pass `raw_*` bytes to sign exactly those bytes."""
    h = raw_header if raw_header is not None else json.dumps(header, separators=(",", ":")).encode()
    p = raw_payload if raw_payload is not None else json.dumps(payload, separators=(",", ":")).encode()
    signing_input = (b64u(h) + "." + b64u(p)).encode("ascii")
    return signing_input.decode("ascii") + "." + b64u(sign(seed, signing_input))
