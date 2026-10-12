#!/usr/bin/env python3
"""Make an Ed25519 key pair for `[[jwt_key]]` and sign test tokens with it (docs/jwt.md section 8).

    python3 scripts/mkjwt.py keygen issuer-a > key.toml
        stdout: the table to add to the deployment file (the public key: not a secret).
        stderr: the seed (the private key), once. The script writes no file, so `> key.toml` cannot put the seed in it.

    echo SEED | python3 scripts/mkjwt.py sign --kid issuer-a --aud api --iss https://issuer.example --ttl 300
        stdout: a compact JWS (a JWT). The seed is read from standard input (never from the command line, which `ps` shows).
        --sub S, --nbf N (seconds from now), --claim name=value (a string claim), --claim-int name=N, --typ T, --no-typ, --no-kid, --alg A, --ttl N (default 300, may be negative)
        make the token a test needs; --alg and the claim flags exist to make *bad* tokens on purpose (a token signed by this script is only as good as its seed).

    python3 scripts/mkjwt.py pub < seed
        stdout: the public key (43 characters of base64url) of the seed on standard input.

Nothing is logged and nothing is written to disk. The seed is 32 random bytes from the operating system's generator. The signing is `scripts/jwtkit.py`: RFC 8032 in pure
Python, not constant time, for test tokens and for making keys; a production issuer signs with its own library.
"""
import json
import re
import secrets
import sys
import time

import jwtkit

NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,31}")


def usage():
    print(__doc__, file=sys.stderr)
    return 2


def read_seed():
    text = sys.stdin.read().strip()
    try:
        seed = jwtkit.unb64u(text)
    except ValueError:
        seed = b""
    if len(text) != 43 or len(seed) != 32 or jwtkit.b64u(seed) != text:
        print("mkjwt: the seed on standard input must be 43 characters of base64url (what keygen printed)", file=sys.stderr)
        sys.exit(2)
    return seed


def keygen(args):
    if len(args) != 1 or not NAME.fullmatch(args[0]):
        print("mkjwt: keygen NAME, with NAME matching [a-z0-9][a-z0-9._-]{0,31}", file=sys.stderr)
        return 2
    seed = secrets.token_bytes(32)
    print('[[jwt_key]]\nname = "%s"\npublic_key = "%s"' % (args[0], jwtkit.b64u(jwtkit.public_key(seed))))
    print("seed (the private key; shown once, never written, keep it where the issuer is): %s" % jwtkit.b64u(seed), file=sys.stderr)
    return 0


def sign(args):
    opts = {"kid": None, "aud": None, "iss": None, "sub": None, "ttl": 300, "nbf": None, "typ": "JWT", "alg": "EdDSA"}
    extra = {}
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("--kid", "--aud", "--iss", "--sub", "--typ", "--alg") and i + 1 < len(args):
            opts[a[2:]] = args[i + 1]
            i += 2
        elif a in ("--ttl", "--nbf") and i + 1 < len(args):
            opts[a[2:]] = int(args[i + 1])
            i += 2
        elif a == "--no-typ":
            opts["typ"] = None
            i += 1
        elif a == "--no-kid":
            opts["kid"] = None
            i += 1
        elif a in ("--claim", "--claim-int") and i + 1 < len(args) and "=" in args[i + 1]:
            name, _, value = args[i + 1].partition("=")
            extra[name] = int(value) if a == "--claim-int" else value
            i += 2
        else:
            return usage()
    seed = read_seed()
    t = int(time.time())
    header = {"alg": opts["alg"]}
    if opts["typ"]:
        header["typ"] = opts["typ"]
    if opts["kid"]:
        header["kid"] = opts["kid"]
    payload = {"exp": t + opts["ttl"]}
    for k in ("iss", "aud", "sub"):
        if opts[k] is not None:
            payload[k] = opts[k]
    if opts["nbf"] is not None:
        payload["nbf"] = t + opts["nbf"]
    payload.update(extra)
    print(jwtkit.compact(header, payload, seed))
    return 0


def main():
    args = sys.argv[1:]
    if not args:
        return usage()
    if args[0] == "keygen":
        return keygen(args[1:])
    if args[0] == "sign":
        return sign(args[1:])
    if args[0] == "pub" and len(args) == 1:
        print(jwtkit.b64u(jwtkit.public_key(read_seed())))
        return 0
    return usage()


if __name__ == "__main__":
    sys.exit(main())
