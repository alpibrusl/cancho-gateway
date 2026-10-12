#!/usr/bin/env python3
"""Make an API key and the lines of a deployment file that hold it (docs/auth.md section 5).

    python3 scripts/mkkey.py NAME            # a new key: the table on standard output, the key on standard error, once
    python3 scripts/mkkey.py NAME --stdin    # hash a key that already exists, read from standard input (never the command line, which `ps` shows)

The standard output is what is appended to a deployment file:

    [[api_key]]
    name = "alice"
    sha256 = "e5294d2b..."

The gateway keeps only that digest. The KEY goes to standard error, so `mkkey.py alice >> deploy.toml` cannot put it in the file; copy it from the
terminal to wherever the caller keeps secrets. This script never writes a file and never logs. A key is `ck_` and 43 characters of URL-safe base64 (256 bits
from the operating system's generator), all inside the credential alphabet the gateway accepts (docs/auth.md section 3).
"""

import base64
import hashlib
import re
import secrets
import sys

NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,31}")
CREDENTIAL = re.compile(r"[A-Za-z0-9._~+/=-]{1,256}")


def new_key():
    return "ck_" + base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")


def table(name, key):
    return '[[api_key]]\nname = "%s"\nsha256 = "%s"\n' % (name, hashlib.sha256(key.encode()).hexdigest())


def main(argv):
    flags = [a for a in argv if a.startswith("--")]
    names = [a for a in argv if not a.startswith("--")]
    if len(names) != 1 or any(f != "--stdin" for f in flags):
        print(__doc__.split("\n\n")[0], file=sys.stderr)
        return 2
    if not NAME.fullmatch(names[0]):
        print("the name must match [a-z0-9][a-z0-9._-]{0,31}: it is written into the access log", file=sys.stderr)
        return 2
    if "--stdin" in flags:
        key = sys.stdin.read().rstrip("\n")
        if not CREDENTIAL.fullmatch(key):
            print("that is not a credential the gateway accepts: 1 to 256 bytes of [A-Za-z0-9._~+/=-]", file=sys.stderr)
            return 2
        sys.stdout.write(table(names[0], key))
        return 0
    key = new_key()
    sys.stdout.write(table(names[0], key))
    print("key for %s (shown once; the gateway cannot show it again): %s" % (names[0], key), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
