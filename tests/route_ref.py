"""The reference route selector (docs/routes.md), written from the specification and not from src/route.cho.

`select(routes, host, method, path)` answers ("route", index) or ("refuse", tag, status). `routes` are the dicts that
scripts/generate.py's `load` returns (host None for any, prefix, mask, upstream, max_body, trust).
"""

import re

METHOD_BIT = {"GET": 1, "HEAD": 2, "POST": 4, "PUT": 8, "DELETE": 16, "PATCH": 32, "OPTIONS": 64}


def path_ok(path):
    if not path.startswith(b"/"):
        return False
    if re.search(rb"[\x00-\x20\x7f-\xff\\]", path) or b"//" in path:
        return False
    for m in re.finditer(rb"%(.?)(.?)", path):
        a, b = m.group(1), m.group(2)
        if not (re.fullmatch(rb"[0-9a-fA-F]", a) and re.fullmatch(rb"[0-9a-fA-F]", b)):
            return False
        if a == b"2" and b.lower() in (b"e", b"f"):
            return False
        if a == b"5" and b.lower() == b"c":
            return False
    return not any(seg in (b".", b"..") for seg in path.split(b"/"))


def host_name(host):
    m = re.fullmatch(rb"(.*?)(?::([0-9]{1,5}))?", host)
    name = m.group(1)
    if b":" in name or not name or len(name) > 253 or not re.fullmatch(rb"[A-Za-z0-9.-]+", name):
        return None
    return name.lower().decode()


def prefix_matches(path, prefix):
    p = prefix.encode()
    return p == b"/" or path == p or path.startswith(p + b"/")


def select(routes, host, method, path):
    name = host_name(host)
    if name is None:
        return ("refuse", "route.host", 400)
    if not path_ok(path):
        return ("refuse", "route.path", 400)
    named = any(r["host"] == name for r in routes)
    chosen = [(i, r) for i, r in enumerate(routes) if (r["host"] == name if named else r["host"] is None)]
    on_path = [(i, r) for i, r in chosen if prefix_matches(path, r["prefix"])]
    bit = METHOD_BIT.get(method.decode("latin-1"), 0)
    allowed = [(i, r) for i, r in on_path if bit and r["mask"] & bit]
    if allowed:
        i, r = max(allowed, key=lambda t: (len(t[1]["prefix"]), -t[0]))
        return ("route", i, r["upstream"], r["max_body"], r["trust"], r["name"])
    return ("refuse", "route.method", 405) if on_path else ("refuse", "route.none", 404)
