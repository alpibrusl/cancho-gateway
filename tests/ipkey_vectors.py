"""The vectors of tests/ipkey_test.cho, written as cancho source (tests/ipkey_vectors.cho) so that the unit test needs no tool (docs/ratelimit.md section 13.2, gate 12).

    python3 tests/ipkey_vectors.py            # rewrite tests/ipkey_vectors.cho
    python3 tests/ipkey_vectors.py --check    # fail if it is not what this script writes

Every expected key is made by Python's `ipaddress`, an implementation that is not ours: the text must be an IPv6 literal of the shapes docs/ratelimit.md section 13.2 allows (at most 53 bytes,
optionally in square brackets with a port, no zone id), then the key is `v` and the 32 hexadecimal digits of the address under a mask of the first `prefix` bits, or the dotted-decimal
text of the IPv4 address of an IPv4-mapped one. An empty expectation is "not an IPv6 literal": the gateway then keys on the element's text. The cases are a fixed list, the whole range of
prefixes for two addresses, and a seeded random sample of valid texts and of single edits of them (the random generator is `random.Random(20261012)`: the file is reproducible).
"""
import ipaddress
import os
import random
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "ipkey_vectors.cho")


def reference(text, prefix):
    """The key of `text` at `prefix` bits, or "" if it is not an IPv6 literal of the allowed shapes."""
    if not 2 <= len(text) <= 53:
        return ""
    inner = text
    if text.startswith("["):
        m = re.fullmatch(r"\[([^\]]*)\](?::([0-9]{1,5}))?", text)
        if not m:
            return ""
        inner = m.group(1)
    if not 2 <= len(inner) <= 45 or "%" in inner or not re.fullmatch(r"[0-9A-Fa-f:.]+", inner):
        return ""
    try:
        addr = ipaddress.IPv6Address(inner)
    except ValueError:
        return ""
    if addr.ipv4_mapped is not None:
        return str(addr.ipv4_mapped)
    bits = prefix if 1 <= prefix <= 128 else 128
    mask = ((1 << bits) - 1) << (128 - bits)
    return "v%032x" % (int(addr) & mask)


FIXED = [
    # the forms that are literals
    "::", "::1", "0:0:0:0:0:0:0:1", "0000:0000:0000:0000:0000:0000:0000:0001", "2001:db8::1", "2001:DB8::1", "2001:db8:0:0::ffff", "2001:db8:0:0:1:2:3:4",
    "2001:db8:85a3:8a2e:370:7334:abcd:ef01", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "1::", "1:2:3:4:5:6:7::", "::2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8", "1:2::7:8", "a::b",
    "fe80::1", "fc00::", "2001:db8::", "::ffff:1.2.3.4", "::ffff:102:304", "::FFFF:1.2.3.4", "0:0:0:0:0:ffff:1.2.3.4", "::1.2.3.4", "1::1.2.3.4", "64:ff9b::192.0.2.33",
    "2001:db8:1:2:3:4:5.6.7.8", "::255.255.255.255", "::0.0.0.0", "::ffff:0.0.0.0", "::ffff:255.255.255.255", "::fffe:1.2.3.4", "0:0:0:0:0:fffe:102:304", "::1:ffff:1.2.3.4",
    "[::1]", "[2001:db8::1]", "[2001:db8::1]:443", "[2001:db8::1]:1", "[2001:db8::1]:65535", "[2001:db8::1]:99999", "[::ffff:1.2.3.4]:80", "[::ffff:1.2.3.4]",
    # the forms that are not
    "", ":", "1", "12", "::::", ":::", "1:::2", "1::2::3", "::1::", ":1::", ":1:2:3:4:5:6:7", "1:2:3:4:5:6:7", "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7:8::", "::1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:",
    "12345::1", "1:2:3:4:5:6:7:8a9b", "g::1", "::g", "2001:db8::1%eth0", "fe80::1%1", "fe80::1%", "%::1", "2001:db8::1 ", " 2001:db8::1", "2001:db8:: 1", "2001:db8::1\"", "::1,::2",
    "1.2.3.4", "1.2.3.4:80", "[1.2.3.4]", "[1.2.3.4]:80", "::1.2.3", "::1.2.3.4.5", "::1.2.3.256", "::1.2.3.04", "::01.2.3.4", "::1.2.3.", "::.1.2.3", "::1..2.3", "::1.2.3.4:5", "1.2.3.4::",
    "1:2:3:4:5:6:1.2.3.4", "1:2:3:4:5:6:7:1.2.3.4", "1:2:3:4:5:1.2.3.4", "1:2:3:4:5:6:7.8.9.0:1", "1.2.3.4:1::", "::1.2.3.4:1", "1:1.2.3.4:1::",
    "[::1", "::1]", "[]", "[", "]", "[[::1]]", "[::1]x", "[::1]:", "[::1]:123456", "[::1]:12a", "[::1]:-1", "[::1] :80", "[ ::1]", "[::1]:80:90", "[::1%eth0]", "[::1]]:80", "[[::1]:80",
    "x" * 54, "1:" * 26 + "1", "::" + "0" * 50, "[::1]:" + "1" * 50, "::ffff:" + "1" * 40,
]

PREFIXES = [1, 2, 7, 8, 9, 15, 16, 17, 31, 32, 33, 47, 48, 49, 55, 56, 57, 63, 64, 65, 71, 72, 96, 120, 127, 128]


def random_literal(rng):
    groups = ["%x" % rng.randrange(0, 1 << rng.choice([1, 4, 8, 12, 16])) for _ in range(8)]
    if rng.random() < 0.2:
        groups = [("%0" + str(rng.randint(1, 4)) + "x") % rng.randrange(0, 16 ** 1) for _ in range(8)]
    if rng.random() < 0.3:
        groups = ["0" if rng.random() < 0.6 else g for g in groups]
    tail4 = None
    if rng.random() < 0.2:
        tail4 = ".".join(str(rng.choice([0, 1, 9, 10, 99, 100, 127, 192, 254, 255])) for _ in range(4))
        groups = groups[:6]
    if rng.random() < 0.6:
        # compress a run of zero groups, the longest first
        best, at = 0, -1
        i = 0
        while i < len(groups):
            j = i
            while j < len(groups) and groups[j] == "0":
                j += 1
            if j - i > best:
                best, at = j - i, i
            i = max(j, i + 1)
        if best >= 1:
            take = rng.randint(1, best)
            head, tail = groups[:at], groups[at + take:]
            text = ":".join(head) + "::" + ":".join(tail)
            if tail4:
                text += (":" if tail else "") + tail4
            groups = None
        else:
            text = None
    else:
        text = None
    if text is None:
        text = ":".join(groups if groups is not None else [])
        if groups is not None and tail4:
            text += ":" + tail4
    if rng.random() < 0.3:
        text = text.upper() if rng.random() < 0.5 else text
    if rng.random() < 0.15:
        text = "[" + text + "]" + (":%d" % rng.randrange(1, 70000) if rng.random() < 0.6 else "")
    return text


def mutate(rng, text):
    kind = rng.randrange(7)
    at = rng.randrange(0, len(text) + 1)
    if kind == 0 and text:
        return text[:at % len(text)] + text[at % len(text) + 1:]
    if kind == 1:
        return text[:at] + rng.choice([":", ".", "%", "[", "]", " ", "g", "0", "f", "::"]) + text[at:]
    if kind == 2:
        return text[:at]
    if kind == 3:
        return text[at:]
    if kind == 4 and text:
        i = at % len(text)
        return text[:i] + rng.choice([":", "1", "f", ".", "x"]) + text[i + 1:]
    if kind == 5:
        return text + rng.choice([":", ":1", "::", ".1", "]", ":80", "%e"])
    return text.replace("::", ":", 1) if "::" in text else text.replace(":", "::", 1)


def cases():
    out = []
    for t in FIXED:
        for p in ([64] if len(out) % 3 else [64, 48, 128]):
            out.append((t, p))
    for a in ("2001:db8:85a3:8a2e:370:7334:abcd:ef01", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"):
        for p in range(1, 129):
            out.append((a, p))
    # prefixes the generator never writes: the module must not trust them
    for p in (0, -1, 129, 1000, 9223372036854775807, -9223372036854775807):
        out.append(("2001:db8::1", p))
    rng = random.Random(20261012)
    valid = []
    while len(valid) < 260:
        t = random_literal(rng)
        out.append((t, rng.choice(PREFIXES)))
        if reference(t, 64):
            valid.append(t)
    for _ in range(420):
        t = mutate(rng, rng.choice(valid))
        out.append((t, rng.choice(PREFIXES)))
    return [(t, p, reference(t, p)) for t, p in out if "\n" not in t]


def lit(text):
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\t", "\\t") + '"'


def render():
    rows = cases()
    # a text with a byte the language cannot spell in a literal is left out (none today); the tab and the newline separate the fields of a row
    blob = "".join("%s\t%d\t%s\n" % (t, p, w) for t, p, w in rows if "\t" not in t)
    ascii_only = "".join(ch for ch in blob if ord(ch) < 128 and (ch >= " " or ch in "\t\n"))
    assert ascii_only == blob, "a vector the file cannot spell: keep the vectors to printable ASCII"
    return "\n".join([
        "edition 5;", "", "module gateway.ipkey_vectors;", "",
        "// GENERATED by tests/ipkey_vectors.py: the cases of tests/ipkey_test.cho, with the keys Python's `ipaddress` gives them. Do not edit.", "",
        "// One row per case: the element's text, the prefix, the expected key (empty: not an IPv6 literal); tab-separated, newline-ended.",
        "pub fn blob() -> [] &static [byte] {", "    return %s;" % lit(blob), "}", ""])


def main():
    text = render()
    n = text.count("\\n")
    if "--check" in sys.argv:
        if not os.path.exists(OUT) or open(OUT).read() != text:
            print("tests/ipkey_vectors.cho is not what tests/ipkey_vectors.py writes")
            return 1
        print("tests/ipkey_vectors.cho is current (%d cases)" % n)
        return 0
    open(OUT, "w").write(text)
    print("wrote tests/ipkey_vectors.cho: %d cases, %d literals, %d not" % (n, sum(1 for c in cases() if c[2]), sum(1 for c in cases() if not c[2])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
