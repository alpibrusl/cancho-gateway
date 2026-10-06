edition 5;

module gateway.out;

// Writing bytes into a caller's buffer at an offset: every function answers the new offset, or `0 - 1` if the bytes do not
// fit (nothing is written past the end, and a failed write leaves the offset's meaning to the caller: it abandons the
// buffer). The one place the gateway builds heads and error bodies.

pub fn put[&o, &s](out: &!o [byte], at: int, s: &s [byte]) -> [] int {
    if at < 0 || at + len(s) > len(out) {
        return 0 - 1;
    }
    var i = 0;
    while i < len(s) {
        out[at + i] = s[i];
        i = i + 1;
    }
    return at + len(s);
}

pub fn put_byte[&o](out: &!o [byte], at: int, b: int) -> [] int {
    if at < 0 || at >= len(out) {
        return 0 - 1;
    }
    out[at] = byte_of(b);
    return at + 1;
}

// A non-negative decimal.
pub fn put_int[&o](out: &!o [byte], at: int, v: int) -> [] int {
    if v < 0 {
        return 0 - 1;
    }
    var scale = 1;
    while v / scale >= 10 {
        scale = scale * 10;
    }
    var rest = v;
    var k = at;
    while scale > 0 {
        k = put_byte(out, k, '0' + rest / scale % 10);
        rest = rest % scale;
        scale = scale / 10;
    }
    return k;
}

// The decimal digits `v` takes.
pub fn digits(v: int) -> [] int {
    var n = 1;
    var scale = 1;
    while v / scale >= 10 {
        scale = scale * 10;
        n = n + 1;
    }
    return n;
}
