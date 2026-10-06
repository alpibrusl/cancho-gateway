edition 5;

module gateway.framing;

import std.bytes;
import std.http;

// Request framing for a proxy (task #3, docs/framing.md): `std.http.parse` plus the refusals a proxy needs and a
// server does not. `std.http` is already strict (docs/framing.md section 2 measures how much); this adds the five
// cases the corpus found it accepts, and gives every refusal a rule tag and the status the gateway answers with.
//
// `judge` answers a positive number (accepted: where the body starts), `0` (not complete yet: read more), or
// `0 - rule` (refused). A refusal always closes the connection: after one, the stream's framing cannot be trusted.

pub fn rule_count() -> [] int {
    return 21;
}

// The head the gateway accepts, in bytes: lower than `std.http.max_head()` (design section 4, `limit.head`).
pub fn head_limit() -> [] int {
    return 16384;
}

pub fn tag(rule: int) -> [] &static [byte] {
    if rule == 1 {
        return "framing.request-line";
    }
    if rule == 2 {
        return "framing.method";
    }
    if rule == 3 {
        return "framing.method-unsupported";
    }
    if rule == 4 {
        return "framing.target";
    }
    if rule == 5 {
        return "framing.target-form";
    }
    if rule == 6 {
        return "framing.version";
    }
    if rule == 7 {
        return "framing.header";
    }
    if rule == 8 {
        return "framing.fold";
    }
    if rule == 9 {
        return "framing.length";
    }
    if rule == 10 {
        return "framing.two-lengths";
    }
    if rule == 11 {
        return "framing.transfer-encoding";
    }
    if rule == 12 {
        return "framing.transfer-encoding-repeated";
    }
    if rule == 13 {
        return "framing.host";
    }
    if rule == 14 {
        return "limit.headers";
    }
    if rule == 15 {
        return "limit.head";
    }
    if rule == 16 {
        return "framing.line-ending";
    }
    if rule == 17 {
        return "framing.chunk-size";
    }
    if rule == 18 {
        return "framing.chunk-extension";
    }
    if rule == 19 {
        return "framing.chunk-framing";
    }
    if rule == 20 {
        return "framing.trailers";
    }
    if rule == 21 {
        return "limit.body";
    }
    return "";
}

pub fn status(rule: int) -> [] int {
    if rule == 3 || rule == 11 {
        return 501;
    }
    if rule == 6 {
        return 505;
    }
    if rule == 14 || rule == 15 {
        return 431;
    }
    if rule == 21 {
        return 413;
    }
    if rule >= 1 && rule <= 20 {
        return 400;
    }
    return 0;
}

fn named[&s, &t, &n](src: &s [byte], table: &t [int], i: int, name: &n [byte]) -> [] bool {
    let have = http.header_name(src, table, i);
    if len(have) != len(name) {
        return false;
    }
    var k = 0;
    while k < len(name) {
        if bytes.to_lower(int_of(have[k])) != int_of(name[k]) {
            return false;
        }
        k = k + 1;
    }
    return true;
}

fn count_named[&s, &t, &n](src: &s [byte], table: &t [int], name: &n [byte]) -> [] int {
    var found = 0;
    var i = 0;
    while i < http.header_count(table) {
        if named(src, table, i, name) {
            found = found + 1;
        }
        i = i + 1;
    }
    return found;
}

// Is the request line `... HTTP/d.d`? Decides between "a version we do not speak" (505) and "not a request line" (400).
fn well_formed_version[&s](src: &s [byte]) -> [] bool {
    var end = 0;
    while end < len(src) && int_of(src[end]) != '\r' && int_of(src[end]) != '\n' {
        end = end + 1;
    }
    if end < 8 {
        return false;
    }
    var spaces = 0;
    var k = 0;
    while k < end {
        if int_of(src[k]) == ' ' {
            spaces = spaces + 1;
        }
        k = k + 1;
    }
    if spaces != 2 {
        return false;
    }
    let v = src[end - 8..end];
    return int_of(v[0]) == 'H' && int_of(v[1]) == 'T' && int_of(v[2]) == 'T' && int_of(v[3]) == 'P' && int_of(v[4]) == '/' && bytes.is_digit(int_of(v[5])) && int_of(v[6]) == '.' && bytes.is_digit(int_of(v[7]));
}

// The rule for a refusal `std.http` made.
fn classify[&s, &t](src: &s [byte], table: &t [int], result: int) -> [] int {
    let code = http.error_code(result);
    if code == 2 {
        return 1;
    }
    if code == 3 {
        return 2;
    }
    if code == 4 {
        return 4;
    }
    if code == 5 {
        if well_formed_version(src) {
            return 6;
        }
        return 1;
    }
    if code == 6 {
        return 7;
    }
    if code == 7 {
        return 14;
    }
    if code == 8 {
        return 9;
    }
    if code == 9 {
        return 8;
    }
    if code == 10 {
        return 15;
    }
    if code == 11 {
        // `std.http` refuses both "two lengths" and "a transfer coding we do not speak" with the same code.
        // Two lengths means a Content-Length header is present too.
        if count_named(src, table, "content-length") > 0 {
            return 10;
        }
        if count_named(src, table, "transfer-encoding") > 1 {
            return 12;
        }
        return 11;
    }
    if code == 12 {
        return 13;
    }
    return 1;
}

fn is_options[&s, &t](src: &s [byte], table: &t [int]) -> [] bool {
    let m = http.method(src, table);
    return len(m) == 7 && int_of(m[0]) == 'O' && int_of(m[1]) == 'P' && int_of(m[2]) == 'T' && int_of(m[3]) == 'I' && int_of(m[4]) == 'O' && int_of(m[5]) == 'N' && int_of(m[6]) == 'S';
}

fn is_connect[&s, &t](src: &s [byte], table: &t [int]) -> [] bool {
    let m = http.method(src, table);
    return len(m) == 7 && int_of(m[0]) == 'C' && int_of(m[1]) == 'O' && int_of(m[2]) == 'N' && int_of(m[3]) == 'N' && int_of(m[4]) == 'E' && int_of(m[5]) == 'C' && int_of(m[6]) == 'T';
}

pub fn judge[&s, &t](src: &s [byte], table: &!t [int]) -> [] int {
    let r = http.parse(src, table);
    if http.is_incomplete(r) {
        if len(src) >= head_limit() {
            return 0 - 15;
        }
        // `std.http` waits for CRLF CRLF, so a head ended with bare LFs would sit "incomplete" until a timeout.
        // Refusing it at once is kinder and closes the door on a peer that counts bare LF as a line end.
        var i = 0;
        while i < len(src) {
            if int_of(src[i]) == '\n' && (i == 0 || int_of(src[i - 1]) != '\r') {
                return 0 - 16;
            }
            i = i + 1;
        }
        return 0;
    }
    if r < 0 {
        return 0 - classify(src, table, r);
    }
    if r > head_limit() {
        return 0 - 15;
    }
    // Accepted by std.http; what a proxy refuses on top.
    if is_connect(src, table) {
        return 0 - 3;
    }
    let target = http.target(src, table);
    if len(target) == 0 {
        return 0 - 4;
    }
    if int_of(target[0]) != '/' {
        // absolute-form, authority-form and asterisk-form; only `OPTIONS *` is a request a proxy forwards.
        if !(is_options(src, table) && len(target) == 1 && int_of(target[0]) == '*') {
            return 0 - 5;
        }
    }
    if count_named(src, table, "content-length") > 1 {
        return 0 - 9;
    }
    if count_named(src, table, "transfer-encoding") > 1 {
        return 0 - 12;
    }
    return r;
}
