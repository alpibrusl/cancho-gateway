edition 5;

module gateway.forward;

import std.bytes;
import std.http;
import gateway.out;

// The request head the gateway sends upstream (task #5; the full header policy is task #7).
//
// Copied from the client's: the request line as it came, and every header except the hop-by-hop ones, which belong to the
// client's connection and not to the request (`Connection`, `Keep-Alive`, `Proxy-Connection`, `Proxy-Authorization`, `TE`,
// `Trailer`, `Upgrade`) and any header the client's `Connection` header names (RFC 9110 7.6.1). Then `Connection: close`: this
// slice opens one upstream connection per request (pooling is task #6), so the upstream's response ends where its connection
// does.
//
// A `Connection` header that names `Content-Length`, `Transfer-Encoding` or `Host` is refused: asking an intermediary to drop the
// framing headers is a smuggling lever (Kettle 2019), and honouring it would change the message's framing between the two
// parsers.

pub fn rule_count() -> [] int {
    return 2;
}

pub fn tag(rule: int) -> [] &static [byte] {
    if rule == 1 {
        return "forward.connection-token";
    }
    if rule == 2 {
        return "forward.head-room";
    }
    return "";
}

pub fn status(rule: int) -> [] int {
    if rule == 1 {
        return 400;
    }
    if rule == 2 {
        return 431;
    }
    return 0;
}

// `a` equals the lowercase literal `lower`, ignoring ASCII case.
fn is[&a, &l](a: &a [byte], lower: &l [byte]) -> [] bool {
    if len(a) != len(lower) {
        return false;
    }
    var i = 0;
    while i < len(a) {
        if bytes.to_lower(int_of(a[i])) != int_of(lower[i]) {
            return false;
        }
        i = i + 1;
    }
    return true;
}

fn hop_by_hop[&n](name: &n [byte]) -> [] bool {
    return is(name, "connection") || is(name, "keep-alive") || is(name, "proxy-connection") || is(name, "proxy-authorization") || is(name, "te") || is(name, "trailer") || is(name, "upgrade");
}

// Visit every token of every `Connection` header: does one equal `lower`?
fn names_token[&s, &t, &l](src: &s [byte], table: &t [int], lower: &l [byte]) -> [] bool {
    var i = 0;
    while i < http.header_count(table) {
        if is(http.header_name(src, table, i), "connection") {
            let value = http.header_value(src, table, i);
            var start = 0;
            var at = 0;
            while at <= len(value) {
                if at == len(value) || int_of(value[at]) == ',' {
                    let token = bytes.trim(value[start..at]);
                    if is(token, lower) {
                        return true;
                    }
                    start = at + 1;
                }
                at = at + 1;
            }
        }
        i = i + 1;
    }
    return false;
}

fn request_line_end[&s](src: &s [byte]) -> [] int {
    var i = 0;
    while i + 1 < len(src) {
        if int_of(src[i]) == '\r' && int_of(src[i + 1]) == '\n' {
            return i + 2;
        }
        i = i + 1;
    }
    return 0;
}

// Write the head into `out` from offset 0; answers its length, or `0 - rule`. `src` and `table` are a request `std.http.parse`
// accepted.
pub fn rewrite[&s, &t, &o](src: &s [byte], table: &t [int], out: &!o [byte]) -> [] int {
    if names_token(src, table, "content-length") || names_token(src, table, "transfer-encoding") || names_token(src, table, "host") {
        return 0 - 1;
    }
    let line = request_line_end(src);
    var k = out.put(out, 0, src[0..line]);
    var i = 0;
    while i < http.header_count(table) {
        let name = http.header_name(src, table, i);
        var drop = hop_by_hop(name);
        var j = 0;
        // A header the client's Connection header names.
        if !drop {
            var start = 0;
            var h = 0;
            while h < http.header_count(table) {
                if is(http.header_name(src, table, h), "connection") {
                    let value = http.header_value(src, table, h);
                    start = 0;
                    j = 0;
                    while j <= len(value) {
                        if j == len(value) || int_of(value[j]) == ',' {
                            let token = bytes.trim(value[start..j]);
                            if len(token) == len(name) && is_same(token, name) {
                                drop = true;
                            }
                            start = j + 1;
                        }
                        j = j + 1;
                    }
                }
                h = h + 1;
            }
        }
        if !drop {
            k = out.put(out, k, name);
            k = out.put(out, k, ": ");
            k = out.put(out, k, http.header_value(src, table, i));
            k = out.put(out, k, "\r\n");
        }
        i = i + 1;
    }
    k = out.put(out, k, "Connection: close\r\n\r\n");
    if k < 0 {
        return 0 - 2;
    }
    return k;
}

fn is_same[&a, &b](x: &a [byte], y: &b [byte]) -> [] bool {
    if len(x) != len(y) {
        return false;
    }
    var i = 0;
    while i < len(x) {
        if bytes.to_lower(int_of(x[i])) != bytes.to_lower(int_of(y[i])) {
            return false;
        }
        i = i + 1;
    }
    return true;
}
