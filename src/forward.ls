edition 5;

module gateway.forward;

import std.bytes;
import std.http;
import gateway.out;

// The request head the gateway sends upstream (task #5; the full header policy is task #7).
//
// Copied from the client's: the request line (as HTTP/1.1) and every header except the hop-by-hop ones, which belong to the
// client's connection and not to the request (`Connection`, `Keep-Alive`, `Proxy-Connection`, `Proxy-Authorization`, `TE`,
// `Trailer`, `Upgrade`) and any header the client's `Connection` header names (RFC 9110 7.6.1). The same rule shapes the
// response head the client gets (`rewrite_response`).
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

fn name_of[&s, &t](src: &s [byte], table: &t [int], i: int) -> [] &s [byte] {
    return src[table[16 + 4 * i]..table[16 + 4 * i + 1]];
}

fn value_of[&s, &t](src: &s [byte], table: &t [int], i: int) -> [] &s [byte] {
    return src[table[16 + 4 * i + 2]..table[16 + 4 * i + 3]];
}

// Is `token` (any case) listed by one of the first `count` headers' `Connection` values? Both parsers (`std.http` and
// `gateway.response`) lay their headers out the same way from slot 16, which is all this reads.
fn connection_lists[&s, &t, &l](src: &s [byte], table: &t [int], count: int, token: &l [byte]) -> [] bool {
    var i = 0;
    while i < count {
        if is(name_of(src, table, i), "connection") {
            let value = value_of(src, table, i);
            var start = 0;
            var at = 0;
            while at <= len(value) {
                if at == len(value) || int_of(value[at]) == ',' {
                    if is_same(bytes.trim(value[start..at]), token) {
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

// Is header `i` named by a `Connection` header's value (so it belongs to the connection, not the message)?
fn named_by_connection[&s, &t](src: &s [byte], table: &t [int], count: int, i: int) -> [] bool {
    return connection_lists(src, table, count, name_of(src, table, i));
}

// The first line of `src`, with its CRLF.
fn first_line_end[&s](src: &s [byte]) -> [] int {
    var i = 0;
    while i + 1 < len(src) {
        if int_of(src[i]) == '\r' && int_of(src[i + 1]) == '\n' {
            return i + 2;
        }
        i = i + 1;
    }
    return 0;
}

// The headers of a message minus the hop-by-hop ones and any a `Connection` header names, as `name: value` lines.
fn copy_headers[&s, &t, &o](src: &s [byte], table: &t [int], count: int, out: &!o [byte], at: int) -> [] int {
    var k = at;
    var i = 0;
    while i < count {
        if !hop_by_hop(name_of(src, table, i)) && !named_by_connection(src, table, count, i) {
            k = out.put(out, k, name_of(src, table, i));
            k = out.put(out, k, ": ");
            k = out.put(out, k, value_of(src, table, i));
            k = out.put(out, k, "\r\n");
        }
        i = i + 1;
    }
    return k;
}

// Write the request head into `out` from offset 0; answers its length, or `0 - rule`. `src` and `table` are a request
// `std.http.parse` accepted. The request line is rebuilt as HTTP/1.1 whatever the client spoke, so the upstream may keep the
// connection open; `keep_alive` false adds `Connection: close` for an upstream that must not.
pub fn rewrite[&s, &t, &o](src: &s [byte], table: &t [int], out: &!o [byte], keep_alive: bool) -> [] int {
    let count = http.header_count(table);
    if connection_lists(src, table, count, "content-length") || connection_lists(src, table, count, "transfer-encoding") || connection_lists(src, table, count, "host") {
        return 0 - 1;
    }
    var k = out.put(out, 0, http.method(src, table));
    k = out.put(out, k, " ");
    k = out.put(out, k, http.target(src, table));
    k = out.put(out, k, " HTTP/1.1\r\n");
    k = copy_headers(src, table, count, out, k);
    if !keep_alive {
        k = out.put(out, k, "Connection: close\r\n");
    }
    k = out.put(out, k, "\r\n");
    if k < 0 {
        return 0 - 2;
    }
    return k;
}

// Write the response head for the client into `out` from offset 0: the upstream's status line and headers, minus the hop-by-hop
// ones, then `Connection: close` (the client's connection closes after the response in this slice). `src` and `table` are a
// head `response.parse` accepted. Answers the length, or `0 - 1` if it does not fit.
pub fn rewrite_response[&s, &t, &o](src: &s [byte], table: &t [int], out: &!o [byte]) -> [] int {
    var k = out.put(out, 0, src[0..first_line_end(src)]);
    k = copy_headers(src, table, table[2], out, k);
    k = out.put(out, k, "Connection: close\r\n\r\n");
    if k < 0 {
        return 0 - 1;
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
