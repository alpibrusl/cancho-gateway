edition 5;

module gateway.route;

import std.bytes;
import gateway.routes_table;

// Route selection (task #4, docs/routes.md): which route, hence which upstream and body limit, a request gets.
//
//   1. The host picks the route set: routes naming that host if there are any, else the routes naming none.
//   2. Inside it, the longest path_prefix that matches on a segment boundary and allows the method wins.
//   3. A path that matches some route but no route that allows the method is 405; one that matches nothing is 404.
//
// `select` answers a route index (0 or more) or `0 - rule`. The table is `generated/routes.ls`, validated at generation time
// (no ties, no malformed prefix), so equal-length matches cannot occur; the first in file order is taken if they ever did.

pub fn rule_count() -> [] int {
    return 4;
}

pub fn tag(rule: int) -> [] &static [byte] {
    if rule == 1 {
        return "route.path";
    }
    if rule == 2 {
        return "route.host";
    }
    if rule == 3 {
        return "route.none";
    }
    if rule == 4 {
        return "route.method";
    }
    return "";
}

pub fn status(rule: int) -> [] int {
    if rule == 1 || rule == 2 {
        return 400;
    }
    if rule == 3 {
        return 404;
    }
    if rule == 4 {
        return 405;
    }
    return 0;
}

// GET 1, HEAD 2, POST 4, PUT 8, DELETE 16, PATCH 32, OPTIONS 64; 0 for any other method.
fn method_bit[&m](method: &m [byte]) -> [] int {
    if bytes.equal(method, "GET") {
        return 1;
    }
    if bytes.equal(method, "HEAD") {
        return 2;
    }
    if bytes.equal(method, "POST") {
        return 4;
    }
    if bytes.equal(method, "PUT") {
        return 8;
    }
    if bytes.equal(method, "DELETE") {
        return 16;
    }
    if bytes.equal(method, "PATCH") {
        return 32;
    }
    if bytes.equal(method, "OPTIONS") {
        return 64;
    }
    return 0;
}

fn is_hex(c: int) -> [] bool {
    return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F';
}

// A request path the gateway will route: it starts with '/', has no control, space, DEL, non-ASCII or backslash byte, no
// '//', no '.' or '..' segment, and no percent escape of '.', '/' or '\' (or a malformed escape). These are the ways one
// path names two resources to two parsers.
fn path_ok[&p](path: &p [byte]) -> [] bool {
    let n = len(path);
    if n == 0 || int_of(path[0]) != '/' {
        return false;
    }
    var i = 0;
    var segment_start = 0;
    while i < n {
        let c = int_of(path[i]);
        if c <= 32 || c >= 127 || c == '\\' {
            return false;
        }
        if c == '/' {
            if i > 0 && int_of(path[i - 1]) == '/' {
                return false;
            }
            segment_start = i + 1;
        }
        if c == '%' {
            if i + 2 >= n {
                return false;
            }
            let a = int_of(path[i + 1]);
            let b = int_of(path[i + 2]);
            if !is_hex(a) || !is_hex(b) {
                return false;
            }
            let lo = bytes.to_lower(b);
            if a == '2' && (lo == 'e' || lo == 'f') {
                return false;
            }
            if a == '5' && lo == 'c' {
                return false;
            }
        }
        // A segment that is exactly '.' or '..', ended here by '/' or by the end of the path.
        if i + 1 == n || int_of(path[i + 1]) == '/' {
            let seg = path[segment_start..i + 1];
            if bytes.equal(seg, ".") || bytes.equal(seg, "..") {
                return false;
            }
        }
        i = i + 1;
    }
    return true;
}

// The host without a trailing `:port`, or an empty slice if it is not a plain DNS name or address: only [A-Za-z0-9.-], at
// most 253 bytes, and a port, if any, is one to five digits. IPv6 literals are refused.
fn host_name[&h](host: &h [byte]) -> [] &h [byte] {
    var end = len(host);
    var colon = 0 - 1;
    var i = 0;
    while i < len(host) {
        if int_of(host[i]) == ':' {
            colon = i;
        }
        i = i + 1;
    }
    if colon >= 0 {
        let digits = len(host) - colon - 1;
        if digits < 1 || digits > 5 {
            return host[0..0];
        }
        var k = colon + 1;
        while k < len(host) {
            if !bytes.is_digit(int_of(host[k])) {
                return host[0..0];
            }
            k = k + 1;
        }
        end = colon;
    }
    if end == 0 || end > 253 {
        return host[0..0];
    }
    var j = 0;
    while j < end {
        let c = int_of(host[j]);
        if !(bytes.is_alpha(c) || bytes.is_digit(c) || c == '.' || c == '-') {
            return host[0..0];
        }
        j = j + 1;
    }
    return host[0..end];
}

fn equal_lower[&a, &b](x: &a [byte], y: &b [byte]) -> [] bool {
    if len(x) != len(y) {
        return false;
    }
    var i = 0;
    while i < len(x) {
        if bytes.to_lower(int_of(x[i])) != int_of(y[i]) {
            return false;
        }
        i = i + 1;
    }
    return true;
}

fn number[&t](text: &t [byte]) -> [] int {
    var v = 0;
    var i = 0;
    while i < len(text) {
        v = v * 10 + int_of(text[i]) - '0';
        i = i + 1;
    }
    return v;
}

// The prefix matches the path on a segment boundary: "/" matches everything; "/api" matches "/api" and "/api/x" but not
// "/apix".
fn prefix_matches[&p, &q](path: &p [byte], prefix: &q [byte]) -> [] bool {
    if len(prefix) == 1 {
        return true;
    }
    if len(path) < len(prefix) || !bytes.equal(path[0..len(prefix)], prefix) {
        return false;
    }
    return len(path) == len(prefix) || int_of(path[len(prefix)]) == '/';
}

fn line_end[&b](blob: &b [byte], start: int) -> [] int {
    var end = start;
    while end < len(blob) && int_of(blob[end]) != '\n' {
        end = end + 1;
    }
    return end;
}

fn line_start[&b](blob: &b [byte], index: int) -> [] int {
    var at = 0;
    var seen = 0;
    while seen < index && at < len(blob) {
        at = line_end(blob, at) + 1;
        seen = seen + 1;
    }
    return at;
}

// The upstream index and body limit of route `index`.
pub fn upstream(index: int) -> [] int {
    let blob = routes_table.blob();
    let at = line_start(blob, index);
    return number(bytes.field(blob[at..line_end(blob, at)], 9, 4));
}

pub fn max_body(index: int) -> [] int {
    let blob = routes_table.blob();
    let at = line_start(blob, index);
    return number(bytes.field(blob[at..line_end(blob, at)], 9, 5));
}

pub fn select[&h, &m, &p](host: &h [byte], method: &m [byte], path: &p [byte]) -> [] int {
    let name = host_name(host);
    if len(name) == 0 {
        return 0 - 2;
    }
    if !path_ok(path) {
        return 0 - 1;
    }
    let blob = routes_table.blob();
    let bit = method_bit(method);
    // Pass 1: does any route name this host?
    var named = false;
    var at = 0;
    while at < len(blob) {
        let end = line_end(blob, at);
        let h = bytes.field(blob[at..end], 9, 1);
        if !bytes.equal(h, "*") && equal_lower(name, h) {
            named = true;
        }
        at = end + 1;
    }
    // Pass 2: the longest matching prefix in the chosen set.
    var best = 0 - 1;
    var best_len = 0;
    var path_matched = false;
    var index = 0;
    at = 0;
    while at < len(blob) {
        let end = line_end(blob, at);
        let line = blob[at..end];
        let h = bytes.field(line, 9, 1);
        var in_set = false;
        if named {
            in_set = !bytes.equal(h, "*") && equal_lower(name, h);
        } else {
            in_set = bytes.equal(h, "*");
        }
        if in_set {
            let prefix = bytes.field(line, 9, 2);
            if prefix_matches(path, prefix) {
                path_matched = true;
                if bit > 0 && number(bytes.field(line, 9, 3)) / bit % 2 == 1 && len(prefix) > best_len {
                    best = index;
                    best_len = len(prefix);
                }
            }
        }
        index = index + 1;
        at = end + 1;
    }
    if best >= 0 {
        return best;
    }
    if path_matched {
        return 0 - 4;
    }
    return 0 - 3;
}
