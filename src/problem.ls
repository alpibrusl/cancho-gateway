edition 5;

module gateway.problem;

import gateway.out;

// A response the gateway makes itself (docs/design.md section 8): `application/problem+json` (RFC 9457) carrying the rule tag,
// so a client or an agent branches on `rule`, not on English. The connection is told to close: after a refusal the gateway does
// not keep it.
//
//     HTTP/1.1 404 Not Found
//     Content-Type: application/problem+json
//     Content-Length: 80
//     Connection: close
//
//     {"type":"about:blank","title":"Not Found","status":404,"rule":"route.none"}

pub fn reason(status: int) -> [] &static [byte] {
    if status == 400 {
        return "Bad Request";
    }
    if status == 404 {
        return "Not Found";
    }
    if status == 405 {
        return "Method Not Allowed";
    }
    if status == 408 {
        return "Request Timeout";
    }
    if status == 413 {
        return "Content Too Large";
    }
    if status == 431 {
        return "Request Header Fields Too Large";
    }
    if status == 501 {
        return "Not Implemented";
    }
    if status == 502 {
        return "Bad Gateway";
    }
    if status == 503 {
        return "Service Unavailable";
    }
    if status == 504 {
        return "Gateway Timeout";
    }
    if status == 505 {
        return "HTTP Version Not Supported";
    }
    return "Error";
}

// The body alone, at `at`; answers the new offset.
pub fn body[&o, &t](out: &!o [byte], at: int, status: int, rule: &t [byte]) -> [] int {
    var k = out.put(out, at, "{\"type\":\"about:blank\",\"title\":\"");
    k = out.put(out, k, reason(status));
    k = out.put(out, k, "\",\"status\":");
    k = out.put_int(out, k, status);
    k = out.put(out, k, ",\"rule\":\"");
    k = out.put(out, k, rule);
    return out.put(out, k, "\"}");
}

// Head and body, from offset 0; answers the length, or `0 - 1` if `out` is too small.
pub fn response[&o, &t](out: &!o [byte], status: int, rule: &t [byte]) -> [] int {
    // The body's length is known without writing it twice: everything but the variable parts is fixed.
    let fixed = len("{\"type\":\"about:blank\",\"title\":\"") + len("\",\"status\":") + len(",\"rule\":\"") + len("\"}");
    let length = fixed + len(reason(status)) + out.digits(status) + len(rule);
    var k = out.put(out, 0, "HTTP/1.1 ");
    k = out.put_int(out, k, status);
    k = out.put(out, k, " ");
    k = out.put(out, k, reason(status));
    k = out.put(out, k, "\r\nContent-Type: application/problem+json\r\nContent-Length: ");
    k = out.put_int(out, k, length);
    k = out.put(out, k, "\r\nConnection: close\r\n\r\n");
    return body(out, k, status, rule);
}
