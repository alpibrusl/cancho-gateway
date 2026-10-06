edition 5;

import std.bytes;
import std.http;
import std.test;
import gateway.forward;

fn test_hop_by_hop_headers_are_dropped_and_connection_close_added() -> [] int {
    region a {
        let table = alloc_slice[a](http.slots(16), 0);
        let out = alloc_slice[a](1024, byte_of(0));
        let req = "GET /x?y=1 HTTP/1.1\r\nHost: a.example\r\nConnection: keep-alive\r\nKeep-Alive: timeout=5\r\nAccept: */*\r\nTE: trailers\r\nUpgrade: websocket\r\nX-Keep: 1\r\n\r\n";
        test.assert(http.parse(req, table) > 0);
        let n = forward.rewrite(req, table, out);
        let want = "GET /x?y=1 HTTP/1.1\r\nHost: a.example\r\nAccept: */*\r\nX-Keep: 1\r\nConnection: close\r\n\r\n";
        test.assert_eq(n, len(want));
        test.assert(bytes.equal(out[0..n], want));
    }
    return 0;
}

fn test_headers_named_by_connection_are_dropped() -> [] int {
    region a {
        let table = alloc_slice[a](http.slots(16), 0);
        let out = alloc_slice[a](1024, byte_of(0));
        let req = "GET / HTTP/1.1\r\nHost: a\r\nConnection: close, X-Secret ,x-other\r\nX-Secret: 1\r\nX-Other: 2\r\nX-Kept: 3\r\n\r\n";
        test.assert(http.parse(req, table) > 0);
        let n = forward.rewrite(req, table, out);
        let want = "GET / HTTP/1.1\r\nHost: a\r\nX-Kept: 3\r\nConnection: close\r\n\r\n";
        test.assert_eq(n, len(want));
        test.assert(bytes.equal(out[0..n], want));
    }
    return 0;
}

fn test_a_connection_header_may_not_name_the_framing_headers() -> [] int {
    region a {
        let table = alloc_slice[a](http.slots(16), 0);
        let out = alloc_slice[a](1024, byte_of(0));
        test.assert(http.parse("POST / HTTP/1.1\r\nHost: a\r\nConnection: Content-Length\r\nContent-Length: 0\r\n\r\n", table) > 0);
        test.assert_eq(forward.rewrite("POST / HTTP/1.1\r\nHost: a\r\nConnection: Content-Length\r\nContent-Length: 0\r\n\r\n", table, out), 0 - 1);
        test.assert(http.parse("POST / HTTP/1.1\r\nHost: a\r\nConnection: close, transfer-encoding\r\nTransfer-Encoding: chunked\r\n\r\n", table) > 0);
        test.assert_eq(forward.rewrite("POST / HTTP/1.1\r\nHost: a\r\nConnection: close, transfer-encoding\r\nTransfer-Encoding: chunked\r\n\r\n", table, out), 0 - 1);
        test.assert(http.parse("GET / HTTP/1.1\r\nHost: a\r\nConnection: HOST\r\n\r\n", table) > 0);
        test.assert_eq(forward.rewrite("GET / HTTP/1.1\r\nHost: a\r\nConnection: HOST\r\n\r\n", table, out), 0 - 1);
    }
    return 0;
}

fn test_framing_headers_pass_through() -> [] int {
    region a {
        let table = alloc_slice[a](http.slots(16), 0);
        let out = alloc_slice[a](1024, byte_of(0));
        let req = "POST /u HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhello";
        let head = len(req) - 5;
        test.assert(http.parse(req, table) > 0);
        let n = forward.rewrite(req, table, out);
        let want = "POST /u HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nConnection: close\r\n\r\n";
        test.assert_eq(n, len(want));
        test.assert(bytes.equal(out[0..n], want));
        test.assert(head > 0);
    }
    return 0;
}

fn test_a_head_that_does_not_fit_is_refused() -> [] int {
    region a {
        let table = alloc_slice[a](http.slots(16), 0);
        let out = alloc_slice[a](30, byte_of(0));
        let req = "GET / HTTP/1.1\r\nHost: a.example\r\n\r\n";
        test.assert(http.parse(req, table) > 0);
        test.assert_eq(forward.rewrite(req, table, out), 0 - 2);
    }
    return 0;
}
