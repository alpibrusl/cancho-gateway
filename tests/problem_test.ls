edition 5;

import std.bytes;
import std.test;
import gateway.out;
import gateway.problem;

fn test_put_int() -> [] int {
    region a {
        let buf = alloc_slice[a](32, byte_of(0));
        test.assert_eq(out.put_int(buf, 0, 0), 1);
        test.assert(bytes.equal(buf[0..1], "0"));
        test.assert_eq(out.put_int(buf, 0, 1048576), 7);
        test.assert(bytes.equal(buf[0..7], "1048576"));
        test.assert_eq(out.put_int(buf, 3, 99), 5);
        test.assert_eq(out.put_int(buf, 0, 0 - 1), 0 - 1);
    }
    return 0;
}

fn test_put_refuses_what_does_not_fit() -> [] int {
    region a {
        let buf = alloc_slice[a](4, byte_of(0));
        test.assert_eq(out.put(buf, 0, "abcd"), 4);
        test.assert_eq(out.put(buf, 1, "abcd"), 0 - 1);
        test.assert_eq(out.put(buf, 4, "a"), 0 - 1);
        test.assert_eq(out.put_int(buf, 2, 12345), 0 - 1);
    }
    return 0;
}

fn test_a_404_is_exactly_this() -> [] int {
    region a {
        let buf = alloc_slice[a](512, byte_of(0));
        let n = problem.response(buf, 404, "route.none");
        let want = "HTTP/1.1 404 Not Found\r\nContent-Type: application/problem+json\r\nContent-Length: 75\r\nConnection: close\r\n\r\n{\"type\":\"about:blank\",\"title\":\"Not Found\",\"status\":404,\"rule\":\"route.none\"}";
        test.assert_eq(n, len(want));
        test.assert(bytes.equal(buf[0..n], want));
    }
    return 0;
}

// Content-Length is the body's real length for every status the gateway sends and a rule of any length.
fn test_content_length_is_the_body_length() -> [] int {
    region a {
        let buf = alloc_slice[a](512, byte_of(0));
        let scratch = alloc_slice[a](512, byte_of(0));
        var status = 400;
        while status <= 505 {
            let n = problem.response(buf, status, "framing.transfer-encoding-repeated");
            test.assert(n > 0);
            let blank = bytes.find(buf[0..n], "\r\n\r\n");
            test.assert(blank > 0);
            let body_len = n - blank - 4;
            let m = out.put(scratch, 0, "Content-Length: ");
            let k = out.put_int(scratch, m, body_len);
            test.assert(bytes.find(buf[0..blank], scratch[0..k]) > 0);
            status = status + 1;
        }
    }
    return 0;
}

fn test_a_buffer_too_small_is_refused() -> [] int {
    region a {
        let buf = alloc_slice[a](40, byte_of(0));
        test.assert_eq(problem.response(buf, 404, "route.none"), 0 - 1);
    }
    return 0;
}
