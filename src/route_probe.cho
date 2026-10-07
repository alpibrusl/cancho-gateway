edition 5;

import std.io;
import std.bytes;
import gateway.route;

// `route_probe <host-hex>:<method-hex>:<path-hex> ...`: one line on standard output per request, in order:
// `route <index> <upstream> <max-body>` or `refuse <tag> <status>`. A test tool (tests/route_test.py drives it, against a
// reference implementation, over generated tables); its authority is gated like the gateway's (authority.toml).

fn hexval(c: int) -> [] int {
    if c >= '0' && c <= '9' {
        return c - '0';
    }
    if c >= 'a' && c <= 'f' {
        return c - 'a' + 10;
    }
    return 0 - 1;
}

fn write_all[&r, &i](io: &!i Io, s: &r [byte]) -> [io_write] int {
    var n = 0;
    while n < len(s) {
        putchar(io, int_of(s[n]));
        n = n + 1;
    }
    return len(s);
}

fn write_int[&i](io: &!i Io, v: int) -> [io_write] int {
    var scale = 1;
    while v / scale >= 10 {
        scale = scale * 10;
    }
    var rest = v;
    while scale > 0 {
        putchar(io, '0' + rest / scale % 10);
        rest = rest % scale;
        scale = scale / 10;
    }
    return 0;
}

// Decode the hex in `text[from..to]` into `out` at `at`; answers the new `at`, or -1 on a bad digit.
fn decode[&t, &o](text: &t [byte], from: int, to: int, out: &!o [byte], at: int) -> [] int {
    if (to - from) % 2 != 0 {
        return 0 - 1;
    }
    var i = from;
    var k = at;
    while i < to {
        let hi = hexval(int_of(text[i]));
        let lo = hexval(int_of(text[i + 1]));
        if hi < 0 || lo < 0 {
            return 0 - 1;
        }
        out[k] = byte_of(hi * 16 + lo);
        k = k + 1;
        i = i + 2;
    }
    return k;
}

fn main(world: World) -> [] int {
    let Split { io, ffi, fs, heap, args, net, clock } = split(world);
    release(ffi);
    release(fs);
    release(heap);
    release(net);
    release(clock);
    var status = 0;
    borrow args as &g in {
        var which = 1;
        while which < arg_count(g) && status == 0 {
            let a = arg(g, which);
            region r {
                let buf = alloc_slice[r](len(a) + 1, byte_of(0));
                var first = 0;
                while first < len(a) && int_of(a[first]) != ':' {
                    first = first + 1;
                }
                var second = first + 1;
                while second < len(a) && int_of(a[second]) != ':' {
                    second = second + 1;
                }
                if first >= len(a) || second >= len(a) {
                    status = 2;
                } else {
                    let host_end = decode(a, 0, first, buf, 0);
                    let method_end = decode(a, first + 1, second, buf, host_end);
                    let path_end = decode(a, second + 1, len(a), buf, method_end);
                    if host_end < 0 || method_end < 0 || path_end < 0 {
                        status = 2;
                    } else {
                        let answer = route.select(buf[0..host_end], buf[host_end..method_end], buf[method_end..path_end]);
                        borrow mut io as &!i in {
                            if answer >= 0 {
                                write_all(i, "route ");
                                write_int(i, answer);
                                write_all(i, " ");
                                write_int(i, route.upstream(answer));
                                write_all(i, " ");
                                write_int(i, route.max_body(answer));
                                write_all(i, " ");
                                write_int(i, route.trust_forwarded(answer));
                            } else {
                                write_all(i, "refuse ");
                                write_all(i, route.tag(0 - answer));
                                write_all(i, " ");
                                write_int(i, route.status(0 - answer));
                            }
                            putchar(i, '\n');
                        }
                    }
                }
            }
            which = which + 1;
        }
    }
    release(args);
    release(io);
    return status;
}
