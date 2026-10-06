edition 5;

import std.io;
import gateway.response;

// `response_probe <head-request 0|1> <hex>`: what `response.parse` makes of the bytes, one line on standard output:
// `head <length> <status> <version> <mode> <content-length> <reusable> <interim>`, `more`, or `refuse <tag> <status>`.
// A test tool (tests/response/run.py drives it); its authority is gated like the gateway's.

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
    var n = v;
    if n < 0 {
        putchar(io, '-');
        n = 0 - n;
    }
    var scale = 1;
    while n / scale >= 10 {
        scale = scale * 10;
    }
    while scale > 0 {
        putchar(io, '0' + n / scale % 10);
        n = n % scale;
        scale = scale / 10;
    }
    return 0;
}

fn main(world: World) -> [] int {
    let Split { io, ffi, fs, heap, args, net, clock } = split(world);
    release(ffi);
    release(fs);
    release(heap);
    release(net);
    release(clock);
    var status = 2;
    region a {
        let data = alloc_slice[a](30000, byte_of(0));
        var n = 0 - 1;
        var head_request = false;
        borrow args as &g in {
            if arg_count(g) == 3 {
                head_request = int_of(arg(g, 1)[0]) == '1';
                let h = arg(g, 2);
                var ok = len(h) % 2 == 0 && len(h) / 2 <= 30000;
                var i = 0;
                while ok && i < len(h) / 2 {
                    let hi = hexval(int_of(h[2 * i]));
                    let lo = hexval(int_of(h[2 * i + 1]));
                    if hi < 0 || lo < 0 {
                        ok = false;
                    } else {
                        data[i] = byte_of(hi * 16 + lo);
                    }
                    i = i + 1;
                }
                if ok {
                    n = len(h) / 2;
                }
            }
        }
        if n >= 0 {
            let table = alloc_slice[a](response.slots(64), 0);
            let r = response.parse(data[0..n], table);
            borrow mut io as &!i in {
                if r == 0 {
                    write_all(i, "more\n");
                    status = 0;
                } else if r < 0 {
                    write_all(i, "refuse ");
                    write_all(i, response.tag(0 - r));
                    write_all(i, " ");
                    write_int(i, response.status(0 - r));
                    write_all(i, "\n");
                    status = 1;
                } else {
                    let mode = response.body_mode(table, head_request);
                    write_all(i, "head ");
                    write_int(i, r);
                    write_all(i, " ");
                    write_int(i, response.code(table));
                    write_all(i, " ");
                    write_int(i, response.version(table));
                    write_all(i, " ");
                    write_int(i, mode);
                    write_all(i, " ");
                    write_int(i, response.content_length(table));
                    write_all(i, " ");
                    if response.reusable(table, mode) {
                        write_all(i, "1 ");
                    } else {
                        write_all(i, "0 ");
                    }
                    if response.interim(table) {
                        write_all(i, "1\n");
                    } else {
                        write_all(i, "0\n");
                    }
                    status = 0;
                }
            }
        }
    }
    release(args);
    release(io);
    return status;
}
