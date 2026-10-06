edition 5;

import std.io;
import std.http;
import gateway.framing;
import gateway.chunked;

// `framing_probe <max-headers> <hex>`: what `std.http.parse` answers for the bytes the hex names, as one line on
// standard output: `accept <body-start> <content-length> <chunked> <keep-alive> <version>` or `refuse <code> <position>`.
// `framing_probe <ignored> <hex> chunked:<max-body>:<piece>`: the same bytes as a chunked body, fed to
// `chunked.advance` in pieces of `<piece>` bytes (0 = all at once): `done <consumed> <body-bytes>`,
// `more <consumed> <body-bytes>` or `refuse <tag> <status>`.
// A test tool (tests/smuggling/run.py drives it); its authority is gated like the gateway's (authority.toml).

fn hexval(c: int) -> [] int {
    if c >= '0' && c <= '9' {
        return c - '0';
    }
    if c >= 'a' && c <= 'f' {
        return c - 'a' + 10;
    }
    return 0 - 1;
}

fn number_at[&a](text: &a [byte], from: int) -> [] int {
    var v = 0;
    var i = from;
    while i < len(text) && int_of(text[i]) >= '0' && int_of(text[i]) <= '9' {
        v = v * 10 + int_of(text[i]) - '0';
        i = i + 1;
    }
    return v;
}

fn colon_after[&a](text: &a [byte], from: int) -> [] int {
    var i = from;
    while i < len(text) && int_of(text[i]) != ':' {
        i = i + 1;
    }
    return i + 1;
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
    var digits = 1;
    var scale = 1;
    while n / scale >= 10 {
        scale = scale * 10;
        digits = digits + 1;
    }
    while scale > 0 {
        putchar(io, '0' + n / scale % 10);
        scale = scale / 10;
    }
    return digits;
}

fn main(world: World) -> [] int {
    let Split { io, ffi, fs, heap, args, net, clock } = split(world);
    release(ffi);
    release(fs);
    release(heap);
    release(net);
    release(clock);
    var status = 2;
    var src = "";
    var headers = 0;
    region a {
        let data = alloc_slice[a](30000, byte_of(0));
        var n = 0 - 1;
        borrow args as &g in {
            if arg_count(g) == 3 || arg_count(g) == 4 {
                let h = arg(g, 2);
                var m = 0;
                var ok = true;
                let hc = arg(g, 1);
                var j = 0;
                while j < len(hc) {
                    m = m * 10 + int_of(hc[j]) - '0';
                    j = j + 1;
                }
                headers = m;
                if len(h) % 2 == 0 && len(h) / 2 <= 30000 {
                    var i = 0;
                    while i < len(h) / 2 {
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
        }
        if n >= 0 && headers > 0 && headers <= 1000 {
            let table = alloc_slice[a](http.slots(headers), 0);
            var gateway = false;
            var chunk_mode = false;
            var max_body = 0;
            var piece = 0;
            var r = 0;
            borrow args as &g in {
                if arg_count(g) == 4 {
                    if int_of(arg(g, 3)[0]) == 'c' {
                        chunk_mode = true;
                        let m = arg(g, 3);
                        let first = colon_after(m, 0);
                        max_body = number_at(m, first);
                        piece = number_at(m, colon_after(m, first));
                    } else {
                        gateway = true;
                    }
                }
            }
            if chunk_mode {
                let st = alloc_slice[a](chunked.state_len(), 0);
                chunked.init(st, max_body);
                var fed = 0;
                var consumed = 0;
                var refused = 0;
                var step = piece;
                if step <= 0 {
                    step = n + 1;
                }
                while fed < n && refused == 0 && !chunked.is_done(st) {
                    var upto = fed + step;
                    if upto > n {
                        upto = n;
                    }
                    let k = chunked.advance(data[fed..upto], st);
                    if k < 0 {
                        refused = 0 - k;
                    } else {
                        consumed = consumed + k;
                        fed = upto;
                    }
                }
                borrow mut io as &!i in {
                    if refused > 0 {
                        write_all(i, "refuse ");
                        write_all(i, framing.tag(refused));
                        write_all(i, " ");
                        write_int(i, framing.status(refused));
                        write_all(i, "\n");
                        status = 1;
                    } else {
                        if chunked.is_done(st) {
                            write_all(i, "done ");
                        } else {
                            write_all(i, "more ");
                        }
                        write_int(i, consumed);
                        write_all(i, " ");
                        write_int(i, chunked.body_bytes(st));
                        write_all(i, "\n");
                        status = 0;
                    }
                }
            } else if gateway {
                r = framing.judge(data[0..n], table);
            } else {
                r = http.parse(data[0..n], table);
            }
            if !chunk_mode {
                borrow mut io as &!i in {
                    if gateway && r == 0 {
                        write_all(i, "more\n");
                        status = 0;
                    } else if gateway && r < 0 {
                        write_all(i, "refuse ");
                        write_all(i, framing.tag(0 - r));
                        write_all(i, " ");
                        write_int(i, framing.status(0 - r));
                        write_all(i, "\n");
                        status = 1;
                    } else if r > 0 {
                        write_all(i, "accept ");
                        write_int(i, r);
                        write_all(i, " ");
                        write_int(i, http.content_length(table));
                        write_all(i, " ");
                        if http.is_chunked(table) {
                            write_all(i, "1 ");
                        } else {
                            write_all(i, "0 ");
                        }
                        if http.keeps_alive(table) {
                            write_all(i, "1 ");
                        } else {
                            write_all(i, "0 ");
                        }
                        write_int(i, http.version(table));
                        write_all(i, "\n");
                        status = 0;
                    } else {
                        write_all(i, "refuse ");
                        write_int(i, http.error_code(r));
                        write_all(i, " ");
                        write_int(i, http.error_position(r));
                        write_all(i, "\n");
                        status = 1;
                    }
                }
            }
        }
    }
    release(args);
    release(io);
    return status;
}
