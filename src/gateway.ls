edition 5;

import std.io;
import gateway.deploy;
import gateway.proxy;
import gateway.version;

// `gateway` -- the reverse proxy (docs/design.md, docs/proxy.md). `gateway --version` prints its name and version; any other
// invocation serves on the port the deployment compiled in (`generated/deploy.ls`).

fn write_all[&r, &i](io: &!i Io, s: &r [byte]) -> [io_write] int {
    var n = 0;
    while n < len(s) {
        putchar(io, int_of(s[n]));
        n = n + 1;
    }
    return len(s);
}

fn main(world: World) -> [] int {
    let Split { io, ffi, fs, heap, args, net, clock } = split(world);
    release(fs);
    release(ffi);
    var status = 0;
    var show_version = false;
    borrow args as &g in {
        show_version = arg_count(g) > 1;
    }
    release(args);
    if show_version {
        borrow mut io as &!i in {
            write_all(i, version.name());
            write_all(i, " ");
            write_all(i, version.number());
            write_all(i, "\n");
        }
        release(io);
        release(heap);
        release(net);
        release(clock);
        return 0;
    }
    release(io);
    var served = 3;
    borrow net as &nn in {
        match tcp_listen(nn, deploy.listen_port(), 1024, 0) {
            Listening::Ok(l) => {
                var listener = l;
                borrow mut heap as &!h in {
                    borrow mut listener as &!lh in {
                        listener_nonblocking(lh);
                        borrow clock as &ck in {
                            served = proxy.run(h, lh, nn, ck);
                        }
                    }
                }
                listener_close(listener);
            }
            Listening::Failed(e) => {
                served = 2;
            }
        }
    }
    release(heap);
    release(net);
    release(clock);
    status = served;
    return status;
}
