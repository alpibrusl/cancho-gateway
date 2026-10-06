edition 5;

import gateway.version;
import gateway.deploy;
import gateway.egress;

// Scaffold (task #2): prints its name and version and exits. The authority row is the smallest one
// (`io_write`); every effect added by a later task widens `authority.toml`, a reviewable diff.

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
    release(args);
    release(net);
    release(clock);
    release(heap);
    release(fs);
    release(ffi);
    var written = 0;
    borrow mut io as &!i in {
        written = write_all(i, version.name());
        written = written + write_all(i, " ");
        written = written + write_all(i, version.number());
        written = written + write_all(i, "\n");
    }
    release(io);
    if written == len(version.name()) + len(version.number()) + 2 {
        return 0;
    }
    return 1;
}
