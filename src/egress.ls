edition 5;

module gateway.egress;

import std.bytes;
import gateway.deploy;

// The gateway's own check of an upstream, before any connect (docs/design.md section 2, gate 4).
//
// The compiler's bound is one string shared by listen and connect, so it cannot carry the upstream set
// (design section 2.1); and a connect outside a bound traps (SIGILL) instead of refusing. So the set is
// compiled in (`gateway.deploy`, generated) and checked here, by exact equality on `host:port`:
// never by prefix, so `10.0.1.5:9000` does not admit `10.0.1.5:90001` or `10.0.1.50:9000`.

pub fn allowed[&a](addr: &a [byte]) -> [] bool {
    var i = 0;
    while i < deploy.upstream_count() {
        if bytes.equal(addr, deploy.upstream_addr(i)) {
            return true;
        }
        i = i + 1;
    }
    return false;
}
