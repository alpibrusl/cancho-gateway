edition 5;

import std.test;
import gateway.deploy;
import gateway.egress;

fn test_every_compiled_in_upstream_is_allowed() -> [] int {
    var i = 0;
    while i < deploy.upstream_count() {
        test.assert(egress.allowed(deploy.upstream_addr(i)));
        i = i + 1;
    }
    return 0;
}

fn test_the_prefix_does_not_over_admit() -> [] int {
    test.assert(!egress.allowed("10.0.1.50:9000"));
    test.assert(!egress.allowed("10.0.1.5:90001"));
    test.assert(!egress.allowed("10.0.1.:9000"));
    test.assert(!egress.allowed("10.0.1.5:9000 "));
    test.assert(!egress.allowed("10.0.1.5"));
    return 0;
}

fn test_nothing_is_allowed_that_is_not_listed() -> [] int {
    test.assert(!egress.allowed(""));
    test.assert(!egress.allowed("127.0.0.1:9000"));
    test.assert(!egress.allowed("localhost:9000"));
    test.assert(!egress.allowed("10.0.1.7:9000"));
    return 0;
}

fn test_the_deployment_is_what_the_example_says() -> [] int {
    test.assert_eq(deploy.listen_port(), 8080);
    test.assert_eq(deploy.upstream_count(), 2);
    return 0;
}
