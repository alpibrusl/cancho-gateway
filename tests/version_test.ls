edition 5;

import std.test;
import gateway.version;

fn test_the_name_is_the_repository_name() -> [] int {
    test.assert_eq(len(version.name()), 14);
    test.assert_eq(int_of(version.name()[0]), 108);
    return 0;
}

fn test_the_version_is_not_empty() -> [] int {
    test.assert(len(version.number()) > 0);
    return 0;
}
