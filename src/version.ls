edition 5;

module gateway.version;

// The program's name and version, as the one place that says them: `gateway --version`,
// `introspect` (task #18) and the access log (task #10) all read it from here.

pub fn name() -> [] &static [byte] {
    return "lexsys-gateway";
}

pub fn number() -> [] &static [byte] {
    return "0.0.0";
}
