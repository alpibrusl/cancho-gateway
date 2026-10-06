# Routes and the deployment file (task #4)

Status: **built and measured: the deployment file with routes, its generator and validation, and route selection.** Not
built: per-route timeouts and policies (they arrive with #5-#9, each adding its own keys), and anything at run time that reads
a file (section 1).

## 1. Where the configuration lives, and why that is not "a loader"

The gateway has no file authority (`authority.toml`: no `fs_*`), and the upstream set must be compiled in (design section
2.1). So the route table is not read at start: **it is part of the deployment file and compiled in by `scripts/generate.py`**,
one binary per deployment (design section 8, D17). The "config parser, with every error a tagged startup refusal naming the
line" of issue #4 is therefore the generator, and its refusals happen when the deployment is built, not when the gateway
starts. A deployment that does not generate has no binary to start.

## 2. The file

```toml
listen = 8080

[[upstream]]            # name and addr (host:port); at most 256
name = "api"
addr = "10.0.1.5:9000"

[[route]]               # at most 256
name = "web-static"     # optional label
host = "api.example.com"   # optional: a lowercase DNS name, no port, no wildcard; omitted = any host
path_prefix = "/static"    # required
methods = ["GET", "HEAD"]  # optional: GET HEAD POST PUT DELETE PATCH OPTIONS; omitted = all
upstream = "web"           # required: a declared upstream
max_body = 0               # optional: 0..1073741824, default 1048576
```

`path_prefix` starts with `/`, has no trailing `/` (except `"/"` alone), no `//`, no `.` or `..` segment, no `%`, no
backslash, control or non-ASCII byte, and at most 255 bytes. An unknown key is refused, with the nearest valid key offered.

## 3. Selection

1. **The host picks the route set.** Routes naming the request's host (case-insensitive, port stripped) if there are any;
   otherwise the routes naming no host. (The nginx `server_name` model: a host with its own routes does not fall back to the
   host-less ones.)
2. **Inside the set, the longest `path_prefix` that matches on a segment boundary and allows the method wins**
   (`/api` matches `/api` and `/api/x`, not `/apix`; `/` matches everything). A method the longest prefix does not allow falls
   to a shorter prefix that does (`POST /static/a` reaches `/` when `/static` allows only `GET` and `HEAD`).
3. A path some route matches but no route allows the method for is **405 `route.method`**; one nothing matches is
   **404 `route.none`**.

Before selection, the request is refused if it names one resource two ways:

| rule | status | |
|---|---|---|
| `route.path` | 400 | not starting with `/`; a control, space, DEL, non-ASCII or backslash byte; `//`; a `.` or `..` segment; a percent escape of `.`, `/` or `\` (any case) or a malformed escape. The gateway refuses rather than normalises: it will not guess what the upstream's parser will do |
| `route.host` | 400 | empty, not `[A-Za-z0-9.-]`, over 253 bytes, an IPv6 literal, or a port that is not one to five digits |
| `route.none` | 404 | |
| `route.method` | 405 | |

**A tie is a configuration error.** Two routes with the same host (or both none), the same `path_prefix` and overlapping
methods are refused at generation (`config.route-conflict`, naming the second route's line). The same prefix with disjoint
methods, or on different hosts, or one with a host and one without, is accepted. So equal-length matches cannot occur at run
time.

## 4. Refusals at generation

One line of JSON on stderr, byte-stable, exit 2: `{"file","hint","key","line","message","rule"}`. Rules: `config.read`,
`config.listen`, `config.upstream`, `config.duplicate`, `config.count`, `config.routes`, `config.unknown-key`,
`config.route`, `config.route-upstream`, `config.route-conflict`. The line is the key's (the table's header for a missing
key); a misspelt key carries `did you mean 'path_prefix'?`.

## 5. Measured

- `python3 tests/generate_test.py`: **34 refusal cases**, each checked for its rule **and the line it names**, 3 accepted
  deployments (the legal near-ties above), 7 prefix cases, the hint, and byte-stability.
- `python3 tests/route_test.py`: a **differential** of `src/route.ls` against `tests/route_ref.py` over 12 seeded random
  deployments and 400 requests each: **4,800 requests (1,279 routed, 3,521 refused), 0 disagreements.**
  `--fixed`: 18 fixed cases against `deploy/example.toml` with literal expectations.
- **Mutants, each killed by the differential:** shortest prefix wins; no segment boundary; the host never selects a set;
  the method ignored; `%2f` allowed; host compared case-sensitively; `..` segment allowed; port not stripped.
- **One real bug the differential caught before it shipped:** the first version of the method check divided by the method's bit
  before testing it was non-zero, so an unknown method (`FETCH`) **trapped the probe** (SIGILL). Reordered; the unguarded
  version is a mutant the differential kills (`probe exited -4`).

## 6. What this does not establish

- **The reference was written by the same author from the same specification** as `src/route.ls`, so a misreading of the
  specification would be in both. The fixed cases and the semantics above are the independent check a reviewer can make.
- The first draw of requests was 97% refusals and exercised selection little; the generator now draws 60% clean requests
  (27% of the final 4,800 are routed).
- Selection is a linear scan of the table per request (at most 256 routes). Not measured; #14 will say whether it matters.
- Per-route timeouts, authentication, rate limits and header policy are not keys yet.
