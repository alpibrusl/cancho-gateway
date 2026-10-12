# Contributing

Read `docs/design.md` first: it fixes scope, the authority row and the gates before the code they judge.

## The gate

All of these pass before anything is called done (CI runs them, `.github/workflows/ci.yml`):

    cancho fmt --check src tests generated
    python3 scripts/generate.py deploy/example.toml --check   # generated/deploy.cho is current
    python3 tests/generate_test.py
    python3 tests/response/run.py                # upstream response heads (docs/pool.md)
    python3 tests/proxy_test.py                  # the proxy core, end to end (docs/proxy.md)
    python3 tests/websocket_test.py              # WebSocket handshake and tunnel, plain and over TLS (docs/websocket.md)
    python3 tests/route_test.py 12 400          # route selection vs the reference; also --fixed (docs/routes.md)
    cancho build
    cancho test
    python3 tests/smuggling/run.py --gateway    # also --prefixes, --fuzz 1500, --chunked (docs/framing.md)
    python3 scripts/lines.py                 # no source file over 2,000 lines; split by concern
    python3 scripts/authority.py --check     # the compiler's authority report, within authority.toml

`CANCHO` or `cancho` on `PATH` is the compiler pinned in `cancho.toml`.

## Rules

- **Design before code**, in `docs/`, with claims measured. A claim found false is corrected in place, in the
  document that made it.
- **Every refusal has a rule tag** with a real status, and **no input may reach a panic.**
- **Widening authority is a reviewable edit** to `authority.toml`; the derived report is recorded in
  `manifests/` (`python3 scripts/authority.py` regenerates it).
- A gate is fixed before the code it judges and must be able to fail: show it failing with a mutant.
