# Contributing

Read `docs/design.md` first: it fixes scope, the authority row and the gates before the code they judge.

## The gate

All of these pass before anything is called done (CI runs them, `.github/workflows/ci.yml`):

    lex-sys fmt --check src tests generated
    python3 scripts/generate.py deploy/example.toml --check   # generated/deploy.ls is current
    python3 tests/generate_test.py
    lex-sys build
    lex-sys test
    python3 scripts/lines.py                 # no source file over 2,000 lines; split by concern
    python3 scripts/authority.py --check     # the compiler's authority report, within authority.toml

`LEX_SYS` or `lex-sys` on `PATH` is the compiler pinned in `lex-sys.toml`.

## Rules

- **Design before code**, in `docs/`, with claims measured. A claim found false is corrected in place, in the
  document that made it.
- **Every refusal has a rule tag** with a real status, and **no input may reach a panic.**
- **Widening authority is a reviewable edit** to `authority.toml`; the derived report is recorded in
  `manifests/` (`python3 scripts/authority.py` regenerates it).
- A gate is fixed before the code it judges and must be able to fail: show it failing with a mutant.
