# Request framing (task #3): what `std.http` already refuses, and what the gateway adds

Status: **request-head framing built and measured; chunked-body framing, the nginx differential and the llhttp/nginx
corpora are not done** (section 6). Every number here is reproduced by `tests/smuggling/run.py` against the pinned compiler.

## 1. Method

`tests/smuggling/corpus.py` holds 60 cases, each with the request bytes, what the gateway must do (`accept`, `refuse` with a
status, or `more` for an incomplete head) and the source that makes it a case. `src/framing_probe.ls` is a small program
(authority `args`, `io_write`; gated like the gateway) that takes the request as hex and answers one line, either through
`std.http.parse` alone (the default) or through `gateway.framing.judge` (`gateway`). The corpus ran against `std.http`
**first**, before any framing code was written; the gaps below are what it found.

**Sources.** RFC 9112 sections (cited per case), RFC 9110 5.1/5.5/7.2, RFC 3986 2, and James Kettle, "HTTP Desync Attacks:
Request Smuggling Reborn" (PortSwigger, 2019) for the Transfer-Encoding obfuscations. **Not yet consulted:** the llhttp and
nginx test suites named in issue #3; no case claims to come from them.

## 2. `std.http` alone (measured)

`python3 tests/smuggling/run.py`: **54 of 60 cases agree.** It already refuses: both-lengths (`Content-Length` with
`Transfer-Encoding`), differing duplicate `Content-Length`, every malformed `Content-Length` (letters, sign, hex, empty, list,
overflow), obfuscated or unknown `Transfer-Encoding` (including a space before the colon, a leading space, obs-fold), bare
LF/CR, NUL and DEL in names or values, a space before a colon, missing or repeated `Host`, a header over the caller's limit,
HTTP/0.9, `HTTP/2.0`, `HTTP/1.2`, a double space, a space, control byte or high byte in the target. **No case made it trap.**

**Six gaps** (cases it accepts that a proxy must refuse):

| case | what `std.http` does | the gateway's rule |
|---|---|---|
| `duplicate-cl-same` | accepts `Content-Length: 5` twice | `framing.length` 400: one framing, no tolerance (RFC 9112 6.3 would allow folding identical values) |
| `te-chunked-twice` | accepts two `Transfer-Encoding: chunked` | `framing.transfer-encoding-repeated` 400 |
| `absolute-form` | accepts `GET http://evil/` | `framing.target-form` 400 |
| `asterisk-form-get` | accepts `GET *` | `framing.target-form` 400 (only `OPTIONS *`) |
| `connect` | accepts `CONNECT` | `framing.method-unsupported` 501 |
| `head-over-limit` | head limit is 64 KiB | `limit.head` 431 at 16 KiB (design section 4) |

Also adapted, not gaps: `std.http` answers one code for "two lengths" and for "a coding we do not speak"; the gateway
tells them apart (400 `framing.two-lengths` vs 501 `framing.transfer-encoding`). A head ended by bare LFs is "incomplete" to
`std.http` and would sit until a timeout; the gateway refuses it at once (`framing.line-ending`).

## 3. Rules

| rule | status | |
|---|---|---|
| `framing.request-line` | 400 | not `method SP target SP HTTP/d.d` |
| `framing.method` | 400 | |
| `framing.method-unsupported` | 501 | `CONNECT` |
| `framing.target` | 400 | |
| `framing.target-form` | 400 | absolute, authority or asterisk form (except `OPTIONS *`) |
| `framing.version` | 505 | well-formed `HTTP/d.d` that is not 1.0 or 1.1 |
| `framing.header` | 400 | |
| `framing.fold` | 400 | obs-fold |
| `framing.length` | 400 | bad, repeated or listed `Content-Length` |
| `framing.two-lengths` | 400 | `Content-Length` with `Transfer-Encoding` |
| `framing.transfer-encoding` | 501 | anything but a single `chunked` |
| `framing.transfer-encoding-repeated` | 400 | |
| `framing.host` | 400 | missing or repeated |
| `limit.headers` | 431 | |
| `limit.head` | 431 | over 16,384 bytes, complete or not |
| `framing.line-ending` | 400 | a bare LF |

Every refusal closes the connection. Deliberately stricter than the RFC where it permits tolerance: identical duplicate
`Content-Length`, bare LF, a leading empty line (`framing.method`).

## 4. Gates, and that they can fail

All pass: `run.py --gateway` (60 cases, status included), `--prefixes` (**2,494** proper prefixes of the corpus: an accepted
head's prefixes are all `more`, a refused head's never accepted), `--fuzz 1500` (seeded mutations of the corpus: **0 traps**;
35 accepted heads each self-contained: the head alone accepts identically and no shorter prefix does).

Mutants, each shown killed on 2026-10-06: duplicate `Content-Length` allowed (`duplicate-cl-same`); head limit off by one
(`head-over-limit`); `CONNECT` not refused as such (`connect`, wrong status: the refusal still happens, as `target-form`);
bare LF left incomplete (`bare-lf`); repeated `Transfer-Encoding` allowed (`te-chunked-twice` and `te-chunked-then-identity`).

## 5. A finding about the tooling

A first probe asked for a 70,000-byte region and **trapped on every input, including bad arguments**: a region's arena is
capped at 64 KiB. The probe is capped at 30,000 bytes, so `std.http`'s own 64 KiB "too large" refusal is **not exercised**
here; `limit.head` triggers at 16 KiB, well under it.

## 6. Not done

- **Chunked bodies:** bounded chunk-size parsing, no overflow, no extension abuse, relay (the second half of #3).
- **The differential run against nginx and one more parser.** nginx was not run here.
- **The llhttp and nginx corpora**, and any case beyond the 60.
- Status for `framing.version` on `HTTP/1.0` with `Transfer-Encoding` (RFC 9112 6.1: a 1.0 request must not carry it) is
  not decided: today it is treated like 1.1.
