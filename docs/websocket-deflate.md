# permessage-deflate (RFC 7692): decided, not built

Status: **decision, 2026-10-13.** The gateway does **not** support `permessage-deflate`, and this document says why with measurements, what the gateway does instead (it is tested), and what supporting it would take. Claims about cancho are about the pinned compiler (`cancho.toml`). A claim found false is corrected in place.

**The decision in one paragraph.** The pinned cancho `std` has no inflate and no deflate. A validating gateway cannot carry compressed messages untouched (it could not check UTF-8, `ws_max_message_bytes` or OCPP on bytes it cannot read), so it would have to inflate, and writing an inflater from scratch for a security boundary is the one thing the task forbids until `std` offers one. So the gateway keeps what it does today, which is the correct behaviour for a validating gateway: **it never negotiates an extension**. The offer is stripped, the upstream is never told about it, an upstream's unsolicited extension is refused, and a compressed (RSV1) frame is a protocol violation. This slice adds the tests that pin that behaviour in every spelling, two mutants, and this document. No route key is added (section 6).

## 1. What the pinned std offers (measured)

`grep -rliE "inflate|deflate|zlib|huffman|gzip" std packages` in the pinned cancho checkout (`/tmp/claude-0/cancho-pin`, the commit in `cancho.toml`): **no file** under `std/` or `packages/`. `std` has `aes`, `chacha20`, `gcm`, `hmac`, `hkdf`, `crypto` (SHA-2), `ed25519`, `ecdsa`, `rsa`, `x25519`, `utf8`, `json`, `http`, `bytes`, `buffer` and no compression of any kind. (The only grep hits in the whole checkout are two Rust conformance tests of the compiler's own version-control code, unrelated.) So: **there is no inflate to build on, and this slice does not write one.**

## 2. Question (a): negotiate it, or refuse it?

Three designs, for a gateway whose job is to validate:

| design | what the gateway sees | verdict |
|---|---|---|
| **A. Pass the extension through** (client and upstream negotiate; the gateway relays the bytes) | RSV1 frames whose payload is deflate output. UTF-8 (`ws.frame-utf8`), `ws_max_message_bytes` and `ws_ocpp` would all judge compressed bytes: wrong answers in both directions (a valid message refused, an invalid one admitted). The size limit would bound the wire size, not the message a back office will allocate, so a 1 KiB frame is a 1 MiB message | **Rejected.** It silently turns every check of `docs/websocket-frames.md` and `docs/ocpp.md` off for exactly the traffic an attacker would choose |
| **B. Negotiate on both sides and inflate to validate** (and, to forward, re-deflate or forward the original bytes) | the real message | The right design if compression is wanted. It needs inflate (section 1: absent), a bomb bound (section 3) and per-connection state (section 4) |
| **C. Never negotiate** (today) | uncompressed frames only | **Chosen.** RFC 6455 4.2.2 lets a server accept none of the offered extensions; RFC 7692 7 says a client that is not given the extension must not use it. A client falls back to plain frames, which is what every OCPP stack does when the server's answer carries no extension |

Design C is not a gap in the handshake, it is the answer RFC 7692 provides for a server that does not want the extension. Whether chargers in the field offer it, and what it would save on OCPP-J traffic (small JSON texts, a few hundred bytes), was **not measured** here; the use case in `docs/websocket.md` gives no reason to believe the saving is worth the machinery.

## 3. Behaviour today, checked and tested

Four places make it hold, each with a test and a mutant:

1. **The offer is removed.** `forward.rewrite_upgrade` drops every `Sec-WebSocket-Extensions` header (any case, any number, any parameters) from the request sent to the upstream (`docs/websocket.md` section 5). The upstream is never offered an extension, so RFC 6455 4.2.2 item 5.5 forbids it from answering with one.
2. **The client's `101` carries none.** `websocket.upgrade_response` builds the head from the checked fields only (accept, chosen subprotocol, `Via`, request id): there is no way for an extension to be echoed to the client.
3. **An upstream's unsolicited extension is refused.** `websocket.check_response` answers `ws.upstream-extensions` (502) for any `Sec-WebSocket-Extensions` in the `101`, whether or not the client offered one.
4. **RSV1 is a violation.** A frame with RSV1, RSV2 or RSV3 set is `ws.frame-rsv`, Close 1002, from either side (`docs/websocket-frames.md` section 3, row 1). So a client that assumes the extension was negotiated, or an upstream that ignores the stripped offer, is closed on its first compressed frame; the gateway never relays or inflates it.

Tests added in this slice (`tests/websocket_test.py`, the whole suite 56 tests, 0 failures):

- `an_offer_of_permessage_deflate_in_any_spelling_is_never_passed_on_or_accepted`: four offers (bare; with `client_max_window_bits` and `server_no_context_takeover`; an upper-case header name plus a second extension on a second line; two headers) each reach the upstream with **no** extension header and no occurrence of "deflate" in the whole head; the client's `101` has no extensions header; then the client sends an RSV1 frame anyway and receives Close 1002.
- `the_upstreams_refusals_of_the_upgrade_each_have_their_tag` gained four upstream answers, each `502 ws.upstream-extensions`: with parameters, an upper-case header name, the header twice, and the header with an empty value (the case `ext`, the bare `permessage-deflate`, was there already; the client offers nothing in these, so the extension is unsolicited).
- `tests/generate_test.py`: a route carrying `ws_extensions` or `ws_compression` is refused `config.unknown-key` (section 6).

Mutants (`tests/websocket_mutants.py`, both **killed**): `d01`, the strip is switched off (the offer reaches the upstream); `d02`, the RSV check admits RSV1 alone (a compressed frame would be relayed unread). `r10` and `f01` (the unit-level versions of 3 and 1) were already in the table.

## 4. Question (b): if it must inflate

Not built; what it would have to meet, with the numbers that are measurable now.

**A compression bomb.** DEFLATE's best ratio is about 1,032:1. Measured with Python's zlib (raw deflate, level 9, a run of zero bytes, `Z_SYNC_FLUSH` as RFC 7692 requires): 1 MiB inflates from **1,037 bytes** (1,011:1), 8 MiB from 8,161 bytes (1,028:1), 64 MiB from 65,236 bytes (1,029:1). Consequences for the bound:

- A **ratio limit alone cannot protect**: the ceiling is a property of the format, so any honest limit (say 1,100:1) admits it. The bound must be an **absolute output cap**: inflated bytes of one message never exceed the route's `ws_max_message_bytes` (default 1 MiB, up to 256 MiB), checked *while* inflating, with output produced in steps no larger than the 16 KiB read buffer so that the 1009 (`ws.message-too-big`) is decided before the message is materialised. A second, tighter cap on the inflated bytes produced from one read of input (a ratio cap per step) bounds the CPU spent on one read: 16 KiB of input can produce 16 MiB.
- The cap must apply to the sum over the fragments of a message (as the limit does today) and the ratio cap to each read, not to a message.
- The test would be a bomb from the table above through the gateway to a 1 MiB limit, expecting Close 1009 within the budget, and a differential of the inflater against Python's `zlib.decompressobj(-15)` on mutated inputs (valid, truncated, bad block types, distances too far back, over-long Huffman codes).

**Per-connection state.** Context takeover (the default) keeps a 32 KiB window per direction, so a tunnel costs **at least 2 x 32 KiB = 64 KiB** of window, plus the Huffman tables of the block in progress, plus a place for the output of a step. This is an estimate from the format, not a measurement of an implementation, since there is none. Against what exists:

| | per tunnel | 100 tunnels |
|---|---|---|
| measured now: resident memory of the gateway with open tunnels, echo traffic (one run, this machine) | **17.6 KiB** a tunnel: 2,316 KiB at start; 2,768 with 1 tunnel; 3,268 with 30; 3,796 with 60; 4,512 with 100 | 4.4 MiB total |
| with inflate state (estimate) | about 17.6 + 64 + tables = **over 82 KiB** (roughly 4.7 times) | over 10 MiB |

The fixed memory model constrains it in two ways. (i) A single `region` allocation over about 64 KiB traps (`docs/framing.md`, `docs/observability.md`: the repository hit this), so the windows cannot be one region: like the frame state (`Core.wsf`, `docs/websocket-frames.md` section 11) they would be a heap slab indexed by the client slot, 256 slots x about 72 KiB, about 18 MiB, touched only when a tunnel negotiates the extension. (ii) The slot table is 256 slots and a tunnel holds two, so at most 127 sessions exist: the slab is bounded by construction. So the memory is boundable; **it is not what rules compression out**. What rules it out is that there is no inflate and writing one is a decision for the compiler's `std`, where it can be reviewed and differentially tested once for every program, not for one gateway.

Negotiating `server_no_context_takeover` and `client_no_context_takeover` would drop the window between messages, but not within one (a message may refer back up to 32 KiB inside itself), so it does not remove the 64 KiB, it only stops the history from leaking between messages.

**Forwarding.** If the gateway inflates, the upstream leg must either be negotiated too (a second, independent extension state per tunnel: the 64 KiB doubles) or be uncompressed, in which case the gateway must also deflate toward the client or answer a compressed client with uncompressed frames only in one direction, which RFC 7692 permits per message (RSV1 is set per message). The simplest correct shape is: compressed on the client leg only, the upstream leg always plain, the gateway inflating client-to-upstream and sending plain upstream-to-client (a deflater is then not needed at all). That is the design a later slice should start from.

## 5. Question (c): the 2,000-line ceiling

`src/proxy.cho` is **1,980 lines** (`wc -l`; `scripts/lines.py` enforces 2,000). Any wiring of an inflater into the tunnel loop (`tunnel_pump`, `tunnel_up`, `tunnel_down`) adds more than the 20 lines of headroom, so it would need `src/proxy.cho` split by concern first (the tunnel code, from `upgrade_answered` to `tunnel_up`, is a natural module), as its own commit with no change of behaviour and all tests green. **This slice adds nothing to `src/proxy.cho` and therefore does not do the split**: moving about 500 lines with no change in behaviour, to make room for code that is not written, would be a risk with no use. The split is listed in section 7 as the first step.

## 6. Keys

No route key. A key whose only accepted value is the current behaviour (`ws_extensions = "none"`) adds a way to misconfigure and nothing to configure, and the unsupported value would have to be refused anyway. A deployment that asks for compression in a route today gets the generator's existing `config.unknown-key` (tested, section 3), which names the key. If a later slice adds the extension, its key (for example `ws_deflate = true`, requiring `websocket = true`, with its own cap) is a new key then, and the stripped behaviour stays the default.

## 7. What supporting it would take

In order, each a separate commit with the gate green:

1. Split `src/proxy.cho` by concern (section 5), behaviour unchanged.
2. An inflater with a hard output cap and a bound on work per call, in cancho `std` (preferred, with its differential against zlib there) or, failing that, as a module here, differentially tested against `zlib.decompressobj(-15)` over valid and mutated streams and fuzzed for panics ("no input may reach a panic").
3. State: the per-slot window slab (section 4), allocated at start, indexed by the client slot.
4. The handshake: parse the offer (RFC 7692 5), accept `permessage-deflate` on routes that ask for it with `server_no_context_takeover; client_no_context_takeover` and the smallest window, keep stripping it toward the upstream, and answer the client's `101` with the accepted parameters.
5. `wsframe.scan`: RSV1 allowed only on the first frame of a data message of a negotiated tunnel, never on a control frame or a continuation (RFC 7692 6.1); the message's inflated bytes feed UTF-8, the size limit and the OCPP recogniser, and the upstream receives the plain message re-framed.
6. Tests: the bomb (section 4), the differential, RSV1 on a control frame and on a continuation, a client that offers parameters the gateway does not accept, a truncated stream, the `websockets` library as client with compression on, and the mutants.
7. Measure the resident memory per tunnel and replace the estimate in section 4.

## 8. Not measured

- An implementation's resident memory per tunnel (there is none); the figure in section 4 is an estimate from the format.
- How many chargers offer the extension, and the bytes it would save on OCPP-J traffic.
- Behaviour above 100 simultaneous tunnels (the memory run stopped at 100).
