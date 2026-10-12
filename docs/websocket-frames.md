# WebSocket frames at the gateway (task #15, slice 2)

Status: **design, written before the code (2026-10-12).** Sections 1 to 14 are the decision; the gates in section 13 are fixed now and must be able to fail. Section 15 (as built, measured, mutants) is written
after the build and corrects, in place and marked *(corrected)*, whatever the build finds false. Claims about cancho are about the pinned compiler (`cancho.toml`, `2fcf4cd`). A claim that is not measured is marked **unknown**.

Slice 1 (`docs/websocket.md`) validates the upgrade and then carries **bytes**: no frame is read, so there is no ping policy, no close handshake of the gateway's own, no message limit, no UTF-8 check, and no Close frame when
a timer ends a tunnel (the gateway cannot know where a frame ends). Slice 2 makes the gateway read frames **in both directions** of the tunnel, with a parser that holds no message, so that each of those becomes possible.
The use case is unchanged: OCPP-J, chargers on `ws`/`wss` talking to a back office for days. The gateway still does **not** understand OCPP.

## 1. Scope

**Built in this slice**

- A bounded **frame parser** in the proxy path, one per direction per tunnel, that tracks frame boundaries without buffering a message and enforces RFC 6455 section 5 (section 3).
- `ws_max_message_bytes` per route: a message longer than that, counted over its fragments, is refused with Close 1009 (section 4).
- Streaming **UTF-8 validation** of text messages, across fragments and across read boundaries, Close 1007 (section 5).
- Gateway-originated keepalive **Ping** to the client (`ws_ping_ms`) with a pong deadline (`ws_pong_ms`); the gateway consumes the Pong of its own Ping and nothing else (section 6).
- A **close handshake of the gateway's own**: a timer, a limit or a violation ends a tunnel with a Close frame placed at a frame boundary, a bounded wait for the echo, then the connection closes; a Close sent by a peer is passed through
  and the wait for the answer is bounded (section 7).
- Deployment keys, rule tags, metrics, one trailing log field, tests, mutants (sections 3 to 13).

**Not in this slice**, said once (section 14 expands): `permessage-deflate` and every other extension (stripped, as in slice 1); OCPP-J message validation (message type, unique id, JSON schema); per-message rate limiting; a binary-versus-text
policy; reading the reason of a Close frame as UTF-8; the Close *code* values a peer may use (checked only for the payload length); more than 127 tunnels.

**What stays exactly as slice 1:** the handshake and its refusals, authentication and rate limiting (upgrade time only), the pool and circuit rules, TLS (`wss`), the slot table, the buffers (16 KiB read, 32 KiB write queue per slot) and the
back-pressure rule: a direction reads from its source only while its sink has room.

## 2. What the parser must be, in this program

The tunnel is a loop that moves bytes from the read buffer of one slot into the write queue of its peer. The parser is a function the loop calls on the bytes it is about to move, and its answer is **how many of them may go**.

Four properties follow from where it sits, and the design is these four:

1. **Nothing is held but a header.** The parser never buffers payload. It tracks, per direction, *where in a frame the next byte is*: at a boundary, or inside a payload with N bytes left. A header (2 to 14 bytes) is **not forwarded until it is whole and has been
   judged**: the bytes stay in the slot's read buffer (which has 16 KiB and the header at most 14), the parser answers "forward the bytes before it", and the next read completes it. This is what makes "the gateway never forwards a bad header" true and what makes
   the stream the gateway has forwarded **always end at a frame boundary or inside a payload**, never inside a header. A Close frame can therefore be appended to a write queue whenever the parser of that direction says *boundary*.
2. **A gateway frame goes between frames.** Appending to a write queue is safe exactly when everything already queued ends at a boundary. The queue holds what the parser has passed; the parser says whether that ends at a boundary; so an insertion
   is a function of the parser's state and of the room in the queue (a Close is 4 to 127 bytes, a Ping 10). Nothing is ever inserted into a frame in flight.
3. **A violation never reaches the other side.** The offending frame is not forwarded: the parser answers the number of bytes *before* it (frames before it in the same read are still forwarded) and a violation code. Where it can be seen from the header
   (everything of section 3 but the UTF-8 check and the truncation) the offending frame's first byte is the end of what was forwarded, so the stream toward the other peer is at a boundary and can still be closed with a Close frame. A UTF-8 error in the middle of
   a payload whose header went on in an earlier read cannot be undone: that stream is inside a frame, no Close can follow, and the connection is closed (the peer sees an abnormal closure, 1006, which is what a truncated frame is).
4. **No allocation, no unbounded arithmetic.** Per tunnel the state is a fixed block of 56 ints (section 11), set at the 101. Lengths are 63-bit; every sum is guarded (section 3).

## 3. The frame rules (RFC 6455 section 5)

`dir 0` is client to upstream (frames must be masked), `dir 1` is upstream to client (must not be masked). The checks run when the **header is whole** (for the checks that need only the first two bytes, as soon as those are there, so that a bad frame is judged
without waiting for bytes it may never send). In this order:

| # | check | on violation: tag, Close code |
|---|---|---|
| 1 | RSV1, RSV2, RSV3 are 0 (no extension is negotiated, because the gateway strips `Sec-WebSocket-Extensions` and refuses an upstream that answers with one: 5.2) | `ws.frame-rsv`, 1002 |
| 2 | opcode is 0, 1, 2, 8, 9 or 10 (3 to 7 and 11 to 15 are reserved: 5.2) | `ws.frame-opcode`, 1002 |
| 3 | a control frame (8 to 10) has FIN set (not fragmented) and a payload length of at most 125 (5.5); a Close of length 1 is refused too (7.1.5: the payload is empty or at least the 2-byte code) | `ws.frame-control`, 1002 (`ws.frame-close` for the Close of length 1) |
| 4 | mask bit: set on `dir 0`, clear on `dir 1` (5.1; the server must close a connection on an unmasked client frame, and a client must on a masked server frame) | `ws.frame-mask`, 1002 |
| 5 | length encoding: 7-bit values 0 to 125 are literal; 126 is followed by 2 bytes whose value must be at least 126; 127 by 8 bytes whose most significant bit is 0 and whose value must be at least 65536 (5.2: "the minimal number of bytes MUST be used to encode the length") | `ws.frame-length`, 1002 |
| 6 | continuation (opcode 0) only inside a fragmented message; a new data frame (1 or 2) only when no message is in progress (5.4) | `ws.frame-continuation` / `ws.frame-sequence`, 1002 |
| 7 | after a Close frame from a direction, no further frame from that direction (5.5.1: no data frames after a Close; the gateway extends it to every frame, the endpoint having ended its side) | `ws.frame-after-close`, 1002 |
| 8 | size: the message's bytes so far plus this frame's declared length must not exceed `ws_max_message_bytes` (section 4); compared as `length > max - so_far`, which cannot overflow because `so_far <= max` always | `ws.message-too-big`, 1009 |
| 9 | UTF-8 of text messages, while the payload goes by (section 5) | `ws.frame-utf8`, 1007 |
| 10 | end of stream (a peer's TCP close, or a reset) with a header held or a payload unfinished | `ws.frame-truncated`, no Close (nobody to send it to, or the stream is inside a frame) |

The order puts the cheapest and most certain checks first and means that one malformed frame has one tag. Check 5 is where 63-bit lengths live: the 8-byte length is assembled from its bytes only after the most significant bit is known to be 0, so
it is at most 2^63 - 1 and nothing is added to it before check 8 has compared it against `max - so_far`. Control frames are never added to a message's size.

**The fragmentation state machine** (per direction): `msgstate` 0 (no message), 1 (a text message in progress), 2 (a binary message in progress). A first frame (opcode 1 or 2) with FIN clear moves 0 to 1 or 2; a continuation moves nothing unless it has FIN set, which returns to 0; a
frame with opcode 1 or 2 and FIN set is a whole message and leaves 0. Control frames (ping, pong, close) may arrive between fragments and change nothing. Every frame's payload goes through as it arrives; `so_far` is the sum of the declared lengths of the message's frames.

**What is not checked**, and why: the Close **code** values (a peer may send 3000 to 4999 for itself and the gateway does not know which codes the endpoints use) and the **reason's** UTF-8 (a 123-byte string no one acts on); both are the endpoints'. A pong's payload is not checked either, except for the gateway's own (section 6).

## 4. `ws_max_message_bytes`

Per route, with `websocket = true` (refused otherwise, `config.websocket`): an integer from **1,024 to 268,435,456** (256 MiB), default **1,048,576** (1 MiB). It is the length of one **message**, summed over its fragments, in either direction.

- OCPP-J messages are small JSON texts: a `BootNotification` is a few hundred bytes; a `StopTransaction` with a full meter-value history, `GetConfiguration` and the largest responses seen in the field are tens of KiB. 1 MiB is two orders of magnitude over
  that and keeps the default safe for a firmware upload that goes over HTTP, not through the tunnel. **A deployment that serves only chargers should set 65,536**, which the example does; this is a recommendation from reading the protocol, not a measurement.
- The check is at the header: a frame whose declared length would take the message past the limit is refused **before any of its payload is forwarded**, so a 4 GiB frame costs the gateway one header. The earlier fragments of the same message have gone by, as they must.
- The bound exists so that `so_far + length` never has to be computed and so that "bytes of one message" fits in an int with room to spare.
- The limit applies to the gateway's view of the message: the **frame's** declared length, not the bytes seen so far. A peer that declares 1 MiB and sends 10 bytes and stops is not a size violation; it is an idle tunnel and the idle timer ends it.

## 5. UTF-8 of text messages: validated

**Decision: the gateway validates, in a streaming validator, and answers Close 1007.** The alternative (leaving it to the endpoints, as `wss` proxies commonly do) was weighed on cost and risk:

- *Cost*, **measured**: a loop in cancho that unmasks a byte (an XOR with the key byte) and steps a UTF-8 automaton over a 16 KiB buffer, 4,096 times (64 MiB), took 33 ms: **about 0.5 ms a MiB** on the reference machine, against 1.4 ms a MiB for the tunnel itself (slice 1). It is paid only on text payload; binary payload and control payload cost nothing but the O(1) skip. *Whole-system overhead is measured in section 15.*
- *Risk*: the automaton is the standard one (Unicode Table 3-7: the second byte's range depends on the first, which excludes overlong forms, surrogates and values above U+10FFFF), kept as three ints per direction (`need` continuation bytes, the `lo`/`hi` bounds of the next byte), so a character split across a read, a frame or a fragment is carried. A text message
  ends validly only with `need = 0`. It has no allocation and no loop that depends on the input's length but the one over the bytes. It is also exactly the thing a back office's JSON parser would reject later and less usefully, and 5.6 requires it of an endpoint, so
  an OCPP back office that is behind this gateway receives text it can decode.
- The state is carried across the **pong and ping frames** that interleave a fragmented message (control frames do not touch it), and reset at the first frame of each text message.
- What is *not* done: a Close frame's reason is not validated (section 3).

Because a text frame's payload must be read to be judged, the parser looks at each byte of text payload (and unmasks it to do so: `dir 0` payload is masked). The bytes it forwards are the **original, masked** bytes: the gateway does not unmask, remask, or change a byte of any frame.

## 6. Ping and pong

**Keys (deployment-wide, refused without a websocket route):** `ws_ping_ms` (0 off, the default; otherwise 1,000 to 86,400,000) and `ws_pong_ms` (default 10,000, 100 to 600,000; refused unless `ws_ping_ms` is set).

**When a Ping is sent.** The gateway sends a Ping to the **client**, never to the upstream (the upstream is the operator's own server and its liveness is the TCP connection's), when the client has been **silent for `ws_ping_ms`**: no byte read from it since
that long, a Pong included. A chatty client is never pinged: it has proved it is alive. The Ping is a final, unmasked frame with an 8-byte payload, the monotonic clock in milliseconds at which it was sent, big-endian (6 + 4 bytes: 10 bytes on the wire). It is
queued **between frames**, which is section 2 property 2: if the downstream parser is inside a payload, the Ping waits for the boundary (a large message from the back office delays a Ping; it does not split it). At most one Ping is outstanding.

**The Pong.** The client's answer is a Pong frame (opcode 10, FIN, masked, length 8) whose payload equals the Ping's payload (RFC 6455 5.5.3). When the upstream-bound parser is at a boundary and a Ping is outstanding and the next frame is such a
Pong, the gateway **consumes it**: it is read, compared (the 8 payload bytes unmasked and compared with the Ping's) and **not forwarded**. The upstream never sees the gateway's Ping or its Pong. For this the parser holds a candidate Pong's 14 bytes in the read buffer
until they are whole (section 2 property 1 already holds any header; this holds 8 bytes more, at most 14 in all) and decides. Everything else passes: a **user ping** from either endpoint and the other side's Pong (the endpoints' own keepalive) are forwarded as ordinary
frames, and a Pong that does not match the outstanding Ping's payload is forwarded (an unsolicited Pong is a legal one-way heartbeat, 5.5.3). The payload is a clock reading, so a coincidence with an endpoint's own value is a collision of 64-bit values; the cost of one
(an endpoint's Pong swallowed) would be a missed keepalive on that endpoint, not a protocol error.

**The deadline.** A Ping outstanding and **no byte read from the client for `ws_pong_ms` since the later of the Ping's time and the last byte heard**: the client is gone. The tunnel is closed as section 7 says, cause `ws.pong-timeout`, **Close 1001** to the upstream (going away: the
charger has gone) and, as a best effort, **1001** to the client (RFC 6455 gives no code for "did not answer"; 1001 says the connection is being closed because an endpoint is going away, which is what the gateway is telling the endpoint it cannot hear; **1002 is not used, because
the client broke no rule**). The gateway does **not** wait for the dead client's echo. *Why "since the later of":* a client uploading a long message cannot answer a Ping that is behind it in its own send queue; while its bytes keep coming it is alive, and the deadline counts from the last of them.

**Interaction with the idle timer.** A Pong consumed by the gateway is a byte heard from the client and **resets the idle timer** (as any byte in the tunnel does), so a client that answers pings is never idle-closed: with keepalive on, `ws_idle_timeout_ms` no longer ends a silent live charger,
`ws_max_lifetime_ms` does. This is the required behaviour ("a live one stays open past the idle timeout via pongs") and it changes what the idle timeout means; it is stated here and in the example. The gateway's own Ping does not reset it.

**What a Ping does for a dead peer, and for a NAT:** a charger that lost power or whose NAT dropped the mapping neither answers nor sends a reset; with the keepalive its slot is freed at about `ws_ping_ms + ws_pong_ms` instead of at `ws_idle_timeout_ms` (the OCPP heartbeat interval times a margin). The Ping also keeps a NAT mapping alive in the gateway-to-client direction. The detection time is a function of
`ws_ping_ms`, `ws_pong_ms` and the 250 ms the loop sleeps at most: tests measure it (section 13).

## 7. The close handshake

The gateway ends a tunnel itself for a **cause**: `ws.idle-timeout`, `ws.lifetime`, `ws.pong-timeout`, `ws.message-too-big`, or a violation of section 3. The sequence, per cause, is the same:

1. **Decide the codes** (the table below). Each side gets at most one Close frame.
2. **Stop forwarding in each direction at its next frame boundary**: the direction forwards the rest of the frame in flight (never splitting it) and then no more. Frames after the boundary are read, parsed for a Close and **discarded**.
3. **Place the Close frame** at that boundary, in the write queue toward that side (a 4-byte frame without a reason toward the client; toward the upstream the same frame masked, 8 bytes: *(corrected: the design said 4 bytes for both)* a server must not send an unmasked frame to a server, and RFC 6455 5.1 makes every frame from the gateway's side of that hop a client frame; the code is 2 bytes). If the stream toward a side is inside a frame that can never be completed (a violation in the middle of a payload on the stream the gateway
   would have to close), that side gets no Close frame.
4. **Wait for the echo, bounded**: until each side that was sent a Close has sent its own Close (or its stream ends), at most `ws_close_ms` after step 1, **which also bounds the wait for a frame boundary in step 2**. A side that caused the close (a violator) is not waited for.
5. **Close both connections.** The outcome is `aborted`, the tag is the cause, `ws_close` is the code sent to the client (or, if none, to the upstream).

| cause | Close to the client | Close to the upstream | waits for |
|---|---|---|---|
| `ws.idle-timeout`, `ws.lifetime` | 1001 | 1001 | both |
| `ws.pong-timeout` | 1001 (best effort) | 1001 | the upstream |
| client violation (`ws.frame-*`, 1002; `ws.frame-utf8`, 1007; `ws.message-too-big`, 1009) | 1002, 1007 or 1009 | 1001 | the upstream |
| upstream violation (the same rules, on `dir 1`) | 1011 | 1002, 1007 or 1009 | the client |
| the upstream or the client connection ends (a FIN, a reset) during any of this | the tunnel is over: both close |

Why a different code for the innocent side: the code tells **that** side whose fault it was. A client whose upstream broke the protocol has done nothing wrong and is told 1011 (internal error); a back office whose charger sent an invalid frame is told 1001 (going away),
not 1002, which would say the **back office** had erred. The log's `ws_close` is the client's code, so **1011 in the log means "the upstream's fault"** and 1002, 1007, 1009 mean the client's.

**When a peer sends Close**, the gateway **passes it through** (the frame is forwarded, so the other endpoint learns the code and the reason), notes that this direction has closed (check 7 of section 3 refuses frames after it), and waits at most `ws_close_ms` for the other
endpoint's Close, forwarding what that endpoint sends meanwhile (a server may send a last message before it echoes). When both Close frames have gone by and the queues are written, both connections close; the outcome is `ok`, there is no rule, `ws_close` is the first code. Past the deadline both close and the rule is `ws.close-timeout`.

**What this does not change:** a peer that closes TCP without a Close frame (a charger that loses power) ends the tunnel as in slice 1 (`ok`, bytes already read forwarded), except that bytes of an unfinished frame or a held header make the end `ws.frame-truncated`.
The gateway does not send the upstream a Close for a client's TCP end: that would be a **guess** that the client meant 1001, and it is not needed (the upstream sees the TCP close, 1006).

**TLS.** A Close frame written toward a `wss` client goes through the same write queue and the TLS engine as any bytes; `close_notify` follows it when the session ends, as for every TLS session.

## 8. The access log and the metrics

**Log.** The tunnel's line is written at the end as in slice 1; `rule` carries the cause (`ws.frame-mask`, `ws.pong-timeout`...). One new trailing key, **`"ws_close":N`**, after `upgrade` (so the order of every other key is unchanged), written **only on a tunnel that saw a Close** (one the gateway sent or the first one a
peer sent), N the code of the first Close of the tunnel (1005 if a peer's Close carried no code). The worst line still fits `accesslog.max_line` (a unit test holds it).

**Metrics.** `ws.tunnels_total` and `tunnels_active` remain. New, all counters except the last, none with a label of its own but the close code: `messages` (data messages whose final frame header was forwarded, both directions), `pings` (gateway Pings sent), `pong_timeouts`, and `closes` by code: 1000, 1001, 1002, 1007, 1008,
1009, 1011 and `other` (the first Close of each tunnel; the label set is closed). JSON: `"ws":{"tunnels_total":…,"tunnels_active":…,"messages":…,"pings":…,"pong_timeouts":…,"closes":{"1000":…,…,"other":…}}`; Prometheus: `ws_messages_total`,
`ws_pings_total`, `ws_pong_timeouts_total`, `ws_closes_total{code=…}`. Every rule of section 3 and 7 is also a tag in `refusals_total` (tags the code owns; the table of 96 has room, section 15 counts). Frames and bytes are **not** counted per frame: `bytes_in` and `bytes_out` of the route already are.

## 9. Interaction with the other parts

- **TLS (`wss`).** The parser reads the plaintext the TLS engine hands over (the client's read buffer after decryption) and the plaintext the upstream sent; it writes into the queues that the engine then encrypts. The only change on that path is that `tunnel_up` and `tunnel_down` call the parser.
- **Back-pressure.** The parser is applied to the bytes the loop is about to move, which are at most the sink's room. A header cut by the room is simply held (property 1); a payload run cut by the room is continued on the next call, since the parser state is the remaining count. A Close
  or a Ping is placed only if the queue has room for it; otherwise the tunnel waits for the flush, as for any byte.
- **Rate limiting and authentication.** Unchanged: they judge the upgrade request and nothing after it (`docs/ratelimit.md`, `docs/auth.md`). There is **no per-message rate limit** in this slice.
- **Timers.** The idle timer is reset by bytes moved or heard, as before, plus a consumed Pong. The lifetime is unchanged. `ws_close_ms` is a third clock, started when the gateway starts a close or sees a peer's Close.
- **The pool and the circuit:** unchanged (a tunnel's connection is never pooled, a tunnel that ends is not a failure of the upstream).

## 10. Deployment keys

Per route (refused without `websocket = true`, tag `config.websocket`): **`ws_max_message_bytes`**, 1,024 to 268,435,456, default 1,048,576.
Deployment-wide (refused without a `websocket` route): **`ws_ping_ms`** (0 or 1,000 to 86,400,000, default 0), **`ws_pong_ms`** (100 to 600,000, default 10,000; refused without `ws_ping_ms`), **`ws_close_ms`** (100 to 60,000, default 5,000).
Every refusal has the tag `config.websocket` and a line number; `tests/generate_test.py` has a case for each (section 13 gate 8).

## 11. Memory

A tunnel's frame state is **56 ints (448 bytes)**: 16 for the tunnel (close state, deadlines, codes, the ping) and 20 for each direction (mode, remaining payload, opcode, mask key and its phase, message state and size, the three UTF-8 ints, the Close code, the event the last scan reported).
It is a new slab, **256 slots x 56 ints = 112 KiB**, allocated at start with the other slabs and indexed by the client's slot (the table is 256 slots). It is not a growth of the slot stride (48 ints, of which 40 to 47 are the tunnel's and the TLS's): growing the stride would grow every slot's state, including the upstream
slots, for a field only 127 clients can use. Nothing is allocated after start. **Unknown** *(measured in section 15)*: the resident size at start and with 120 tunnels, against 2.2 MiB and 4.6 MiB for slice 1.

## 12. CPU

The parser touches **headers** and **text payload** byte by byte; every other payload byte is skipped by arithmetic (`min(remaining, available)`). A binary tunnel therefore costs the same as slice 1 plus a call per read; a text tunnel costs the 0.5 ms a MiB of section 5 more. One thread: the cost adds to everything else.
**Measured in section 15** against the slice-1 tunnel (1.4 ms a MiB downstream on the reference machine).

## 13. Gates, fixed before the code; each must be able to fail

1. **A cancho unit test of the state machine** (`tests/wsframe_test.cho`): a corpus of valid streams (every length class, fragmented, interleaved control frames, a Close) and of invalid ones (every row of section 3); each valid stream fed in **every split** (all pairs of cut points of the shortest, all single cuts of the longest), 1 byte at a time, and whole,
   with the forwarded bytes concatenated equal to the stream and the final state equal across splits; each invalid one giving the same rule at every split; **random streams** (several thousand, a fixed seed in the test) never trapping, never reporting a forward count over the available bytes, and always either consuming everything or stopping at a held header or a reported event.
2. **End to end with a Python RFC 6455 endpoint and client written for the test from the RFC** (`tests/wsframes_test.py`): every violation of section 3, each producing the documented Close code **on the right side**, the documented tag in the log, and **nothing of the offending frame at the other side**; truncated frames then EOF; valid traffic byte-for-byte unchanged when fed in 1-byte pieces, random pieces and whole.
3. **Size and back-pressure:** messages of 1 MiB, 8 MiB and 32 MiB through a route whose limit admits them, with slow readers, byte for byte; a message one byte over the limit, fragmented and whole, closed 1009 with the earlier fragments delivered and the frame that crosses the limit not.
4. **UTF-8:** valid multi-byte text split at every position across reads and across fragments with pings interleaved; each class of invalid sequence (overlong, surrogate, over U+10FFFF, a stray continuation, a truncated sequence at the end of the message, a truncated sequence at a fragment boundary that is not the end) closed 1007.
5. **Ping and pong:** a dead client (stops answering) is closed at the pong deadline with `ws.pong-timeout`; a live one stays open past the idle timeout through pongs; the upstream never sees a gateway Ping or its Pong; a user ping from each endpoint passes in both directions, and a user Pong too; a ping in the middle of a fragmented message.
6. **Close:** a timer close sends a Close at a frame boundary **even when a large message is in flight in either direction when the lifetime expires** (the Close must not split a frame in flight); a peer's Close is passed through and the answer is passed back; a peer that never answers is closed at `ws_close_ms`; the log's `ws_close` and the counters.
7. **Third party:** the `websockets` library (17.2) as client and as upstream, plain and TLS, valid traffic of every kind, a message over the limit, a ping and a close; skipped without the library.
8. **Generator:** one test for each new refusal, counts updated; `deploy/examples/ocpp.toml` carries the keys.
9. **Mutants** of the new code, single edits, targeted tests, the table recorded in section 15.
10. **The authority report does not change**; no source file over 2,000 lines; the existing suites pass, with the tests that sent frames the new rules refuse (slice 1 sent random bytes through a tunnel) changed to say so.

## 14. Not done, and what a next slice could be

| not done | why / what it would take |
|---|---|
| `permessage-deflate` and other extensions | stripped at the request (slice 1); with RSV bits judged here an extension would need the parser to know its framing: a decision for its own slice, and `ws_max_message_bytes` would have to bound the *inflated* size |
| **OCPP-J message validation** | out of scope. A next slice could read the first bytes of a **text message** (`[2,"<unique id>","Action",{...}]` and the `3` and `4` shapes): check the message type id and that the unique id is a string of at most 36 characters, and refuse a Call over the route's limit by its action; it would need to hold the first ~60 bytes of a message (a bounded prefix, the same trick as the header) and would not need a JSON parser; a JSON-schema check would need one |
| per-message rate limiting | a token bucket per tunnel keyed on messages, using the parser's message count; the buckets exist (`docs/ratelimit.md`) but are per request, not per tunnel |
| a binary versus text policy | `ws_binary = false` per route would refuse opcode 2 at the header (OCPP-J is text only); trivial given the parser, not asked |
| a reason string and code validation in Close | left to the endpoints (section 3) |
| a gateway Close on a client's TCP end | would be a guess (section 7) |
| thousands of tunnels | the slot table (slice 1 section 9); unchanged |

## 15. As built

Built 2026-10-12 on a branch of its own, against the pinned compiler (`2fcf4cd`). Everything below was run on the development machine (one core shared with the test processes; CI will differ in timing).

**What exists.**

- *`src/wsframe.cho`* (pure, no effect): the parser `scan`, the close plan `begin_close`, the keepalive clock (`ping_due`, `pong_expired`), the gateway's own frames (`put_close`, `put_close_masked`, `put_ping`), the rule tags. The state is 56 ints per client slot in a new slab, `Core.wsf`, of `256 x 56` ints (112 KiB).
- *The tunnel* (`src/proxy.cho`, 1,925 lines; `scripts/lines.py` passes): `tunnel_pump` (one direction, written once for both), `tunnel_run`, `tunnel_mark`, `tunnel_close`; the old `tunnel_down` / `tunnel_up` are thin callers. The sweep closes with a Close frame instead of dropping, Pings a silent client and watches the pong deadline.
- *Keys* (`scripts/generate.py`, tag `config.websocket`): per route `ws_max_message_bytes`; deployment-wide `ws_ping_ms`, `ws_pong_ms`, `ws_close_ms`. The route table has one more column (22); `generated/deploy.cho` has `ws_ping_ms`, `ws_pong_ms`, `ws_close_ms`.
- *Log and metrics:* `line_full` (`ws_close` last), `metrics.ws_messages`, `ws_pinged`, `ws_pong_timeout`, `ws_closed` (twelve more ints after the TLS block). `accesslog.max_line` went from 768 to 784 (the worst line with an identity and a close code was 769).
- *Tests:* `tests/wsframe_test.cho` (21 cancho tests), `tests/wsframes_test.py` (25 end-to-end tests), `tests/wsframes_mutants.py`, `tests/wsframes_bench.py`; 36 generator cases (refusals and acceptances) for the new keys; 1 metrics test, 1 log-line test. `tests/websocket_test.py` changed where slice 1's behaviour was a byte tunnel (below).

**Where the build found the design wrong or incomplete** *(corrected in place above where it mattered)*:

| design | built | why |
|---|---|---|
| section 7: the Close the gateway writes is "4 bytes" | 4 bytes toward the client, **8 toward the upstream** (a masked frame, key of four zero bytes) | a Close toward the upstream is a *client* frame and must be masked (RFC 6455 5.1); the first runs sent an unmasked one |
| section 7: both sides get a Close | a direction that has already carried a Close frame (the peer's, passed through) gets **no second one** | two Close frames in one direction is itself a violation; found by the `frame after Close` case |
| section 7, step 5: close both connections after the echo | after a violation **by the client**, the client **lingers** (input read and discarded, 0.5 s of silence, 3 s at most) before the connection is closed | closing a socket with unread input resets the connection, which can destroy the Close frame in flight to it; a client still sending a 6 MiB frame at the moment of the refusal lost its Close (test `a_client_that_is_still_sending...`; mutant c15) |
| section 7: the end of a side while closing ends the tunnel | it marks that side finished and the other is still waited for; **bytes of a frame in flight are not discarded** | the first version dropped the 32 MiB frame the upstream had sent when the upstream then closed its end after echoing the Close; mutant c14 |
| section 3, check 5 judged "when the header is whole" | judged as soon as the length bytes are there (before the mask key) | found by the case table: a non-minimal length is refused one read earlier |
| section 13 gate 10: "tests that sent frames the new rules refuse are changed" | `bytes_that_are_not_frames_cross_a_tunnel_unchanged` became `..._do_not_cross_a_tunnel`; the tests that read an idle or lifetime close now read the Close frame (1001) | slice 1 delivered 3 MiB of junk exactly; slice 2 answers Close 1002 and the upstream sees only the gateway's 8-byte Close |
| section 5: "the conservative position wins if cost is high" | UTF-8 **validated**; the cost measured below is about 3 ms a MiB of text | the micro-benchmark said 0.5 ms a MiB; the real loop is six times that, still small against OCPP messages of a few hundred bytes |
| the metrics' rule table of 96 | **not enlarged**; the 14 new tags join it | the table already could not hold every TLS engine tag (43) beside the gateway's own (about 80): a hostile TLS client can fill it with engine tags and a later `ws.*` tag is then counted under `other` (the log line keeps the tag). A known limit, recorded here, not new |

Violations seen in the middle of a payload: only UTF-8 (the size is judged at headers). For those the stream toward the other peer is inside a frame, no Close can follow it, and the connection is closed after the Close to the offender (`a_violation_inside_a_payload...`: the upstream receives the valid bytes and then the end of the stream).

**Gates.**

| gate | status | where |
|---|---|---|
| 1 state machine, every split, random streams | **met** | `wsframe_test.cho`: every valid corpus stream in every pair of cut points (the shortest) or every fifth/seventh (the longest) and byte by byte, the same final state; every refusal at every split with the same rule; 3,000 random byte and random-frame streams and 1,500 random valid streams (text cut inside characters, pings between fragments) in random pieces: none traps, none is answered more than given, an answer short of the data always has a reason (a held header) |
| 2 every violation, right Close code on the right side, nothing garbage at the other side | **met** | `wsframes_test.py`: 40 client cases (reserved bits x3, reserved opcodes x4, control frames x5, a Close of one byte, an unmasked frame, lengths x6, continuation and sequence x5, size x4, UTF-8 x11) and 18 upstream cases; the upstream's received bytes are compared **for equality** with the valid frames plus the gateway's masked Close; the client's with the valid frames plus `88 02 03 f3`; truncated frames then end of stream (payload, header, key, half a length; both directions); a violation inside a payload |
| valid traffic unchanged across deliveries | **met** | whole, one byte at a time and random pieces of 1 to 59 bytes, both directions, compared byte for byte (`valid_traffic_is_unchanged_in_any_delivery`) |
| 3 sizes and back-pressure | **met** | 1, 8 and 32 MiB echoed with a reader a second late and a 64 KiB receive buffer; 8 MiB in 64 KiB fragments; exactly the limit passes, one byte more is 1009; fragments counted together |
| 4 UTF-8 | **met** | invalid classes at three positions each (whole frame, first fragment, last fragment), a character split across reads and fragments with pings between at every byte |
| 5 ping and pong | **met** | a dead client is closed at 2.1 s (ping at 1 s, 0.8 s to answer; asserted between 1.5 and 3.2); a live one answers its Pings for 6.5 s with an idle time of 2.5 s and stays; the upstream's frames are exactly its own (no Ping, no gateway Pong); user pings and pongs pass both ways; a Ping due while 8 MiB is in flight arrives after the frame; a chatty client is not Pinged, a silent one that ignores the Ping but then sends is not closed |
| 6 close | **met** | the lifetime ends with 32 MiB in flight toward the client (read slowly: 4.3 s) and with 32 MiB in flight toward the upstream (drained at 1 MiB per 0.1 s): both frames arrive intact, then the Close; a peer's Close is passed through and its answer; a peer that never answers is closed at `ws_close_ms` (`ws.close-timeout`); the counters |
| 7 third party | **met** | `websockets` 17.2 as a client (text, 300 kB binary, ping, close 1000, a 5,000-byte message over a 4,096 limit answered 1009), plain and over TLS. *As an upstream behind the gateway* it served every one of those tests (the route `lib*` points at it); a message it sends over the limit was not tested (it only echoes) |
| 8 generator | **met** | 36 new cases |
| 9 mutants | **66 new + 75 of slice 1: 138 killed, 3 argued** *(the 3 are slice 1's)* | below |
| 10 authority and the suites | **met** | labels unchanged; `manifests/` re-recorded (function counts only); no file over 2,000 lines |

**Measured** *(one machine, the gateway's CPU from `/proc`, 256 MiB each way, median of three, slice 1 and slice 2 built from the same deployment, `tests/wsframes_bench.py`)*:

| traffic | slice 1 (bytes) | slice 2 (frames) | ratio |
|---|---|---|---|
| upstream to client, 8 MiB binary frames | 1.56 ms/MiB | 1.64 ms/MiB | 1.05 |
| upstream to client, 64 KiB text frames | 1.72 | 4.53 | 2.64 |
| upstream to client, 100-byte text frames | 1.48 | 5.04 | 3.39 |
| client to upstream, 8 MiB binary frames (masked) | 1.84 | 1.84 | 1.00 |
| client to upstream, 64 KiB text frames | 1.76 | 5.23 | 2.98 |
| client to upstream, 100-byte text frames | 1.99 | 5.62 | 2.82 |

*Binary payload costs nothing* (the parser skips it by arithmetic). *Text costs about 3 ms a MiB more*: six times the micro-benchmark of section 5 (0.5 ms), whose loop kept the automaton in locals; the real one keeps it in the state array and handles the unmasking, the Close code and the bounds per byte. An OCPP message of 300 bytes costs the gateway about a microsecond more. **One core**: a deployment moving 100 MiB/s of *text* would spend 0.3 of it on the parser; OCPP traffic is orders of magnitude below that. *Memory:* resident 1.94 MiB at start (slice 1) against 2.07 MiB (slice 2: the `wsf` slab, touched when a tunnel starts); 60 tunnels with traffic: 2.96 MiB in both; unchanged after they close. *Latency* was not re-measured.

**Mutants** (`python3 tests/wsframes_mutants.py`: copy the tree, apply one edit, run the tests that should notice it, then the whole suite if they do not). **66 edits, 66 killed.** Two were first written wrongly (a27, c23: the old text had been reformatted, a killer test did not exist in this suite) and corrected; one (c15, no lingering) first **survived** because no test sent while being refused, and was killed after `a_client_that_is_still_sending...` was added. The classes: every row of section 3 removed (a01 to a13), the limit (a14 to a16), the UTF-8 automaton's every range (a17 to a24), the Close code, the Pong recognition and compare (a25 to a27), the stop at a boundary and the held header (a28, a29), the close plan's codes and the second-Close rule (a30 to a33), the keepalive clock (a34, a35), the parser's state after a refusal (a36), the tunnel (c01 to c27: unmasked Close, no boundary wait, Ping inside a frame, Pong forwarded or not resetting the idle timer, the client's clock, deadline and Ping removed, violation ignored, Close code and wait not kept, truncation untagged, in-flight bytes discarded, no lingering, counters, limit unread, column off by one, log field, outcome), the generator (g01 to g04). **Slice 1's 75 mutants were re-run** after the tunnel was rewritten: ten had to be rewritten to the new code (the tunnel is one function for both directions: p09 to p17, p22, p25), then **72 killed, 3 survive for the same reasons as before** (r08, p20, p29: section 13 of `docs/websocket.md`; p29 is now "read_client does not call tunnel_up", still equivalent).

**Counts, verbatim from the last full run:**

`wsframes_test.py`: `25 tests, 0 failures` (the two interop-library tests included; without `websockets`, 2 skipped). `websocket_test.py`: `55 tests, 0 failures`. `proxy_test.py`, three runs: `77 tests, 0 failures` each. `admin_test.py`: `16 tests, 0 failures`. `tls_test.py`: `22 tests, 0 failures`. `ratelimit_test.py`: `16 tests, 0 failures`. `auth_test.py`: `14 tests, 0 failures`. `generate_test.py`: `7 prefix cases, 376 refusal cases, 57 accepted, 0 failures`. `cancho test`: 14 suites, 204 tests, 0 failed (wsframe 21). After merging the JWT work (`origin/main` `5aeb220`): `jwt_test.py` `16 tests, 0 failures`, `jwt_differential.py 1500`: `0 disagreements`, `jwt_vectors.py --check` ok. `route_test.py 12 400`: `12 tables, 4800 requests (1356 routed, 3444 refused), 0 failures`; `--fixed`: `18 fixed cases, 0 failures`. `response/run.py`: `55 cases, 0 failures`. `smuggling/run.py --gateway`: `67 cases, 0 disagreements`; `--prefixes`: `2815 prefixes checked, 0 failures`; `--chunked`: `43 chunked cases x 6 deliveries = 258 runs, 0 failures`; `--fuzz 1500`: `1500 fuzzed heads, 31 accepted, 0 failures`. `check_site.py`, `figures.py --check`, `proof.py --check`, `authority.py --check`, `authority_test.py`, `lines.py`, `cancho fmt --check src tests generated` and both `generate.py --check`: pass. The `headers/differential.py` run (needs nginx) was not run here.

**Not done, and not known.**

- **The JWT work** was merged afterwards (see the report). The merge touched the same route-table column list (this slice's column was 22 and moved to 26 in the merge), `src/metrics.cho` (`worst_case`, the route block), `generate.py`, the log (`identity` comes before `ws_close`) and the evidence pages.
- **Not measured:** latency through the parser; hundreds of tunnels with this slice (60 with traffic here, 120 in slice 1); the benchmark harness; a browser.
- **A Close frame's reason and code values** are not validated (section 3).
- **Close 1008 (policy violation) is never sent** (the metrics label exists for a peer's); per-message rate limiting, a binary versus text policy and OCPP validation are section 14.
- **A violation by a peer during a close** is only counted as the end of that side (no second tag).
- **The gateway Ping's 8-byte payload is its clock reading**: a peer's own Pong with the same value would be swallowed (section 6).
