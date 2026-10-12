# OCPP-J message validation at the gateway (task #15, slice 3)

Status: **design, written before the code (2026-10-12).** Sections 1 to 10 are the decision and the gates of section 9 are fixed now and must be able to fail. Section 11 (as built, measured, mutants) is written
after the build and corrects, in place and marked *(corrected)*, whatever the build finds false. Claims about cancho are about the pinned compiler (`cancho.toml`, `2fcf4cd`). A claim that is not measured is marked **unknown**.

Slice 2 (`docs/websocket-frames.md`) reads the frames of a tunnel and validates RFC 6455 and the UTF-8 of text. It says in its section 14 that a next slice "could read the first bytes of a text message" and "would not need a JSON parser". This
slice does the larger thing and decides, below, why. The use case is unchanged: chargers on `ws`/`wss` talking OCPP-J to a back office; the gateway is the edge that refuses what is not OCPP-J before the back office's parser sees it.

## 1. Scope

**Built in this slice**

- A per-route key, `ws_ocpp`, that turns on **OCPP-J frame validation**: every complete text message, in both directions of the tunnel, must be a well-formed OCPP-J frame (section 3).
- A **streaming recogniser** (one per direction per tunnel, eight ints, no buffer) that reads the message byte by byte as it goes by, after reassembly of its fragments (section 4).
- Refusals with a rule tag each (`ws.ocpp-*`), a Close frame (1007 for a message that is not a well-formed frame, 1008 for a message the route's policy refuses), a counter in the metrics (section 6).
- Generator validation of the key, each refusal tagged and tested (section 7).

**Not in this slice**, said once (section 10 expands, and "what is NOT validated" is section 5): action names against a list, payloads against JSON schema, uniqueId correlation, OCPP 2.1 (message types 5 and 6), the CALLERROR code against the specification's
table, duplicate member names, any rule that needs a conversation rather than a message.

**What stays exactly as slice 2:** the frame parser and every rule of its section 3, `ws_max_message_bytes`, the UTF-8 check (it runs on the same byte first), ping and pong, the close handshake and its wait, the handshake and subprotocol negotiation, authentication
and rate limiting. A route without `ws_ocpp` behaves byte for byte as before: the recogniser is not called.

## 2. The decision: a streaming recogniser, not a prefix check, not a buffered parse

Three designs were weighed against the properties this gateway keeps (bounded memory, nothing held but a header, an auditable function):

| design | memory | what it validates | what it costs |
|---|---|---|---|
| **A. a prefix check** (slice 2's suggestion): hold the first ~60 bytes of a message, check `[`, type id, unique id | 60 bytes a direction | the first elements only; the payload could be anything, even not JSON | a held prefix in the read buffer, interacting with the held header and the Pong candidate (14 bytes) |
| **B. buffer the whole message and parse it with `std.json`** (the `json_claims` way) | up to `ws_max_message_bytes` per direction per tunnel: at the recommended 65,536, 127 tunnels x 2 x 64 KiB = **16 MiB**; at the default 1 MiB, **254 MiB** | everything `std.json` and `json_claims` know (and a tape of ints on top) | the slot's buffers are 16 KiB and the queue 32 KiB: holding a message means a new buffer per tunnel and a back-pressure rule for "a message not yet complete", which today does not exist (a direction forwards as it reads); the tunnel loop changes shape |
| **C. a streaming recogniser** over the bytes the parser already looks at | **8 ints a direction (64 bytes)**, nothing else; the `ws` state block grows from 56 to 72 ints (448 to 576 bytes a tunnel; the slab from 112 to 144 KiB) | the whole grammar of an OCPP-J frame *and* well-formed JSON in the payload, with a bound on nesting | one more step per byte of text (measured in section 11); no new allocation; the tunnel loop does not change |

**Decision: C.** The reasons, in order: (1) memory is bounded by construction, not by a limit an operator must set; (2) the parser already walks every text byte (to unmask it and to run the UTF-8 automaton), so the recogniser is one more state step in a loop that exists, and the
tunnel's forwarding model (bytes go on as they are judged) is untouched; (3) the grammar is small enough to audit as one function (section 4) and to test against `json.loads` on every split.

**Why not `json_claims`/`std.json`.** They parse a *whole document held in memory* into a tape. That is design B, and it is the right tool for a JWT of 1 KiB (`docs/jwt.md`); it is the wrong one for a tunnel that lives for days and may carry a message of any size up to the limit. `json_claims.depth_of` (the
nesting bound) is reused **as an idea**, not as code: the recogniser counts depth itself, in a bit stack.

**What C cannot do, and it must be said plainly.** The gateway forwards a message's bytes *as it validates them*. A message that is bad in the middle has had its earlier bytes forwarded **if they were in an earlier read than the byte that is bad**. Two cases:

1. **The frame's header and the byte that breaks a rule are in the same read** (every OCPP message of a few hundred bytes arriving in one TCP segment: the usual case). The parser answers "forward the bytes before this frame": **the offending frame, its header and all, never reaches the other side**, and the stream
   toward it ends at a frame boundary, so the Close frame can follow. This is the same mechanism as every other violation of slice 2.
2. **The bad byte comes in a later read than the frame's header** (a large message, or a segmented one). The earlier bytes have gone on; the other side sees a frame that never completes. That stream is inside a frame, **no Close can follow it**, and the connection is closed after the Close to the
   offender: the same outcome as slice 2's UTF-8 error in the middle of a payload (`docs/websocket-frames.md` section 2 property 3). A back office behind this gateway must therefore still treat its own parser's errors as errors; **the gateway reduces what reaches it, it does not give a guarantee** that a rejected message was never partly delivered.

A message fragmented over several frames (RFC 6455 section 5.4) is reassembled in the only sense the recogniser needs: its state is carried from one frame to the next; control frames between the fragments do not touch it.

## 3. What a valid message is

`ws_ocpp` is set on a route: every text message in either direction must match this grammar exactly; the first byte that cannot continue a match is the violation. **Notation:** *ws* is any run of space, tab, CR, LF; JSON is RFC 8259.

```
message  = ws "[" ws element-0 ws "," ws element-1 ws "," ws ... ws "]" ws          (the elements by type, below)
type 2   CALL         [2, uniqueId, action,  payload]                                 4 elements
type 3   CALLRESULT   [3, uniqueId, payload]                                          3 elements
type 4   CALLERROR    [4, uniqueId, errorCode, errorDescription, errorDetails]        5 elements

MessageTypeId   the single digit 2, 3 or 4 as a JSON number token ("2.0", "02", 2e0, "2" are refused)
uniqueId        a JSON string of 1 to 36 characters, each a byte from 0x20 to 0x7E other than " and \   (no escape, no non-ASCII: section 5)
action          a JSON string of 1 to 64 characters, each A-Z, a-z or 0-9
errorCode       the same grammar as action
errorDescription any JSON string (escapes and UTF-8 allowed; its length is bounded by ws_max_message_bytes only)
payload, errorDetails   a JSON object whose every value is well-formed JSON, nested at most 32 levels deep (the payload's own braces are level 1)
```

The refusals, one tag each, by the first byte that breaks the grammar. The Close code says what kind of refusal: **1007** (invalid payload data: the text is not an OCPP-J frame, RFC 6455 7.4.1) when the message is malformed, **1008** (policy violation) when it is a thing this route's
policy refuses and the bytes might be well-formed.

| tag | rule | Close |
|---|---|---|
| `ws.ocpp-binary` | a binary message (opcode 2) on an OCPP route: OCPP-J is text; judged at the frame header, so it is always at a boundary | 1008 |
| `ws.ocpp-json` | not a JSON array where the message begins; a byte that is not JSON where JSON is expected (including inside the payload: a missing colon, a bare word, a bad escape, a control character in a string, a malformed number); bytes after the closing `]`; a message that ends before the `]` (including an empty one) | 1007 |
| `ws.ocpp-type` | element 0 is not the digit 2, 3 or 4 | 1007 |
| `ws.ocpp-arity` | the closing `]` where another element is due (too few), or a `,` after the last (too many) | 1007 |
| `ws.ocpp-id` | element 1 is not a string of the grammar above (a number, an empty string, 37 characters, an escape, a non-ASCII byte) | 1007 |
| `ws.ocpp-action` | a CALL's element 2 is not a string of the action grammar | 1007 |
| `ws.ocpp-payload` | the payload (CALL element 3, CALLRESULT element 2) or the CALLERROR details (element 4) is not an object | 1007 |
| `ws.ocpp-code` | a CALLERROR's element 2 is not a string of the action grammar, or element 3 is not a string | 1007 |
| `ws.ocpp-depth` | nesting past 32 levels: **the gateway's own bound**, which a well-formed document can exceed | 1008 |

The order of checks is the order of the bytes: the first byte that cannot be part of a valid message decides the tag. One malformed message has one tag. The UTF-8 check of slice 2 runs on each byte before the recogniser sees it, so an invalid UTF-8 byte is `ws.frame-utf8` (1007) even where the recogniser
would also have refused it. The Close code goes to the offending side and **1011 or 1001 to the other** by slice 2's table (section 7 there): a back office that sends a malformed frame is closed on, and its charger is told 1011.

**Version and the key.** `ws_ocpp` is `"1.6"`, `"2.0.1"` or a list of them (`["1.6", "2.0.1"]`). The route's `subprotocols` must be **exactly** the matching `ocpp1.6` / `ocpp2.0.1` tokens (so the handshake of `docs/websocket.md` already refuses a client that offers none and an
upstream that answers another). The frame grammar above is **the same in both versions**: CALL, CALLRESULT and CALLERROR have the same shape in OCPP 1.6J and 2.0.1; what differs is the actions and the payloads, which this slice does not read. The key therefore pins the subprotocol and
names the grammar; a later version with other message types (2.1 adds 5 and 6) is a new value of the same key, not a new key.

## 4. The recogniser

A state machine over the **unmasked** bytes of a text message, stepped by `wsframe.scan` beside the UTF-8 automaton, in `src/ocppframe.cho` (a new module, pure, no effect, no allocation; `wsframe.cho` is 663 lines and the 2,000-line ceiling is not near, but the grammar is a concern of its own).

**State per direction (eight ints, offsets 20 to 27 of the direction's block):** 20 the position in the grammar (below); 21 the nesting stack (one bit per level, 1 an object); 22 the depth; 23 a counter (the characters of a restricted string so far, or the hex digits of a `\u` still due); 24 the message type (0 not yet read); 25 the index of the element in hand; 26 1 if the string in hand is an object member's name; 27 1 if the direction is validated at all (set when the tunnel starts, from the route; 0 and the recogniser is never called). The ints 20 to 26 are reset at the first frame of each text message.

**Positions.** *Frame level*: before the `[`; at the start of an element (whitespace is skipped); the digit of the type read; between elements (a `,` or the `]` is due); after the `]`. *Restricted strings* (id, action, code): inside, counting. *JSON values* (inside a payload): a value is due; just
after `[` (a value or `]`); between array items; just after `{` (a name or `}`); a name is due (after a `,`); a `:` is due; between members; inside a string, after a `\`, inside the four hex digits of a `\u`; each position of a number (after `-`, after a leading 0, in the integer part, after `.`, in the fraction,
after `e`, after the exponent's sign, in the exponent); each position inside `true`, `false` and `null`. About forty positions in all, and a function of one byte: `step(state, c)` answers the next state or a refusal. A number ends at the first byte that is not part of it; that byte is then read again as
the byte after a value (one re-read, bounded). Depth is checked when a container opens, so the stack cannot overflow its 32 bits.

**At the end of a message** (the FIN frame's last byte, or an empty FIN frame) the position must be *after the `]`*; anything else is `ws.ocpp-json` (truncated). A message that is binary is refused at its header.

**Cost per byte:** one comparison of the byte against the position and an update of the array; measured in section 11. **Memory:** nothing is allocated; the block of the tunnel grows by 16 ints (72 in all). **No input may reach a panic:** every index is a constant or a bounded counter, the stack is shifted by one bit
per level and never more than 32 levels, and the random-stream test of section 9 runs thousands of byte streams through every state.

## 5. What is NOT validated

Said once, and again in the examples and `AGENTS`-style summaries. This slice checks the **shape of a frame**; it does not make the gateway an OCPP endpoint.

- **The action is not checked against a list.** `"Foo"` is a well-formed action; so is an action of the other protocol version, a vendor extension (`DataTransfer` carries those inside its payload, but a vendor may also invent an action) or a typo. The reason is the one the brief gave: an allow-list is either a table in the binary per
  version (about 28 actions for 1.6, 64 for 2.0.1, which the gateway would have to keep correct) or one more deployment key that every operator must keep right; the length and character bound keeps what the gateway holds fixed and auditable. A per-route action list is a possible next slice (section 10).
- **The payload is not checked against the message's JSON schema**: not its fields, not their types, not their ranges. Only that it is well-formed JSON in an object, at most 32 deep.
- **uniqueId correlation**: that a CALLRESULT answers a CALL that is outstanding, that ids do not repeat, that a charger has at most one outstanding CALL: those are conversation rules and the gateway holds no table.
- **Direction**: a CALL of an action only a back office may send, arriving from a charger, is well-formed.
- **The CALLERROR code against the specification's table**: only its grammar (the specification's list differs between versions and the gateway does not claim to know it).
- **Duplicate member names in an object** and **numbers' magnitude** (`1e999` is well-formed JSON), and **a `\u` escape that is a lone surrogate** (the JSON grammar allows it; a decoder may not).
- **OCPP 2.1** (message types 5, CALLRESULTERROR, and 6, SEND): refused as `ws.ocpp-type`, because `ws_ocpp` names no 2.1 grammar.
- **Stricter than the specification, on purpose**: the id may not hold an escape or a non-ASCII byte and may not be empty; the action and code are letters and digits only. The specification calls the id a string of at most 36 characters; a charger that sends an id with an escape or an accented letter is refused here, and a charger that
  sends an empty id too. *This is a decision from reading the protocol and the fleets' habit of UUIDs and counters, not a measurement of a fleet; unknown whether any real charger does it.* The cost of being wrong is a refused charger; it is for the operator to turn `ws_ocpp` off for that route.
- **Whitespace** between the tokens is accepted (it is JSON), so `[ 2 , "a" , "B" , { } ]` is valid; what the gateway forwards is always the original bytes.
- **The message after a refusal is not looked at**: a tunnel is closed at the first violation.
- **That a message was not partly delivered**: section 2 says when it was.

## 6. The log, the metrics

**Log.** A refusal is the tunnel's `rule` (`ws.ocpp-id`...), as every other cause; `ws_close` is the code the client got (1007, 1008, or 1011 when the upstream was the offender). No new key, so no new line length.

**Metrics.** One new counter, **`ocpp_violations`** (JSON `"ws":{...,"pong_timeouts":N,"ocpp_violations":N,"closes":{...}}`; Prometheus `ws_ocpp_violations_total`): tunnels the gateway closed for one of the nine rules, either direction. It is a counter of its own because the per-rule `refusals_total` table (96 names) can fill with
TLS engine tags (`docs/websocket-frames.md` section 15) and then count a later `ws.ocpp-*` as `other`; this one cannot be lost. The nine tags are also in `refusals_total` like every other rule. The metrics block grows by one int.

## 7. Deployment key

Per route, refused without `websocket = true` (tag **`config.websocket`**, with the line): **`ws_ocpp`**, a string `"1.6"` or `"2.0.1"`, or a list of one or both, distinct. And the route's `subprotocols` must be exactly the set `{"ocpp" + v}`; otherwise `config.websocket` names both keys. Refusals tested (`tests/generate_test.py`): a
number, a boolean, an empty list, an empty string, `"1.5"`, `"2.1"`, `"ocpp1.6"` (the token, not the version), a duplicate, a list of three, a non-string in a list, `ws_ocpp` without `websocket`, no `subprotocols`, `subprotocols` with another token, with an extra one, with a missing one. The route table gets one more column (27):
a bitmask, 1 for 1.6, 2 for 2.0.1, 0 for none; `--explain` says what each route validates. `deploy/examples/ocpp.toml` sets it.

## 8. Interaction with the other parts

- **Upgrade, authentication, rate limits, the pool and the circuit**: unchanged; they judge the upgrade.
- **`ws_max_message_bytes`**: unchanged and still the bound on a message; the recogniser adds no length bound of its own beyond the id, the action and the nesting.
- **Ping, Pong, Close**: control frames carry no OCPP and are not looked at by the recogniser; the Pong candidate and the held header are unchanged.
- **A fragmented message**: the recogniser's state is carried across the fragments and across control frames.
- **A route without `ws_ocpp`**: `scan` is given 0 and the recogniser is never called, so the bytes, the state and the cost are slice 2's.

## 9. Gates, fixed before the code; each must be able to fail

1. **A cancho unit test of the recogniser** (`tests/ocppframe_test.cho`, and the parser's cases in `tests/wsframe_test.cho`): a corpus of valid messages (every message type, whitespace everywhere it is allowed, every JSON value kind, nesting at 32, a 36-character id, a 64-character action, escapes and UTF-8 in a description) fed through `wsframe.scan` **in every split** (all pairs of cut points
   of the shortest, a stride of the longest), byte by byte, and whole, with the final state the same; each invalid one giving the same rule at every split; every row of section 3's table; **random streams** (several thousand, a fixed seed): never trapping, never answering more than given.
2. **A differential against Python's `json.loads` and a reference of the grammar written separately** (`tests/ocpp_test.py`, not the same code as the gateway's): thousands of generated and mutated messages (each valid message with one byte changed, inserted or deleted at every position, plus random documents) are sent through a built gateway, one tunnel each, to the recording upstream; the verdict (forwarded whole, or closed with a code) and the tag in the log are compared with the reference's. **They agree**, and
   wherever the gateway accepts, `json.loads` accepts and the shape is OCPP-J (an accepted message that `json.loads` rejects, or the reverse where the document is within the bounds, is a disagreement).
3. **End to end** (`tests/ocpp_test.py`, a Python RFC 6455 client and the recording upstream of `tests/wsframes_test.py`): every refusal of section 3 from the client, each answered with the documented Close code on the right side, the documented tag in the log, the counter incremented, and **nothing of the offending message at the upstream when the message arrived in one read**; the same from the upstream (client told 1011);
   valid OCPP-J traffic of every shape passes **byte for byte**, whole, one byte at a time and in random pieces, fragmented with a ping between; a binary message is refused 1008 at its header; a violation inside a large payload (a later read) closes the tunnel after the earlier bytes (section 2 case 2 is asserted, not hidden); a route without `ws_ocpp` forwards the same bad messages unchanged.
4. **The generator**: a case for each refusal of section 7, counts updated; `deploy/examples/ocpp.toml` carries the key.
5. **Metrics**: the counter in JSON and Prometheus, the unit test and the admin test updated.
6. **Mutants**: single edits to the recogniser, the parser's wiring, the tunnel, the metrics and the generator, each killed by a named test; the table in section 11.
7. **The authority report does not change** (no new capability: a pure module); no source file over 2,000 lines; the existing suites pass.
8. **Cost measured** against slice 2 on an OCPP-shaped stream (`tests/wsframes_bench.py`), in section 11; the bound that matters is stated there, and a result worse than the design's expectation is written as it is.

## 10. Not done, and what a next slice could be

| not done | why / what it would take |
|---|---|
| an action allow-list per route | `ws_ocpp_actions = [...]` bounded at 64 names of 64 bytes: a table in the binary, one comparison per CALL at element 2; refuses a typo and the other version's actions; needs the operator to keep it right |
| JSON schema | needs the whole message parsed (design B) and the schemas, 30 to 60 documents per version; the largest piece of OCPP work and a different gateway |
| id correlation, one outstanding CALL | a per-tunnel table or a 36-byte slot; conversation state in a gateway that holds none today |
| OCPP 2.1 | a value `"2.1"` and types 5 and 6 in the grammar |
| the upstream's choice of version | the negotiated subprotocol is not read by the recogniser; with several versions per route it could select the grammar |
| a per-message rate limit | slice 2's counter exists; a bucket per tunnel does not |
