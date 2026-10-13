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

**Not in this slice**, said once (section 10 expands, and "what is NOT validated" is section 5): action names against a list, payloads against JSON schema, uniqueId correlation, the CALLERROR code against the specification's
table, duplicate member names, any rule that needs a conversation rather than a message. *(Corrected 2026-10-13: OCPP 2.1, message types 5 and 6, was listed here as not built; it is built, section 13, by a later slice on top of the seam of section 12.)*

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
| `ws.ocpp-type` | element 0 is not the digit 2, 3 or 4, or is missing (`[]`); a type digit followed by anything but white space, a `,` or a `]` (`[22`, `[2.0`, `[2x`). *(corrected: the first draft of this table did not say where `[]` and `[22` go; the unit tests fixed it.)* | 1007 |
| `ws.ocpp-arity` | the closing `]` where another element is due (too few: `[2]`, `[2,"a"]`, `[2,"a","B",]`), or a `,` after the last (too many) | 1007 |
| `ws.ocpp-id` | element 1 is not a string of the grammar above (a number, an empty string, 37 characters, an escape, a non-ASCII byte) | 1007 |
| `ws.ocpp-action` | a CALL's element 2 is not a string of the action grammar | 1007 |
| `ws.ocpp-payload` | the payload (CALL element 3, CALLRESULT element 2) or the CALLERROR details (element 4) is not an object | 1007 |
| `ws.ocpp-code` | a CALLERROR's element 2 is not a string of the action grammar, or element 3 is not a string | 1007 |
| `ws.ocpp-depth` | nesting past 32 levels: **the gateway's own bound**, which a well-formed document can exceed | 1008 |

The order of checks is the order of the bytes: the first byte that cannot be part of a valid message decides the tag. One malformed message has one tag. The UTF-8 check of slice 2 runs on each byte before the recogniser sees it, so an invalid UTF-8 byte is `ws.frame-utf8` (1007) even where the recogniser
would also have refused it. The Close code goes to the offending side and **1011 or 1001 to the other** by slice 2's table (section 7 there): a back office that sends a malformed frame is closed on, and its charger is told 1011.

**Version and the key.** `ws_ocpp` is `"1.6"`, `"2.0.1"` or a list of them (`["1.6", "2.0.1"]`); *(since section 13: `"2.1"` too, and the three-element list)*. The route's `subprotocols` must be **exactly** the matching `ocpp1.6` / `ocpp2.0.1` tokens (so the handshake of `docs/websocket.md` already refuses a client that offers none and an
upstream that answers another). The frame grammar above is **the same in both versions**: CALL, CALLRESULT and CALLERROR have the same shape in OCPP 1.6J and 2.0.1; what differs is the actions and the payloads, which this slice does not read. The key therefore pins the subprotocol and
names the grammar; a later version with other message types (2.1 adds 5 and 6) is a new value of the same key, not a new key. *(Section 13 does exactly that: the grammar above is the grammar of 1.6 and 2.0.1; on a connection negotiated as 2.1 two more message types exist.)*

## 4. The recogniser

A state machine over the **unmasked** bytes of a text message, stepped by `wsframe.scan` beside the UTF-8 automaton *(since the refactor of section 12, through the interface of `src/wsvalidate.cho`)*, in `src/ocppframe.cho` (a new module, pure, no effect, no allocation; `wsframe.cho` is 663 lines and the 2,000-line ceiling is not near, but the grammar is a concern of its own).

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
- **OCPP 2.1** (message types 5, CALLRESULTERROR, and 6, SEND): refused as `ws.ocpp-type` by this slice, because `ws_ocpp` named no 2.1 grammar. *(Corrected: accepted on a connection negotiated as `ocpp2.1`, and still `ws.ocpp-type` on every other, section 13.)*
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
number, a boolean, an empty list, an empty string, `"1.5"`, `"2.1"` *(corrected: valid since section 13; `"2.2"` and `"2.1.0"` are refused)*, `"ocpp1.6"` (the token, not the version), a duplicate, a list of three, a non-string in a list, `ws_ocpp` without `websocket`, no `subprotocols`, `subprotocols` with another token, with an extra one, with a missing one. The route table gets one more column (32, after the rate limit's):
a bitmask, 1 for 1.6, 2 for 2.0.1, 4 for 2.1 *(section 13)*, 0 for none; `--explain` says what each route validates. `deploy/examples/ocpp.toml` sets it.

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
| OCPP 2.1 | *(built, section 13)* a value `"2.1"` and types 5 and 6 in the grammar |
| the upstream's choice of version | *(built, section 13)* the negotiated subprotocol is read from the `101` and selects the grammar |
| a per-message rate limit | slice 2's counter exists; a bucket per tunnel does not |

## 11. As built

Built 2026-10-12 on a branch of its own, against the pinned compiler (`2fcf4cd`), on top of `origin/main` `3560c05`. Everything below was run on the development machine (one core shared with the test processes; CI will differ in timing).

**What exists.**

- *`src/ocppframe.cho`* (470 lines, pure, no effect): the recogniser `step`, `reset`, `complete`; about forty positions in one function, with the helpers `value`, `between`, `element`, `open`, `close`. *`src/wsframe.cho`* (728 lines when built; 714 after section 12) steps it beside the UTF-8 automaton (one call per text byte of a validated direction), refuses a binary message at its header, and refuses a message that ends before the grammar does; it also carried the nine tags, `own_code` (1008 for binary and nesting, 1007 for the rest), `is_ocpp` and `enable_ocpp` *(corrected: the tags and codes are now in `src/wsvalidate.cho`, section 12; `wsframe` forwards)*. The state block is **72 ints** a tunnel (28 a direction: 20 to 26 the recogniser, 27 the flag), the `wsf` slab 256 x 72 ints = **144 KiB** (arithmetic, not a resident-size measurement).
- *The tunnel* (`src/proxy.cho`, **1,980 lines** after the merge with the rate-limit work: `scripts/lines.py` passes, with 20 to spare): four lines switch the flag on from the route's column when the 101 is relayed, three count a violation. Nothing else in `tunnel_pump` changed. *(Corrected: the tunnel is now `src/wstunnel.cho`, `proxy.cho` is 1,278 lines, and the two places call `wsbind`, section 12.)*
- *Key and table* (`scripts/generate.py`): `ws_ocpp`, column 32 of the route table (27 before the merge with the rate-limit work, which took 27 to 31) (`route.ws_ocpp`), `--explain` says which route validates. *Metrics:* `ocpp_violations` (JSON) and `ws_ocpp_violations_total` (Prometheus), one more int; `worst_case()` grew by 256 bytes and `fill` in the bound test moved its rule table by one int.
- *Tests:* `tests/ocppframe_test.cho` (25 cancho tests, 206 message cases, each in both directions), `tests/ocpp_test.py` (10 end-to-end tests, below), 23 generator refusals, 5 accepted deployments and one compiled-table test, `tests/ocpp_mutants.py` (70 mutants), `tests/ocpp_bench.py`. `tests/wsframe_test.cho` changed only where it had the state size or a direction's offset written as a number. The recording upstream of `tests/wsframes_test.py` now answers `ocpp2.0.1` as well as `ocpp1.6`.

**Where the build found the design wrong or incomplete** *(corrected in place above where it mattered)*:

| design | built | why |
|---|---|---|
| section 3: where `[]`, `[22`, `[2]` go | `[]` and `[22` are `ws.ocpp-type`, `[2]` is `ws.ocpp-arity` | found writing the unit table; the rule is "the first byte that cannot continue a match", and a type digit's follower decides |
| section 9 gate 2: the differential through "a small cancho probe" | through real tunnels, one per message, eight at a time | no probe is needed: the gateway is the thing under test, and a tunnel answers with the echo or a Close; the cost is about 40 ms a message |
| the first run of the end-to-end tests | the recording upstream answered only `ocpp1.6`, so the routes for `ocpp2.0.1` got a 502 from the gateway's own upstream check | a test-harness gap, not a gateway one (the check worked); the stub now picks the first offered token |
| the first run of the benchmark | an "up" stream of 0.3 ms/MiB for the validated route | `wsframes_bench.frame` writes a mask key and does not apply it: a byte-agnostic gateway never minds, this one refused the first message. The bench masks properly now; the numbers below are from the fixed one |
| a first end-to-end assertion that the echo of a valid message sent just before a binary one is delivered | not asserted | the Close is decided in the same read, so the echo may or may not arrive first (slice 2's helper already says so) |

**Gates.**

| gate | status | where |
|---|---|---|
| 1 recogniser, every split, random mutations | **met** | `ocppframe_test.cho`: every valid and every refused message of section 3's table (206 cases, client and server direction) whole, at every pair of cut points (a stride of 3 over 70 bytes) and byte by byte, with one verdict; a refusal fed whole forwards nothing and is at a frame boundary; fragmented at every byte with a ping between; an empty final fragment; messages in a stream restart the machine; a payload of 3,000 opening brackets is refused at the 33rd; 3,000 random mutations of valid messages, in three pieces and byte by byte, have one verdict |
| 2 differential | **met** | `ocpp_test.py`: **2,140 messages** (every valid one with each ASCII byte deleted, 1,800 random edits of one to three bytes, deep documents, random printable text) through real tunnels: **797 accepted, 1,343 refused** (`ws.ocpp-json` 833, `-type` 170, `-id` 111, `-code` 100, `-action` 70, `-payload` 47, `-arity` 10, `-depth` 2); gateway and reference agree on every verdict, Close code and log tag; every accepted one is echoed whole and `json.loads` accepts it; no message `json.loads` refuses is accepted. *Arity and depth are thinly covered by mutation (a deleted byte rarely changes a count); the unit table and the end-to-end refusals cover them by construction.* An earlier run of 3,165 messages agreed too |
| 3 end to end | **met** | 44 refusals from the client (route, tag, Close code, the log, `ws_close`, **the upstream's bytes equal to the gateway's Close 1001 and nothing else**), 13 from the upstream (client told 1011, the upstream its code, the valid message before it delivered whole), binary at the header (whole, empty, fragmented, after a valid message), valid traffic of nine messages on the 1.6, 2.0.1 and both routes whole, byte by byte and in random pieces, byte for byte, a fragmented message with pings, a violation in a later read (the upstream gets the header and the valid bytes and then the end; asserted), a route without `ws_ocpp` forwards the same bad text and a binary message unchanged, the other version's subprotocol refused at the handshake |
| 4 generator | **met** | 23 refusals (`config.websocket`, with lines) and 5 accepted; a compiled-table test (masks 1, 2, 3, 0 and `--explain`); `deploy/examples/ocpp.toml` carries the key and the site shows it |
| 5 metrics | **met** | the counter in both formats (unit test, the admin test's key list, an end-to-end count of five violations by both peers and the per-tag `refusals`); an RFC 6455 violation is not counted as an OCPP one |
| 6 mutants | **70 edits, 69 killed, 1 argued** | below |
| 7 authority, lines, suites | **met** | labels unchanged (`manifests/` re-recorded: function names only); no file over 2,000 lines; every suite of `CONTRIBUTING.md` that was run passes (below) |
| 8 cost | **measured** | below |

**Mutants** (`python3 tests/ocpp_mutants.py -j 3`). **70 edits: 69 killed, 1 survives.** The classes: the recogniser's every position and bound (o01 to o44: the nesting bound both ways, the stack, every number position, escapes, hex digits, literals, the id and action bounds and alphabets, the arity of each type, white space, the comma rules, the element index), the parser's wiring (w01 to w13: not stepped, the end-of-message check, binary, the reset, control frames read as OCPP, the Close codes, a tag, the counter's predicate, each direction's flag), the tunnel (p01 to p04: never enabled, always enabled, the counter, the column), the metrics (t01 to t03) and the generator (g01 to g06). Most are killed by the cancho suite, which is what it is for; the ones the unit tests cannot see (the flag from the route, the column, the counter's predicate) are killed by the end-to-end tests. **o07** (a number with a leading zero is admitted, by removing the check after `0`) **survives, and is equivalent**: the next byte then reaches `between`, which refuses every digit with the same tag, so `01` is still `ws.ocpp-json`; the check it removes is redundant by construction. `o10` (an exponent's sign need not be followed by a digit) was first killed **only by the differential**, which showed a gap in the unit table (`1e+}` was there, but the byte after the sign was swallowed and the next closed the message: `1e+}}]` was not); the cases were added and the unit test kills it now. `g02` is killed by a crash (an unknown version raises in the generator and the table test sees exit 1), which is a kill, not a pretty one. Equivalent generator edits that were **not written** because they cannot be killed: dropping the "ws_ocpp needs websocket" check (a route without `websocket` has no `subprotocols`, so the next check refuses it with the same tag and line) and dropping the "distinct versions" check (a repeated version cannot match the distinct subprotocols).

**Measured** *(one machine, the gateway's CPU from `/proc`, 64 MiB each way, one tunnel, median of three, `tests/ocpp_bench.py`; the same gateway, a route without `ws_ocpp` against one with it; valid OCPP-J messages)*:

| traffic | plain route | `ws_ocpp` | ratio |
|---|---|---|---|
| upstream to client, 331-byte CALLs | 5.00 ms/MiB | 8.59 ms/MiB | 1.72 |
| upstream to client, 4,991-byte CALLRESULTs | 5.62 | 8.12 | 1.44 |
| client to upstream, 331-byte CALLs (masked) | 5.16 | 9.38 | 1.82 |
| client to upstream, 4,991-byte CALLRESULTs (masked) | 5.00 | 9.06 | 1.81 |

*The plain route already pays for the UTF-8 automaton* (slice 2, section 15), so the recogniser costs about **3 to 4 ms a MiB** more: about 1.1 microseconds on a 331-byte message. It is a function call and a chain of comparisons a byte, in a language without a switch; a deployment moving 100 MiB/s of OCPP text would spend about 0.35 of a core on it. OCPP traffic is orders of magnitude below that. *Not measured:* memory at hundreds of tunnels (the slab is 144 KiB by arithmetic), latency, a browser, `wss` (the recogniser runs on the plaintext the TLS engine hands over, as the frame parser does; the new tests are plain; slice 2's `wss` tests still pass).

**Counts, from the last full run of the gate** (a few lines of tests were added after it, and `cancho test` and `ocpp_test.py` were re-run: noted where): `generate_test.py`: `7 prefix cases, 399 refusal cases, 62 accepted, 0 failures`. `ocpp_test.py`: `10 tests, 0 failures`. `wsframes_test.py`: `25 tests, 0 failures`. `websocket_test.py`: `55 tests, 0 failures`. `proxy_test.py`: `77 tests, 0 failures`. `admin_test.py`: `16 tests, 0 failures`. `tls_test.py`: `22 tests, 0 failures`. `ratelimit_test.py`: `16 tests, 0 failures`. `auth_test.py`: `14 tests, 0 failures`. `jwt_test.py`: `16 tests, 0 failures`. `jwt_differential.py 1500`: `0 disagreements`. `route_test.py 12 400`: `12 tables, 4800 requests, 0 failures`; `--fixed`: `18 fixed cases, 0 failures`. `response/run.py`: `55 cases, 0 failures`. `smuggling/run.py --gateway`: `67 cases, 0 disagreements`. `cancho test`: every suite ok (`ocppframe` 25, `wsframe` 21). `check_site.py`, `figures.py --check`, `proof.py --check` (after regenerating the report tables), `authority.py --check`, `authority_test.py`, `lines.py`, `cancho fmt --check src tests generated` and `generate.py deploy/example.toml --check`: pass. **Not run:** `headers/differential.py` (needs nginx), `smuggling/run.py --prefixes`, `--chunked` and `--fuzz` (the framing code did not change), the `websockets` library as an OCPP peer of the new tests.

**Not done, and not known.**

- **Whether any real charger sends an id with an escape, a non-ASCII byte or an empty id, or an action with a hyphen**: unknown (section 5); the gateway refuses them.
- **The negotiated version is not read**: with `["1.6", "2.0.1"]` the same grammar is applied whichever the charger chose. *(Section 13 reads it: it matters for 2.1, because 5 and 6 exist there only. Between 1.6 and 2.0.1 the grammar is still the same.)*
- **A violation by a peer while the gateway is already closing** is not tagged a second time (slice 2's rule), and a refusal that comes in a later read than its frame's header leaves the other side with half a frame (section 2).
- **Interaction with PR #47** (rate limiting: route table, metrics, proxy): *(resolved: #46 and #47 merged first; `origin/main` `b095614` was merged into this branch, `ws_ocpp` became column 32, `worst_case()` kept both additions, the gate was run again on the merge, and `proxy.cho` has 20 lines left under the ceiling.)*

## 12. Where a second grammar would plug in (the validator seam)

*Added 2026-10-13 with the refactor of `docs/websocket-frames.md` section 16 (behaviour, keys, tags and metric names unchanged; the existing tests pass unchanged).* The question was whether the general gateway should know OCPP. It still does, in four named places, and nowhere else:

1. **`src/ocppframe.cho`**: the grammar (section 4). Unchanged.
2. **`src/wsvalidate.cho`**: the validator kinds, the range of rule numbers each owns (OCPP-J: 17 to 25), the nine tags and the Close codes (1008 binary and nesting, 1007 the rest), and the dispatch `begin` / `step` / `finish` / `binary`. This replaces what `wsframe.cho` carried (`tag`, `own_code`, `is_ocpp`, `enable_ocpp`, the steps); `wsframe` keeps `is_ocpp` and `enable_ocpp` as forwards for the unit tests.
3. **`src/wsbind.cho`**: `kind_of_route` (the route table's `ws_ocpp` column, `route.ws_ocpp`, becomes kind 1) and `count` (rules 17 to 25 feed `ws_ocpp_violations_total`).
4. **`src/route.cho`, `src/metrics.cho`, `scripts/generate.py`**: the key `ws_ocpp`, its column, its counter. Unchanged.

`wstunnel.cho`, `proxy.cho` and the frame layer of `wsframe.cho` do not mention OCPP.

**What a second grammar (call it kind 2) would cost**, from the code as it is:

| step | where | size |
|---|---|---|
| the grammar as a stream machine over at most seven ints (`step`, a `complete` test, a `reset`) | a new `src/<name>frame.cho`, pure | the OCPP one is 470 lines; a grammar needing more than seven ints needs the block grown (72 ints a tunnel, 144 KiB in `core.wsf`, by arithmetic) |
| the kind, the rule range, the tags, the Close codes | `wsvalidate.cho`: one more `if kind == 2` in each of five functions, `kind_of_rule`, `tag`, `close_code` | about 40 lines; `wsframe.rule_count()` (25) grows |
| the route key and the counter | `generate.py` (a key, its validation, a column), `route.cho` (an accessor), `metrics.cho` (a counter in both formats and the bound), `wsbind.cho` (two branches) | the largest part: a key is not free (section 7) |
| tests | the recogniser's unit table, the end-to-end refusals, a differential against a reference, the mutants | as section 9 |

What the seam does **not** make cheap: a grammar that needs to see a whole message (JSON schema, correlation of ids) cannot be a stream machine in seven ints; it needs a buffer the size of the message, which this program does not allocate (regions under 64 KiB, no heap growth after start). That is a different design, not a second kind.

**OCPP versions inside kind 1.** The key is a list (`"1.6"`, `"2.0.1"`; a later `"2.1"` is "a new value of the same key", section 3), `route.ws_ocpp` answers a bitmask, and `kind_of_route` only asks whether it is nonzero, because the grammar is the same in every version supported. A version that changes the grammar (2.1 adds message types 5 and 6) is therefore a change *inside* `ocppframe.cho`, which would need the mask: the cheapest way is to pack it with the kind in the direction's eighth int (kind in the low bits, the mask above), written by `wsbind` and read by `ocppframe.step`; no new block, no new key. *(Built as section 13, with one correction to this paragraph: what is packed is the version the handshake **negotiated**, not the route's mask, because the route's mask cannot say which of its versions a connection is.)*

**Measured, before and after the refactor** *(same machine, `tests/ocpp_bench.py`, 64 MiB each way, medians; the validated route in ms/MiB, plain route in brackets; this machine's run-to-run spread is about 10 %)*:

| traffic | before (5 rounds) | after (5 rounds) | after (7 rounds) |
|---|---|---|---|
| down, 331-byte | 8.59 (4.53) | 8.59 (5.00) | 9.38 (4.84) |
| down, 4,991-byte | 8.59 (4.84) | 7.97 (4.84) | 8.44 (5.00) |
| up, 331-byte | 10.31 (5.62) | 10.31 (6.25) | 10.16 (6.09) |
| up, 4,991-byte | 9.37 (5.94) | 11.56 (5.78) | 9.69 (5.78) |

No regression beyond the spread (the one high cell, 11.56, is 9.69 on the repeat). *Line counts:* `proxy.cho` 1,980 before, 1,278 after (`slots.cho` 357, `wstunnel.cho` 412, `wsvalidate.cho` 120, `wsbind.cho` 26; `wsframe.cho` 728 to 714).

## 13. OCPP 2.1 (message types 5 and 6, selected by the negotiated subprotocol)

*Added 2026-10-13, on the seam of section 12. Design first; the measured parts are marked and are in section 13.8.* The user requirement is that a route can serve OCPP 1.6 **and** 2.1. Sections 1 to 12 handled 1.6 and 2.0.1, which share one frame grammar. This section is what 2.1 changes in the frame, what the gateway does about it, and what could not be checked.

### 13.1 What 2.1 changes in OCPP-J framing, and how sure that is

| claim | status |
|---|---|
| 2.1 keeps the three frames of 1.6 and 2.0.1 unchanged: CALL `[2, id, action, payload]`, CALLRESULT `[3, id, payload]`, CALLERROR `[4, id, code, description, details]` | **from memory, and consistent with every implementer note found; not read in the specification** |
| 2.1 adds **CALLRESULTERROR**, message type **5**: `[5, id, errorCode, errorDescription, errorDetails]`, an error answering a CALLRESULT the receiver could not process; it has the arity and the element kinds of a CALLERROR | **secondary source only** (a library's documentation found by web search, `ocpp.hexdocs.pm`, which states the shape and the purpose); matches what the task brief and my memory say; **the specification's own text was not read** |
| 2.1 adds **SEND**, message type **6**: `[6, id, action, payload]`, a message that is not answered and is not subject to the one-outstanding-CALL rule (its example is `NotifyPeriodicEventStream`); it has the arity and the element kinds of a CALL | **secondary source only**, as above |
| the subprotocol token of 2.1 is `ocpp2.1` | **from memory; not checked against the specification or the IANA WebSocket Subprotocol registry in this work** |

**Could NOT be verified offline, so not relied on and not guessed.** There is no copy of the OCPP 2.1 specification (OCA's Part 4, OCPP-J) in the repository and none could be read here; the only external material reached was one library's documentation, through a web search, and its `frame` page itself could not be fetched. Therefore:

- *that CALLRESULTERROR's `errorCode` is a code of the same table and grammar as CALLERROR's, that its `errorDescription` is any string and its `errorDetails` an object* (**uncertain**: assumed because the shape is said to be the same);
- *that a SEND's `payload` is always an object* (**uncertain**: assumed because it is a request like a CALL);
- *the length and the alphabet of the id in 2.1* (**uncertain**: the id rule of section 3 is applied unchanged, and it is already stricter than the 36-character text of 1.6 and 2.0.1, section 5);
- *whether 2.1 changed anything else in the frame* (new error codes, a changed rule about ids of SEND, a rule that a receiver ignores a frame of an unknown type, which the same library documentation attributes to the specification, with an erratum of 2026-04 that was not seen). **Unknown.** The gateway does not ignore: an unknown type is `ws.ocpp-type`, as in section 3;
- *whether a charger in the field sends 5 or 6 on a 2.1 connection at all, and with what ids*: unknown, as for every fleet question in section 5.

**Decision under that uncertainty: acceptance stays strict.** The gateway accepts a type 5 as the grammar of type 4 and a type 6 as the grammar of type 2 (section 3, every restriction of it included), **only** on a connection negotiated as 2.1, and nothing more. If the specification turns out wider (an id of another kind, a payload that is not an object), the cost is a refused message, which the operator can handle by turning `ws_ocpp` off on the route, as section 5 says for the id; if it turns out narrower, the gateway forwards a message the back office's own parser refuses, which section 2 already says it must be able to do. A claim of the table above that is found false is corrected here, in place.

### 13.2 The rules

On a connection negotiated as 2.1, in both directions, a text message is valid if it is valid by section 3 **or** it is:

```
type 5   CALLRESULTERROR  [5, uniqueId, errorCode, errorDescription, errorDetails]    5 elements, the grammar of type 4 element by element
type 6   SEND             [6, uniqueId, action, payload]                                4 elements, the grammar of type 2 element by element
```

The type digit is a single `5` or `6` as a JSON number token, as for 2, 3 and 4 (`[55`, `[5.0`, `[05`, `["5"` and the like stay `ws.ocpp-type`). Everything after the digit gives the refusals of the type whose shape it has: a CALLRESULTERROR with four elements is `ws.ocpp-code` (element 3 is the description, then the details are due: `{}` is not a string), with a payload that is not an object `ws.ocpp-payload`, and so on, the same tags, the same Close codes (1007; nesting past 32 levels 1008). **No new tag, no new rule number, no new counter**: the rule range 17 to 25 of `wsvalidate` is unchanged, `rule_count()` is still 25.

On a connection negotiated as 1.6, as 2.0.1, or as anything the gateway cannot map to a version (cannot happen on a route with `ws_ocpp`, see 13.4; treated as "not 2.1"), the types 5 and 6 are **refused exactly as before this section**: `ws.ocpp-type`, Close 1007, at the type digit, whatever follows. Nothing about 1.6 and 2.0.1 changes: a test says that every case of the 1.6 corpus has the same verdict on those versions as it had.

### 13.3 The key and the table

`ws_ocpp` accepts `"2.1"` and lists of distinct versions of the three (`["1.6", "2.1"]`, `["1.6", "2.0.1", "2.1"]`). The route's `subprotocols` must be exactly the matching tokens `ocpp1.6`, `ocpp2.0.1`, `ocpp2.1` (section 7's rule, unchanged: the set is compared, the order is the operator's), and the handshake's exact-match rule (`docs/websocket.md`) applies to the new token as to the others: `OCPP2.1`, `ocpp2.1.0` and `ocpp2.2` are not served. The route table's column 32 is the bitmask, now `1 | 2 | 4`; **no new column**. The mask says which versions a route may serve. It cannot say which one a connection is, and that is the next section.

### 13.4 Which version a connection is: the negotiated subprotocol

Today (sections 3 and 11) a route with several versions applies one grammar to all of them. For 2.1 that is wrong: a charger that negotiated `ocpp1.6` must not be allowed to send a type 6 because the route also serves 2.1. Reading the code as it is before this section: the `Sec-WebSocket-Protocol` of the upstream's `101` is checked by `websocket.check_response` against the route's tokens **and** the client's offer (a token the client did not offer, or the route does not serve, is `ws.upstream-subprotocol` 502), and is the only place the choice is made. **The upstream chooses** among the tokens the client offered that the route serves; the client's order is a preference the upstream may ignore; the gateway checks the answer.

So the gateway reads the choice where it is checked: `websocket.chosen_protocol` (the header of the checked `101`), `wsbind.negotiated` (the token to a version bit: `ocpp1.6` 1, `ocpp2.0.1` 2, `ocpp2.1` 4, anything else 0, compared exactly), and `wsvalidate`'s eighth int of each direction packs **the kind in the low four bits and the negotiated version bit above them** (`kind + 16 * version`): the packing section 12 proposed, with the correction that it is the negotiated version and not the route's mask (the mask is not about one connection). `ocppframe.element` asks `version(ws, o) == 4` where a message type digit is `5` or `6`, and nothing else in the recogniser reads it. The head of the `101` is overwritten when the first bytes after it are moved, so the version is taken **before** that move (a mutant moves it after, 13.7). The state block is still 72 ints, the slab and the slot layout are unchanged, and a route without `ws_ocpp` still never calls the recogniser.

What follows from the upstream choosing: on a route `["1.6", "2.1"]`, a charger that offers `ocpp1.6, ocpp2.1` is a 1.6 connection if the back office answers `ocpp1.6` and a 2.1 connection if it answers `ocpp2.1`; a charger that offers only `ocpp2.1` is 2.1; one that offers only `ocpp1.6` is 1.6. The version is fixed for the life of the tunnel, so a first message of 1.6 shape does not change it.

### 13.5 What is not done

- **Version-specific actions and payloads** are not read for any version (section 5): a `SEND` of an action 2.1 does not have is well-formed here.
- **That a CALLRESULTERROR answers a CALLRESULT** and that SEND is unanswered: conversation rules, none kept (section 5).
- **A 2.1 connection offering the tokens of the older versions to the upstream**: not changed; the gateway only reads the answer.
- **Version negotiation errors other than the existing ones**: an upstream that answers a token the client did not offer is already `ws.upstream-subprotocol`.

### 13.6 Gates, fixed before the code

1. **Unit** (`tests/ocppframe_test.cho`): the version packed with the kind (values 17, 33, 65 and 1 for 1.6, 2.0.1, 2.1 and "not known", the kind readable beside it); types 5 and 6 valid on 2.1 at every pair of cut points and byte by byte, in both directions; the same messages `ws.ocpp-type` on 1.6, 2.0.1 and "not known" at every cut; every refusal of a type 5 and a type 6 by its tag; types 7, 1, 0, `55`, `5.0`, `"5"` still the type on 2.1; fragments with a ping between, the digit alone in the first fragment, a stream of messages (the version belongs to the connection, not the first message), a binary message; random mutations of 2.1 messages: one verdict at every cut, and 2.1 accepts a superset of 1.6 (a message 1.6 accepts, 2.1 accepts; where they differ 1.6 said `ws.ocpp-type`).
2. **Generator** (`tests/generate_test.py`): `"2.1"` and the lists accepted with the matching subprotocols and masks 4, 5 and 7; refused: `"2.2"`, `"2.1.0"`, `"ocpp2.1"`, `2.1` (a number), duplicates, four entries, `"2.1"` with the other tokens, with the token missing, with an extra one, without `websocket`.
3. **End to end** (`tests/ocpp_test.py`, a route for 2.1, one for `["1.6", "2.1"]` and one for all three): types 5 and 6 byte for byte on 2.1, whole, one byte at a time and in random pieces, in both directions; every refusal by its tag and Close code with nothing at the upstream; the upstream's refusals 1011; 1.6 and 2.0.1 routes refuse 5 and 6; **a connection negotiated as 1.6 on a route that also allows 2.1 refuses a type 6** (and one negotiated as 2.1 on the same route accepts it), with the choice made by the upstream (the recording upstream takes `pref-<token>` in the path), for the two-version and the three-version route; the handshake refuses `ocpp2.1` on routes that do not serve it and near misses of the token.
4. **Differential against the reference grammar** (`tests/ocpp_test.py`, `ref`, written separately): the reference gains a `v21` flag; the gateway and the reference agree on every verdict, Close code and tag over mutations of a corpus that includes the 2.1 messages, on a 2.1 route with `v21` and on 1.6 and 2.0.1 routes without it; where the reference accepts, `json.loads` accepts and the shape is OCPP-J (types 5 and 6 included only for 2.1).
5. **Mutants** on the new logic (`tests/ocpp_mutants.py`, v01 to v22, g07 to g09), each killed by a named test; the table in 13.8.
6. **The authority report does not change** (no new capability); no source file over 2,000 lines (`ocppframe.cho` 470 to about 480, `tests/ocppframe_test.cho` about 1,290, `tests/ocpp_test.py` about 1,000); the existing suites pass; the cost of a recogniser that reads one more int is measured against section 12's numbers.

### 13.7 What was found while building it

*(Written after the build; each row is something the design above did not say or got wrong, corrected in place where it mattered.)* Filled in at 13.8.

### 13.8 As built, measured

Filled in below when the gate has been run.
