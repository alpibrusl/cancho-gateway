#!/usr/bin/env python3
"""OCPP-J message validation end to end (docs/ocpp.md section 9): a built gateway, the RFC 6455 client and the recording upstream of tests/wsframes_test.py.

    python3 tests/ocpp_test.py [test_name ...]      # all tests, or the named ones
    WS_TREE=/path/to/copy python3 tests/ocpp_test.py ...   # build the gateway from another copy of the tree (tests/ocpp_mutants.py)

One gateway is built from loose files (as tests/wsframes_test.py does): routes for OCPP 1.6 (limit 64 KiB), 2.0.1, both, a large-limit one for a violation that comes in a later read than
the frame's header, and a WebSocket route without `ws_ocpp` that must behave as slice 2 did.

`Differential` is the gate that matters most: `ref` below is a recursive-descent checker of the grammar of section 3, written here from the document and sharing nothing with the gateway's state machine;
thousands of messages (each valid one with a byte deleted, replaced or inserted, at sampled places) go through real tunnels, and the gateway's verdict and its log tag must equal the reference's. Where
the reference accepts, Python's `json.loads` must accept too; where `json.loads` refuses, the reference must.
"""

import json
import os
import pathlib
import random
import re
import socket
import struct
import sys
import tempfile
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import proxy_test as pt  # noqa: E402
import websocket_test as wt  # noqa: E402
import wsframes_test as ft  # noqa: E402

cframe, sframe, expect_close, drain, code_of = ft.cframe, ft.sframe, ft.expect_close, ft.drain, ft.code_of

ROUTES = """
[[route]]
name = "o16"
path_prefix = "/o16"
websocket = true
subprotocols = ["ocpp1.6"]
ws_ocpp = "1.6"
ws_max_message_bytes = 65536
upstream = "up"

[[route]]
name = "o201"
path_prefix = "/o201"
websocket = true
subprotocols = ["ocpp2.0.1"]
ws_ocpp = "2.0.1"
ws_max_message_bytes = 65536
upstream = "up"

[[route]]
name = "oboth"
path_prefix = "/oboth"
websocket = true
subprotocols = ["ocpp1.6", "ocpp2.0.1"]
ws_ocpp = ["1.6", "2.0.1"]
ws_max_message_bytes = 65536
upstream = "up"

[[route]]
name = "o21"
path_prefix = "/o21"
websocket = true
subprotocols = ["ocpp2.1"]
ws_ocpp = "2.1"
ws_max_message_bytes = 65536
upstream = "up"

[[route]]
name = "o1621"
path_prefix = "/o1621"
websocket = true
subprotocols = ["ocpp1.6", "ocpp2.1"]
ws_ocpp = ["1.6", "2.1"]
ws_max_message_bytes = 65536
upstream = "up"

[[route]]
name = "oall"
path_prefix = "/oall"
websocket = true
subprotocols = ["ocpp1.6", "ocpp2.0.1", "ocpp2.1"]
ws_ocpp = ["1.6", "2.0.1", "2.1"]
ws_max_message_bytes = 65536
upstream = "up"

[[route]]
name = "obig"
path_prefix = "/obig"
websocket = true
subprotocols = ["ocpp1.6"]
ws_ocpp = "1.6"
ws_max_message_bytes = 268435456
upstream = "up"

[[route]]
name = "plainws"
path_prefix = "/plainws"
websocket = true
subprotocols = ["ocpp1.6"]
ws_max_message_bytes = 65536
upstream = "up"

[[route]]
name = "other"
path_prefix = "/"
upstream = "up"
"""

PROTOCOL = {"/o16": ("ocpp1.6",), "/o201": ("ocpp2.0.1",), "/oboth": ("ocpp1.6", "ocpp2.0.1"), "/o21": ("ocpp2.1",), "/o1621": ("ocpp1.6", "ocpp2.1"), "/oall": ("ocpp1.6", "ocpp2.0.1", "ocpp2.1"), "/obig": ("ocpp1.6",), "/plainws": ("ocpp1.6",)}


def go(gw, path):
    prefix = "/" + path.split("/")[1]
    return wt.connect_ws(gw, path, protocols=PROTOCOL[prefix])


def log_of(gw, n0, path, **want):
    return gw.find(n0, 6, path=path, **want)


# ---------------------------------------------------------------------------------------------------------------------- the reference


class Bad(Exception):
    def __init__(self, name):
        super().__init__(name)
        self.tag = "ws.ocpp-" + name


SPACE = b" \t\r\n"
NUMBER = re.compile(rb"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
HEX = b"0123456789abcdefABCDEF"
ALNUM = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")


def skip(m, i):
    while i < len(m) and m[i] in SPACE:
        i += 1
    return i


def restricted(m, i, limit, alnum, rule):
    if m[i] != 0x22:
        raise Bad(rule)
    j, n = i + 1, 0
    while True:
        if j >= len(m):
            raise Bad("json")
        c = m[j]
        if c == 0x22:
            if n == 0:
                raise Bad(rule)
            return j + 1
        if c < 32 or c > 126 or c == 0x5C or (alnum and c not in ALNUM):
            raise Bad(rule)
        n += 1
        if n > limit:
            raise Bad(rule)
        j += 1


def string(m, i):
    j = i + 1
    while True:
        if j >= len(m):
            raise Bad("json")
        c = m[j]
        if c == 0x22:
            return j + 1
        if c < 32:
            raise Bad("json")
        if c == 0x5C:
            if j + 1 >= len(m):
                raise Bad("json")
            e = m[j + 1]
            if e in b'"\\/bfnrt':
                j += 2
                continue
            if e == 0x75:
                if j + 5 >= len(m) or any(x not in HEX for x in m[j + 2:j + 6]):
                    raise Bad("json")
                j += 6
                continue
            raise Bad("json")
        j += 1


def value(m, i, depth):
    if i >= len(m):
        raise Bad("json")
    c = m[i]
    if c == 0x7B:
        return obj(m, i, depth + 1)
    if c == 0x5B:
        return arr(m, i, depth + 1)
    if c == 0x22:
        return string(m, i)
    for lit in (b"true", b"false", b"null"):
        if m.startswith(lit, i):
            return i + len(lit)
    hit = NUMBER.match(m, i)
    if hit:
        return hit.end()
    raise Bad("json")


def obj(m, i, depth):
    if depth > 32:
        raise Bad("depth")
    i = skip(m, i + 1)
    if i < len(m) and m[i] == 0x7D:
        return i + 1
    while True:
        if i >= len(m) or m[i] != 0x22:
            raise Bad("json")
        i = skip(m, string(m, i))
        if i >= len(m) or m[i] != 0x3A:
            raise Bad("json")
        i = skip(m, value(m, skip(m, i + 1), depth))
        if i >= len(m):
            raise Bad("json")
        if m[i] == 0x7D:
            return i + 1
        if m[i] != 0x2C:
            raise Bad("json")
        i = skip(m, i + 1)


def arr(m, i, depth):
    if depth > 32:
        raise Bad("depth")
    i = skip(m, i + 1)
    if i < len(m) and m[i] == 0x5D:
        return i + 1
    while True:
        i = skip(m, value(m, i, depth))
        if i >= len(m):
            raise Bad("json")
        if m[i] == 0x5D:
            return i + 1
        if m[i] != 0x2C:
            raise Bad("json")
        i = skip(m, i + 1)


def check(m, v21=False):
    """`v21`: the connection was negotiated as OCPP 2.1 (docs/ocpp.md section 13): message types 5 (CALLRESULTERROR, the shape of a CALLERROR) and 6 (SEND, the shape of a CALL) exist."""
    i = skip(m, 0)
    if i >= len(m) or m[i] != 0x5B:
        raise Bad("json")
    i = skip(m, i + 1)
    if i >= len(m):
        raise Bad("json")
    if m[i] not in (b"23456" if v21 else b"234"):
        raise Bad("type")
    ty = m[i] - 48
    arity = {2: 4, 3: 3, 4: 5, 5: 5, 6: 4}[ty]
    i = skip(m, i + 1)
    if i >= len(m):
        raise Bad("json")
    if m[i] == 0x5D:
        raise Bad("arity")
    if m[i] != 0x2C:
        raise Bad("type")
    i += 1
    for idx in range(1, arity):
        i = skip(m, i)
        if i >= len(m):
            raise Bad("json")
        if m[i] == 0x5D:
            raise Bad("arity")
        if idx == 1:
            i = restricted(m, i, 36, False, "id")
        elif idx == 2 and ty in (2, 6):
            i = restricted(m, i, 64, True, "action")
        elif idx == 2 and ty in (4, 5):
            i = restricted(m, i, 64, True, "code")
        elif idx == 3 and ty in (4, 5):
            if m[i] != 0x22:
                raise Bad("code")
            i = string(m, i)
        else:
            if m[i] != 0x7B:
                raise Bad("payload")
            i = obj(m, i, 1)
        i = skip(m, i)
        if i >= len(m):
            raise Bad("json")
        if idx < arity - 1:
            if m[i] == 0x2C:
                i += 1
                continue
            raise Bad("arity" if m[i] == 0x5D else "json")
        if m[i] == 0x5D:
            i += 1
            break
        raise Bad("arity" if m[i] == 0x2C else "json")
    if skip(m, i) != len(m):
        raise Bad("json")


def ref(m, v21=False):
    """The tag the grammar of docs/ocpp.md section 3 (and section 13 for a 2.1 connection) gives `m`, or None if it is a valid message."""
    try:
        check(m, v21)
        return None
    except Bad as e:
        return e.tag


def code_for(tag):
    return 1008 if tag in ("ws.ocpp-binary", "ws.ocpp-depth") else 1007


def strict_loads(m):
    def refuse(x):
        raise ValueError(x)
    return json.loads(m.decode("utf-8"), parse_constant=refuse)


# ---------------------------------------------------------------------------------------------------------------------- the corpus

VALID = [
    b'[2,"19223201","BootNotification",{"chargePointVendor":"VendorX","chargePointModel":"SingleSocketCharger"}]',
    b'[3,"19223201",{"status":"Accepted","currentTime":"2013-02-01T20:53:32.486Z","interval":300}]',
    b'[4,"19223201","NotImplemented","unknown action",{}]',
    b'[2,"a","B",{}]',
    b'[3,"a",{}]',
    b'[4,"a","C","",{}]',
    b' [ 2 , "a b" , "Get15118EVCertificate" , { "k" : [ 1 , -2.5e+3 , true , false , null , "\\u00e9\\n" , { } , [ ] ] } ] \n',
    b'[2,"123456789012345678901234567890123456","MeterValues",{"connectorId":1,"meterValue":[{"timestamp":"2013-03-07T16:52:16Z","sampledValue":[{"value":"0.1","unit":"kWh"}]}]}]',
    b'[4,"77","GenericError","caf\xc3\xa9 \xe2\x82\xac \xf0\x9f\x98\x80 \\"quoted\\"",{"k":{"j":[[]]}}]',
]

# Each reaches one rule (section 3's table); (name, message, tag).
REFUSED = [
    ("json-empty", b"", "ws.ocpp-json"),
    ("json-object", b"{}", "ws.ocpp-json"),
    ("json-trailing", b'[2,"a","B",{}]x', "ws.ocpp-json"),
    ("json-two-messages", b'[2,"a","B",{}][3,"a",{}]', "ws.ocpp-json"),
    ("json-truncated", b'[2,"a","B",{}', "ws.ocpp-json"),
    ("json-literal", b'[2,"a","B",{"a":tru}]', "ws.ocpp-json"),
    ("json-leading-zero", b'[2,"a","B",{"a":01}]', "ws.ocpp-json"),
    ("json-escape", b'[2,"a","B",{"a":"\\x"}]', "ws.ocpp-json"),
    ("json-control", b'[2,"a","B",{"a":"x\ny"}]', "ws.ocpp-json"),
    ("json-trailing-comma", b'[2,"a","B",{"a":1,}]', "ws.ocpp-json"),
    ("json-mismatch", b'[2,"a","B",{"a":[1}}]', "ws.ocpp-json"),
    ("id-single-quote", b"[2,'a','B',{}]", "ws.ocpp-id"),
    ("type-1", b'[1,"a","B",{}]', "ws.ocpp-type"),
    ("type-5", b'[5,"a","B",{}]', "ws.ocpp-type"),
    ("type-22", b'[22,"a","B",{}]', "ws.ocpp-type"),
    ("type-string", b'["2","a","B",{}]', "ws.ocpp-type"),
    ("type-float", b'[2.0,"a","B",{}]', "ws.ocpp-type"),
    ("type-none", b"[]", "ws.ocpp-type"),
    ("arity-1", b"[2]", "ws.ocpp-arity"),
    ("arity-call-3", b'[2,"a","B"]', "ws.ocpp-arity"),
    ("arity-call-5", b'[2,"a","B",{},{}]', "ws.ocpp-arity"),
    ("arity-result-4", b'[3,"a",{},{}]', "ws.ocpp-arity"),
    ("arity-error-4", b'[4,"a","C","d"]', "ws.ocpp-arity"),
    ("arity-error-6", b'[4,"a","C","d",{},{}]', "ws.ocpp-arity"),
    ("id-number", b'[2,1,"B",{}]', "ws.ocpp-id"),
    ("id-empty", b'[2,"","B",{}]', "ws.ocpp-id"),
    ("id-37", b'[2,"' + b"1" * 37 + b'","B",{}]', "ws.ocpp-id"),
    ("id-escape", b'[2,"a\\u0041","B",{}]', "ws.ocpp-id"),
    ("id-non-ascii", b'[2,"caf\xc3\xa9","B",{}]', "ws.ocpp-id"),
    ("id-null-result", b'[3,null,{}]', "ws.ocpp-id"),
    ("action-number", b'[2,"a",1,{}]', "ws.ocpp-action"),
    ("action-empty", b'[2,"a","",{}]', "ws.ocpp-action"),
    ("action-dash", b'[2,"a","Boot-Notification",{}]', "ws.ocpp-action"),
    ("action-65", b'[2,"a","' + b"A" * 65 + b'",{}]', "ws.ocpp-action"),
    ("payload-array", b'[2,"a","B",[]]', "ws.ocpp-payload"),
    ("payload-string", b'[2,"a","B","x"]', "ws.ocpp-payload"),
    ("payload-null", b'[2,"a","B",null]', "ws.ocpp-payload"),
    ("result-null", b'[3,"a",null]', "ws.ocpp-payload"),
    ("details-string", b'[4,"a","C","d","x"]', "ws.ocpp-payload"),
    ("code-number", b'[4,"a",1,"d",{}]', "ws.ocpp-code"),
    ("code-dash", b'[4,"a","C-D","d",{}]', "ws.ocpp-code"),
    ("description-number", b'[4,"a","C",1,{}]', "ws.ocpp-code"),
    ("depth-33", b'[2,"a","B",' + b'{"a":' * 33 + b"1" + b"}" * 33 + b"]", "ws.ocpp-depth"),
    ("depth-arrays", b'[2,"a","B",{"a":' + b"[" * 40 + b"]" * 40 + b"}]", "ws.ocpp-depth"),
]


# OCPP 2.1 (docs/ocpp.md section 13): the messages of types 5 and 6, valid on a connection negotiated as 2.1 and the type on any other.
VALID21 = [
    b'[5,"19223201","FormatViolation","payload does not match the schema",{}]',
    b'[5,"a","C","",{}]',
    b'[5,"77","GenericError","caf\xc3\xa9 \xe2\x82\xac \\"quoted\\"",{"k":{"j":[[]]}}]',
    b' [ 5 , "a b" , "RpcFrameworkError" , "d" , { "k" : [ 1 , -2.5e+3 , true , null ] } ] \n',
    b'[6,"19223201","NotifyPeriodicEventStream",{"id":1,"pending":0,"basetime":"2025-01-01T00:00:00Z","data":[{"t":0.0,"v":"1.5"}]}]',
    b'[6,"a","B",{}]',
    b'[6,"123456789012345678901234567890123456","Get15118EVCertificate",{"k":[1,2,{"x":null}]}]',
    b' [ 6 , "a" , "B" , { } ] ',
]

# (name, message, tag) on a 2.1 connection; each reaches one rule for types 5 and 6.
REFUSED21 = [
    ("c5-arity-4", b'[5,"a","C",{}]', "ws.ocpp-code"),
    ("c5-arity-short", b'[5,"a","C","d"]', "ws.ocpp-arity"),
    ("c5-arity-long", b'[5,"a","C","d",{},{}]', "ws.ocpp-arity"),
    ("c5-id-empty", b'[5,"","C","d",{}]', "ws.ocpp-id"),
    ("c5-id-37", b'[5,"' + b"1" * 37 + b'","C","d",{}]', "ws.ocpp-id"),
    ("c5-code-dash", b'[5,"a","C-D","d",{}]', "ws.ocpp-code"),
    ("c5-code-number", b'[5,"a",1,"d",{}]', "ws.ocpp-code"),
    ("c5-description-number", b'[5,"a","C",1,{}]', "ws.ocpp-code"),
    ("c5-details-array", b'[5,"a","C","d",[]]', "ws.ocpp-payload"),
    ("c5-details-null", b'[5,"a","C","d",null]', "ws.ocpp-payload"),
    ("c5-json", b'[5,"a","C","d",{"a":tru}]', "ws.ocpp-json"),
    ("c5-trailing", b'[5,"a","C","d",{}]x', "ws.ocpp-json"),
    ("s6-arity-3", b'[6,"a","B"]', "ws.ocpp-arity"),
    ("s6-arity-5", b'[6,"a","B",{},{}]', "ws.ocpp-arity"),
    ("s6-result-shape", b'[6,"a",{}]', "ws.ocpp-action"),
    ("s6-id-number", b'[6,1,"B",{}]', "ws.ocpp-id"),
    ("s6-action-dash", b'[6,"a","B-C",{}]', "ws.ocpp-action"),
    ("s6-action-65", b'[6,"a","' + b"A" * 65 + b'",{}]', "ws.ocpp-action"),
    ("s6-payload-array", b'[6,"a","B",[]]', "ws.ocpp-payload"),
    ("s6-json", b'[6,"a","B",{"a":01}]', "ws.ocpp-json"),
    ("s6-depth-33", b'[6,"a","B",' + b'{"a":' * 33 + b"1" + b"}" * 33 + b"]", "ws.ocpp-depth"),
    ("type-7", b'[7,"a","B",{}]', "ws.ocpp-type"),
    ("type-55", b'[55,"a","C","d",{}]', "ws.ocpp-type"),
    ("type-5-float", b'[5.0,"a","C","d",{}]', "ws.ocpp-type"),
    ("type-6-string", b'["6","a","B",{}]', "ws.ocpp-type"),
    ("type-1", b'[1,"a","B",{}]', "ws.ocpp-type"),
]

ROUTE_OF = ["/o16", "/o201", "/oboth"]


def up_close(code):
    return ft.close_masked(code)


# ---------------------------------------------------------------------------------------------------------------------- the tests


class Ocpp:
    def every_refusal_by_the_client_is_closed_with_its_code_and_stays_off_the_upstream(gw, up):
        for k, (name, msg, tag) in enumerate(REFUSED):
            prefix = ROUTE_OF[k % 3]
            path = "%s/c-%s/echo" % (prefix, name)
            n0 = len(gw.lines())
            ws = go(gw, path)
            ws.sock.sendall(cframe(1, msg))
            try:
                payload = expect_close(ws, code_for(tag), echo=False)
            except AssertionError as e:
                raise AssertionError("%s: %s" % (name, e))
            assert len(payload) == 2, (name, payload)
            assert drain(ws) == b"", name
            e = log_of(gw, n0, path)
            assert e["rule"] == tag and e["outcome"] == "aborted" and e["status"] == 101 and e["ws_close"] == code_for(tag), (name, e)
            c = up.conn(path)
            assert bytes(c.raw) == ft.CLOSE_1001_MASKED, "%s: the upstream received %r: nothing of the message, then the gateway's Close 1001" % (name, bytes(c.raw)[:80])

    def a_binary_message_is_refused_1008_at_its_header(gw, up):
        for k, msg in enumerate((VALID[0], b"", b"\x00\x01\x02")):
            path = "/o16/bin%d/echo" % k
            n0 = len(gw.lines())
            ws = go(gw, path)
            ws.sock.sendall(cframe(2, msg))
            expect_close(ws, 1008, echo=False)
            assert drain(ws) == b""
            e = log_of(gw, n0, path)
            assert e["rule"] == "ws.ocpp-binary" and e["ws_close"] == 1008, e
            assert bytes(up.conn(path).raw) == ft.CLOSE_1001_MASKED
        # a fragmented binary message: refused at the first fragment's header
        path = "/o16/binfrag/echo"
        n0 = len(gw.lines())
        ws = go(gw, path)
        ws.sock.sendall(cframe(2, VALID[3][:5], fin=False) + cframe(0, VALID[3][5:]))
        expect_close(ws, 1008, echo=False)
        e = log_of(gw, n0, path)
        assert e["rule"] == "ws.ocpp-binary", e
        # a valid message first is delivered, the binary one is not
        path = "/o16/binlate/echo"
        ws = go(gw, path)
        ws.sock.sendall(cframe(1, VALID[3]) + cframe(2, b"x"))
        expect_close(ws, 1008, echo=False)      # the echo of the valid message may or may not be delivered before the Close was decided
        c = up.conn(path)
        assert bytes(c.raw) == cframe(1, VALID[3]) + ft.close_masked(1001), bytes(c.raw)

    def every_refusal_by_the_upstream_is_1011_to_the_client_and_its_code_to_the_upstream(gw, up):
        good = sframe(1, VALID[1])
        cases = [(n, m, t) for n, m, t in REFUSED if n in ("json-empty", "json-trailing", "type-1", "arity-call-3", "id-37", "id-non-ascii", "action-dash", "payload-array",
                                                         "code-number", "depth-33", "json-literal", "arity-result-4")]
        cases.append(("binary", None, "ws.ocpp-binary"))
        for name, msg, tag in cases:
            path = "/o16/u-%s/script" % name
            bad = sframe(2, VALID[3]) if msg is None else sframe(1, msg)
            up.script[path] = good + bad
            n0 = len(gw.lines())
            ws = go(gw, path)
            want = good + bytes([0x88, 0x02, 0x03, 0xF3])
            got = bytes(ws.reader.buf)
            ws.reader.buf.clear()
            while len(got) < len(want):
                d = ws.sock.recv(65536)
                assert d, "%s: the connection ended after %r" % (name, got[:60])
                got += d
            assert got == want, "%s: the client received %r, wanted %r" % (name, got[:80], want[:80])
            ws.sock.sendall(cframe(8, ft.close_payload(1011)))
            assert drain(ws) == b"", name
            e = log_of(gw, n0, path)
            assert e["rule"] == tag and e["outcome"] == "aborted" and e["ws_close"] == 1011, (name, e)
            frames, rest = ft.up_frames(up.conn(path))
            assert rest == b"" and frames[-1][1] == 8 and code_of(frames[-1][2]) == code_for(tag), (name, frames[-3:])

    def valid_traffic_passes_byte_for_byte_whole_in_single_bytes_and_in_random_pieces(gw, up):
        rng = random.Random(7)
        for k, prefix in enumerate(ROUTE_OF * 3):
            mode = ("whole", "bytes", "random")[k // 3]
            path = "%s/v-%d-%s/echo" % (prefix, k, mode)
            n0 = len(gw.lines())
            ws = go(gw, path)
            stream = b"".join(cframe(1, m) for m in VALID)
            if mode == "whole":
                ws.sock.sendall(stream)
            else:
                i = 0
                while i < len(stream):
                    step = 1 if mode == "bytes" else rng.randrange(1, 40)
                    ws.sock.sendall(stream[i:i + step])
                    i += step
                    time.sleep(0.0002)
            for m in VALID:
                ws.expect(1, m)
            ws.sock.sendall(cframe(8, ft.close_payload(1000)))
            expect_close(ws, 1000, echo=False)
            drain(ws)
            e = log_of(gw, n0, path)
            assert e["rule"] == "" and e["outcome"] == "ok", e
            assert bytes(up.conn(path).raw).startswith(stream), "the upstream received what the client sent, byte for byte"

    def a_fragmented_message_with_pings_between_its_fragments_passes(gw, up):
        path = "/o16/frag/echo"
        n0 = len(gw.lines())
        ws = go(gw, path)
        m = VALID[7]
        cuts = [0, 1, 5, 40, len(m) - 1, len(m)]
        stream = b""
        last = 0
        for c in cuts[1:]:
            stream += cframe(1 if last == 0 else 0, m[last:c], fin=False) + cframe(9, b"p")
            last = c
        stream += cframe(0, b"", fin=True)
        ws.sock.sendall(stream)
        got = b""
        pongs = 0
        while True:
            fin, op, payload = ws.reader.frame()
            if op == 10:
                pongs += 1
            elif op in (0, 1):
                got += payload
                if fin:
                    break
        assert got == m and pongs >= 1, (got[:40], pongs)
        ws.sock.sendall(cframe(8, ft.close_payload(1000)))
        expect_close(ws, 1000, echo=False)
        e = log_of(gw, n0, path)
        assert e["rule"] == "" and e["outcome"] == "ok", e
        # the same, with the last fragment bad: the earlier fragments went on, the last did not
        path = "/o16/fragbad/echo"
        n0 = len(gw.lines())
        ws = go(gw, path)
        bad = b'[2,"a","B",{"k":tru}]'
        first = cframe(1, bad[:10], fin=False)
        ws.sock.sendall(first)
        time.sleep(0.2)
        ws.sock.sendall(cframe(0, bad[10:]))
        expect_close(ws, 1007, echo=False)
        e = log_of(gw, n0, path)
        assert e["rule"] == "ws.ocpp-json", e
        assert bytes(up.conn(path).raw) == first + ft.close_masked(1001), bytes(up.conn(path).raw)

    def a_violation_in_a_later_read_closes_the_client_but_cannot_close_the_upstream(gw, up):
        """Section 2 case 2 of the design, asserted and not hidden: the frame's first bytes have gone on, and the other side sees them and then the end."""
        path = "/obig/mid/echo"
        n0 = len(gw.lines())
        ws = go(gw, path)
        msg = b'[2,"a","B",{"k":[1,2,3,tru,5]}]' + b" " * 200
        frame = cframe(1, msg)
        head = frame[:8 + 20]                 # the header (2 + 2 + 4 bytes) and the first 20 bytes of the payload: valid so far
        ws.sock.sendall(head)
        time.sleep(0.3)
        ws.sock.sendall(frame[len(head):])
        expect_close(ws, 1007, echo=False)
        assert drain(ws) == b""
        e = log_of(gw, n0, path)
        assert e["rule"] == "ws.ocpp-json" and e["ws_close"] == 1007, e
        c = up.conn(path)
        assert bytes(c.raw) == head, "no Close can follow half a frame: the upstream got the header and the bytes that were valid, then the end"
        assert c.eof.is_set()

    def a_route_without_ws_ocpp_forwards_what_slice_two_did(gw, up):
        path = "/plainws/x/echo"
        n0 = len(gw.lines())
        ws = go(gw, path)
        sent = [(1, b"not json at all"), (1, b'[9,{"a":'), (2, VALID[0]), (1, b"")]
        for op, payload in sent:
            ws.sock.sendall(cframe(op, payload))
        for op, payload in sent:
            ws.expect(op, payload)
        ws.sock.sendall(cframe(8, ft.close_payload(1000)))
        expect_close(ws, 1000, echo=False)
        e = log_of(gw, n0, path)
        assert e["rule"] == "" and e["outcome"] == "ok", e

    def the_counters_and_the_refusal_tags(gw, up):
        gw.wait_active(0)
        m0 = gw.metrics()
        r0 = m0["refusals"]
        for name, msg, tag in (("c1", b'[2,"","B",{}]', "ws.ocpp-id"), ("c2", b"[2]", "ws.ocpp-arity"), ("c3", b"{}", "ws.ocpp-json")):
            ws = go(gw, "/o16/m-%s/echo" % name)
            ws.sock.sendall(cframe(1, msg))
            expect_close(ws, 1007, echo=False)
            drain(ws)
        up.script["/o16/m-up/script"] = sframe(1, b"[7]")
        ws = go(gw, "/o16/m-up/script")
        expect_close(ws, 1011, echo=False)
        drain(ws)
        ws = go(gw, "/o16/m-bin/echo")
        ws.sock.sendall(cframe(2, b"x"))
        expect_close(ws, 1008, echo=False)
        drain(ws)
        gw.wait_active(0)
        m1 = gw.metrics()
        assert m1["ws"]["ocpp_violations"] == m0["ws"]["ocpp_violations"] + 5, (m0["ws"], m1["ws"])
        r1 = m1["refusals"]
        for tag in ("ws.ocpp-id", "ws.ocpp-arity", "ws.ocpp-json", "ws.ocpp-binary", "ws.ocpp-type"):
            assert r1.get(tag, 0) == r0.get(tag, 0) + 1, (tag, r0, r1)
        assert m1["ws"]["closes"]["1007"] == m0["ws"]["closes"]["1007"] + 3 and m1["ws"]["closes"]["1008"] == m0["ws"]["closes"]["1008"] + 1 and \
            m1["ws"]["closes"]["1011"] == m0["ws"]["closes"]["1011"] + 1, (m0["ws"], m1["ws"])
        # an ordinary violation of RFC 6455 is not counted as an OCPP one
        ws = go(gw, "/o16/m-rsv/echo")
        ws.sock.sendall(bytes([0xC1, 0x80]) + ft.KEY)
        expect_close(ws, 1002, echo=False)
        drain(ws)
        gw.wait_active(0)
        assert gw.metrics()["ws"]["ocpp_violations"] == m1["ws"]["ocpp_violations"]
        text = socket.create_connection(("127.0.0.1", gw.admin), timeout=5)
        text.sendall(b"GET /metrics?format=prometheus HTTP/1.1\r\nHost: a\r\nAccept: text/plain\r\nConnection: close\r\n\r\n")
        data = b""
        while True:
            d = text.recv(65536)
            if not d:
                break
            data += d
        text.close()
        assert re.search(rb"cancho_gateway_ws_ocpp_violations_total [1-9][0-9]*\n", data), data[-600:]

    def a_charger_that_offers_the_other_version_is_refused_at_the_handshake(gw, up):
        raw, key = wt.request_bytes("/o201/CP1", protocols=("ocpp1.6",))
        s = wt.open_socket(gw)
        s.sendall(raw)
        head, rest = wt.read_head(s)
        assert head.startswith(b"HTTP/1.1 4"), head[:60]
        s.close()


class Ocpp21:
    """OCPP 2.1 (docs/ocpp.md section 13): message types 5 and 6 exist only on a connection whose negotiated subprotocol is `ocpp2.1`, whatever else the route allows."""

    def types_5_and_6_pass_byte_for_byte_on_a_2_1_connection_whole_in_single_bytes_and_in_random_pieces(gw, up):
        rng = random.Random(21)
        for k, mode in enumerate(("whole", "bytes", "random")):
            path = "/o21/v-%d-%s/echo" % (k, mode)
            n0 = len(gw.lines())
            ws = go(gw, path)
            assert ws.protocol == "ocpp2.1", ws.headers
            stream = b"".join(cframe(1, m) for m in VALID21 + VALID)
            if mode == "whole":
                ws.sock.sendall(stream)
            else:
                i = 0
                while i < len(stream):
                    step = 1 if mode == "bytes" else rng.randrange(1, 40)
                    ws.sock.sendall(stream[i:i + step])
                    i += step
                    time.sleep(0.0002)
            for m in VALID21 + VALID:
                ws.expect(1, m)
            ws.sock.sendall(cframe(8, ft.close_payload(1000)))
            expect_close(ws, 1000, echo=False)
            drain(ws)
            e = log_of(gw, n0, path)
            assert e["rule"] == "" and e["outcome"] == "ok", e
            assert bytes(up.conn(path).raw).startswith(stream)

    def types_5_and_6_from_the_upstream_pass_on_a_2_1_connection(gw, up):
        path = "/o21/fromup/script"
        up.script[path] = b"".join(sframe(1, m) for m in VALID21)
        n0 = len(gw.lines())
        ws = go(gw, path)
        for m in VALID21:
            ws.expect(1, m)
        ws.sock.sendall(cframe(8, ft.close_payload(1000)))
        expect_close(ws, 1000, echo=False)
        drain(ws)
        e = log_of(gw, n0, path)
        assert e["rule"] == "" and e["outcome"] == "ok", e

    def every_malformed_type_5_and_6_by_the_client_is_closed_with_its_code_and_stays_off_the_upstream(gw, up):
        for name, msg, tag in REFUSED21:
            path = "/o21/c-%s/echo" % name
            n0 = len(gw.lines())
            ws = go(gw, path)
            ws.sock.sendall(cframe(1, msg))
            try:
                expect_close(ws, code_for(tag), echo=False)
            except AssertionError as e:
                raise AssertionError("%s: %s" % (name, e))
            assert drain(ws) == b"", name
            e = log_of(gw, n0, path)
            assert e["rule"] == tag and e["outcome"] == "aborted" and e["ws_close"] == code_for(tag), (name, e)
            assert bytes(up.conn(path).raw) == ft.CLOSE_1001_MASKED, (name, bytes(up.conn(path).raw)[:80])

    def a_malformed_type_5_or_6_by_the_upstream_is_1011_to_the_client(gw, up):
        good = sframe(1, VALID21[0])
        for name, msg, tag in (("c5-details-array", b'[5,"a","C","d",[]]', "ws.ocpp-payload"), ("s6-action-dash", b'[6,"a","B-C",{}]', "ws.ocpp-action"),
                               ("type-7", b'[7,"a","B",{}]', "ws.ocpp-type")):
            path = "/o21/u-%s/script" % name
            up.script[path] = good + sframe(1, msg)
            n0 = len(gw.lines())
            ws = go(gw, path)
            want = good + bytes([0x88, 0x02, 0x03, 0xF3])
            got = bytes(ws.reader.buf)
            ws.reader.buf.clear()
            while len(got) < len(want):
                d = ws.sock.recv(65536)
                assert d, "%s: the connection ended after %r" % (name, got[:60])
                got += d
            assert got == want, (name, got[:80])
            ws.sock.sendall(cframe(8, ft.close_payload(1011)))
            assert drain(ws) == b"", name
            e = log_of(gw, n0, path)
            assert e["rule"] == tag and e["ws_close"] == 1011, (name, e)

    def types_5_and_6_are_the_type_on_a_1_6_or_2_0_1_connection(gw, up):
        for prefix in ("/o16", "/o201"):
            for name, msg in (("c5", VALID21[0]), ("s6", VALID21[4]), ("s6-min", VALID21[5]), ("c5-ws", VALID21[3])):
                path = "%s/no21-%s/echo" % (prefix, name)
                n0 = len(gw.lines())
                ws = go(gw, path)
                ws.sock.sendall(cframe(1, msg))
                expect_close(ws, 1007, echo=False)
                assert drain(ws) == b""
                e = log_of(gw, n0, path)
                assert e["rule"] == "ws.ocpp-type" and e["ws_close"] == 1007, (prefix, name, e)
                assert bytes(up.conn(path).raw) == ft.CLOSE_1001_MASKED
            # and from the upstream
            path = "%s/no21-up/script" % prefix
            up.script[path] = sframe(1, VALID21[4])
            n0 = len(gw.lines())
            ws = go(gw, path)
            expect_close(ws, 1011, echo=False)
            drain(ws)
            e = log_of(gw, n0, path)
            assert e["rule"] == "ws.ocpp-type" and e["ws_close"] == 1011, (prefix, e)

    def the_negotiated_subprotocol_decides_on_a_route_that_allows_1_6_and_2_1(gw, up):
        # the upstream picks the first token of its order that the client offered (`pref-<token>` in the path moves one to the front)
        cases = [
            # (path, offered, negotiated)
            ("/o1621/a/echo", ("ocpp1.6", "ocpp2.1"), "ocpp1.6"),
            ("/o1621/pref-ocpp2.1/b/echo", ("ocpp1.6", "ocpp2.1"), "ocpp2.1"),
            ("/o1621/c/echo", ("ocpp2.1",), "ocpp2.1"),
            ("/o1621/d/echo", ("ocpp1.6",), "ocpp1.6"),
            ("/o1621/pref-ocpp2.1/e/echo", ("ocpp1.6",), "ocpp1.6"),
            ("/oall/a/echo", ("ocpp1.6", "ocpp2.0.1", "ocpp2.1"), "ocpp1.6"),
            ("/oall/pref-ocpp2.0.1/b/echo", ("ocpp1.6", "ocpp2.0.1", "ocpp2.1"), "ocpp2.0.1"),
            ("/oall/pref-ocpp2.1/c/echo", ("ocpp1.6", "ocpp2.0.1", "ocpp2.1"), "ocpp2.1"),
            ("/oall/d/echo", ("ocpp2.1",), "ocpp2.1"),
            ("/oall/e/echo", ("ocpp2.0.1",), "ocpp2.0.1"),
        ]
        for path, offered, negotiated in cases:
            for msg in (VALID21[0], VALID21[4]):
                p = path.replace("/echo", "-%s/echo" % msg[1:2].decode())
                n0 = len(gw.lines())
                ws = wt.connect_ws(gw, p, protocols=offered)
                assert ws.protocol == negotiated, (p, offered, ws.protocol)
                ws.sock.sendall(cframe(1, msg))
                if negotiated == "ocpp2.1":
                    ws.expect(1, msg)
                    ws.sock.sendall(cframe(8, ft.close_payload(1000)))
                    expect_close(ws, 1000, echo=False)
                    drain(ws)
                    e = log_of(gw, n0, p)
                    assert e["rule"] == "" and e["outcome"] == "ok", (p, e)
                else:
                    expect_close(ws, 1007, echo=False)
                    assert drain(ws) == b""
                    e = log_of(gw, n0, p)
                    assert e["rule"] == "ws.ocpp-type" and e["ws_close"] == 1007, (p, negotiated, e)
                    assert bytes(up.conn(p).raw) == ft.CLOSE_1001_MASKED, (p, bytes(up.conn(p).raw)[:80])

    def a_1_6_message_first_does_not_make_the_connection_1_6_nor_2_1(gw, up):
        # the version is the connection's, not the first message's: a 1.6 CALL is valid on both, and the next message is judged by the negotiated version
        for path, ok in (("/o1621/seq-a/echo", False), ("/o1621/pref-ocpp2.1/seq-b/echo", True)):
            n0 = len(gw.lines())
            ws = wt.connect_ws(gw, path, protocols=("ocpp1.6", "ocpp2.1"))
            ws.sock.sendall(cframe(1, VALID[3]) + cframe(1, VALID21[5]) + cframe(1, VALID[4]))
            if ok:
                ws.expect(1, VALID[3])
                ws.expect(1, VALID21[5])
                ws.expect(1, VALID[4])
                ws.sock.sendall(cframe(8, ft.close_payload(1000)))
                expect_close(ws, 1000, echo=False)
                drain(ws)
            else:
                expect_close(ws, 1007, echo=False)      # the echo of the first message may or may not come before the Close (section 11)
                drain(ws)
            e = log_of(gw, n0, path)
            assert e["rule"] == ("" if ok else "ws.ocpp-type"), (path, e)
            c = bytes(up.conn(path).raw)
            assert c.startswith(cframe(1, VALID[3])) and (ok or c == cframe(1, VALID[3]) + ft.CLOSE_1001_MASKED), (path, c[:80])

    def a_2_1_message_fragmented_with_pings_between_its_fragments_passes_and_a_binary_one_is_refused(gw, up):
        path = "/o21/frag/echo"
        n0 = len(gw.lines())
        ws = go(gw, path)
        m = VALID21[4]
        stream = cframe(1, m[:2], fin=False) + cframe(9, b"p") + cframe(0, m[2:30], fin=False) + cframe(9, b"p") + cframe(0, m[30:])
        ws.sock.sendall(stream)
        got = b""
        while True:
            fin, op, payload = ws.reader.frame()
            if op in (0, 1):
                got += payload
                if fin:
                    break
        assert got == m
        ws.sock.sendall(cframe(8, ft.close_payload(1000)))
        expect_close(ws, 1000, echo=False)
        assert log_of(gw, n0, path)["rule"] == ""
        path = "/o21/bin/echo"
        n0 = len(gw.lines())
        ws = go(gw, path)
        ws.sock.sendall(cframe(2, m))
        expect_close(ws, 1008, echo=False)
        assert log_of(gw, n0, path)["rule"] == "ws.ocpp-binary"

    def the_counter_counts_a_refused_2_1_message_and_nothing_else_changes(gw, up):
        gw.wait_active(0)
        m0 = gw.metrics()
        ws = go(gw, "/o1621/cnt/echo")        # negotiated 1.6 (the upstream's default order)
        assert ws.protocol == "ocpp1.6"
        ws.sock.sendall(cframe(1, VALID21[4]))
        expect_close(ws, 1007, echo=False)
        drain(ws)
        ws = go(gw, "/o21/cnt/echo")
        ws.sock.sendall(cframe(1, VALID21[4]))
        ws.expect(1, VALID21[4])
        ws.sock.sendall(cframe(8, ft.close_payload(1000)))
        expect_close(ws, 1000, echo=False)
        drain(ws)
        gw.wait_active(0)
        m1 = gw.metrics()
        assert m1["ws"]["ocpp_violations"] == m0["ws"]["ocpp_violations"] + 1, (m0["ws"], m1["ws"])
        assert m1["refusals"].get("ws.ocpp-type", 0) == m0["refusals"].get("ws.ocpp-type", 0) + 1

    def the_handshake_still_admits_only_the_routes_tokens(gw, up):
        for path, offered in (("/o21/x", ("ocpp1.6",)), ("/o21/x", ("ocpp2.0.1",)), ("/o16/x", ("ocpp2.1",)), ("/o201/x", ("ocpp2.1",)), ("/o1621/x", ("ocpp2.0.1",)),
                              ("/o1621/x", ("ocpp2.2",)), ("/o21/x", ("OCPP2.1",)), ("/o21/x", ("ocpp2.1.0",))):
            raw, key = wt.request_bytes(path, protocols=offered)
            s = wt.open_socket(gw)
            s.sendall(raw)
            head, rest = wt.read_head(s)
            assert head.startswith(b"HTTP/1.1 4"), (path, offered, head[:60])
            s.close()


def differential(gw, up, prefix, v21, seed, corpus, extra_shapes, rounds):
    """The gateway's verdict and tag on `prefix` (a route negotiated as 2.1 if `v21`) equal the reference's on every mutation of `corpus`."""
    if True:
        rng = random.Random(seed)
        pool = [b"[", b"]", b"{", b"}", b",", b'"', b":", b"\\", b"0", b"-", b"e", b"x", b" ", b"2", b"4", b"9", b".", b"\n", b"\xc3\xa9", b"t", b"n", b"u", b"E", b"+"]
        cases = list(corpus)
        for base in corpus:
            for i in range(len(base)):
                if base[i] < 128:
                    cases.append(base[:i] + base[i + 1:])
        for _ in range(rounds):
            base = rng.choice(corpus)
            m = bytearray(base)
            for _ in range(rng.choice((1, 1, 1, 2, 3))):
                if not m:
                    break
                i = rng.randrange(len(m) + 1)
                how = rng.randrange(3)
                if how == 0 and i < len(m) and m[i] < 128:
                    m[i:i + 1] = rng.choice(pool)
                elif how == 1:
                    m[i:i] = rng.choice(pool)
                elif i < len(m) and m[i] < 128:
                    del m[i]
            try:
                bytes(m).decode("utf-8")
            except UnicodeDecodeError:
                continue
            cases.append(bytes(m))
        # a few of the shapes that mutation does not reach
        cases += extra_shapes
        for i in range(0, 4):
            cases += [bytes(rng.randrange(32, 127) for _ in range(rng.randrange(0, 30))) for _ in range(40)]
        seen = set()
        todo = []
        for m in cases:
            if m not in seen:
                seen.add(m)
                todo.append(m)
        n0 = len(gw.lines())
        results = {}

        def probe(i):
            m = todo[i]
            path = "%s/d%d/echo" % (prefix, i)
            for attempt in range(3):
                try:
                    ws = go(gw, path)
                    ws.sock.sendall(cframe(1, m))
                    while True:
                        fin, op, payload = ws.reader.frame()
                        if op == 8:
                            results[i] = ("close", code_of(payload))
                            break
                        if op == 1:
                            results[i] = ("echo", payload)
                            ws.sock.sendall(cframe(8, ft.close_payload(1000)))
                            break
                    ws.sock.settimeout(3)
                    try:
                        while ws.sock.recv(65536):
                            pass
                    except OSError:
                        pass
                    ws.sock.close()
                    return
                except (OSError, EOFError, AssertionError):
                    time.sleep(0.05)
            results[i] = ("error", None)

        with ThreadPoolExecutor(max_workers=8) as pool_:
            list(pool_.map(probe, range(len(todo))))
        deadline = time.time() + 15
        tags = {}
        while time.time() < deadline:
            tags = {l["path"]: l["rule"] for l in gw.lines()[n0:] if l.get("path", "").startswith(prefix + "/d")}
            if len(tags) >= len(todo):
                break
            time.sleep(0.1)
        valid = invalid = 0
        by_tag = {}
        for i, m in enumerate(todo):
            want = ref(m, v21)
            kind, got = results[i]
            try:
                strict_loads(m)
                loads_ok = True
            except ValueError:      # includes UnicodeDecodeError
                loads_ok = False
            if want is None:
                assert loads_ok, ("the reference accepts what json.loads refuses", m)
                shape = strict_loads(m)
                assert isinstance(shape, list) and type(shape[0]) is int and shape[0] in ((2, 3, 4, 5, 6) if v21 else (2, 3, 4)) and len(shape) == {2: 4, 3: 3, 4: 5, 5: 5, 6: 4}[shape[0]], ("not OCPP-J", m)
                assert kind == "echo" and got == m, ("the reference accepts, the gateway did not", m, kind, got)
                assert tags.get("%s/d%d/echo" % (prefix, i)) == "", (m, tags.get("%s/d%d/echo" % (prefix, i)))
                valid += 1
            else:
                assert kind == "close" and got == code_for(want), ("the reference refuses (%s), the gateway did not agree" % want, m, kind, got)
                assert tags.get("%s/d%d/echo" % (prefix, i)) == want, ("the tag", m, want, tags.get("%s/d%d/echo" % (prefix, i)))
                invalid += 1
                by_tag[want] = by_tag.get(want, 0) + 1
            if not loads_ok:
                assert want is not None, ("json.loads refuses and the reference accepts", m)
        assert valid > 100 and invalid > (1000 if rounds > 1000 else 300), (valid, invalid)
        for tag in ("ws.ocpp-json", "ws.ocpp-type", "ws.ocpp-arity", "ws.ocpp-id", "ws.ocpp-action", "ws.ocpp-payload", "ws.ocpp-code", "ws.ocpp-depth"):
            assert by_tag.get(tag, 0) > 0, ("the corpus never reached", tag, by_tag)
        print("      %s: %d messages: %d accepted, %d refused %s" % (prefix, len(todo), valid, invalid, json.dumps(by_tag, sort_keys=True)))
        return by_tag




SHAPES = [b'[2,"a","B",' + b'{"a":' * d + b"1" + b"}" * d + b"]" for d in (1, 31, 32, 33)] + [b'[2,"a","B",{"a":' + b"[" * d + b"]" * d + b"}]" for d in (30, 31, 32)]
SHAPES21 = [b'[6,"a","B",' + b'{"a":' * d + b"1" + b"}" * d + b"]" for d in (1, 31, 32, 33)] + [b'[5,"a","C","d",' + b'{"a":' * d + b"1" + b"}" * d + b"]" for d in (31, 32, 33)]


class Differential:
    def the_gateway_and_the_reference_agree_on_mutated_messages(gw, up):
        differential(gw, up, "/o16", False, 20261012, VALID, SHAPES, 1800)

    def on_a_2_1_connection_the_gateway_and_the_reference_agree_on_mutated_messages_of_types_2_to_6(gw, up):
        by_tag = differential(gw, up, "/o21", True, 20261013, VALID + VALID21, SHAPES + SHAPES21, 1800)
        assert by_tag.get("ws.ocpp-type", 0) > 0

    def a_1_6_connection_agrees_with_the_reference_that_has_no_types_5_and_6(gw, up):
        # the same 2.1 corpus on a route that is not 2.1: the reference without v21 (everything that begins with 5 or 6 is the type)
        differential(gw, up, "/o16", False, 20261014, VALID + VALID21, SHAPES + SHAPES21, 1200)

    def a_2_0_1_connection_agrees_with_the_reference_that_has_no_types_5_and_6(gw, up):
        differential(gw, up, "/o201", False, 20261015, VALID + VALID21, SHAPES + SHAPES21, 1200)


def main():
    groups = {"Ocpp": Ocpp, "Ocpp21": Ocpp21, "Differential": Differential}
    wanted = sys.argv[1:]
    todo = []
    for gname, cls in groups.items():
        for name in vars(cls):
            if name.startswith("_") or not callable(getattr(cls, name)) or name.isupper():
                continue
            if not wanted or name in wanted or gname in wanted:
                todo.append((gname, cls, name))
    unknown = [w for w in wanted if not any(w == t[2] or w == t[0] for t in todo)]
    if unknown:
        print("no such test: %s" % ", ".join(unknown))
        return 2
    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        up = ft.Upstream(pt.free_port())
        gw = wt.Gateway(tmp, up.port, pt.free_port(), close_ms=1500, routes=ROUTES)
        try:
            for gname, cls, name in todo:
                t0 = time.time()
                try:
                    getattr(cls, name)(gw, up)
                    if not gw.alive():
                        raise AssertionError("the gateway died")
                    print("ok    %-96s %.1fs" % (name, time.time() - t0))
                except (AssertionError, OSError, EOFError, KeyError, IndexError, ValueError) as e:
                    failures += 1
                    print("FAIL  %-96s %s: %s" % (name, type(e).__name__, str(e)[:600]))
                    if os.environ.get("WS_TRACE"):
                        traceback.print_exc()
                    if not gw.alive():
                        print("      the gateway died: exit %s %s" % (gw.proc.returncode, gw.proc.stderr.read()[:300]))
                        break
        finally:
            gw.stop()
            up.shutdown()
    print("%d tests, %d failures" % (len(todo), failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
