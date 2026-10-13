#!/usr/bin/env python3
"""Mutants of JWT verification (docs/jwt.md section 11, gate 6): copy the tree, apply one single edit, run the tests that should notice it.

    python3 tests/jwt_mutants.py [-j N] [ID ...]      # all mutants, or the named ones; N at a time (default 3)

A mutant is KILLED when a test fails, SURVIVED when none does (every test is then run, to be sure: the unit tests, the generator's, the end-to-end test and the differential),
INVALID when the edited tree does not build (the edit is then wrong, not the tests). The output is the table section 13 of the document records. Needs `build/deps` filled by one
`cancho build`. An edit is one (old, new) pair, or a list of pairs when one idea needs two places. A mutant listed in ARGUED is expected to SURVIVE, and the document says why.

How each is killed first: ("unit", suite) runs `cancho test --test suite`; "gen" the generator tests (which run mkjwt.py too); "diff" the differential against OpenSSL; a list of names the
end-to-end tests of tests/jwt_test.py (the whole file follows if those pass).
"""

import concurrent.futures
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
LEX = os.environ.get("CANCHO", "cancho")

M = []
ARGUED = {}


def m(ident, path, edit, *rest):
    if isinstance(edit, str):
        old, (new, kill, what) = edit, rest
        M.append((ident, path, [(old, new)], kill, what))
    else:
        kill, what = rest
        M.append((ident, path, edit, kill, what))


U = ("unit", "jwt")
J = "src/jwt.cho"
# ---- base64url
m("b01", J, "    if c >= 'A' && c <= 'Z' {", "    if c >= 'A' && c <= 'Y' {", U, "'Z' is not in the alphabet")
m("b02", J, "        return c - 'a' + 26;", "        return c - 'a' + 27;", U, "lower case letters are one too high")
m("b03", J, "        return c - '0' + 52;", "        return c - '0' + 53;", U, "digits are one too high")
m("b04", J, "    if c == '-' {\n        return 62;", "    if c == '-' {\n        return 63;", U, "'-' is 63")
m("b05", J, "    if c == '_' {\n        return 63;", "    if c == '_' || c == '+' {\n        return 63;", U, "'+' is accepted")
m("b06", J, "    if c == '-' {\n        return 62;", "    if c == '-' || c == '/' {\n        return 62;", U, "'/' is accepted")
m("b07", J, "    if rem == 1 {\n        return false;", "    if rem == 5 {\n        return false;", U, "a length of 1 modulo 4 is accepted")
m("b08", J, "if rem == 2 && b64_value(int_of(s[len(s) - 1])) % 16 != 0 {", "if rem == 2 && b64_value(int_of(s[len(s) - 1])) % 32 != 0 {", U, "two characters may carry non-zero spare bits")
m("b09", J, "if rem == 3 && b64_value(int_of(s[len(s) - 1])) % 4 != 0 {", "if rem == 3 && b64_value(int_of(s[len(s) - 1])) % 8 != 0 {", U, "three characters may carry non-zero spare bits")
m("b10", J, "    let n = len(s) / 4 * 3 + len(s) % 4 * 3 / 4;", "    let n = len(s) / 4 * 3 + len(s) % 4 * 2 / 4;", U, "a tail of three characters is one byte")
m("b11", J, "b64_value(int_of(s[i])) * 262144 +", "b64_value(int_of(s[i])) * 262143 +", U, "the first character of a group is mis-weighted")
m("b12", J, "        out[o + 1] = byte_of(v / 256 % 256);", "        out[o + 1] = byte_of(v / 128 % 256);", U, "the middle byte of a group is shifted")
m("b13", J, "        out[o + 1] = byte_of(v / 4 % 256);", "        out[o + 1] = byte_of(v / 8 % 256);", U, "the second byte of a three-character tail is shifted")
m("b14", J, "    return bytes.count_byte(s, '.');", "    return bytes.count_byte(s, ',');", U, "dots are commas")
m("b15", J, "    if len(out) < n {\n        return 0 - 1;\n    }", "", U, "a short buffer is written past")
# ---- the header
m("h01", J, "bytes.to_lower(int_of(a[i])) != int_of(lower[i])", "int_of(a[i]) != int_of(lower[i])", U, "typ is case-sensitive")
m("h02", J, "        if auth.allowed(allowed, index) {\n            open = open + 1;", "        if true {\n            open = open + 1;", U, "a route's key list is ignored")
m("h03", J, "    if open == 1 {\n        return only;", "    if open >= 1 {\n        return only;", U, "a token with no kid picks the last of several keys")
m("h04", J, "    if open == 1 {\n        return only;", "    if open == 1 {\n        return open;", U, "a token with no kid always picks the first key")
m("h05", J, '    if alg < 0 || !json.string_equals(doc, tape, alg, "EdDSA") {', "    if alg < 0 {", U, "any algorithm is accepted")
m("h06", J, '    if json.get(doc, tape, 0, "crit") >= 0 {', '    if json.get(doc, tape, 0, "crit") >= 1000 {', U, "crit is ignored")
m("h07", J, "    if typ >= 0 && !lower_equals(", "    if typ >= 1000 && !lower_equals(", U, "typ is ignored")
m("h08", J, '        return 0 - 2;\n    }\n    if json.get(doc, tape, 0, "crit")', '        return 0 - 1;\n    }\n    if json.get(doc, tape, 0, "crit")', U, "a wrong algorithm is malformed")
m("h09", J, "    let key = pick_key(doc, tape, keys, allowed);\n    if key == 0 {\n        return 0 - 4;\n    }", "    let key = pick_key(doc, tape, keys, allowed);\n    if key == 0 {\n        return 0 - 1;\n    }", U, "an unknown kid is malformed")
m("h10", J, "        let buf = alloc_slice[r](192, byte_of(0));", "        let buf = alloc_slice[r](191, byte_of(0));", U, "a header of 192 bytes does not fit")
m("h11", J, "            if kid >= 0 && json.string_equals(doc, tape, kid, auth.name_in(keys, index)) && found == 0 {", "            if kid >= 0 && json.string_equals(doc, tape, kid, auth.name_in(keys, index)) {", U, "the last key of that name wins")
# ---- the claims
m("c01", J, "    if exp < 0 || nbf == 0 - 2 || iat == 0 - 2 {", "    if exp < 0 || nbf == 0 - 2 {", U, "iat that is not an integer is accepted")
m("c02", J, "    if exp < 0 || nbf == 0 - 2 || iat == 0 - 2 {", "    if exp < 0 || iat == 0 - 2 {", U, "nbf that is not an integer is accepted")
m("c03", J, "    if exp < 0 || nbf == 0 - 2 || iat == 0 - 2 {", "    if exp < 0 - 1 || nbf == 0 - 2 || iat == 0 - 2 {", U, "a missing exp is accepted as expired, not as malformed claims")
m("c04", J, "    if l > max_leeway() {\n        l = max_leeway();", "    if l > max_leeway() + 1000000 {\n        l = max_leeway();", U, "the leeway is unbounded")
m("c05", J, "    if l < 0 {\n        l = 0;", "    if l < 0 - 1000 {\n        l = 0;", U, "a negative leeway shortens a token's life")
m("c07", J, "    if t < clock_floor() {", "    if t < 0 {", U, "a clock before the floor is believed")
m("c08", J, "    if t >= exp + l {", "    if t > exp + l {", U, "a token is valid in the second of its exp")
m("c09", J, "    if t + l < nbf {", "    if t + l <= nbf {", U, "a token is not valid in the second of its nbf")
m("c10", J, "    if t >= exp + l {", "    if t >= exp {", U, "the leeway does not extend exp")
m("c11", J, "    if t + l < nbf {", "    if t < nbf {", U, "the leeway does not bring nbf forward")
m("c12", J, "    if len(iss) > 0 && !json_claims.string_claim_is(doc, tape, \"iss\", iss) {", "    if !json_claims.string_claim_is(doc, tape, \"iss\", iss) {", U, "an unconfigured issuer is required to be empty")
m("c13", J, "    if len(iss) > 0 && !json_claims.string_claim_is(doc, tape, \"iss\", iss) {", "    if false {", U, "the issuer is not checked")
m("c14", J, "    if len(aud) > 0 && !json_claims.audience_is(doc, tape, aud) {", "    if false {", U, "the audience is not checked")
m("c15", J, "    if len(aud) > 0 && !json_claims.audience_is(doc, tape, aud) {", "    if !json_claims.audience_is(doc, tape, aud) {", U, "an unconfigured audience is required to be empty")
m("c16", J, "        return 0 - 9;\n    }\n    if len(aud)", "        return 0 - 8;\n    }\n    if len(aud)", U, "a wrong issuer is called a wrong audience")
m("c17", J, "        let buf = alloc_slice[r](1024, byte_of(0));", "        let buf = alloc_slice[r](1023, byte_of(0));", U, "a payload of 1,024 bytes does not fit")
m("c18", J, "    return 1788220800;", "    return 1788220800 + 100000000;", U, "the floor is in the future")
m("c19", J, "    return 60;\n}", "    return 61;\n}", U, "the leeway may be 61")
# ---- the signature and the order
m("s01", J, "            ok = ed25519.verify(pk, msg, sig) == 1;", "            ok = ed25519.verify(pk, msg, sig) >= 0;", U, "every signature verifies")
m("s02", J, "    if !signature_ok(cred[0..d2], sseg, keys, key - 1) {", "    if !signature_ok(cred[0..d2 + 1], sseg, keys, key - 1) {", U, "the dot before the signature is signed too")
m("s03", J, "    if !signature_ok(cred[0..d2], sseg, keys, key - 1) {", "    if !signature_ok(cred[0..d2], sseg, keys, key) {", U, "the next key verifies")
m("s04", J, "        return 0 - 11;\n    }\n    return key;", "        return 0 - 11;\n    }\n    return 1;", U, "every token is key 1")
m("s05", J, "if b64url_decode(bytes.field(auth.line_in(keys, index), 9, 2), pk) == 32 &&", "if b64url_decode(bytes.field(auth.line_in(keys, index), 9, 2), pk) >= 0 &&", U, "a key that is not 32 bytes verifies as if it were")
m("s06", J, "    let claims = claims_check(pseg, aud, iss, leeway, now);\n    if claims < 0 {\n        return claims;\n    }\n    if !signature_ok(cred[0..d2], sseg, keys, key - 1) {\n        return 0 - 11;\n    }",
  "    if !signature_ok(cred[0..d2], sseg, keys, key - 1) {\n        return 0 - 11;\n    }\n    let claims = claims_check(pseg, aud, iss, leeway, now);\n    if claims < 0 {\n        return claims;\n    }", U, "the signature is checked before the claims")
m("s07", J, "    if len(sseg) != signature_segment() || !b64url_valid(sseg) {", "    if !b64url_valid(sseg) {", U, "a signature of the wrong length is a signature failure")
m("s08", J, "    if len(sseg) != signature_segment() || !b64url_valid(sseg) {", "    if len(sseg) != signature_segment() {", U, "a non-canonical signature is a signature failure")
m("s09", J, "    let key = header_check(hseg, keys, allowed);\n    if key < 0 {\n        return key;\n    }", "    let key = header_check(hseg, keys, allowed);\n    if key < 0 {\n        return 0 - 1;\n    }", U, "every header refusal is malformed")
m("s10", J, "    if claims < 0 {\n        return claims;\n    }", "    if claims < 0 {\n        return 0 - 1;\n    }", U, "every claim refusal is malformed")
m("s11", J, '        return "jwt.expired";', '        return "jwt.nbf";', U, "expired is called nbf")
m("s12", J, '        return "not_yet_valid";', '        return "nbf";', U, "not_yet_valid is called nbf")
# the redundancies of verify: every one is a second line behind a first (the document says which)
m("r01", J, "    if len(cred) > max_token() || dots(cred) != 2 {", "    if len(cred) > max_token() + 100000 || dots(cred) != 2 {", U, "the whole-token cap is gone (the segment caps imply 1,710 bytes)")
m("r02", J, "    if len(hseg) < 1 || len(pseg) < 1 || len(hseg) > max_header_segment() || len(pseg) > max_payload_segment() {", "    if len(hseg) < 0 || len(pseg) < 0 || len(hseg) > max_header_segment() || len(pseg) > max_payload_segment() {", U, "an empty segment reaches the decoder")
m("r03", J, "    if len(hseg) < 1 || len(pseg) < 1 || len(hseg) > max_header_segment() || len(pseg) > max_payload_segment() {", "    if len(hseg) < 1 || len(pseg) < 1 || len(hseg) > max_header_segment() + 50 || len(pseg) > max_payload_segment() + 50 {", U, "the segment caps are loose (the buffers cut them)")
m("r04", J, "    if len(cred) > max_token() || dots(cred) != 2 {", "    if len(cred) > max_token() || dots(cred) < 2 {", U, "three dots are read as two")
m("r05", J, "if b64url_decode(bytes.field(auth.line_in(keys, index), 9, 2), pk) == 32 && b64url_decode(sseg, sig) == 64 {", "if b64url_decode(bytes.field(auth.line_in(keys, index), 9, 2), pk) == 32 && b64url_decode(sseg, sig) >= 0 {", U, "a signature that is not 64 bytes is read")
ARGUED.update({
    "h11": "two keys cannot share a name (rule 17), so there is never a second match for `found == 0` to ignore",
    "r01": "the segment caps bound a token at 256 + 1 + 1,366 + 1 + 86 = 1,710 bytes: the whole-token cap of 2,048 is a second line that also stops a scan of a 16 KiB credential",
    "r02": "an empty header or payload decodes to nothing and `n > 0` refuses it as malformed, the tag the guard gives",
    "r03": "a longer segment decodes past the 192- and 1,024-byte buffers, which `b64url_decode` refuses as malformed, the tag the cap gives",
    "r04": "a token with three dots has a fourth segment, which the signature's own length and alphabet checks refuse as malformed",
    "r05": "the signature segment is exactly 86 canonical characters by then: it always decodes to 64 bytes",
})

C = "src/json_claims.cho"
CU = ("unit", "jwt")
m("j01", C, "    return 4;\n}", "    return 5;\n}", CU, "nesting may be 5 deep")
m("j02", C, "            } else if c == '\\\\' {\n                escaped = true;", "            } else if c == '\\\\' && false {\n                escaped = true;", CU, "an escaped quote ends a string for the depth count")
m("j03", C, "        } else if (c == ']' || c == '}') && depth > 0 {", "        } else if (c == ']' || c == '}') && depth > 100 {", CU, "closing a bracket does not lower the depth")
m("j04", C, "(json.count(tape, i) > max_members() ||", "(json.count(tape, i) > max_members() + 1 ||", CU, "65 members are accepted")
m("j05", C, "if lens[x] == lens[y] && bytes.equal(", "if lens[x] == lens[y] + 1 && bytes.equal(", CU, "a repeated name is not found")
m("j06", C, "            var y = x + 1;", "            var y = x + 2;", CU, "neighbouring names are not compared")
m("j07", C, "|| json.kind(tape, 0) != json.kind_object() {", "{", CU, "a root that is not an object is accepted")
m("j08", C, "    while i < nodes {\n        if json.kind(tape, i) == json.kind_object()", "    while i < 1 {\n        if json.kind(tape, i) == json.kind_object()", CU, "only the root object is checked for repeated names")
m("j09", C, "    if !json.fits_int(src, tape, at) {\n        return 0 - 2;\n    }", "", CU, "a float is an integer")
m("j10", C, "    if v < 0 || v > max_time() {", "    if v > max_time() {", CU, "a negative time is a time")
m("j11", C, "    if v < 0 || v > max_time() {", "    if v < 0 || v > max_time() + 1 {", CU, "the year 10000 is a time")
m("j12", C, "    if !json.is_array(tape, at) || json.count(tape, at) > 16 {", "    if !json.is_array(tape, at) || json.count(tape, at) > 17 {", CU, "an audience array may have 17 elements")
m("j13", C, "        if !json.is_string(tape, e) {\n            return false;\n        }\n", "", CU, "a non-string in an audience array is skipped")
m("j14", C, "    if json.is_string(tape, at) {\n        return json.string_equals(src, tape, at, want);\n    }", "", CU, "a string audience is no audience")
m("j15", C, "    return json.string_equals(src, tape, at, want);\n    }\n    if !json.is_array", "    return !json.string_equals(src, tape, at, want);\n    }\n    if !json.is_array", CU, "a string audience matches when it differs")
m("j16", C, "    if len(tape) < json.tape_len(src) || depth_of(src) > max_depth() {", "    if len(tape) < json.tape_len(src) {", CU, "nesting is not bounded")
ARGUED["j17"] = "the tape's length is checked twice: `json.parse` answers a negative code when the tape is too small, and `nodes < 1` refuses it with the same answer"
m("j17", C, "    if len(tape) < json.tape_len(src) || depth_of(src) > max_depth() {", "    if depth_of(src) > max_depth() {", CU, "a tape that is too small is not checked first")
ARGUED["j18"] = "a name longer than the slab's 64 bytes is also refused by `string_into` (it answers -1 when its output is too short), so the explicit length test is a second line"
m("j18", C, "            if l < 0 || l > max_name() {", "            if l < 0 || l > max_name() + 1000 {", CU, "the name length is not tested before decoding")

N = "src/metrics.cho"
NU = ("unit", "metrics")
m("n01", N, "        let at = route_index * route_block() + 28 + rule;", "        let at = route_index * route_block() + 29 + rule;", NU, "the JWT counters are one slot too far")
m("n02", N, "    if route_index >= 0 && route_index < routes() && rule >= 1 && rule <= 11 {", "    if route_index >= 0 && route_index < routes() && rule >= 1 && rule <= 12 {", NU, "a twelfth kind is written past the counters")
m("n03", N, "            k = jnum(out, k, jwt_kind(j), stats[base + 29 + j]);", "            k = jnum(out, k, jwt_kind(j), stats[base + 28 + j]);", NU, "the JSON shows each counter under its neighbour's name")
m("n04", N, '            k = sample2(out, k, "jwt_refused_total", "route", route.name(i), "kind", jwt_kind(a), stats[i * route_block() + 29 + a]);', '            k = sample2(out, k, "jwt_refused_total", "route", route.name(i), "kind", jwt_kind(a), stats[i * route_block() + 30 + a]);', NU, "the Prometheus text shows each counter under its neighbour's name")
m("n05", N, '        return "not_yet_valid";', '        return "nbf";', NU, "a kind has another name")
m("n06", N, "fn route_block() -> [] int {\n    return 48;", "fn route_block() -> [] int {\n    return 40;", NU, "the route block is too small for the counters")

P = "src/proxy.cho"
SL = "src/slots.cho"
E = lambda *names: list(names)
m("p01", P, "        if route.auth(sel) == 2 || route.auth(sel) == 3 && jwt.dots(cred) == 2 {", "        if route.auth(sel) == 2 {", E("a_route_that_takes_both_kinds_decides_by_the_shape_and_never_falls_back"), "a route that takes both kinds never reads a token")
m("p02", P, "        if route.auth(sel) == 2 || route.auth(sel) == 3 && jwt.dots(cred) == 2 {", "        if route.auth(sel) >= 2 {", E("a_route_that_takes_both_kinds_decides_by_the_shape_and_never_falls_back"), "a route that takes both kinds never reads an API key")
m("p03", P, "route.auth(sel) == 3 && jwt.dots(cred) == 2 {", "route.auth(sel) == 3 && jwt.dots(cred) >= 1 {", E("a_route_that_takes_both_kinds_decides_by_the_shape_and_never_falls_back"), "one dot makes a token")
m("p04", P, "(contents(core.ids)[2] + now) / 1000);", "now / 1000);", E("a_valid_token_passes_and_the_credential_is_not_forwarded"), "the clock is the gateway's uptime")
m("p05", P, "(contents(core.ids)[2] + now) / 1000);", "(contents(core.ids)[2] + now) / 1024);", E("a_valid_token_passes_and_the_credential_is_not_forwarded", "the_leeway_is_a_margin_on_exp_and_nbf_and_nothing_else"), "a second is 1,024 ms")
m("p06", P, 'slots.refuse_as(tab, core, k, 401, "auth.invalid", jwt.tag(0 - verdict), now);', "slots.refuse_as(tab, core, k, 401, jwt.tag(0 - verdict), jwt.tag(0 - verdict), now);", E("every_invalid_token_is_refused_with_the_same_response_and_its_own_tag_in_the_log"), "the client is told the cause")
m("p07", P, 'slots.refuse_as(tab, core, k, 401, "auth.invalid", jwt.tag(0 - verdict), now);', 'slots.refuse_as(tab, core, k, 401, "auth.invalid", "auth.invalid", now);', E("every_invalid_token_is_refused_with_the_same_response_and_its_own_tag_in_the_log"), "the log does not say the cause")
m("p08", P, "                metrics.jwt_refused(contents(core.stats), sel, 0 - verdict);\n", "", E("the_counters_agree_with_what_the_clients_were_told"), "a refused token is not counted")
m("p09", P, "metrics.jwt_refused(contents(core.stats), sel, 0 - verdict);", "metrics.jwt_refused(contents(core.stats), sel, 1);", E("the_counters_agree_with_what_the_clients_were_told"), "every refused token is counted as malformed")
m("p10", P, "            st[p + shared.auth_slot()] = 100 + verdict;", "            st[p + shared.auth_slot()] = verdict;", E("a_valid_token_passes_and_the_credential_is_not_forwarded"), "the identity of a token is an API key's")
m("p11", P, "        cap = jwt.credential_cap();", "        cap = jwt.max_token();", E("every_invalid_token_is_refused_with_the_same_response_and_its_own_tag_in_the_log"), "an oversize token is a malformed header")
m("p12", P, "route.jwt_keys(sel), route.jwt_aud(sel), route.jwt_iss(sel), route.jwt_leeway(sel),", 'route.jwt_keys(sel), "", route.jwt_iss(sel), route.jwt_leeway(sel),', E("a_token_valid_for_one_route_is_refused_on_a_route_with_another_audience"), "no route requires an audience")
m("p13", P, "route.jwt_keys(sel), route.jwt_aud(sel), route.jwt_iss(sel), route.jwt_leeway(sel),", 'route.jwt_keys(sel), route.jwt_aud(sel), "", route.jwt_leeway(sel),', E("a_token_valid_for_one_route_is_refused_on_a_route_with_another_audience"), "no route requires an issuer")
m("p14", P, "route.jwt_keys(sel), route.jwt_aud(sel), route.jwt_iss(sel), route.jwt_leeway(sel),", "route.jwt_keys(sel), route.jwt_aud(sel), route.jwt_iss(sel), 0,", E("the_leeway_is_a_margin_on_exp_and_nbf_and_nothing_else"), "no route has leeway")
m("p15", P, "route.jwt_keys(sel), route.jwt_aud(sel), route.jwt_iss(sel), route.jwt_leeway(sel),", 'route.jwt_keys(sel), route.jwt_aud(sel), route.jwt_iss(sel), 60,', E("the_leeway_is_a_margin_on_exp_and_nbf_and_nothing_else"), "every route has 60 seconds of leeway")
m("p16", P, "routes_table.jwt_keys_blob(), route.jwt_keys(sel),", 'routes_table.jwt_keys_blob(), "*",', E("a_route_only_accepts_the_keys_it_allows"), "every route accepts every key")
m("p17", P, "                slots.refuse_as(tab, core, k, 401, \"auth.invalid\", jwt.tag(0 - verdict), now);\n                return true;", "                slots.refuse_as(tab, core, k, 401, \"auth.invalid\", jwt.tag(0 - verdict), now);\n                return false;", E("every_invalid_token_is_refused_with_the_same_response_and_its_own_tag_in_the_log"), "a refused token goes on to the upstream")
m("p18", P, "        if auth.credential_ok(cred) {\n            let found", "        if true {\n            let found", E("a_route_that_takes_both_kinds_decides_by_the_shape_and_never_falls_back"), "an oversize key is looked up")
m("p19", P, "route.auth(st[p + 31] - 1) > 0 && route.auth_forward", "route.auth(st[p + 31] - 1) == 1 && route.auth_forward", E("a_valid_token_passes_and_the_credential_is_not_forwarded"), "a token is forwarded")
m("p20", P, [("    if unauthenticated(tab, core, k, sel, view, tb, now) {\n        return 0;\n    }\n    if route.websocket(sel)", "    if route.websocket(sel)"),
             ("    if rate_limited(tab, core, k, sel, view, tb, now) {\n        return 0;\n    }", "    if rate_limited(tab, core, k, sel, view, tb, now) || unauthenticated(tab, core, k, sel, view, tb, now) {\n        return 0;\n    }")], E("authentication_comes_before_the_rate_limiter"), "authentication comes after the rate limiter")
m("p21", P, [("    if unauthenticated(tab, core, k, sel, view, tb, now) {\n        return 0;\n    }\n    if route.websocket(sel)", "    if route.websocket(sel)"),
             ("    let max_body = route.max_body(sel);\n    if http.is_chunked(tb) {", "    if unauthenticated(tab, core, k, sel, view, tb, now) {\n        return 0;\n    }\n    let max_body = route.max_body(sel);\n    if http.is_chunked(tb) {")], E("a_websocket_upgrade_is_authenticated_and_a_refused_one_takes_no_tunnel_place"), "a refused upgrade keeps its place among the tunnels")
m("p22", SL, "    shared.meta_put(core, k, 68, 40, 1, shown);", "    shared.meta_put(core, k, 68, 40, 1, rule);", E("every_invalid_token_is_refused_with_the_same_response_and_its_own_tag_in_the_log"), "the log says what the client is told")

A = "src/auth.cho"
m("a01", A, "        if n == index {\n            return blob[at..end];", "        if n == index + 1 {\n            return blob[at..end];", U, "a key is read from its neighbour's line")
m("a02", A, "    if slot > 100 {\n        return name_in(routes_table.jwt_keys_blob(), slot - 101);", "    if slot > 101 {\n        return name_in(routes_table.jwt_keys_blob(), slot - 101);", E("a_valid_token_passes_and_the_credential_is_not_forwarded"), "the first JWT key is named as an API key")
m("a03", A, "return name_in(routes_table.jwt_keys_blob(), slot - 101);", "return name_in(routes_table.jwt_keys_blob(), slot - 100);", E("a_valid_token_passes_and_the_credential_is_not_forwarded"), "a JWT key is named by its neighbour")
m("a04", A, "    return parse_cap(src, table, name, max_credential());", "    return parse_cap(src, table, name, max_credential() + 1);", ("unit", "auth"), "an API key of 257 bytes is read")
m("a05", "src/route.cho", "    return bytes.field(blob[at..line_end(blob, at)], 9, 23);", "    return bytes.field(blob[at..line_end(blob, at)], 9, 24);", E("a_token_valid_for_one_route_is_refused_on_a_route_with_another_audience"), "the audience is the issuer's field")
m("a06", "src/route.cho", "    return number(bytes.field(blob[at..line_end(blob, at)], 9, 25));", "    return number(bytes.field(blob[at..line_end(blob, at)], 9, 24));", E("the_leeway_is_a_margin_on_exp_and_nbf_and_nothing_else"), "the leeway is the issuer's field")
m("a07", "src/shared.cho", "        identity = auth.identity(st[p + auth_slot()]);", "        identity = auth.identity(st[p + auth_slot()] + 1);", E("a_valid_token_passes_and_the_credential_is_not_forwarded"), "the log names the next key")

G = "scripts/generate.py"
m("g01", G, "        if any(kname == n for n, _ in jwt_keys) or kname in key_names:", "        if any(kname == n for n, _ in jwt_keys):", "gen", "a JWT key may have an API key's name")
m("g02", G, "        if any(kname == n for n, _ in jwt_keys) or kname in key_names:", "        if kname in key_names:", "gen", "two JWT keys may share a name")
m("g03", G, 'JWT_PUBLIC_KEY = re.compile(r"[A-Za-z0-9_-]{43}")', 'JWT_PUBLIC_KEY = re.compile(r"[A-Za-z0-9_-]{42,44}")', "gen", "a public key may be 42 or 44 characters")
m("g04", G, "            if raw is not None and (len(raw) != 32 or jwtkit.b64u(raw) != text):", "            if raw is not None and (len(raw) != 32):", "gen", "a public key may be non-canonical base64url")
m("g05", G, "        if jwtkit.small_order(point):", "        if False:", "gen", "a public key of small order is accepted")
m("g06", G, "        if point is None:", "        if False:", "gen", "a public key that is not a point is accepted")
m("g07", G, "        if any(text == t for _, t in jwt_keys):", "        if False:", "gen", "two names may share a public key")
m("g08", G, "MAX_JWT_KEYS = 8", "MAX_JWT_KEYS = 9", "gen", "nine public keys are accepted")
m("g09", G, " or len(set(map(str, kinds))) != len(kinds)", "", "gen", "auth may name a kind twice")
m("g10", G, '    if not has_api and "auth_keys" in r:', "    if False:", "gen", "auth_keys on a route without API keys is accepted")
m("g11", G, "        if not has_jwt and key in r:", "        if False:", "gen", "jwt_* on a route that does not accept tokens is accepted")
m("g12", G, '        if "jwt_alg" in r and r["jwt_alg"] != "EdDSA":', '        if "jwt_alg" in r and r["jwt_alg"] not in ("EdDSA", "none"):', "gen", "jwt_alg may be none")
m("g13", G, '        if jk is not None and (not isinstance(jk, list) or not jk or len(set(map(str, jk))) != len(jk) or', '        if jk is not None and (not isinstance(jk, list) or not jk or', "gen", "jwt_keys may name a key twice")
m("g14", G, 'JWT_CLAIM = re.compile(r"[ !#-\\[\\]-~]{1,96}")', 'JWT_CLAIM = re.compile(r"[ !#-\\[\\]-~]{1,97}")', "gen", "an audience may be 97 bytes")
m("g15", G, "JWT_LEEWAY_MAX = 60", "JWT_LEEWAY_MAX = 61", "gen", "the leeway may be 61 seconds")
m("g16", G, '        if auth["auth"] & 2 and not jwt_keys:', "        if False:", "gen", "a route that accepts tokens may have no key")
m("g17", G, '    if jwt_keys and not any(r["auth"] & 2 for r in routes):', "    if False:", "gen", "public keys that protect nothing are compiled in")
m("g18", G, '    if has_jwt and header.lower() != "authorization":', "    if False:", "gen", "a token may be read from another header")
m("g19", G, '    if key == "a" and jwt:', "    if False:", "gen", "an identity may be the rate key on a route that takes tokens")
m("g20", G, 'jwt=bool(auth["auth"] & 2))', 'jwt=bool(auth["auth"] == 2))', "gen", "a route that takes both kinds may rate-limit by identity")
m("g21", G, '",".join(str(jwt_names.index(n)) for n in jk)', '",".join(str(jwt_names.index(n) + 1) for n in jk)', "gen", "a route's JWT key list is shifted by one")
m("g22", G, 'r["jwt_keys"], r["jwt_aud"], r["jwt_iss"], r["jwt_leeway"]) for r in routes)', 'r["jwt_keys"], r["jwt_iss"], r["jwt_aud"], r["jwt_leeway"]) for r in routes)', "gen", "the audience and the issuer are swapped in the table")
m("g23", G, '"%s\\t%s\\n" % k for k in jwt_keys', '"%s\\t%s\\n" % (k[0], k[1].upper()) for k in jwt_keys', "gen", "the public keys are compiled in uppercase")
m("g24", G, '    auth_routes = [j for j, r in enumerate(routes) if r["auth"]]', '    auth_routes = [j for j, r in enumerate(routes) if r["auth"] & 1]', "gen", "a token may cross a plain listener without the flag")
m("g25", G, '"auth": (1 if has_api else 0) + (2 if has_jwt else 0)', '"auth": (1 if has_api else 0) + (1 if has_jwt else 0)', "gen", "the kinds a route takes are mis-encoded")
m("g26", G, '        if "jwt_alg" in r and r["jwt_alg"] != "EdDSA":', '        if "jwt_alg" in r and str(r["jwt_alg"]).upper() != "EDDSA":', "gen", "jwt_alg may be eddsa")
m("g27", G, "        if \"jwt_leeway\" in r:\n            v = r[\"jwt_leeway\"]\n            if not isinstance(v, int) or isinstance(v, bool) or not 0 <= v <= JWT_LEEWAY_MAX:", "        if \"jwt_leeway\" in r:\n            v = r[\"jwt_leeway\"]\n            if not isinstance(v, int) or not 0 <= v <= JWT_LEEWAY_MAX:", "gen", "the leeway may be true")
m("g28", "scripts/jwtkit.py", "    return equal(mul(8, p), IDENTITY)", "    return equal(mul(4, p), IDENTITY)", "gen", "a point of order 8 is not small")
m("g29", "scripts/mkjwt.py", '    print("seed (the private key; shown once, never written, keep it where the issuer is): %s" % jwtkit.b64u(seed), file=sys.stderr)', '    print("seed (the private key; shown once, never written, keep it where the issuer is): %s" % jwtkit.b64u(seed))', "gen", "the seed goes to standard output, where a redirect would put it in the file")
m("g30", "scripts/mkjwt.py", "    seed = secrets.token_bytes(32)", "    seed = secrets.token_bytes(32)[:8] + bytes(24)", "gen", "a seed of 64 bits")
m("g31", "scripts/jwtkit.py", "    r = _h(prefix + msg) % Q", "    r = _h(prefix + msg) % Q + 1", "gen", "the signer is wrong")
m("g32", "scripts/generate.py", '        if isinstance(text, str) and JWT_PUBLIC_KEY.fullmatch(text):', '        if isinstance(text, str) and JWT_PUBLIC_KEY.match(text):', "gen", "a public key may have text after its 43 characters")
ARGUED["g03"] = "a text of 42 or 44 characters decodes to 31 or 33 bytes, which the length test on the decoded key (`len(raw) != 32`) refuses with the same rule: the pattern is a second line"
ARGUED["g32"] = "`re.match` stops at the end of the match, but the `{43}` pattern then meets the canonical re-encoding test (`b64u(raw) != text`), which refuses a longer text; the second test makes the first redundant"

D = "diff"
m("d01", "src/json_claims.cho", "        if json.kind(tape, i) == json.kind_object() && (json.count(tape, i) > max_members() ||", "        if json.kind(tape, i) == json.kind_object() && i == 0 && (json.count(tape, i) > max_members() ||", D, "only the root object is checked (the first version)")
m("d02", J, '    if json.get(doc, tape, 0, "crit") >= 0 {', '    if json.get(doc, tape, 0, "crit") >= 0 && json.is_array(tape, json.get(doc, tape, 0, "crit")) {', D, "a crit that is not an array is ignored")


def tree(tmp):
    for name in ("src", "scripts", "tests", "generated", "deploy"):
        shutil.copytree(ROOT / name, tmp / name, ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copy(ROOT / "cancho.toml", tmp / "cancho.toml")
    (tmp / "build").mkdir()
    shutil.copytree(ROOT / "build" / "deps", tmp / "build" / "deps")


def failing(output):
    return re.findall(r"^FAIL +(\S+)", output, re.M)


def run_mutant(mutant):
    ident, path, edits, kill, what = mutant
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="jwtmut"))
    try:
        tree(tmp)
        text = (tmp / path).read_text()
        for old, new in edits:
            if text.count(old) != 1:
                return ident, what, "INVALID", "the old text occurs %d times in %s" % (text.count(old), path)
            text = text.replace(old, new)
        (tmp / path).write_text(text)
        env = dict(os.environ, JWT_TREE=str(tmp), AUTH_TREE=str(tmp), RL_TREE=str(tmp))
        if isinstance(kill, tuple):
            attempts = [("unit", kill[1]), ("gen", None), ("e2e", None), ("diff", None), ("unit", None)]
        elif kill == "gen":
            attempts = [("gen", None), ("unit", None), ("e2e", None), ("diff", None)]
        elif kill == "diff":
            attempts = [("diff", None), ("unit", None), ("gen", None), ("e2e", None)]
        else:
            attempts = [("e2e", kill), ("e2e", None), ("unit", None), ("gen", None), ("diff", None)]
        for how, arg in attempts:
            if how == "unit":
                cmd = [LEX, "test"] + (["--test", arg] if arg else [])
                r = subprocess.run(cmd, cwd=tmp, capture_output=True, text=True, env=env, timeout=1200)
                out = r.stdout + r.stderr
                if "error:" in out and "test result" not in out:
                    return ident, what, "INVALID", out.strip().splitlines()[-1][:160]
                if r.returncode != 0:
                    names_ = re.findall(r"^test (test_\S+) \.\.\. FAILED", out, re.M)
                    return ident, what, "KILLED", "cancho test%s: %s" % (" --test " + arg if arg else "", (", ".join(names_[:3]) or "a build or run failure"))
            elif how == "gen":
                r = subprocess.run([sys.executable, str(tmp / "tests" / "generate_test.py")], cwd=tmp, capture_output=True, text=True, env=env, timeout=900)
                if r.returncode != 0:
                    return ident, what, "KILLED", "generate_test: " + "; ".join(l[:90] for l in r.stdout.splitlines() if l.startswith("FAIL"))[:200]
            elif how == "diff":
                r = subprocess.run([sys.executable, str(ROOT / "tests" / "jwt_differential.py"), "1500"], cwd=ROOT, capture_output=True, text=True, env=env, timeout=1500)
                out = r.stdout + r.stderr
                if "build failed" in out:
                    return ident, what, "INVALID", out.strip().splitlines()[-1][:200]
                if r.returncode != 0:
                    return ident, what, "KILLED", "differential: " + "; ".join(l[:100] for l in out.splitlines() if l.startswith("DISAGREE"))[:200] if "DISAGREE" in out else "differential: " + out.strip().splitlines()[-1][:120]
            else:
                r = subprocess.run([sys.executable, str(ROOT / "tests" / "jwt_test.py")] + (arg or []), cwd=ROOT, capture_output=True, text=True, env=env, timeout=1500)
                out = r.stdout + r.stderr
                if "build failed" in out:
                    return ident, what, "INVALID", out.strip().splitlines()[-1][:200]
                if r.returncode != 0:
                    return ident, what, "KILLED", ("e2e: " + ", ".join(failing(out)[:3])) if failing(out) else "e2e: " + out.strip().splitlines()[-1][:120]
        return ident, what, "SURVIVED", "no test failed, the whole suite included"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    args = sys.argv[1:]
    jobs = 3
    if args[:1] == ["-j"]:
        jobs, args = int(args[1]), args[2:]
    chosen = [x for x in M if not args or x[0] in args]
    with concurrent.futures.ThreadPoolExecutor(jobs) as pool:
        results = list(pool.map(run_mutant, chosen))
    width = max(len(r[1]) for r in results)
    for ident, what, verdict, detail in results:
        print("%-4s %-8s %-*s  %s" % (ident, verdict, width, what, detail))
    killed = sum(1 for r in results if r[2] == "KILLED")
    survived = [r[0] for r in results if r[2] == "SURVIVED"]
    print("%d mutants: %d killed, %d survived (%s), %d invalid" % (len(results), killed, len(survived), ", ".join(survived), sum(1 for r in results if r[2] == "INVALID")))
    for ident in survived:
        print("  %s: %s" % (ident, ARGUED.get(ident, "NOT ARGUED")))
    return 0 if all(r[2] == "KILLED" or r[0] in ARGUED and r[2] == "SURVIVED" for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
