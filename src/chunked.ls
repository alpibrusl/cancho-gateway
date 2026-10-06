edition 5;

module gateway.chunked;

import std.bytes;

// A chunked request body, framed incrementally (task #3, docs/framing.md section 7). Sans-io: the caller owns the buffers
// and calls `advance` with whatever bytes have arrived; the state lives in a small int slice, so a body split at any byte
// decodes the same (tests/smuggling/run.py --chunked checks it).
//
// What it refuses, beyond the RFC's minimum, because each is a known smuggling lever: chunk extensions (`;`), whitespace
// around the size, trailer fields, and a size of more than eight hex digits. Every refusal closes the connection.
//
// The state slice (`state_len()` ints): 0 phase, 1 size being read or bytes left in the chunk, 2 hex digits read,
// 3 body bytes so far, 4 the body limit.

pub fn state_len() -> [] int {
    return 5;
}

// Rule numbers: the same table as `gateway.framing` (its `tag` and `status` print them).
pub fn rule_chunk_size() -> [] int {
    return 17;
}

pub fn rule_chunk_extension() -> [] int {
    return 18;
}

pub fn rule_chunk_framing() -> [] int {
    return 19;
}

pub fn rule_trailers() -> [] int {
    return 20;
}

pub fn rule_body_limit() -> [] int {
    return 21;
}

fn phase_size() -> [] int {
    return 0;
}

fn phase_size_lf() -> [] int {
    return 1;
}

fn phase_data() -> [] int {
    return 2;
}

fn phase_data_cr() -> [] int {
    return 3;
}

fn phase_data_lf() -> [] int {
    return 4;
}

fn phase_final_cr() -> [] int {
    return 5;
}

fn phase_final_lf() -> [] int {
    return 6;
}

fn phase_done() -> [] int {
    return 7;
}

pub fn init[&t](state: &!t [int], max_body: int) -> [] int {
    state[0] = phase_size();
    state[1] = 0;
    state[2] = 0;
    state[3] = 0;
    state[4] = max_body;
    return 0;
}

pub fn is_done[&t](state: &t [int]) -> [] bool {
    return state[0] == phase_done();
}

// Body bytes passed through so far.
pub fn body_bytes[&t](state: &t [int]) -> [] int {
    return state[3];
}

fn hexval(c: int) -> [] int {
    if c >= '0' && c <= '9' {
        return c - '0';
    }
    if c >= 'a' && c <= 'f' {
        return c - 'a' + 10;
    }
    if c >= 'A' && c <= 'F' {
        return c - 'A' + 10;
    }
    return 0 - 1;
}

// Consume as much of `src` as the framing allows; answer how many bytes were consumed, or `0 - rule` for a refusal. It
// stops early only at the end of the message (the bytes after it belong to the next request) or at a refusal. Data bytes
// are counted, not inspected: the caller relays `src[..consumed]` as it sees fit.
pub fn advance[&s, &t](src: &s [byte], state: &!t [int]) -> [] int {
    var at = 0;
    while at < len(src) && state[0] != phase_done() {
        let phase = state[0];
        if phase == phase_data() {
            var take = len(src) - at;
            if take > state[1] {
                take = state[1];
            }
            at = at + take;
            state[1] = state[1] - take;
            state[3] = state[3] + take;
            if state[1] == 0 {
                state[0] = phase_data_cr();
            }
        } else {
            let c = int_of(src[at]);
            at = at + 1;
            if phase == phase_size() {
                let v = hexval(c);
                if v >= 0 {
                    if state[2] >= 8 {
                        return 0 - rule_chunk_size();
                    }
                    state[1] = state[1] * 16 + v;
                    state[2] = state[2] + 1;
                } else if c == ';' {
                    return 0 - rule_chunk_extension();
                } else if c == '\r' && state[2] > 0 {
                    state[0] = phase_size_lf();
                } else {
                    return 0 - rule_chunk_size();
                }
            } else if phase == phase_size_lf() {
                if c != '\n' {
                    return 0 - rule_chunk_framing();
                }
                if state[1] == 0 {
                    state[0] = phase_final_cr();
                } else if state[3] + state[1] > state[4] {
                    return 0 - rule_body_limit();
                } else {
                    state[0] = phase_data();
                }
            } else if phase == phase_data_cr() {
                if c != '\r' {
                    return 0 - rule_chunk_framing();
                }
                state[0] = phase_data_lf();
            } else if phase == phase_data_lf() {
                if c != '\n' {
                    return 0 - rule_chunk_framing();
                }
                state[0] = phase_size();
                state[1] = 0;
                state[2] = 0;
            } else if phase == phase_final_cr() {
                if c != '\r' {
                    return 0 - rule_trailers();
                }
                state[0] = phase_final_lf();
            } else {
                if c != '\n' {
                    return 0 - rule_chunk_framing();
                }
                state[0] = phase_done();
            }
        }
    }
    return at;
}
