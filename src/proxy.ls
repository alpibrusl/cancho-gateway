edition 5;

module gateway.proxy;

import std.bytes;
import std.conns;
import std.http;
import gateway.chunked;
import gateway.deploy;
import gateway.egress;
import gateway.forward;
import gateway.framing;
import gateway.problem;
import gateway.response;
import gateway.route;

// The proxy core, first slice (task #5, docs/proxy.md): one thread, one poller, memory sized at start.
//
// A request is read, judged (`framing`), routed (`route`), checked against the compiled-in upstreams (`egress`), forwarded on a
// fresh upstream connection with `Connection: close` (`forward`; pooling is task #6), and the upstream's response is relayed
// to the client verbatim until the upstream closes. The client's connection closes after the response: no keep-alive on
// either side in this slice.
//
// Clients and upstream connections share one slot table, one buffer slab and one state slab; a slot is a client or an upstream
// connection, and the two ends of one request point at each other. Nothing is allocated after start.
//
// Per slot `k`, `state[24k..24k+24]` is:
//
//     0  1 if the slot is in use
//     1  kind: 1 client, 2 upstream in use, 3 upstream idle in the pool
//     2  the peer slot, or -1
//     3  phase. Client: 0 reading the head, 1 wants an upstream connection, 2 connecting, 3 streaming, 4 sending an error,
//                5 lingering after one (input read and discarded)
//                Upstream: 0 connecting, 1 connected
//     4  bytes in `bufs[k]` read from this connection and not yet passed on
//     5  bytes in `pends[k]` waiting to be written to this connection
//     6  what the poller watches it for (1 read, 2 write, 0 neither)
//     7  deadline of the current phase in milliseconds, or 0
//     8  1 if the session ends once `pends[k]` has been written
//     9  client: request body bytes still to forward (a Content-Length), or -1 for a chunked body
//    10  client: 1 once the whole request body has been forwarded (or there is none)
//    11  client: the upstream index the route chose
//    12  client: deadline for the whole request, in milliseconds
//    13  client: 1 once any response byte has been queued for it
//    14  upstream: 1 once it has said goodbye; client: 1 once it has (no more reading)
//    15  client: the length of its request head in `bufs[k]`
//    16  client: 1 if its request has no body and is idempotent, so it may be sent again on a fresh connection; the head is then
//        kept in `bufs[k]` until the session ends.   upstream: 0 awaiting the response head, 1 relaying its body
//    17  client: 1 once it has been sent again.   upstream: how the body is framed (0 none, 1 Content-Length, 2 chunked, 3 until close)
//    18  client: 1 if the request was a HEAD.   upstream: body bytes still to come (Content-Length)
//    19  upstream: 1 if the connection may carry another request once this response is done
//    20  upstream: 1 if the connection came from the pool
//    21  client: the expiry of the half-open trial it holds (0: none)
//    22  upstream: 1 if the request it is answering was a HEAD
//    23  (unused)

fn slot_limit() -> [] int {
    return 256;
}

fn buf_size() -> [] int {
    return 16384;
}

fn pend_size() -> [] int {
    return 32768;
}

fn stride() -> [] int {
    return 24;
}

// Idle upstream connections kept per upstream, and for how long; 0 keeps none (every request then uses its own connection).
fn pool_max() -> [] int {
    return deploy.pool_idle_max();
}

fn idle_ms() -> [] int {
    return deploy.idle_ms();
}

// The passive circuit: this many consecutive failures to one upstream open it for `circuit_open_ms()`; 0 never opens it.
fn circuit_threshold() -> [] int {
    return deploy.circuit_threshold();
}

fn circuit_open_ms() -> [] int {
    return deploy.circuit_open_ms();
}

// Milliseconds, from the deployment: the head must arrive, the upstream must connect and start answering, and the request must
// end. (`flush_ms`: how long a refusal has to be written before the connection is dropped.)
fn header_ms() -> [] int {
    return deploy.header_ms();
}

fn connect_ms() -> [] int {
    return deploy.connect_ms();
}

fn upstream_ms() -> [] int {
    return deploy.upstream_ms();
}

fn total_ms() -> [] int {
    return deploy.total_ms();
}

fn flush_ms() -> [] int {
    return 5000;
}

// After a refusal has been written the connection is kept open until the client has been silent this long (and for at most three
// seconds), its input read and thrown away: closing a socket with
// unread request bytes in it sends a reset, which can destroy the response before the client has read it (RFC 9112 9.6).
// lex-sys has no half-close, so the gateway lingers instead.
fn linger_ms() -> [] int {
    return 500;
}

res struct Core {
    poller: Poller,
    // `poller_wait` fills these with (token, readiness) pairs.
    events: Box[[int]],
    state: Box[[int]],
    bufs: Box[[byte]],
    pends: Box[[byte]],
    // The parse table of the head in hand.
    table: Box[[int]],
    // One chunked-body state per slot.
    chunks: Box[[int]],
    // Per upstream, four ints: consecutive failures, when the circuit is open until (0: closed), until when a half-open trial
    // request is in flight (0: none), unused.
    health: Box[[int]],
}

fn token_of(k: int) -> [] int {
    return k + 1;
}

// If client `k` was admitted as the half-open trial and the circuit has not yet heard its outcome, hand the trial back (its
// request ended without a verdict: refused locally, or abandoned by its client). `st[24k+21]` is the trial's expiry as it was
// issued; it only releases the trial if that is still the one outstanding.
fn release_trial[&c](core: &!c Core, k: int) -> [] int {
    let st = contents(core.state);
    let p = stride() * k;
    if st[p + 1] == 1 && st[p + 21] != 0 {
        let h = contents(core.health);
        if h[4 * st[p + 11] + 2] == st[p + 21] {
            h[4 * st[p + 11] + 2] = 0;
        }
        st[p + 21] = 0;
    }
    return 0;
}

// Close slot `k` and its peer and forget both.
fn drop_session[&t, &c](tab: &!t conns.Table, core: &!c Core, k: int) -> [] int {
    let st = contents(core.state);
    let peer = st[stride() * k + 2];
    release_trial(core, k);
    if peer >= 0 {
        release_trial(core, peer);
    }
    conns.close(tab, k);
    st[stride() * k] = 0;
    if peer >= 0 && st[stride() * peer] == 1 {
        conns.close(tab, peer);
        st[stride() * peer] = 0;
    }
    return 0;
}

// What `k` is watched for now: room to write if output is queued, input if the phase wants it.
fn settle[&t, &c](tab: &!t conns.Table, core: &!c Core, k: int) -> [poll] int {
    let st = contents(core.state);
    let p = stride() * k;
    if st[p] != 1 {
        return 0;
    }
    var want = 0;
    if st[p + 5] > 0 {
        want = 2;
    }
    if st[p + 1] == 1 {
        // A client is read while its head or its body is arriving, or while it is lingering after a refusal; afterwards only a
        // hang-up matters, and the loop does not look for one (an HTTP client may half-close after its request).
        if st[p + 3] == 0 || st[p + 3] == 5 || st[p + 3] == 3 && st[p + 10] == 0 && st[p + 4] < buf_size() && st[p + 14] == 0 {
            want = want + 1;
        }
    } else if st[p + 1] == 3 {
        // Idle in the pool: anything it says, or its closing, means it is no longer fit for use.
        want = 1;
    } else if st[p + 3] == 0 {
        want = 2;
    } else if st[p + 14] == 0 && st[p + 4] < buf_size() {
        want = want + 1;
    }
    if want != st[p + 6] {
        conns.rewatch(tab, core.poller, k, token_of(k), want);
        st[p + 6] = want;
    }
    return 0;
}

// Close slot `k`, whatever it is, and forget it.
fn close_slot[&t, &c](tab: &!t conns.Table, core: &!c Core, k: int) -> [] int {
    conns.close(tab, k);
    contents(core.state)[stride() * k] = 0;
    return 0;
}

// How many idle connections to upstream `idx` the pool holds.
fn idle_count[&c](core: &c Core, idx: int) -> [] int {
    let st = contents(core.state);
    var n = 0;
    var k = 0;
    while k < slot_limit() {
        if st[stride() * k] == 1 && st[stride() * k + 1] == 3 && st[stride() * k + 11] == idx {
            n = n + 1;
        }
        k = k + 1;
    }
    return n;
}

// An idle connection to upstream `idx`, or -1.
fn pool_find[&c](core: &c Core, idx: int) -> [] int {
    let st = contents(core.state);
    var k = 0;
    while k < slot_limit() {
        if st[stride() * k] == 1 && st[stride() * k + 1] == 3 && st[stride() * k + 11] == idx {
            return k;
        }
        k = k + 1;
    }
    return 0 - 1;
}

// Upstream `u` has finished a response and may carry another request: keep it, if the pool has room, else close it.
fn pool_return[&t, &c](tab: &!t conns.Table, core: &!c Core, u: int, now: int) -> [poll] int {
    let st = contents(core.state);
    let p = stride() * u;
    if pool_max() == 0 || idle_count(core, st[p + 11]) >= pool_max() {
        close_slot(tab, core, u);
        return 0;
    }
    st[p + 1] = 3;
    st[p + 2] = 0 - 1;
    st[p + 3] = 1;
    st[p + 4] = 0;
    st[p + 5] = 0;
    st[p + 7] = now + idle_ms();
    st[p + 8] = 0;
    st[p + 14] = 0;
    st[p + 16] = 0;
    st[p + 17] = 0;
    st[p + 18] = 0;
    st[p + 19] = 0;
    st[p + 20] = 0;
    st[p + 22] = 0;
    settle(tab, core, u);
    return 0;
}

// The oldest idle connection is closed to make room. Answers 1 if there was one.
fn evict_idle[&t, &c](tab: &!t conns.Table, core: &!c Core) -> [] int {
    let st = contents(core.state);
    var oldest = 0 - 1;
    var k = 0;
    while k < slot_limit() {
        if st[stride() * k] == 1 && st[stride() * k + 1] == 3 && (oldest < 0 || st[stride() * k + 7] < st[stride() * oldest + 7]) {
            oldest = k;
        }
        k = k + 1;
    }
    if oldest < 0 {
        return 0;
    }
    close_slot(tab, core, oldest);
    return 1;
}

// May a request go to upstream `idx` now? 0: yes, the circuit is closed. 1: yes, as the single trial after the open period.
// 2: no, the circuit is open, or a trial is already in flight.
fn circuit_admit[&c](core: &!c Core, idx: int, now: int) -> [] int {
    let h = contents(core.health);
    let b = 4 * idx;
    if circuit_threshold() == 0 || h[b + 1] == 0 {
        return 0;
    }
    if now < h[b + 1] {
        return 2;
    }
    // Half open: one request at a time, and a trial that never reports back does not hold the circuit shut for ever.
    if h[b + 2] != 0 && now < h[b + 2] {
        return 2;
    }
    h[b + 2] = now + connect_ms() + upstream_ms();
    return 1;
}

// Upstream `idx` answered: the failures are forgotten and the circuit, if open, closes.
fn health_ok[&c](core: &!c Core, idx: int) -> [] int {
    let h = contents(core.health);
    let b = 4 * idx;
    h[b] = 0;
    h[b + 1] = 0;
    h[b + 2] = 0;
    return 0;
}

// Upstream `idx` failed (it would not connect, did not answer in time, hung up without answering on a fresh connection, or said
// something unreadable). Enough in a row opens the circuit, and its idle pooled connections go. The count is not reset when the
// circuit opens, so a failed trial after the open period reopens it at once.
fn health_fail[&t, &c](tab: &!t conns.Table, core: &!c Core, idx: int, now: int) -> [] int {
    if circuit_threshold() == 0 {
        return 0;
    }
    let h = contents(core.health);
    let st = contents(core.state);
    let b = 4 * idx;
    h[b] = h[b] + 1;
    if h[b] >= circuit_threshold() {
        h[b + 1] = now + circuit_open_ms();
        h[b + 2] = 0;
        var k = 0;
        while k < slot_limit() {
            if st[stride() * k] == 1 && st[stride() * k + 1] == 3 && st[stride() * k + 11] == idx {
                close_slot(tab, core, k);
            }
            k = k + 1;
        }
    }
    return 0;
}

// Upstream `u` has hung up, failed, or been written to in vain. If it was a pooled connection that died before saying anything and
// the request may be sent again (no body, idempotent) and has not been, it is sent again on a fresh connection; otherwise
// the client is answered 502, or, if the response was under way, simply closed.
fn upstream_lost[&t, &c](tab: &!t conns.Table, core: &!c Core, u: int, now: int) -> [poll] int {
    let st = contents(core.state);
    let p = stride() * u;
    let client = st[p + 2];
    if client < 0 || st[stride() * client] != 1 {
        close_slot(tab, core, u);
        return 0;
    }
    let pc = stride() * client;
    if st[p + 16] == 1 {
        drop_session(tab, core, client);
        return 0;
    }
    if st[p + 20] == 0 && st[p + 16] == 0 {
        // A fresh connection that hung up before answering: the upstream's failing, not a pooled connection going stale.
        health_fail(tab, core, st[p + 11], now);
    }
    if st[p + 4] == 0 && st[p + 20] == 1 && st[pc + 16] == 1 && st[pc + 17] == 0 {
        close_slot(tab, core, u);
        st[pc + 2] = 0 - 1;
        st[pc + 3] = 1;
        st[pc + 17] = 1;
        st[pc + 7] = now + connect_ms();
        return 0;
    }
    refuse(tab, core, client, 502, "proxy.upstream-closed", now);
    return 0;
}

// Write what is queued for `k`, and, once nothing is left and `k` is to close, close it (a refusal first lingers). Answers 1 if
// the session ended or the upstream was replaced (the write failed, or `k` has closed).
fn flush[&t, &c](tab: &!t conns.Table, core: &!c Core, k: int, now: int) -> [conn_write, poll] int {
    let st = contents(core.state);
    let pd = contents(core.pends);
    let p = stride() * k;
    let base = k * pend_size();
    if st[p] != 1 {
        return 0;
    }
    if st[p + 5] > 0 {
        match conns.write(tab, k, pd[base..base + st[p + 5]]) {
            Sent::Wrote(n) => {
                copy_into(pd[base..base + st[p + 5] - n], pd[base + n..base + st[p + 5]]);
                st[p + 5] = st[p + 5] - n;
            }
            Sent::Again => {
            }
            Sent::Failed(e) => {
                if st[p + 1] == 2 {
                    upstream_lost(tab, core, k, now);
                } else {
                    drop_session(tab, core, k);
                }
                return 1;
            }
        }
    }
    if st[p + 5] == 0 && st[p + 8] == 1 {
        if st[p + 1] == 1 && st[p + 3] == 4 {
            // A final answer is out while the client may still be sending: linger, reading and discarding, until it stops or
            // the time is up.
            st[p + 3] = 5;
            st[p + 8] = 0;
            st[p + 7] = now + linger_ms();
            // The lingering cap: the request's own total deadline, or three seconds, whichever comes first.
            if st[p + 12] == 0 || st[p + 12] > now + 3000 {
                st[p + 12] = now + 3000;
            }
            settle(tab, core, k);
            return 0;
        }
        drop_session(tab, core, k);
        return 1;
    }
    return 0;
}

// Refuse the request of client `k` with `status` and `rule`: the upstream, if any, is closed, and a problem+json response is
// queued and the connection closed once it is sent (the poller reports the socket writable at once). If a response has already
// begun there is nothing honest to send: the session just ends.
fn refuse[&t, &c, &r](tab: &!t conns.Table, core: &!c Core, k: int, status: int, rule: &r [byte], now: int) -> [poll] int {
    let st = contents(core.state);
    let pd = contents(core.pends);
    let p = stride() * k;
    release_trial(core, k);
    if st[p + 13] == 1 {
        drop_session(tab, core, k);
        return 0;
    }
    let peer = st[p + 2];
    if peer >= 0 && st[stride() * peer] == 1 {
        conns.close(tab, peer);
        st[stride() * peer] = 0;
    }
    st[p + 2] = 0 - 1;
    let base = k * pend_size();
    let n = problem.response(pd[base..base + pend_size()], status, rule);
    if n < 0 {
        drop_session(tab, core, k);
        return 0;
    }
    st[p + 5] = n;
    st[p + 8] = 1;
    st[p + 3] = 4;
    st[p + 4] = 0;
    st[p + 7] = now + flush_ms();
    settle(tab, core, k);
    return 0;
}

// The upstream's response is complete: the client's connection ends once what is queued for it has been written, and the
// upstream goes back to the pool if it may carry another request (its framing allows it, nothing is left unread, the request's
// body was fully sent and the upstream did not hang up), else it is closed.
fn finish_response[&t, &c](tab: &!t conns.Table, core: &!c Core, u: int, now: int) -> [conn_write, poll] int {
    let st = contents(core.state);
    let pu = stride() * u;
    let client = st[pu + 2];
    let pc = stride() * client;
    let reuse = st[pu + 19] == 1 && st[pu + 4] == 0 && st[pc + 10] == 1 && st[pu + 14] == 0;
    st[pc + 2] = 0 - 1;
    st[pc + 8] = 1;
    if st[pc + 10] == 0 {
        // The upstream answered before the request body was all sent: the client may still be sending, so it lingers.
        st[pc + 3] = 4;
    }
    if reuse {
        pool_return(tab, core, u, now);
    } else {
        close_slot(tab, core, u);
    }
    if flush(tab, core, client, now) == 0 {
        settle(tab, core, client);
    }
    return 0;
}

// Move what the upstream `u` has said to its client: first its head (parsed, rewritten, interim responses passed on), then its
// body as its framing says, as far as the client's queue has room.
fn pump_response[&t, &c](tab: &!t conns.Table, core: &!c Core, u: int, now: int) -> [conn_write, poll] int {
    let st = contents(core.state);
    let bf = contents(core.bufs);
    let pd = contents(core.pends);
    let ch = contents(core.chunks);
    let tb = contents(core.table);
    let pu = stride() * u;
    let client = st[pu + 2];
    if client < 0 || st[stride() * client] != 1 {
        close_slot(tab, core, u);
        return 0;
    }
    let pc = stride() * client;
    let ub = u * buf_size();
    let cb = client * pend_size();
    var going = true;
    while going {
        going = false;
        if st[pu + 16] == 0 {
            if st[pu + 4] > 0 {
                let view = bf[ub..ub + st[pu + 4]];
                let r = response.parse(view, tb);
                if r < 0 {
                    health_fail(tab, core, st[pu + 11], now);
                    refuse(tab, core, client, response.status(0 - r), response.tag(0 - r), now);
                    return 0;
                }
                if r > 0 && pend_size() - st[pc + 5] >= r + 64 {
                    if response.interim(tb) {
                        // Passed on as it came; the final response is still to come.
                        copy_into(pd[cb + st[pc + 5]..cb + st[pc + 5] + r], view[0..r]);
                        st[pc + 5] = st[pc + 5] + r;
                        st[pc + 13] = 1;
                    } else {
                        health_ok(core, st[pu + 11]);
                        let m = forward.rewrite_response(view[0..r], tb, pd[cb + st[pc + 5]..cb + pend_size()]);
                        if m < 0 {
                            drop_session(tab, core, client);
                            return 0;
                        }
                        st[pc + 5] = st[pc + 5] + m;
                        st[pc + 13] = 1;
                        // The response has begun: only the total deadline remains.
                        st[pc + 7] = 0;
                        let mode = response.body_mode(tb, st[pu + 22] == 1);
                        st[pu + 17] = mode;
                        st[pu + 18] = response.content_length(tb);
                        st[pu + 19] = 0;
                        if response.reusable(tb, mode) {
                            st[pu + 19] = 1;
                        }
                        if mode == 2 {
                            chunked.init(ch[u * chunked.state_len()..u * chunked.state_len() + chunked.state_len()], 1099511627776);
                        }
                        st[pu + 16] = 1;
                    }
                    copy_into(bf[ub..ub + st[pu + 4] - r], bf[ub + r..ub + st[pu + 4]]);
                    st[pu + 4] = st[pu + 4] - r;
                    if st[pu + 16] == 1 && st[pu + 17] == 0 {
                        // A response with no body is complete with its head.
                        finish_response(tab, core, u, now);
                        return 0;
                    }
                    if flush(tab, core, client, now) == 1 {
                        return 0;
                    }
                    going = true;
                }
            }
        } else {
            var room = pend_size() - st[pc + 5];
            var take = st[pu + 4];
            if take > room {
                take = room;
            }
            if take > 0 {
                var used = take;
                var done = false;
                let mode = st[pu + 17];
                if mode == 1 {
                    if used > st[pu + 18] {
                        used = st[pu + 18];
                    }
                    st[pu + 18] = st[pu + 18] - used;
                    done = st[pu + 18] == 0;
                } else if mode == 2 {
                    let slot_chunks = ch[u * chunked.state_len()..u * chunked.state_len() + chunked.state_len()];
                    let n = chunked.advance(bf[ub..ub + take], slot_chunks);
                    if n < 0 {
                        // A body that is not valid chunked framing: nothing honest to do but end the session.
                        drop_session(tab, core, client);
                        return 0;
                    }
                    used = n;
                    done = chunked.is_done(slot_chunks);
                }
                copy_into(pd[cb + st[pc + 5]..cb + st[pc + 5] + used], bf[ub..ub + used]);
                copy_into(bf[ub..ub + st[pu + 4] - used], bf[ub + used..ub + st[pu + 4]]);
                st[pu + 4] = st[pu + 4] - used;
                st[pc + 5] = st[pc + 5] + used;
                let before = st[pc + 5];
                if done {
                    finish_response(tab, core, u, now);
                    return 0;
                }
                if flush(tab, core, client, now) == 1 {
                    return 0;
                }
                going = st[pc + 5] < before && st[pu + 4] > 0;
            }
        }
    }
    // The upstream has hung up and everything it said has been passed on.
    if st[pu + 14] == 1 && st[pu + 4] == 0 {
        if st[pu + 16] == 1 && st[pu + 17] == 3 {
            // A body that runs until the connection closes ends here.
            finish_response(tab, core, u, now);
        } else {
            upstream_lost(tab, core, u, now);
        }
        return 0;
    }
    settle(tab, core, client);
    settle(tab, core, u);
    return 0;
}

// Move request-body bytes from client `c`'s buffer to its upstream's queue, framed, and write them as far as there is room.
fn pump_request[&t, &c](tab: &!t conns.Table, core: &!c Core, k: int, now: int) -> [conn_write, poll] int {
    let st = contents(core.state);
    let bf = contents(core.bufs);
    let pd = contents(core.pends);
    let ch = contents(core.chunks);
    let p = stride() * k;
    let u = st[p + 2];
    if u < 0 || st[stride() * u] != 1 || st[stride() * u + 3] != 1 {
        return 0;
    }
    let pu = stride() * u;
    var moving = true;
    while moving {
        moving = false;
        if st[p + 10] == 0 && st[p + 4] > 0 {
            var room = pend_size() - st[pu + 5];
            var take = st[p + 4];
            if take > room {
                take = room;
            }
            let cb = k * buf_size();
            let ub = u * pend_size();
            if take > 0 {
                var used = take;
                if st[p + 9] >= 0 {
                    if used > st[p + 9] {
                        used = st[p + 9];
                    }
                    st[p + 9] = st[p + 9] - used;
                    if st[p + 9] == 0 {
                        st[p + 10] = 1;
                    }
                } else {
                    let slot_chunks = ch[k * chunked.state_len()..k * chunked.state_len() + chunked.state_len()];
                    let n = chunked.advance(bf[cb..cb + take], slot_chunks);
                    if n < 0 {
                        refuse(tab, core, k, framing.status(0 - n), framing.tag(0 - n), now);
                        return 0;
                    }
                    used = n;
                    if chunked.is_done(slot_chunks) {
                        st[p + 10] = 1;
                    }
                }
                copy_into(pd[ub + st[pu + 5]..ub + st[pu + 5] + used], bf[cb..cb + used]);
                st[pu + 5] = st[pu + 5] + used;
                if st[p + 10] == 1 {
                    // Whatever follows the request is not this request's: the connection closes after the response.
                    st[p + 4] = 0;
                } else {
                    copy_into(bf[cb..cb + st[p + 4] - used], bf[cb + used..cb + st[p + 4]]);
                    st[p + 4] = st[p + 4] - used;
                }
                let before = st[pu + 5];
                if flush(tab, core, u, now) == 1 {
                    return 0;
                }
                moving = st[p + 10] == 0 && st[pu + 5] < before && st[p + 4] > 0;
            }
        }
    }
    // A request with no body to forward still has its head waiting.
    if st[pu + 5] > 0 && flush(tab, core, u, now) == 1 {
        return 0;
    }
    settle(tab, core, k);
    settle(tab, core, u);
    return 0;
}

// Client `k` has bytes while its head is arriving: judge them, route the request, and ask for an upstream connection.
fn head_ready[&t, &c](tab: &!t conns.Table, core: &!c Core, k: int, now: int) -> [poll] int {
    let st = contents(core.state);
    let bf = contents(core.bufs);
    let tb = contents(core.table);
    let ch = contents(core.chunks);
    let p = stride() * k;
    let base = k * buf_size();
    let view = bf[base..base + st[p + 4]];
    let r = framing.judge(view, tb);
    if r == 0 {
        settle(tab, core, k);
        return 0;
    }
    if r < 0 {
        refuse(tab, core, k, framing.status(0 - r), framing.tag(0 - r), now);
        return 0;
    }
    let sel = route.select(http.header(view, tb, "host"), http.method(view, tb), http.path(view, tb));
    if sel < 0 {
        refuse(tab, core, k, route.status(0 - sel), route.tag(0 - sel), now);
        return 0;
    }
    let max_body = route.max_body(sel);
    if http.is_chunked(tb) {
        chunked.init(ch[k * chunked.state_len()..k * chunked.state_len() + chunked.state_len()], max_body);
        st[p + 9] = 0 - 1;
        st[p + 10] = 0;
    } else if http.content_length(tb) > max_body {
        refuse(tab, core, k, 413, "limit.body", now);
        return 0;
    } else if http.content_length(tb) > 0 {
        st[p + 9] = http.content_length(tb);
        st[p + 10] = 0;
    } else {
        st[p + 9] = 0;
        st[p + 10] = 1;
    }
    // Last of the checks the gateway makes itself: a request refused above never uses up the circuit's one trial.
    let admit = circuit_admit(core, route.upstream(sel), now);
    if admit == 2 {
        refuse(tab, core, k, 503, "proxy.circuit-open", now);
        return 0;
    }
    st[p + 21] = 0;
    if admit == 1 {
        st[p + 21] = contents(core.health)[4 * route.upstream(sel) + 2];
    }
    st[p + 11] = route.upstream(sel);
    st[p + 15] = r;
    // A request with no body and an idempotent method may be sent again, once, if a pooled connection turns out to be dead.
    let method = http.method(view, tb);
    st[p + 16] = 0;
    if st[p + 10] == 1 && (bytes.equal(method, "GET") || bytes.equal(method, "HEAD") || bytes.equal(method, "DELETE") || bytes.equal(method, "OPTIONS")) {
        st[p + 16] = 1;
    }
    st[p + 17] = 0;
    st[p + 18] = 0;
    if bytes.equal(method, "HEAD") {
        st[p + 18] = 1;
    }
    st[p + 3] = 1;
    st[p + 7] = now + connect_ms();
    settle(tab, core, k);
    return 0;
}

// Write the request head for client `k` into the queue of upstream slot `slot` (already in the table and initialised), and tie
// the two together. Answers 1 if that failed and the client was refused.
fn attach[&t, &c](tab: &!t conns.Table, core: &!c Core, k: int, slot: int, now: int) -> [poll] int {
    let st = contents(core.state);
    let bf = contents(core.bufs);
    let pd = contents(core.pends);
    let tb = contents(core.table);
    let p = stride() * k;
    let q = stride() * slot;
    // Rebuild the head's parse (another client may have used the table since) and rewrite it for the upstream.
    let kb = k * buf_size();
    let view = bf[kb..kb + st[p + 15]];
    var failed = 0;
    if http.parse(view, tb) < 0 {
        failed = 1;
    } else {
        let m = forward.rewrite(view, tb, pd[slot * pend_size()..slot * pend_size() + pend_size()], pool_max() > 0);
        if m < 0 {
            failed = 0 - m + 1;
        } else {
            st[q + 5] = m;
        }
    }
    if failed > 0 {
        close_slot(tab, core, slot);
        if failed == 1 {
            refuse(tab, core, k, 502, "proxy.head", now);
        } else {
            refuse(tab, core, k, forward.status(failed - 1), forward.tag(failed - 1), now);
        }
        return 1;
    }
    // The head is now the upstream's. What follows it in the client's buffer is request body, unless the request can be sent
    // again, in which case the head stays where it is until the session ends.
    if st[p + 16] != 1 {
        let hl = st[p + 15];
        copy_into(bf[kb..kb + st[p + 4] - hl], bf[kb + hl..kb + st[p + 4]]);
        st[p + 4] = st[p + 4] - hl;
        if st[p + 10] == 1 {
            st[p + 4] = 0;
        }
    }
    st[p + 2] = slot;
    return 0;
}

// Give client `k` an upstream connection, from the pool if there is an idle one (and this is not a second attempt), else a
// new one, and put the request head in its queue. Owns the table because `conns.put` does.
fn dial[&h, &n, &c](heap: &!h Heap, tab: conns.Table, net: &n Net(""), core: &!c Core, k: int, now: int) -> [heap, conn_write, poll, net_out("")] conns.Table {
    var table = tab;
    let st = contents(core.state);
    let p = stride() * k;
    let idx = st[p + 11];
    let addr = deploy.upstream_addr(idx);
    if !egress.allowed(addr) {
        borrow mut table as &!tw in {
            refuse(tw, core, k, 502, "proxy.egress", now);
        }
        return table;
    }
    var pooled = 0 - 1;
    if st[p + 17] == 0 {
        pooled = pool_find(core, idx);
    }
    if pooled >= 0 {
        let q = stride() * pooled;
        st[q + 1] = 2;
        st[q + 2] = k;
        st[q + 3] = 1;
        st[q + 4] = 0;
        st[q + 5] = 0;
        st[q + 7] = 0;
        st[q + 8] = 0;
        st[q + 14] = 0;
        st[q + 16] = 0;
        st[q + 17] = 0;
        st[q + 18] = 0;
        st[q + 19] = 0;
        st[q + 20] = 1;
        st[q + 22] = st[p + 18];
        borrow mut table as &!tw in {
            if attach(tw, core, k, pooled, now) == 0 {
                st[p + 3] = 3;
                st[p + 7] = now + upstream_ms();
                settle(tw, core, pooled);
                settle(tw, core, k);
                pump_request(tw, core, k, now);
            }
        }
        return table;
    }
    let host = bytes.field(addr, ':', 1);
    let port_text = bytes.field(addr, ':', 2);
    var port = 0;
    var i = 0;
    while i < len(port_text) {
        port = port * 10 + int_of(port_text[i]) - '0';
        i = i + 1;
    }
    match tcp_connect_start(net, host, port) {
        Dialed::Ok(conn) => {
            let (grown, slot) = conns.put(heap, table, conn);
            table = grown;
            if slot < 0 || slot >= slot_limit() {
                borrow mut table as &!tw in {
                    if slot >= 0 {
                        conns.close(tw, slot);
                    }
                    refuse(tw, core, k, 503, "limit.connections", now);
                }
                return table;
            }
            let q = stride() * slot;
            st[q] = 1;
            st[q + 1] = 2;
            st[q + 2] = k;
            st[q + 3] = 0;
            st[q + 4] = 0;
            st[q + 5] = 0;
            st[q + 6] = 0;
            st[q + 7] = 0;
            st[q + 8] = 0;
            st[q + 11] = idx;
            st[q + 14] = 0;
            st[q + 16] = 0;
            st[q + 17] = 0;
            st[q + 18] = 0;
            st[q + 19] = 0;
            st[q + 20] = 0;
            st[q + 22] = st[p + 18];
            borrow mut table as &!tw in {
                if attach(tw, core, k, slot, now) == 0 {
                    if conns.watch(tw, core.poller, slot, token_of(slot), 2) != 0 {
                        close_slot(tw, core, slot);
                        refuse(tw, core, k, 502, "proxy.connect", now);
                    } else {
                        st[q + 6] = 2;
                        st[p + 3] = 2;
                        st[p + 7] = now + connect_ms();
                        settle(tw, core, k);
                    }
                }
            }
        }
        Dialed::Failed(e) => {
            borrow mut table as &!tw in {
                health_fail(tw, core, idx, now);
                refuse(tw, core, k, 502, "proxy.connect", now);
            }
        }
    }
    return table;
}

fn read_client[&t, &c](tab: &!t conns.Table, core: &!c Core, k: int, now: int) -> [conn_read, conn_write, poll] int {
    let st = contents(core.state);
    let bf = contents(core.bufs);
    let p = stride() * k;
    let base = k * buf_size();
    match conns.read(tab, k, bf[base + st[p + 4]..base + buf_size()]) {
        Received::Data(got) => {
            st[p + 4] = st[p + 4] + got;
            if st[p + 3] == 0 {
                head_ready(tab, core, k, now);
            } else {
                pump_request(tab, core, k, now);
            }
        }
        Received::End => {
            if st[p + 3] == 0 || st[p + 10] == 0 {
                // It left before its request was whole.
                drop_session(tab, core, k);
            } else {
                st[p + 14] = 1;
                settle(tab, core, k);
            }
        }
        Received::Again => {
        }
        Received::Failed(e) => {
            drop_session(tab, core, k);
        }
    }
    return 0;
}

fn read_upstream[&t, &c](tab: &!t conns.Table, core: &!c Core, u: int, now: int) -> [conn_read, conn_write, poll] int {
    let st = contents(core.state);
    let bf = contents(core.bufs);
    let p = stride() * u;
    let base = u * buf_size();
    match conns.read(tab, u, bf[base + st[p + 4]..base + buf_size()]) {
        Received::Data(got) => {
            st[p + 4] = st[p + 4] + got;
            pump_response(tab, core, u, now);
        }
        Received::End => {
            st[p + 14] = 1;
            pump_response(tab, core, u, now);
        }
        Received::Again => {
        }
        Received::Failed(e) => {
            st[p + 14] = 1;
            pump_response(tab, core, u, now);
        }
    }
    return 0;
}

// The poller said slot `k` is ready: readiness 1 is readable (or hung up), 2 is writable.
fn step[&t, &c](tab: &!t conns.Table, core: &!c Core, k: int, readiness: int, now: int) -> [conn_read, conn_write, poll] int {
    let st = contents(core.state);
    let p = stride() * k;
    if st[p] != 1 {
        return 0;
    }
    if st[p + 1] == 1 {
        if st[p + 3] == 4 {
            if readiness % 4 >= 2 {
                flush(tab, core, k, now);
            } else {
                drop_session(tab, core, k);
            }
            return 0;
        }
        if st[p + 3] == 5 {
            // Lingering: read and discard until the client closes.
            let bf = contents(core.bufs);
            match conns.read(tab, k, bf[k * buf_size()..k * buf_size() + buf_size()]) {
                Received::Data(got) => {
                    // Still sending: wait for it to stop, up to the lingering cap.
                    if now + linger_ms() < st[p + 12] {
                        st[p + 7] = now + linger_ms();
                    }
                }
                Received::End => {
                    drop_session(tab, core, k);
                }
                Received::Again => {
                }
                Received::Failed(e) => {
                    drop_session(tab, core, k);
                }
            }
            return 0;
        }
        if st[p + 5] > 0 && readiness % 4 >= 2 {
            if flush(tab, core, k, now) == 1 {
                return 0;
            }
            // Room has opened for more of the response.
            let up = st[p + 2];
            if up >= 0 && st[stride() * up] == 1 {
                pump_response(tab, core, up, now);
            }
            if st[p] != 1 {
                return 0;
            }
        }
        if readiness % 2 == 1 && (st[p + 3] == 0 || st[p + 3] == 3 && st[p + 10] == 0) {
            read_client(tab, core, k, now);
        }
        return 0;
    }
    if st[p + 1] == 3 {
        // Idle in the pool and heard from: it hung up, or spoke out of turn. Either way it is finished.
        close_slot(tab, core, k);
        return 0;
    }
    // An upstream connection.
    let client = st[p + 2];
    if client < 0 || st[stride() * client] != 1 {
        drop_session(tab, core, k);
        return 0;
    }
    if st[p + 3] == 0 {
        let outcome = conns.connect_status(tab, k);
        if outcome != 0 {
            health_fail(tab, core, st[p + 11], now);
            refuse(tab, core, client, 502, "proxy.connect", now);
            return 0;
        }
        st[p + 3] = 1;
        st[stride() * client + 3] = 3;
        st[stride() * client + 7] = now + upstream_ms();
        pump_request(tab, core, client, now);
        return 0;
    }
    if st[p + 5] > 0 && readiness % 4 >= 2 {
        if flush(tab, core, k, now) == 1 {
            return 0;
        }
        pump_request(tab, core, client, now);
        if st[p] != 1 {
            return 0;
        }
    }
    if readiness % 2 == 1 && st[p + 14] == 0 {
        read_upstream(tab, core, k, now);
    }
    return 0;
}

// Deadlines: a client whose phase or whole request has run out of time is answered 408 or 504, or, if its response has
// begun, simply closed.
fn sweep[&t, &c](tab: &!t conns.Table, core: &!c Core, now: int) -> [poll] int {
    let st = contents(core.state);
    var k = 0;
    while k < slot_limit() {
        let p = stride() * k;
        if st[p] == 1 && st[p + 1] == 3 && now >= st[p + 7] {
            close_slot(tab, core, k);
        }
        if st[p] == 1 && st[p + 1] == 1 {
            if st[p + 12] != 0 && now >= st[p + 12] {
                refuse(tab, core, k, 504, "timeout.total", now);
            } else if st[p + 7] != 0 && now >= st[p + 7] {
                if st[p + 3] == 0 {
                    refuse(tab, core, k, 408, "timeout.header", now);
                } else if st[p + 3] == 1 || st[p + 3] == 2 {
                    health_fail(tab, core, st[p + 11], now);
                    refuse(tab, core, k, 504, "timeout.connect", now);
                } else if st[p + 3] == 3 {
                    health_fail(tab, core, st[p + 11], now);
                    refuse(tab, core, k, 504, "timeout.upstream", now);
                } else {
                    drop_session(tab, core, k);
                }
            }
        }
        k = k + 1;
    }
    return 0;
}

// Take every client waiting on the listener, up to the limit.
fn accept_all[&h, &l, &c](heap: &!h Heap, conn: conns.Table, listener: &!l Listener, core: &!c Core, now: int) -> [heap, conn_accept, poll] conns.Table {
    let st = contents(core.state);
    var table = conn;
    var more = true;
    while more {
        match tcp_accept(listener) {
            Accepted::Ok(c) => {
                var held = 0;
                borrow table as &tt in {
                    held = conns.live(tt);
                }
                // A session holds two slots: leave room for the upstream half, closing an idle pooled connection if that is what it takes.
                if held + 2 > slot_limit() {
                    var made = 0;
                    borrow mut table as &!et in {
                        made = evict_idle(et, core);
                    }
                    held = held - made;
                }
                if held + 2 > slot_limit() {
                    conn_close(c);
                } else {
                    let (grown, slot) = conns.put(heap, table, c);
                    table = grown;
                    if slot >= slot_limit() {
                        borrow mut table as &!ct in {
                            conns.close(ct, slot);
                        }
                    } else if slot >= 0 {
                        let p = stride() * slot;
                        st[p] = 1;
                        st[p + 1] = 1;
                        st[p + 2] = 0 - 1;
                        st[p + 3] = 0;
                        st[p + 4] = 0;
                        st[p + 5] = 0;
                        st[p + 6] = 1;
                        st[p + 7] = now + header_ms();
                        st[p + 8] = 0;
                        st[p + 9] = 0;
                        st[p + 10] = 0;
                        st[p + 11] = 0;
                        st[p + 12] = now + total_ms();
                        st[p + 13] = 0;
                        st[p + 14] = 0;
                        st[p + 15] = 0;
                        st[p + 16] = 0;
                        st[p + 17] = 0;
                        st[p + 18] = 0;
                        st[p + 19] = 0;
                        st[p + 20] = 0;
                        st[p + 21] = 0;
                        st[p + 22] = 0;
                        borrow mut table as &!ct in {
                            if conns.nonblocking(ct, slot) != 0 || conns.watch(ct, core.poller, slot, token_of(slot), 1) != 0 {
                                conns.close(ct, slot);
                                st[p] = 0;
                            }
                        }
                    }
                }
            }
            Accepted::Again => {
                more = false;
            }
            Accepted::Failed(e) => {
                more = false;
            }
        }
    }
    return table;
}

// Serve until the process is killed. Answers a non-zero status only if it could not start.
pub fn run[&h, &l, &n, &k](heap: &!h Heap, listener: &!l Listener, net: &n Net(""), clock: &k Clock) -> [heap, conn_accept, conn_read, conn_write, poll, clock, net_out("")] int {
    match poller_new() {
        Polling::Ok(pl) => {
            var poller = pl;
            borrow mut poller as &!pw in {
                poller_add_listener(pw, listener, 0);
            }
            let limit = slot_limit();
            var core = Core { poller: poller, events: box_slice(heap, 128, 0), state: box_slice(heap, stride() * limit, 0), bufs: box_slice(heap, limit * buf_size(), byte_of(0)), pends: box_slice(heap, limit * pend_size(), byte_of(0)), table: box_slice(heap, http.slots(64), 0), chunks: box_slice(heap, limit * chunked.state_len(), 0), health: box_slice(heap, 4 * 256, 0) };
            var tab = conns.empty(heap, 64);
            while true {
                var ready = 0 - 1;
                borrow mut core as &!cw in {
                    ready = poller_wait(cw.poller, contents(cw.events), 250);
                }
                let now = clock_ms(clock);
                var j = 0;
                while j < ready {
                    var token = 0 - 1;
                    var readiness = 0;
                    borrow core as &cr in {
                        token = contents(cr.events)[2 * j];
                        readiness = contents(cr.events)[2 * j + 1];
                    }
                    if token == 0 {
                        borrow mut core as &!cw in {
                            tab = accept_all(heap, tab, listener, cw, now);
                        }
                    } else {
                        borrow mut tab as &!tw in {
                            borrow mut core as &!cw in {
                                step(tw, cw, token - 1, readiness, now);
                            }
                        }
                    }
                    j = j + 1;
                }
                // Clients that asked for an upstream connection this turn.
                var k = 0;
                while k < limit {
                    var wants = false;
                    borrow core as &cr in {
                        let s = contents(cr.state);
                        wants = s[stride() * k] == 1 && s[stride() * k + 1] == 1 && s[stride() * k + 3] == 1;
                    }
                    if wants {
                        borrow mut core as &!cw in {
                            tab = dial(heap, tab, net, cw, k, now);
                        }
                    }
                    k = k + 1;
                }
                borrow mut tab as &!tw in {
                    borrow mut core as &!cw in {
                        sweep(tw, cw, now);
                    }
                }
            }
            conns.drop(heap, tab);
            let Core { poller, events, state, bufs, pends, table, chunks, health } = core;
            poller_close(poller);
            unbox_slice(heap, events);
            unbox_slice(heap, state);
            unbox_slice(heap, bufs);
            unbox_slice(heap, pends);
            unbox_slice(heap, table);
            unbox_slice(heap, chunks);
            unbox_slice(heap, health);
            return 0;
        }
        Polling::Failed(e) => {
            return 4;
        }
    }
}
