# Passive health: the circuit (task #6, second part)

Status: **built and measured: a per-upstream circuit that opens after consecutive failures, refuses requests to that upstream
while open, and lets one trial through afterwards.** Not built: the optional active health check, failover to another upstream
(a route has exactly one), any metric or log line for a state change (#10), and a `Retry-After` header on the refusal.

## 1. What it does

A request to an upstream is a **failure** if the upstream would not connect, did not connect or answer in time
(`timeout.connect`, `timeout.upstream`), hung up without answering on a **fresh** connection, or sent a response the gateway cannot
read (`response.*`). It is a **success** when a final response head has been read. After `circuit_threshold` failures in a row
(default 5; **0 turns the circuit off**) the circuit **opens** for `circuit_open_ms` (default 10,000):

- requests that would use that upstream are refused at once with **503 `proxy.circuit-open`**, without a connection attempt;
- its idle pooled connections are closed;
- other upstreams are unaffected (the state is per upstream, in a four-int slot of its own).

When the open period ends the circuit is **half open**: exactly **one** request is let through as a trial; any others are refused
as before. If the trial succeeds the circuit closes and the count is forgotten; if it fails the circuit reopens for another full
period (the count is not reset, so one failure is enough).

What is deliberately **not** a failure: a **reused pooled connection** that died before saying anything. That is a connection
going stale, not an upstream failing (it is retried or answered 502 as `docs/pool.md` says), and counting it would open the circuit
on ordinary idle-timeout churn.

**A trial must always be given back.** A request the gateway refuses itself after the circuit admitted it (a `413`, a `Connection`
header naming the framing headers) or whose client leaves before a verdict hands the trial back at once. Otherwise anyone could keep
an upstream shut out by sending bad requests when the circuit is half open. (An issued trial also expires after the connect plus
upstream timeouts, as a safety valve; no path reaches that expiry today.)

Deployment keys: `circuit_threshold` (0 to 1000) and `circuit_open_ms` (100 to 600000), checked by the generator.

## 2. Measured: `python3 tests/proxy_test.py` (53 tests, about 55 s; 13 new)

Against an upstream the test can take down and bring back (it shuts the listening socket down for real; see section 3):

- three refused connections open the circuit, and the fourth request is refused in under half a second **without a connection reaching
  the upstream, even though it is back up**;
- after the open period a trial goes through, succeeds, and the circuit closes; a failing trial reopens it at once;
- five concurrent requests after the open period: **exactly one reaches the upstream**, four are refused, and the trial's success
  closes the circuit;
- two failures, a success, two failures do not open a circuit of three;
- an upstream that never answers (three `timeout.upstream` in a row) opens it; so do three unreadable responses in a row;
- opening the circuit closes the idle pooled connections (four idle, three consumed by the unreadable answers, the fourth gone);
- twelve rounds of a pooled connection going stale, and **four stale connections in a row with no success between them**, never open it;
- a trial whose client leaves mid-upload, and a trial the gateway refuses itself, are handed back and the next request is admitted;
- other upstreams keep answering while one circuit is open; with `circuit_threshold = 0`, eight failures in a row never open it.

## 3. Mutants, survivors, and what the tests found

Each killed by the test named: the circuit never opening; an open circuit admitting everything; a success not resetting the count; a
half-open circuit admitting many trials; a stale pooled connection counted as a failure; idle connections left open; timeouts not
counted; an unreadable response not counted; a dropped session not handing the trial back; a local refusal not handing it back.

**Survivors, then strengthened:**
- *A stale pooled connection counted as a failure* survived the first test (a retried `GET`, which succeeds on its fresh connection and
  so resets the count). It is killed by four stale connections in a row with no success between them.
- *A trial that is never handed back* had been tested with a "lost trial", but the upstream there simply timed out, which counts as
  a failure and ends the trial. Real loss needed a client that leaves mid-upload. Designing that test is what exposed the real
  design problem: **a request refused locally could use up the trial and hold an upstream shut out for the whole safety-valve period
  (connect plus upstream timeouts: 35 s by default)**. The first version of the code had that flaw (the circuit check ran before the
  gateway's own refusals); the check now runs last, and refusals and dropped sessions hand the trial back.
- *A local refusal not handing the trial back* survived once more, because the refusal's lingering connection later closes and the
  close handed the trial back anyway. The test now keeps the refused client's connection open, so only the refusal itself can.

**Equivalent mutants, honestly:** treating `circuit_threshold = 0` as 1 inside the failure counter is unobservable, because the admission
check also tests for 0 (a second guard); and the expiry of an issued trial cannot be reached through any code path now that every end of
a session hands the trial back, so a mutant that removes the expiry survives by construction.

**Bug in the test harness:** closing a listening socket does not stop it listening while another thread is blocked in `accept()`; the first
version of the flapping upstream kept accepting. It now shuts the socket down first.

## 4. Not done

- **The optional active health check** (probing an upstream while the circuit is open or in the background).
- **Failover, balancing, several upstreams per route.** A dead upstream means 503s for its routes, not another upstream.
- **Visibility.** There is no log line or metric when the circuit opens or closes (#10), and the 503 carries no `Retry-After`.
- The failure count is **across all clients at once**: concurrent in-flight requests all count, so a burst of timeouts opens it at once.
  Not measured against real traffic.
- The circuit state is in memory only and starts closed.
