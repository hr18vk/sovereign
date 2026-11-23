# ADR-0059: Bound mesh writes and suspect peers after write failures

- **Status:** Accepted
- **Date:** 2026-09-25

## Context

Before this change, `transport.TransmitTLSFrame` wrote without a deadline.
The 11 mesh write sites then present converged on `PeerSet.Publish`, while
the anti-entropy sweep visited peers serially and shared one delta and its
EBR pin across the round. A peer that acknowledged TCP packets but stopped
reading could fill both socket buffers and block a write until the kernel's
retransmission abort, about 924.6 s with the default `tcp_retries2` setting.
One peer could therefore delay anti-entropy to every healthy peer for about
15 minutes.

A loopback reproduction completed the TLS handshake, stopped reading, and
reduced the send and receive buffers to 8 KiB. A 256 KiB publish remained
blocked beyond a 2.5 s watchdog. The fix had to bound that stall without
parallelizing the sweep or changing the frame format.

## Decision

1. Set a fresh absolute write deadline before every frame sent through
   `PeerSet.writeToPC`. `--mesh-write-timeout` defaults to 10s; zero disables
   the deadline and preserves the old behavior. The budget applies per frame,
   not across a connection's lifetime. Batches contain at most 256 deltas,
   digests are approximately 20-41KB, and root announcements are small bounded
   frames. `SetWriteTimeout` configures the path before readers start.
2. Abort the underlying connection with `pc.conn.NetConn().Close()` after any
   write error. Go 1.26.1's TLS implementation records a write timeout as a
   permanent error, so later writes on that TLS connection cannot recover it.
   Calling `tls.Conn.Close` instead would attempt close-notify over the same
   blocked socket with its own 5 s deadline; a wedged 256 KiB write measured
   an additional 5.223 s. The TCP abort wakes the read loop immediately. The
   receiver treats the abrupt EOF like a peer crash, within the AEAD record
   layer and the 16 MiB `FrameReader` bound.
3. Leave the per-peer read loops and serial anti-entropy sweep unchanged.
   Concurrent writers on one TLS connection serialize on its output mutex;
   with the deadline each holds it for at most about `d`, so two writers can
   take about `2d` before the connection is fully removed.
4. Reuse the existing recovery chain after an abort: the read loop closes
   `done`, removes the dead entry, and lets `ReconnectLoop` dial a fresh
   connection with its 1s->10s backoff. Publishes during the dead window fail
   immediately because no live peer is installed. Connection challenge writes
   also use `writeToPC`, so they have the same deadline and abort behavior.
5. Keep suspect state on `PeerSet`, keyed by the configured address for an
   outbound connection and by the certificate node ID for an inbound one.
   The key survives replacement connections. An atomic `skipUntil` avoids a
   new hot-path mutex; any write error marks it and a successful write clears
   it. `DefaultSuspectBackoff` is 10s, matching the reconnect backoff ceiling
   rather than the 100ms sweep tick. The window always expires and the next
   write re-probes the peer. Expired entries are removed lazily during later
   suspect-map mutations.
6. Report actual timeout errors through `SetWriteTimeoutReporter` and
   increment `MeshWriteTimeouts`, exported as
   `supremum.mesh.write_timeouts`. Ordinary peer drops do not increment it,
   and `pkg/mesh` does not import `internal/telemetry`.

## Consequences

- A failing peer costs about `d` once per suspect window, or about `2d` with
  two serialized writers, rather than delaying the sweep for about 924.6 s.
- Healthy writes retain the same wire bytes. A full convergence with a 500ms
  deadline completed in one round with zero timeout reports and no suspect
  state. A 1ns fault-injection deadline confirms that false firing is visible.
- The TLS dial still has no explicit deadline. A wedged dial can occupy its
  reconnect goroutine until the kernel timeout, but it does not block the
  sweep. Read-side dead-peer probing remains separate work.
- Other lifecycle paths still use TLS close and can wait for close-notify on
  a blocked socket. A close that may follow a write stall should use the same
  underlying-connection abort.
- The WAN margin is projected, not measured: a 256KB frame on a 1 Mbps link
  takes about 2.1s, roughly a 5x margin under the 10s deadline. The measured
  margin tests are loopback-only.

## Evidence

The regression cases in `pkg/mesh/net_write_deadline_test.go` use real TLS
listeners and fault-injection controls enabled by
`SOVEREIGN_TEST_FAULT_WRITE_DEADLINE=1`.

- With one wedged and one healthy peer, a 250ms deadline bounded the sweep at
  403.2ms; the healthy peer converged and the reporter fired once. Disabling
  the deadline left the sweep blocked past its 3s watchdog.
- The close-on-error case timed out at 200.19ms, then closed the connection
  and removed the dead entry. A direct write on the retained TLS connection
  failed immediately, confirming the permanent TLS error. Recovery then dialed
  a fresh connection and converged.
- The first suspect cycle took 151.1ms, the post-redial skip took 7.4µs, and
  the post-window re-probe took 150.9ms. Disabling the breaker made the next
  cycle pay the full deadline again.
- Fifty 256KiB loopback frames had a maximum write time of 1.14991ms, an
  8696x margin under the 10s default. This is not a WAN measurement.
- The focused race-enabled tests, the full `pkg/mesh` suite,
  `TestTwoNodeConvergence_InMemory`,
  `TestPartitionHeal_ConvergesUnder100ms`, and
  `TestHotPathZeroAllocations` passed. Build, vet, and formatting checks were
  clean.

