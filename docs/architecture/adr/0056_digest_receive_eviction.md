# ADR-0056: Digest receive-state eviction

**Status:** Accepted  
**Date:** 2026-09-21

## Context

[ADR-0055](0055_deterministic_cross_process_iblt_hash.md) added sweep-time eviction for
`peerRoots`, but the companion `digestRecv` map still had no delete path. At the time of this
decision its type was `map[[16]byte]chan *peerDigest`: one blocking-receive channel for each
peer whose change gate admitted a digest exchange. Membership churn therefore retained a
channel for every peer identity ever seen.

Only `registerDigestRecv`, called by `generateSweepDelta` on the sweep goroutine, created an
entry. `digestRecvFor` read the map for `DeliverDigest`. With stratified anti-entropy disabled,
`NewGossiper` allocated the map but the registration path was unreachable, so it remained
empty. Creating entries on the receive path would instead let arbitrary inbound frames grow
the map on the hotter connection goroutines.

Two related verification gaps remained. A truncated root announcement could be mistaken for
a complete root and corrupt the change gate's input, and the two longest race-detector suites
exceeded the verification runner's timeout before they could finish.

## Decision

Apply the same live-peer eviction rule to digest receive state, reject short root announcements,
and allow the long verification suites to finish rather than treating their timeouts as passes.

### Sweep-time eviction

`evictStaleDigestRecv` runs once at the start of each stratified sweep, immediately after
`evictStalePeerRoots`. It takes `digestRecvMu`, returns for a nil or empty map or a nil peer
set, and deletes entries for which `PeerSet.isLive` is false. The lock order is `digestRecvMu`
followed by the peer set's read lock. Registration and lookup do not hold the peer-set lock,
and peer-set methods do not call back into gossiper maps.

The receive path remains read-only with respect to the map. Neither `DeliverDigest` nor
`digestRecvFor` creates an entry, so unsolicited traffic cannot cause retention. Disabled
stratified anti-entropy never calls the eviction path and retains its original empty-map
behavior.

Deleting an entry drops only the map's reference. A sweeper already blocked on the channel
keeps its own reference and still leaves through its context or `digestWaitTimeout`. A late
`DeliverDigest` after eviction finds no channel and drops the response through the nonblocking
path. The peer may need another exchange, but the connection cannot panic or leave a sweeper
blocked indefinitely.

Live entries are retained deliberately. Evicting one could lose a response and force a
full-keyset fallback; retaining a departed entry until the next sweep costs only its receive
state. If no peers remain, the sweep returns before eviction, so entries persist until a peer
returns and liveness can be evaluated again.

### Truncated root announcements

`digestFrameRoot` requires the complete fixed header, the `seLen` word, and the full 32-byte
Merkle root. A shorter frame returns `ok=false`, and `DeliverDigest` leaves `peerRoots`
unchanged. At the time of this decision a complete announcement was a 65-byte frame and the test
covered every truncation from 0 through 64 bytes. Later header fields increase the minimum;
the parser computes it from the current header and root lengths rather than fixing it at the
old frame size.

### Verification timeouts

Cold 32-core c8g.8xlarge race-detector runs measured 1993.429s for `pkg/sync` and 2197.718s
for `pkg/mesh`, both beyond the previous 1500s cap. The verification-only cap became 2400s at
four call sites covering the mesh subset, both sync runs, and the full mesh sweep. Other suites
kept the 1500s default. The runner sets and restores `RUN_GATE_TIMEOUT` explicitly around the
four calls rather than relying on a shell-function environment prefix, so the override cannot
persist into unrelated commands.

The mesh measurement used about 92% of the new cap. Raising the cap lets the suite report its
real result; it does not skip tests or turn a test failure into a pass. A suite that grows
beyond the cap needs another timing review rather than removal of the long-running coverage.

## Consequences

`digestRecv` and `peerRoots` now share the same bound: after a sweep with a usable peer set,
their entries name only live peers. Later receive bookkeeping wraps the channel in a wait
record with timing state, but registration remains sweep-owned and eviction follows the same
rule.

The memory inventory at the time of the decision distinguished these peer-keyed bounds from
other caches with different ownership:

| State | Retention rule |
|:--|:--|
| `peerRoots` | Evict departed peers at sweep start. |
| `digestRecv` | Evict departed peers at sweep start. |
| `relayCache.m` | No entry-count bound; retained relay state remains a separate memory concern. |
| `relayCache.batchForward` | Reference-counted; deleted when `batchRefs` reaches zero, with live retained keys kept by design. |
| `relayCache.batchReverse` | Written by `retainBatch` with no corresponding deletion in this inventory. |
| `relayCache.batchRefs` | Deleted with its forward batch entry. |
| `payloadCache.m` | No entry-count bound; self-only writes and byte tracking continue the payload-cache design in [ADR-0007](0007_real_socket_mesh.md). |
| `sweepEnvCache` | Reset at the start of a round. |
| `PeerSet.peers` and `PeerSet.byAddr` | Deleted when `ClosePeer` removes the connection. |
| `TopologyManager.regions` | Bounded by the provisioned topology. |
| `stratDiag.exchange` and `stratDiag.fallback` | Reset when a diagnostic snapshot is taken. |

This table does not claim that every cache is bounded by live membership. In particular, the
relay and payload caches have their own retention requirements. The eviction decision covers
only `digestRecv` and reuses the existing `peerRoots` mechanism.

## Evidence

The eviction test drives `AntiEntropySweep` on a three-node loopback-TLS mesh. It first checks
that the unknown-root round created receive entries for both peers. After one peer departs, a
sweep removes that peer's entry and retains the live peer's entry. After rejoin and convergence,
`digestGateSkips` increases and the converged peers do not register new receive state. A
negative control that disables eviction leaves the departed peer's entry behind and fails the
test.

The truncation test drives the production delivery path. It first records a well-formed
announcement to prove that observation is active, then presents every truncated length below
the current minimum. `digestFrameRoot` rejects each one, no truncated frame overwrites the
recorded root, and the valid sender's existing entry survives. A control that accepts a short
frame fails at the zero-length case.

The timeout evidence comes from completed cold runs, not from raising the cap until failures
disappeared: `pkg/sync` completed in 1993.429s and `pkg/mesh` in 2197.718s with no test failures.
The previous 1500s cap could report only a timeout for those runs; the 2400s cap exposed their
actual results.


