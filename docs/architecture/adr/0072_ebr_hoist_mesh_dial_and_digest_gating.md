# ADR-0072: EBR hazard-snapshot hoist, mesh dialing, and digest gating

- **Status:** Accepted
- **Date:** 2026-10-29

## Context

`(*EBRManager).AdvanceEpoch` detaches the retired-list heads for a safe epoch
across 256 shards. Calling `freeRetiredList` for each shard repeated the
participant hazard scan even though all of those lists could use one snapshot.
The repeated scans dominated reclamation under the race detector.

Three mesh receive-path cases also lost or misclassified exchanges:

- `(*PeerSet).Dial` checked the configured address in `ps.byAddr` but not the
  peer ID in `ps.peers`. A live inbound connection indexed by an ephemeral
  remote address therefore did not prevent a duplicate outbound dial, whose
  installation could replace the inbound edge.
- During simultaneous mutual dialing, both outbound sides could install their
  connections before either inbound side completed registration. Each inbound
  side then declined the apparent duplicate. Without a separate challenge
  handle, the declined connection could not establish the identity required by
  `DigestConnVerified`, so its digest frames were dropped.
- `(*Gossiper).DeliverDigest` treated requests as responses for the per-peer
  wait channel. An unsolicited request could remain in that channel and be
  counted as the next drained exchange, distorting the adaptive digest wait.
  Root announcements also entered arrival-latency accounting despite having no
  build timestamp.

## Decision

Take one hazard snapshot after `AdvanceEpoch` finds at least one detached
retired list, and pass it to `freeRetiredListWithHazards` for every non-empty
shard. The snapshot uses a bounded stack buffer; if that buffer fills,
reclamation falls back to a complete live hazard scan for each candidate. The
empty-drain case retains the existing `freeRetiredList` calls and their pacing.

Make `Dial` idempotent for a live peer ID as well as for a live configured
address. A closed connection remains replaceable.

For a declined inbound connection, `ArmDeclinedInbound` creates an unregistered
`PeerConnHandle` and starts the key-possession challenge.
`HandleDeclinedChallengeFrame` verifies a challenge response through that
handle without changing `ps.peers` or `ps.byAddr`; other challenge frames keep
the stateless response path. Digest delivery still requires the connection's
own verified bit.

Finally, deposit only `digestRoleResponse` and `digestRoleResponseV2` frames
into the per-peer response channel. Requests continue through asynchronous
response handling. Exclude `digestRoleRootAnnounce` from build-stamp arrival
accounting while retaining its peer-root update.

## Consequences

Epoch advancement no longer rescans the participant list once per non-empty
retired-list shard. Hazard protection remains authoritative when the snapshot
buffer is exhausted.

Mutual dialing can retain one registered edge while still authenticating the
declined connection for digest exchange. Requests cannot impersonate responses
in the wait channel, and a root announcement cannot create a false broken
arrival or response-latency sample.

## Evidence

- `TestEBR_HoistedHazardSnapshotAdversarialRace` exercises reclamation with
  concurrent participants and retired lists. The crossover regression tests in
  `pkg/mesh/defer_crossover_test.go` exercise the paths previously delayed by
  repeated hazard scans.
- The tests in `pkg/mesh/declined_conn_challenge_test.go` cover sequential and
  simultaneous mutual dialing, rejection of request frames by the response
  channel gate, and exclusion of root announcements from broken-arrival
  accounting.

These are correctness and race-detector tests. This record does not attach a
fleet timing claim to them.
