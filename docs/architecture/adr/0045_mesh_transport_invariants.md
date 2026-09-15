# ADR-0045: Mesh Transport Correctness Invariants — the Two-Release Discipline

- **Status:** Accepted. The invariants are implemented and silicon-gated.
- **Date:** 2026-08-19 (recovery-law amendment through 2026-09-04)
- **Author:** Harsh Rawat
- **Scope:** `pkg/mesh/{peer,gossip}.go`, `pkg/receive/receiver.go`, `pkg/durability/{bridge,recovery,snapshot}.go`, `internal/chaos/wal.go`, `cmd/sovereign-node/main.go`. The five merge-law/wire-schema files are untouched.
- **Supersedes:** the implicit assumption in the earlier multi-region design that the mesh transport "just worked."

The multi-region design specified the target topology (intra-region full-mesh, inter-region fan-out) and the reconciliation primitive (IBLT), but it never specified the transport-layer invariants that make a real TCP+TLS mesh physically converge. Silicon proved the gaps were live, not theoretical. This ADR records the invariants, the exact-WAL recovery law, and the honest limits.

## 1. Context — three root causes

- **Asymmetric connection graph.** The peer set's live map (which `Publish` queries) was populated only on outbound `Dial`; the accept loop received frames but never registered the inbound peer. A connection B→A was a publishable edge for B, not for A. At 100 nodes the boot-dial races 99 listeners and every lost dial permanently excluded that peer; at 3 nodes the race never bites. A cardinality cliff.
- **Broken relay.** The ship path looked the payload up in an origin-side-only cache, so a peer that received a foreign delta could not forward it. The relay envelope with the embedded payload existed but was built only for 0-hop origin frames — so the O(log N) convergence the topology assumed never occurred; the origin had to reach every peer directly.
- **Missing verification tier.** The loopback tests used an in-process mailbox model that bypasses the real PeerSet/Dial/Accept stack, so no loopback test could reproduce a connection-graph or relay defect. Silicon was the only tier that exercised the real transport — at 100 nodes, the worst place to find a cardinality bug.

## 2. The invariants

```
INV-1 (Connection Symmetry): every accepted TLS connection registers the inbound
  peer into the live-peer map, keyed under the real nodeID decoded from the TLS
  leaf CN — the same identity Dial reconciles on. A connection becomes a
  bidirectional publishable edge; a lost outbound dial no longer permanently
  excludes a peer that dialed us.

INV-2 (Relay With Payload): for a FOREIGN entry (received, not originated), the
  ship path forwards the last-received relay envelope — payload embedded, not
  regenerated from the HAMT + cache. The next hop reassembles and joins WITHOUT a
  cache hit on the origin. This is what makes fan-out-N reach all N nodes in
  O(log N) rounds.

INV-3 (Real-TCP Verification Tier): the mesh transport is exercised over real
  TCP+TLS before the silicon tier. A deterministic staggered-boot RED→GREEN test
  (2–3 nodes, net.Listener, not net.Pipe) closes the coverage gap; a mailbox or
  in-process test asserting convergence here would pass vacuously.
```

Implementation: INV-1 lives in `pkg/mesh/peer.go` (`RegisterInbound`/`ReleaseInbound`/`nodeIDFromConn`). INV-2 lives in `pkg/receive/receiver.go` (the relay hook + retainer, fired before the accept returns) and `pkg/mesh/gossip.go` (the relay cache, `RetainForeign`, and the `shipDelta` FOREIGN branch that publishes the received envelope byte-identical — no re-origin-sign). INV-3 lives in `pkg/mesh/asymmetric_dial_test.go`. A `sync.Once`-guarded close on the peer connection closes a close-of-closed-channel race between the read-loop's deferred close and the inbound-release path that only surfaces under accept-loop churn at fleet scale.

## 3. The two-release ladder

- **Release A** (this ADR): INV-1 + INV-2 + INV-3 → the 100-node convergence gate. The dial graph is still O(N²) (halved by symmetry, still quadratic) — fine at 100 nodes, strained at ~1K, impossible at 10K. The honest claim is "proven at 100 nodes," not "planetary."
- **Release B** (the planetary follow-up): partial-view membership — each node dials O(fanout) peers and deltas relay through the partial view in O(log N) rounds, dropping connections from O(N²) to O(N·fanout). INV-2's relay is the hard prerequisite: a partial view that cannot relay can never converge. Release B is gated on a ≥1K-node silicon run before any "planetary" restatement.

The ordering is physical, not a preference: relay (INV-2) is the prerequisite for partial-view membership, so the sequence is INV-1 → INV-2 → gate at 100 → partial view → gate at 1K+.

## 4. The exact-WAL recovery law

Crash recovery is rebuilt on identity, not counters. The load-bearing decision: **replay restores the recorded dot — it never re-mints.**

1. Every WAL record retains its sequence; the final checkpoint records its sequence cut; the post-checkpoint replay tail is selected by record position, never by a scalar Lamport counter.
2. Replayed mutations are restored at their recorded (DotNodeID, DotCounter) via the synthetic-delta Join route; `InsertLocal` is forbidden on the replay path (re-minting double-mints and corrupts).
3. The WAL persists the complete 120-byte CRDTEntry semantics, with the persisted origin/dot stamped from the returned CausalDot; format evolution is a versioned record type — old bytes are never reinterpreted, and a legacy log is announced as legacy, never silently zero-filled.
4. Snapshots are bound to the exact checkpoint sequence and validated; local snapshot dots are cross-checked against durable WAL identity; local phantoms are rejected; foreign image state is kept only when safely anchored; any anchor failure takes the loud, machine-observable full-replay fallback.
5. `RecoveryWitness` is extended (checkpoint cut, path, records applied, snapshot validation, fallback reason, legacy status); `ErrRecoveryRootMismatch` stays load-bearing; the concurrent-writer checkpoint race is closed without a write-path mutex.

## 5. The integrity oracle

Recovery is verified by an armed oracle, not assumed: a recovered root must re-equal the pre-crash root, and a corrupted or mismatched image refuses to boot loudly rather than silently serving wrong state. The oracle is armed on the snapshot path and the sequence contiguity of the WAL tail is asserted, so a skipped or forged record is caught at boot.

## 6. Acceptance gates

- **Real-TCP RED→GREEN teeth** for INV-1 (a 3-node staggered boot) and INV-2 (a linear A→B→C chain with A partitioned from C: B must forward to C via the embedded-payload relay). Each tooth is proven load-bearing by a bug-inject control — disabling the mechanism turns the tooth red. The relay chain is proven load-bearing by `TestRelayChainLoadBearing`; the byAddr cardinality bound by `TestB1_ByAddrBoundedByLiveEdges`; the hybrid PQ convergence by `TestB7_ThreeNodeHybridConverges`.
- **The 100-node silicon gate:** a 10K-key delta converges across 100 nodes / 3 regions, WAL-durable. Measured: all 100 nodes converged in 9.610 s against the 10 s SLO (batch-size 100, region-aware fan-out).
- **The crash-recovery leg:** a seed node is killed mid-run and rejoins with its recovered root re-equaling the fleet.

## 7. Honest limits (open items, not closed)

- **Memory:** one gate run measured max node RSS 567,616 KB against a 512,000 KB threshold (a 10.9% breach). The relay-cache refcount is unit-proven, so the growth driver is elsewhere (the unbounded-by-intent payload cache and the arena high-water are candidates). This is root-caused before any production-memory claim; the convergence gate passing does not close it.
- **Sweep cost:** the sweep hoist removed redundant delta generation, but per-peer build+sign still dominates a sweep.
- **Budget refill:** the admission budget is a lifetime quota with no time-based refill; a long production run will eventually exhaust it. Time-based refill is Release-B work.
- **Cold boot:** the gate ran with the Lamport absolute-slack raised (a scoped, disclosed stop-gap) so a cold peer's first 10K batch is admitted; the general verified-origin bulk-transfer catch-up is Release-B work.

## 8. Status

Accepted. The invariants and the exact-WAL recovery law are implemented and silicon-gated at 100 nodes. Release B (partial-view membership) is the committed planetary follow-up, gated on a ≥1K-node run. The open items in §7 are disclosed, not closed.
