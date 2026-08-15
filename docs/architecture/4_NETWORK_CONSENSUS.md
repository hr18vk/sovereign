# 4. Network Consensus and Distributed State — The Math

## 4.1 $\delta$-CRDT State Propagation

The engine is a **state-based $\delta$-CRDT** (delta Commutative Replicated
Data Type) synchronization substrate. A CRDT is a data structure whose states
form a join-semilattice $(S, \sqcup, \bot)$ where $\sqcup$ is commutative,
associative, and idempotent. The $\delta$-variant avoids shipping the full
state across the network: each mutation produces a $\delta$-state
$\Delta \in S$ that, when joined at a remote node, yields the same result as
joining the entire state ($\bigsqcup \delta_i = \bigsqcup s_i$).

This is the engine's distributed correctness theorem. It is not a protocol
optimization layered on top of an underlying consensus vote; it **is** the
consensus. Convergence is guaranteed by lattice completeness: **once all nodes
eventually receive all deltas, their final state matrices must perfectly
converge**, regardless of delivery order, duplication, or transient loss.
There is no quorum to lose, no leader to elect, no two-phase commit to block
on.

The local mutation primitive is `InsertLocal(entityID, entry CRDTEntry)
CausalDot`. The returned `CausalDot = {DotNodeID, DotCounter}` is minted from
that node's strictly monotonic Lamport counter; the dot is the engine's unique
identifier for the mutation and is the sole participant in the Merkle root.

## 4.2 Birkhoff's Representation Theorem And Irredundant Join-Decomposition

The blueprint mandates an **irredundant join-decomposition** of network
egress: the engine transmits only the join irreducibles of the symmetric
difference between sender and receiver. A join-irreducible element
$x \in S$ is one that cannot be expressed as $x = \bigsqcup_{y < x} y$. This
is precisely **Birkhoff's representation theorem**: every element of a finite
join-semilattice is uniquely representable as the join of its join-irreducible
components.

Concretely, the symmetric difference between two nodes is the set of dots
present in one but not the other; each dot is itself join-irreducible (a
single mutation has no sub-join representation). Anti-entropy therefore ships
**only newly-minted dots**, and the receiver's `Join(delta)` applies them once
and only once — the CRDT lattice $\sqcup$ is idempotent, so a duplicate
delivery is a no-op. This bounds network egress by the set difference rather
than the state size, which is the economic motivation for the $\delta$ model
under degraded planetary-scale networks.

## 4.3 IBLT — Sub-Linear State Reconciliation

The set difference is too large to enumerate over the wire. The engine computes
it with an **Invertible Bloom Lookup Table (IBLT)**, a probabilistic data
structure invented by Goodrich, Mitzenmacher, et al., based on the work of
Eppstein, Goodrich, et al. on invertible summaries. An IBLT stores a multiset
in $n$ buckets using $k$ hash functions; each bucket accumulates an XOR of the
keys it received and a running checksum. The wire footprint is $O(n)$ where
$n$ is proportional to the symmetric difference size — *sub-linear in the
state size*. Reconciliation is a two-message exchange: each side ships its
IBLT, they subtract, and the residual "peels" to recover the missing keys.

### 4.3.1 The Hash Scheme

The implementation uses double hashing — a single $O(1)$ key derivation that
expresses $k$ indices without $k$ independent hash functions:

$$
h_i(x) = \bigl( h_1(x) + i \cdot h_2(x) \bmod n \bigr), \quad i \in \{0, \ldots, k{-}1\}
$$

The engine keys its IBLT with `HashCausalDot(dot, PayloadDigest)` — a hash of
the mutation's identity, not its location — so the IBLT encodes what's
*different*, not where. The `StrataEstimator` layers IBLTs by the trailing
zero count of the key, giving a sub-linear estimator of the symmetric
difference size $|d|$, which sizes the *targeted* reconciliation IBLT
dynamically (via `NewDynamicIBLT`) so the bucket array is never oversized
when the diff is small and never oversparsed when the diff is large.

### 4.3.2 The Peeling Proof

Let $T_a$ and $T_b$ be the two nodes' IBLTs over the same key set. After
$T_a - T_b$, a bucket contains precisely the entries of $T_a$ that were not
in $T_b$ minus the entries of $T_b$ that were not in $T_a$. A bucket is
**peelable** iff it contains a single entry, in which case its key
$\text{key} = \text{bucket.keySum}$ and the entry is removed from every other
bucket that hashes to it via $h_i$. Peeling cascades — iterating peelable
buckets uncovers new peelable buckets — until no buckets remain (success) or
no buckets are peelable (failure due to collisions from an undersized table).
The engine's `NewIBLTWithSeed(n, k, seed)` uses $n \sim 1.5 \times$ the
expected difference size and $k = 4$ hashes, which empirically yields
zero false-positive peels in `TestIBLT_ZeroFalsePositives` over 100
differences (50 local + 50 remote) seeded atop 100,000 shared keys in a
single deterministic run — not a 100-iteration property loop.

### 4.3.3 Recovering From A Raw SIGSEGV

The same reconciliation primitive recovers distributed state after a raw
node crash. A `SIGSEGV` collapses a worker process; the worker's in-memory
HAMT dies with it. But the WAL reconstructs the mutation stream, and a worker
restarted from the WAL replays the dots into a fresh engine. Because the
Merkle root folds only `(DotNodeID, DotCounter)` pairs, the replayed engine
and a peer that never crashed converge to the same root — the IBLT-mediated
anti-entropy proves they hold the same dot set within one gossip round.

## 4.4 Conflict Resolution — Lossless Merge-Union, not an Eager TOKI Algebra

The tri-temporal event model does not overwrite; it accrues. Two events
$A$, $B$ describing the same entity at overlapping Valid-Time intervals are
*both* retained in the append-only HAMT — the engine never picks a winner at
the write/merge boundary. The blueprint's Track 4.3 once named a "TOKI
Conflict Resolution Integration" built around an eager-lossy
`LWWOperator.Resolve(eventA, eventB)` that *drops* the loser; that package
(`internal/temporal_store/toki.go` and its `TOKI` interface, `AuditRecord`,
and a 7-field LWW cascade) was **DELETED** as zero-importer dead code (Day 28,
ADR-0033) and the blueprint line is marked **WON'T-FIX** precisely because
wiring an eager drop into `Join` would break convergence.

The convergence law forbids the eager drop. `Join` is a FROZEN
**MERGE-UNION** semilattice: applying an incoming $\delta$ inserts every
incoming `CausalDot` keyed by `HashCausalDot(dot, PayloadDigest)` — no dot
is dropped, ever (`pkg/sync/crdt.go:1089` `Join`; `:1221` `perShardMerge`;
`:1580` `HashCausalDot`). Because `Join(a, b) = a \sqcup b` is monotone,
idempotent, and commutative, a CRDT converges by lattice completeness — once
all deltas are received, every node's state matrix is byte-equal regardless
of delivery order, duplication, or loss. An eager `Resolve` that returned
`(winner, loser)` and dropped the loser would make the dropped dot
un-re-mergeable across a crash-recovery gap (the WAL-replay seed discipline
re-runs minting starting at `LamportHigh - len(Mutations)`), so the CRDT
would *not* converge — a data-corruption regression. The deleted TOKI
algebra is therefore not merely absent; it is *incompatible* with the engine's
correctness theorem.

Conflict resolution that the lossless lattice does *not* provide — a single
"latest" value for a read response — is applied at **read time**, not merge
time, and it is lossless: the loser stays in the HAMT. The live selector is
`selectLatestDot` (`pkg/mesh/gossip.go:531`), a pure, order-independent
function with a 2-dimensional pick — max `DotCounter`, then ties broken by
smallest `DotNodeID` via `bytes.Compare`:

```go
func selectLatestDot(entries []eng.CRDTEntry) (eng.CRDTEntry, bool)
```

This is *not* the 7-field cascade (`SystemTime → PayloadDigest →
ValidTimeStart → AssertionTime → ValidTimeEnd → H3Index → EntityID`) the
deleted `LWWOperator.Resolve` implemented: that cascade described a package
that no longer exists (`grep -rn 'TOKI\|LWWOperator\|AuditRecord\|Resolve(eventA' --include='*.go'` returns zero hits) and is not the live mechanism.
Both `handleGet` and the standalone `LatestPayload` route through this one
selector so the `/v1/get` response and the accessor can never pick different
"latest" values for the same entry slice. The pick is a deterministic
tie-break, explicitly documented as a tie-break (not a causal claim — dots
from different origins are not totally ordered by counter alone); a future
query at a different txTime may pick a different winner from the same
append-only dot set.

### 4.4.1 Audit-Log Ingest Path — Planned, Not Implemented

A prior revision of this section described a "lock-free MPMC CAS ring buffer"
audit-ingest path in which a full ring parks the ingress goroutine via
`gopark`, halting `net.Conn.Read()` so the kernel advertises TCP Zero-Window
to the remote peer. That mechanism is **not implemented**: there is no
`AuditRecord` type, no `JudgeLog`/`Judge-Log` symbol, and no `gopark`/`MPMC`/
`ZeroWindow` reference anywhere in the engine (`grep -rn 'gopark\|MPMC\|zero-window\|ZeroWindow\|Judge-Log\|JudgeLog\|AuditRecord' --include='*.go'` returns zero hits; the only 128-byte / two-cache-line structs in the codebase are `ElimSlot` in `pkg/sync/elimination.go` and `flatCombPub` in `pkg/sync/flatcomb.go`, both unrelated elimination/flat-combining slots). An audit-log ingest path with
transport-coupled backpressure may be a future addition; until then this
subsection is documentation-only and presents nothing as built.

## 4.5 Convergence Gate After Network Partition

The blueprint's Stage 6 §3 mandates a *chaotic virtual network partition*:
packets are dropped, aggressively duplicated by retries, and arrive
out-of-order, then connectivity is restored and `Node[i].MerkleRoot()` must
equal `Node[j].MerkleRoot()`. The engine implements this as an in-memory
**Chaos VirtualNet** (`internal/chaos/virtualnet.go`): a time-wheel fabric with
ambient drop probability, per-message duplicate (with independent jitter so
duplicates arrive out-of-order), and explicit `Partition` blackholes. A 32-node
orchestrator distributes 64 temporal events, partitions the fabric into two
isolation groups across 512 blackholed edges, gossips under the partition,
heals, and asserts byte-equal Merkle roots across all 32 nodes.

`TestStage6MerkleConvergenceAfterPartition` verifies convergence under 5%
ambient drop, 20% duplication, 8 ms reordering jitter. The test's
`pumpUntilConverged` caps the post-heal pump at 80 gossip rounds and
returns/logs the actual count; in practice intra-group convergence is
observed at ~17 rounds, well within the 80-round cap (the count is an
observed run value, not a code invariant — there is no constant 18). The
**determinism gate**
(`TestStage6ConvergenceDeterminismAcrossRuns`) takes two completely
independent 8-node runs with `Dedup: false` — i.e., the engine's idempotent
`Join`, not the orchestrator's SeqNo dedup, is what guarantees correctness —
and asserts both runs converge to the *same* Merkle root. This proves §3's
math is a deterministic lattice join, not a transport-dependent artifact.

### 4.5.1 The OS-Level Half (external; not in-repo)

The blueprint originally named a second half: OS-level fault injection via
Kubernetes Chaos Mesh CRDs (`IOChaos`, `NetworkChaos`). D8 FIX: no
`chaos-mesh/` manifest directory exists in this repository — the prior
revision's references to `network-partition.yaml`, `network-loss.yaml`,
`network-delay.yaml`, and `io-delay.yaml` pointed at files that were never
shipped. The verified chaos half lives entirely in-process in this repo:
`internal/chaos/virtualnet.go` (per-node mailbox goroutines, time-wheel
delivery, ambient drop, duplicate, and per-edge blackhole) and
`internal/chaos/partition.go` (the symmetric-partition orchestrator). A
future Kubernetes deployment may re-introduce Chaos Mesh manifests; until
then this section is documentation-only and the `internal/chaos/*.go` files
are the source of truth.

## 4.6 Zero-Copy Edge Compute

Edge ubiquity requires the same tri-temporal substrate on a browser with no
server in the path. D8 FIX: the prior revision referenced an
`EXTERNAL_INTEGRATIONS_DEFERRED.md` document that does not exist in this
repo. The edge substrate is intentionally out-of-scope for the core ledger
ball and is described here at the architectural level only; the three layers
are:

- **SQLite-WASM persistence** with one of three OPFS VFSes:
  `AccessHandlePoolVFS` (exclusive single-tab), `OPFSCoopSyncVFS` (leader-tab
  multiplexing with `BroadcastChannel` and Web Locks), and
  `OPFSWriteAheadVFS` (the production choice: dual-WAL rotation exploiting
  Chromium's `readwrite-unsafe` OPFS mode, mathematically guaranteeing reads
  never block writes across multiple browser tabs).
- **DuckDB-WASM analytical vectorization** issues HTTP range requests against
  Parquet files on decentralized object storage, bypassing centralized egress
  and executing the analytical workload in the browser at the cost of a cold
  HTTP fetch per column chunk.
- **Zero-copy Cap'n Proto RPC** — the engine ships
  `GenerateDelta(*DeltaCRDTEngine, *IBLT) *CRDTDelta`, whose `Entries` lazy
  iterator yields the (entityID, CRDTEntry) pairs the remote peer is missing.
  A transport encodes those pairs into the wire format (the canonical
  length-prefixed deltagram encoding lives in `internal/chaos/partition.go`);
  the receiver applies them via `Join`. The ingestion plane uses the
  `TriTemporalEvent` Cap'n Proto schema (see
  `api/capnp/api/capnp/schema.capnp`), whose backing segment is readable
  directly from the network socket memory without CPU deserialization.
  Cap'n Proto structs are cache-aligned in their encoding, so the same
  discipline that made the arena cache-friendly maintained the edge's
  economic feasibility: a battery-powered edge device can hydrate an
  ingestion event without a deserialization pass.

The composition is a supremumty property: the edge node, on a phone, over a
flaky cellular link, can hold a bitemporal projection of the same lattice the
datacenter does, reconcile to it asynchronously via IBLT, and resolve local
conflicts via the same lossless `Join` merge-union + read-time
`selectLatestDot` pick (§4.4) — all without a synchronous round-trip to a
centralized authority.
