# 4. Network Consensus and Distributed State — The Math

## 4.1 $\delta$-CRDT State Propagation

The engine is a **state-based $\delta$-CRDT** (delta Commutative Replicated
Data Type) synchronization substrate. Its states form a join-semilattice
$(S, \sqcup, \bot)$ whose join is commutative, associative, and idempotent.
Each mutation produces a $\delta$-state $\Delta \in S$ that a remote node can
join without receiving the sender's entire state
($\bigsqcup \delta_i = \bigsqcup s_i$).

These lattice properties provide convergence without a consensus vote. If
every mutation eventually reaches every node, delivery order, duplication,
and retransmission after loss do not change the final dot set. The protocol
elects no leader, requires no quorum, and does not use two-phase commit.

The local mutation primitive is `InsertLocal(entityID string, entry
CRDTEntry) CausalDot`. It assigns the next counter on the node's Lamport clock
and returns a `CausalDot{NodeID, Counter}` that uniquely identifies the
mutation. A `CRDTEntry` stores those fields as `DotNodeID` and `DotCounter`.
The Merkle root hashes the sorted dot pairs, not the entry payloads.

## 4.2 Birkhoff's Representation Theorem and Join Decomposition

Anti-entropy seeks an **irredundant join decomposition** of the symmetric
difference between sender and receiver. A join-irreducible element $x \in S$
cannot be expressed as $x = \bigsqcup_{y < x} y$. For the finite set lattice
formed by dots, Birkhoff's representation theorem gives the corresponding
decomposition into join-irreducible elements.

The symmetric difference contains the dots present on one node but not the
other. Each dot represents one mutation and is join-irreducible in this set
lattice. A successful reconciliation therefore sends the missing dots rather
than the whole state. The receiver's `Join(delta)` computes their union with
local state; because join is idempotent, receiving the same dot again does not
change the result. If reconciliation cannot recover the difference, the
fallback sends the full local set instead (§4.3.2).

## 4.3 IBLT — Sub-Linear State Reconciliation

Enumerating the full state on every sweep would make traffic grow with state
size even when peers differ by only a few dots. The engine instead uses an
**Invertible Bloom Lookup Table (IBLT)**. An IBLT stores a multiset in $n$
buckets using $k$ indices per key. Each bucket holds a signed count, the XOR
of its keys, and the XOR of their hashes. A serialized digest occupies $O(n)$
bucket space; when $n$ is small relative to the state, the digest is smaller
than an enumeration of that state.

With `--stratified-anti-entropy` enabled, a digest request and response
precede the delta. The requester uses the response's seed and bucket count to
build a compatible local table, subtracts the remote table, and peels the
residual to select which entries to send.

### 4.3.1 Hash Placement and Digest Sizing

The default placement uses double hashing to derive $k$ indices from one
primary hash:

$$
h_i(x) = \bigl( h_1(x) + i \cdot h_2(x) \bmod n \bigr), \quad i \in \{0, \ldots, k{-}1\}
$$

The inserted key is `HashCausalDot(dot, PayloadDigest)`, which covers the
mutation's node ID, counter, and payload digest rather than its location in
the HAMT.

`--iblt-v2` opts into the IBL2 wire format and decorrelated placement. For
each index, it adds a distinct golden-ratio multiple to the primary hash,
applies the splitmix64 finalizer, and takes the result modulo $n$. Peers must
use the same scheme: v1 and v2 nodes reject each other's digest encodings
([ADR-0064](adr/0064_iblt_reconciliation.md)).

The default digest uses a fixed bucket count. The v2 path keeps a per-peer
sizing ladder, doubling after an incomplete peel and halving after 4
consecutive clean peels. `--iblt-v2-min-buckets` can raise
its floor. The normal exchange no longer sends a `StrataEstimator`, and
`NewDynamicIBLT` is not the live sizing path. A v2 request carries only an
8-byte IBLT body containing the scheme and requested count; the responder
builds its table with that count ([ADR-0074](adr/0074_var_freelist_aba_and_v2_digest_requests.md)).

### 4.3.2 Peeling and Fallback

Let $T_a$ and $T_b$ be compatible IBLTs from two nodes. In $T_a - T_b$, common
keys cancel. A bucket is pure when its count is $\pm 1$ and its hash sum
matches the one remaining key; its key sum then identifies that key. Removing
the key from its other buckets can make those buckets pure in turn. Peeling
succeeds when no non-empty buckets remain and stops with `ErrIncompletePeel`
when collisions leave no pure bucket.

`GenerateDelta(remoteDigest)` builds its local table with the remote table's
seed and bucket count. Subtraction or peeling failure selects the full local
set, so an undersized or incompatible digest causes extra traffic rather than
an incomplete delta.

Digest construction checks every shard root after filling the table. If a
concurrent write changed any root, it clears the buckets and rebuilds from a
fresh root snapshot, with at most 3 attempts. This prevents a completed build
from silently combining different shard snapshots.

`TestIBLT_ZeroFalsePositives` checks exact recovery of 100 differences (50
local and 50 remote) on top of 100,000 shared keys, using $k=4$ and a fixed
seed. It is one deterministic regression test, not a guarantee
that every seed and table size peels successfully.

### 4.3.3 Crash Recovery and Reconciliation

WAL replay restores each mutation at its recorded dot through `Join`; it does
not call `InsertLocal` to mint a replacement identity
([ADR-0045 §2](adr/0045_mesh_transport_invariants.md)). Because the Merkle
root hashes sorted `(DotNodeID, DotCounter)` pairs, the same restored dot set
produces the same root. Normal anti-entropy then supplies any dots the
restarted node is missing. The root checks dot identity; the separate state
fingerprint covers the remaining entry bytes.

## 4.4 Conflict Resolution — Lossless Merge Union

The tri-temporal event model retains concurrent mutations. Two events $A$ and
$B$ for the same entity can occupy overlapping valid-time intervals; both
remain in the append-only HAMT. `Join` merges each distinct entity-and-dot
pair without selecting a write-time winner. Once nodes hold the same dots,
their logical states and Merkle roots agree regardless of arrival order.

An earlier design resolved conflicts eagerly through last-writer-wins and
discarded the losing event. That approach was removed because dropping a
mutation at the merge boundary is incompatible with the lattice's convergence
property ([ADR-0033](adr/0033_toki_closure_ghost_exorcism.md)). The IBLT key
`HashCausalDot(dot, PayloadDigest)` supports set reconciliation; it is not a
conflict-resolution rule.

Choosing one current value for a read is a separate operation. The pure
`selectLatestDot` function imposes a deterministic order: greatest
`DotCounter`, then smallest `DotNodeID` using `bytes.Compare`.

```go
func selectLatestDot(entries []eng.CRDTEntry) (eng.CRDTEntry, bool)
```

Both `handleGet` and `LatestPayload` use this selector, so `/v1/get` and the
accessor choose the same entry from the same input. Unselected entries remain
in the HAMT. The counter comparison is a deterministic tie-break, not a causal
ordering between independent origins.

### 4.4.1 Audit-Log Ingest Is Not Implemented

The repository does not contain an audit-record model or an audit-ingest ring
that applies backpressure by pausing socket reads. `ElimSlot` and
`flatCombPub` are cache-line-padded coordination slots for the CRDT write
path, not an audit pipeline. This subsection records scope only; it does not
describe a built capability.

## 4.5 Convergence After Network Partition

The in-memory `VirtualNet` (`internal/chaos/virtualnet.go`) provides a
time-wheel fabric with message loss, duplication, reordering jitter, and
explicit `Partition` blackholes. `TestMerkleConvergenceAfterPartition` builds
32 engines, generates 64 events before the partition and another 64 while it
is active, and blocks 512 directed edges between two groups. The profile has
5% ambient loss, 20% duplication, and 8 ms reordering jitter. After healing,
`pumpUntilConverged` allows up to 80 gossip rounds and the test requires every
Merkle root to match.

`TestConvergenceDeterminismAcrossRuns` performs two independent 8-node runs
with the test driver's sequence-number deduplication disabled. Both runs must
reach the same root, demonstrating that idempotent `Join` does not depend on
that transport-level deduplication.

The live mesh also supports opt-in partial views and hierarchical gateways.
With `--region-aware` configured, `--partial-intra-view` rotates a partial
intra-region view, while `--gateways-per-region` designates gateways and keeps
interior nodes from dialing other regions directly. Both options are off by
default ([ADR-0063](adr/0063_partial_intra_view.md),
[ADR-0073](adr/0073_hierarchical_gateway_topology_and_boot_dial.md)).

The published 100-node receipt records a 10,000-key write converging in
8.950 s after origin quiescence on 100 node processes across three
c7gd.8xlarge machines, one each in us-east-1, eu-west-1, and ap-southeast-2.
That run met its 10 s target; it is one measurement, not a latency guarantee
([receipt](../evidence/convergence-100-node.txt)).

### 4.5.1 Scope of the Fault Injection

`VirtualNet` and the symmetric-partition driver in
`internal/chaos/partition.go` exercise message-level faults in process. The
repository does not include Kubernetes Chaos Mesh manifests or OS-level fault
injection. These tests therefore do not simulate kernel, device, or physical
network failures.

## 4.6 Delta Encoding and Edge Scope

`func (*DeltaCRDTEngine) GenerateDelta(remoteDigest *IBLT) *CRDTDelta` returns
a lazy `Entries` iterator over the local entries selected by reconciliation. The
caller must release the delta after consuming it. A successful peel selects
the entries missing from the remote digest; the fallback described in §4.3.2
selects the full local set.

Engine-to-engine synchronization uses `CRDTDeltaEvent` and `CRDTDeltaBatch`
from the [Cap'n Proto schema](../../api/capnp/api/capnp/schema.capnp). Client
ingestion uses the distinct `TriTemporalEvent` schema. Cap'n Proto accessors
read fields from the message's segments without first deserializing the whole
event into a separate Go value; the message and its backing storage must
remain alive while those views are in use.

No browser edge runtime is included. SQLite-WASM persistence, OPFS VFS
integration, and DuckDB-WASM analytics are not capabilities of this
repository. An edge implementation would need to supply that runtime and use
the same delta and read-time selection semantics described above.
