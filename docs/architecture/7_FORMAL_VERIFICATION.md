# 7. Formal Specifications & Mechanically-Enforced Properties

Sovereign Engine is designed for hardware faults, network partitions, and arbitrary OS scheduling. This document records design-level specifications for convergence and durability and identifies the Go tests that exercise the corresponding properties.

> **Verification boundary.** No `.tla` files are checked into this repository, and no TLC model-checker run backs the specifications below. They are hand-written models of intended invariants, not proofs. The executable checks cited below are Go tests; their scopes and skip conditions are stated with them.

---

## 1. Conflict Resolution: Dot-Merge-Union Join + Lossless Read-Time Pick

Conflict resolution has two layers: `Join` retains every distinct causal dot, and the read path selects one live entry only when a caller requests a single value. [ADR-0033](adr/0033_toki_closure_ghost_exorcism.md) records the removal of `internal/temporal_store/`, whose `LWWOperator.Resolve` returned a winner and loser for eager last-writer-wins resolution. Dropping the loser during `Join` would violate the merge law. In particular, a dot discarded before entering state cannot be reintroduced by `AdvanceLamportTo`; replay would advance the clock without restoring the missing state. The current merge does not use that operator.

**Merge layer: `Join` unions causal dots.** `(*DeltaCRDTEngine).Join` in `pkg/sync/crdt.go` groups incoming entries by entity and merges each entity's entries by `(DotNodeID, DotCounter)`. `HAMT.Set(entityID, merged)` stores the resulting slice in the HAMT. `HashCausalDot(dot, digest)` is used separately to key entries in the IBLT; it does not key the HAMT. Duplicate dots are ignored, while distinct dots remain in live state. The result is a join-semilattice modulo causal-dot identity: monotone, idempotent, commutative, and associative.

**Read layer: `selectLatestDot` picks from live entries.** `(*ControlServer).handleGet` and `(*Gossiper).LatestPayload` call `PointGet(entityID)` and pass the resulting entry slice to `selectLatestDot` in `pkg/mesh/gossip.go`. The selector orders entries by two fields:

1. `DotCounter`: the entry with the larger counter wins.
2. `DotNodeID`: on a counter tie, `bytes.Compare` chooses the lexicographically smaller 16-byte node ID.

The selector depends only on the slice contents, not their order. The node-ID tie-break is deterministic, not a causal ordering between origins. Unselected entries remain in the HAMT. `e.ebr.Retire` reclaims replaced or unpublished HAMT roots after compare-and-swap; it does not remove dots from live state. `/v1/get` and `LatestPayload` always read current live state. Historical selection by `txTime` belongs to `/v1/query`, which calls `Resolver.AsOf`.

Concurrent updates to one entity can therefore produce one deterministic response without deleting the other updates from CRDT state. The deleted `CompareEvents` cascade ordered seven fields; the current live-read selector uses only the two fields above.

---

## 2. $\delta$-CRDT Convergence & Anti-Entropy

Anti-entropy uses Invertible Bloom Lookup Tables (IBLTs) to subtract replica summaries and peel set differences before sending missing deltas. `GenerateDelta` falls back to full local state when subtraction or peeling fails. The HAMT holds current dot sets; the IBLT is the synchronization summary, not the store of record.

### $\delta$-CRDT Convergence — Design-Level Specification

The `Delta_CRDT_Sync` model below abstracts those exchanges as sets. It expresses capacity-bounded peeling, full-state fallback, and join-based receipt of deltas. It has not been model-checked. These Go property tests exercise the merge laws on generated deltas:

- `TestCRDTJoinCommutativity` in `pkg/sync/crdt_property_test.go`
- `TestCRDTJoinAssociativity` in `pkg/sync/crdt_property_test.go`
- `TestCRDTJoinIdempotence` in `pkg/sync/crdt_property_test.go`

The tests sample the implementation's behavior; they are not proofs for arbitrary inputs. The `EventualConvergence` predicate states the intended condition when no messages remain. It is not a temporal-liveness formula, and it has not been checked by TLC.

```tla
--------------------------- MODULE Delta_CRDT_Sync ---------------------------
EXTENDS Naturals, Sets

CONSTANT Replicas, Keys, MaxIBLTCapacity

VARIABLES replicaState, networkBuffer

Vars == <<replicaState, networkBuffer>>

TypeOK ==
    /\ replicaState \in [Replicas -> SUBSET Keys]
    /\ networkBuffer \in SUBSET [
         src          : Replicas,
         dst          : Replicas,
         type         : {"Digest", "Delta"},
         digestSeed   : Nat,
         payload      : SUBSET Keys,
         ibltCapacity : Nat
       ]

Init ==
    /\ replicaState \in [Replicas -> SUBSET Keys]
    /\ networkBuffer = {}

(* Replica A sends a causal state digest (represented by IBLT) to Replica B *)
SendDigest(src, dst) ==
    /\ networkBuffer' = networkBuffer \cup {[
         src          |-> src,
         dst          |-> dst,
         type         |-> "Digest",
         digestSeed   |-> 42,
         payload      |-> replicaState[src],
         ibltCapacity |-> MaxIBLTCapacity
       ]}
    /\ UNCHANGED replicaState

(* Replica B receives the digest, subtracts it, and peels the difference *)
ReceiveDigest(dst, msg) ==
    /\ msg.type = "Digest"
    /\ msg.dst = dst
    /\ LET
         localState  == replicaState[dst]
         remoteState == msg.payload
         symDiff     == (localState \ remoteState) \cup (remoteState \ localState)
       IN
         IF Cardinality(symDiff) <= msg.ibltCapacity THEN
             (* Peeling succeeds: Extract and transmit only the missing keys *)
             /\ networkBuffer' = (networkBuffer \ {msg}) \cup {[
                  src          |-> dst,
                  dst          |-> msg.src,
                  type         |-> "Delta",
                  payload      |-> localState \ remoteState,
                  digestSeed   |-> msg.digestSeed,
                  ibltCapacity |-> msg.ibltCapacity
                ]}
             /\ UNCHANGED replicaState
         ELSE
             (* Peeling fails: Fallback to sending full local state *)
             /\ networkBuffer' = (networkBuffer \ {msg}) \cup {[
                  src          |-> dst,
                  dst          |-> msg.src,
                  type         |-> "Delta",
                  payload      |-> localState,
                  digestSeed   |-> msg.digestSeed,
                  ibltCapacity |-> msg.ibltCapacity
                ]}
             /\ UNCHANGED replicaState

(* Replica A receives the delta state and merges it using the join-semilattice *)
ReceiveDelta(dst, msg) ==
    /\ msg.type = "Delta"
    /\ msg.dst = dst
    /\ replicaState' = [replicaState EXCEPT ![dst] = @ \cup msg.payload]
    /\ networkBuffer' = networkBuffer \ {msg}

Next ==
    \E A, B \in Replicas :
        \/ /\ A /= B
           /\ SendDigest(A, B)
        \/ \E msg \in networkBuffer :
             \/ ReceiveDigest(B, msg)
             \/ ReceiveDelta(B, msg)

(* Intended condition when no messages remain: all replica states are equal *)
EventualConvergence ==
    \A A, B \in Replicas : (networkBuffer = {}) => (replicaState[A] = replicaState[B])
=============================================================================
```

---

## 3. Deterministic Chaos Simulator Constraints

`internal/chaos/supervisor.go` runs the engine in a separate worker process connected by stdin/stdout pipes. A worker crash closes its pipe; the supervisor starts a fresh worker that replays the WAL. The supervisor does not own a `net.Listener`: the daemon front end, or the test process, owns it outside the worker's failure domain.

The model below covers listener survival and reconstruction of database state from the WAL. In the implementation, `Submit` retries an interrupted submission once after recovery and returns an error if that retry fails.

### Supervisor/Worker Isolation — Design-Level Specification

The following Go tests exercise specific parts of this design:

- `TestSIGSEGVSurvival` in `internal/chaos/survival_test.go` is intended to check that a TCP connection remains usable while an external worker crashes and recovers with an equal Merkle root. It skips in `-short` mode or when `CHAOS_WORKER_BIN` is unset. When the variable is set, the test ignores the supplied path and unconditionally attempts to build `./cmd/chaos-worker/`. That directory is absent from this tree, so the test fails before creating a worker and provides no current end-to-end crash-survival result.
- `TestWALRecoveryDeterminism` in `internal/chaos/wal_test.go` checks the recovered Merkle root and Lamport clock after WAL replay, without spawning a process.
- `TestRecoveryDeterminism_KillRebuildMerkleEqual` in `pkg/durability/bridge_test.go` closes the live engine and WAL, rebuilds from the WAL, and compares roots and Lamport clocks.
- `TestSnapshot_Determinism_PreVsPostCheckpoint_MerkleEqual` in `pkg/durability/snapshot_test.go` compares bounded and full recovery over the same origin-only WAL and requires both roots to equal the live root.

```tla
--------------------- MODULE Supervisor_Worker_Isolation ---------------------
EXTENDS Naturals, Sequences

VARIABLES 
    workerState,     \* {"Dead", "Alive"}
    listenerState,   \* {"Listening", "Closed"}
    wal,             \* Seq([id: Nat])
    dbState,         \* SUBSET [id: Nat]
    unackedSubmits,  \* SUBSET [id: Nat]
    supervisorState  \* {"Normal", "Recovering"}

Transactions == [id : Nat]

Init ==
    /\ workerState = "Alive"
    /\ listenerState = "Listening"
    /\ wal = << >>
    /\ dbState = {}
    /\ unackedSubmits = {}
    /\ supervisorState = "Normal"

(* Client submits a transaction while the front-end listener is open *)
ClientSubmit(tx) ==
    /\ listenerState = "Listening"
    /\ supervisorState = "Normal"
    /\ unackedSubmits' = unackedSubmits \cup {tx}
    /\ UNCHANGED <<workerState, listenerState, wal, dbState, supervisorState>>

(* Worker writes the transaction to the WAL, commits, and returns AckOK *)
WorkerCommit(tx) ==
    /\ workerState = "Alive"
    /\ supervisorState = "Normal"
    /\ tx \in unackedSubmits
    /\ wal' = Append(wal, tx)
    /\ dbState' = dbState \cup {tx}
    /\ unackedSubmits' = unackedSubmits \ {tx}
    /\ UNCHANGED <<workerState, listenerState, supervisorState>>

(* An off-heap fault (SIGSEGV) kills the worker process *)
WorkerCrash ==
    /\ workerState = "Alive"
    /\ workerState' = "Dead"
    /\ supervisorState' = "Recovering"
    /\ UNCHANGED <<listenerState, wal, dbState, unackedSubmits>>

(* Supervisor reaps the dead worker, reboots it, and replays the WAL *)
SupervisorRecovery ==
    /\ workerState = "Dead"
    /\ supervisorState = "Recovering"
    /\ workerState' = "Alive"
    /\ supervisorState' = "Normal"
    /\ dbState' = {wal[i] : i \in 1..Len(wal)}
    /\ UNCHANGED <<listenerState, wal, unackedSubmits>>

Next ==
    \/ \E tx \in Transactions : ClientSubmit(tx)
    \/ \E tx \in unackedSubmits : WorkerCommit(tx)
    \/ WorkerCrash
    \/ SupervisorRecovery

(* Formal Invariants *)

(* Invariant 1: A worker crash does not close the front-end listener *)
ListenerNeverClosed ==
    listenerState = "Listening"

(* Invariant 2: No committed transaction in the WAL is ever lost *)
NoCommittedDataLoss ==
    \A i \in 1..Len(wal) :
        (workerState = "Alive" /\ supervisorState = "Normal") => wal[i] \in dbState
=============================================================================
```

The first model covers set reconciliation; the second covers worker replacement and WAL reconstruction. Neither models the production network, storage format, or all crash timings. The Go tests exercise specific implementations and scenarios; they do not turn these design models into general proofs.

---

## What is not formally verified

The boundary is as follows:

- **No checked TLA+ artifact.** No `.tla` files are checked into the repository, and no TLC result backs the models in this document. They are hand-written specifications, not artifacts extracted from the Go implementation or checked by a theorem prover.

- **No proof of the deleted seven-dimensional order.** The `CompareEvents` cascade over `(SystemTime, PayloadDigest, ValidTimeStart, AssertionTime, ValidTimeEnd, H3Index, EntityID)` belonged to the removed `internal/temporal_store/toki.go`. It was not extracted to `.tla`, and its eager-lossy `Resolve` is not part of `Join`. The current read-path selector is the two-field `selectLatestDot` described in §1.

- **Convergence tests have defined scopes.** The property tests in §2 exercise the merge laws on generated deltas. In `pkg/mesh/loopback_convergence_test.go`, `TestLoopbackConverges100` inserts keys into one of 100 in-process engines and requires equal non-empty roots. It skips in `-short` mode and on hosts with fewer than 32 logical CPUs. `TestLoopbackConverges100NegativeControl` has the same skip conditions, drops every delta to one engine, and requires divergence. `TestLoopbackConverges10K` checks 10,000 keys across eight in-process engines and skips in `-short` mode. `TestPQ_HybridE2EConverges` in `pkg/mesh/pq_hybrid_test.go` covers a two-engine mesh with hybrid signing and verification enabled. These are in-process tests, not multi-machine or WAN results.

- **The three-node and five-node convergence tests check cardinality and key presence.** `TestCRDTEngine_ThreeNodeConvergence` and `TestCRDTEngine_FiveNodeConvergence` in `pkg/sync/crdt_test.go` assert `state.Len()` and `state.Get(key) != nil` for each engine. They do not compare Merkle roots. Root equality across replicas belongs to the loopback tests named above, not these unit tests.

- **Durability checks are scenario-specific.** The other tests cited in §3 cover WAL replay, close-and-rebuild recovery, and bounded snapshot recovery. `TestSIGSEGVSurvival` is intended to add a process-crash scenario, but the build failure described above means it supplies no current end-to-end result. There is no model-checker or theorem-prover artifact backing a general durability claim.
