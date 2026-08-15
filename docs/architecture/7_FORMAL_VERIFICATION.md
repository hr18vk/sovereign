# 7. Formal Specifications & Mechanically-Enforced Properties

The Supremum Engine operates under the strict assumption that hardware fails, networks partition, and OS schedulers are adversarial. This document records the **design-level formal specifications** of the engine's convergence and durability invariants, and maps each to the **Go tests that mechanically enforce** those properties at runtime.

> **Honesty caveat — what is and is not mechanically verified here.** No `.tla` file is checked into this repository (`find . -name '*.tla'` returns zero hits), and no TLC model-checker run has ever been executed against the engine. The TLA+ blocks below are **design-level specifications**: hand-authored models of the intended invariants, not machine-checked proofs. The mechanical enforcement of every property named in this document is carried by **Go tests** (property tests and mesh loopback teeth), cited per-section below — not by a model checker. The section "What is NOT formally verified" at the end of this document states the precise boundary.

---

## 1. Conflict Resolution: Dot-Merge-Union Join + Lossless Read-Time Pick

The engine has **no eager/lossy conflict-resolution operator**. This is by design, and it is load-bearing. ADR-0033 (`docs/architecture/adr/0033_toki_closure_ghost_exorcism_track28.md`, Day 28) deleted the `internal/temporal_store/` module — a Day-1-era scaffolding that exposed an `LWWOperator.Resolve` returning `(winner, loser, audit)` with the caller **dropping** the loser — precisely because wiring that eager-lossy operator into `Join` would violate the CRDT convergence law (a dropped dot cannot re-merge across a foreign `AdvanceLamportTo` replay, so the CRDT would not converge across a crash-recovery gap — a convergence-law regression / data-corruption class). That module no longer exists in the tree; `grep -rn LWWOperator --include='*.go'` returns zero hits.

Conflict resolution in the engine is therefore two-layered, both **lossless** (no dot is ever dropped from the data path):

**Write-path / merge layer — `Join` is a dot-merge-union, NOT last-writer-wins.** `DeltaCRDTEngine.Join` (`pkg/sync/crdt.go:1089`) runs `perShardMerge` (`crdt.go:1221`): every incoming `CausalDot` is **inserted** into the append-only HAMT, keyed by `HashCausalDot(dot, digest)` (`crdt.go:1580`). No dot is dropped. `Join` is a join-semilattice: $\text{Join}(a, b) = a \cup b$ modulo causal-dot identity — monotone, idempotent, and commutative. This is the CRDT convergence law; it is the reason replicas converge.

**Read-path / resolution layer — `selectLatestDot` is a lossless 2-dimensional pick.** When the query/control layer must report *one* value for an entity, `selectLatestDot` (`pkg/mesh/gossip.go:531`) selects from the full dot set `engine.State().Get(key)`. It is a **2-dimensional** deterministic pick, not a 7-dimensional cascade:

1. **`DotCounter`** — the entry with the larger counter wins.
2. **`DotNodeID`** — on counter tie, `bytes.Compare` of the 16-byte `DotNodeID`; the lexicographically smaller wins.

The loser **stays** in the append-only HAMT (`grep Prune|Reset|Retire` over the data path is empty); a future query at a different `txTime` may pick a different winner. Both `handleGet` and `LatestPayload` route through this one selector, so `/v1/get` and the standalone accessor can never disagree on "latest" for the same entry slice. The pick is a pure function of `entries` (deterministic; independent of slice/map iteration order); the tie-break is a documented deterministic choice, not a causal claim — dots from different origins are not totally ordered by counter alone.

The set of concurrent updates to the same entity is resolved to a single response value, deterministically, **without dropping any update from the data path**. This replaces the deleted 7-dimensional `CompareEvents` cascade (which modeled code that no longer exists).

---

## 2. $\delta$-CRDT Convergence & Anti-Entropy

The synchronization topology relies on exact anti-entropy over causal graphs via an off-heap HAMT. In `pkg/sync/crdt.go`, synchronization uses Invertible Bloom Lookup Tables (IBLT) to subtract replica states and peel the symmetric difference.

### $\delta$-CRDT Convergence — Design-Level Specification

This specification models the IBLT subtraction, peeling success constraints (bounded by the table capacity), and the subsequent delta merging that guarantees eventual state convergence. It is a **design-level TLA+ specification**, not a model-checked proof (no `.tla` file is checked in; no TLC run has been executed — see the honesty caveat above). The join-semilattice axioms it names — commutativity, associativity, idempotence of `Join` — are **mechanically enforced by Go property tests**, not by a model checker:

- `TestCRDTJoinCommutativity` (`pkg/sync/crdt_property_test.go:154`)
- `TestCRDTJoinAssociativity` (`pkg/sync/crdt_property_test.go:183`)
- `TestCRDTJoinIdempotence` (`pkg/sync/crdt_property_test.go:215`)

These hold because `Join` is the dot-merge-union of §1 (`crdt.go:1089` + `perShardMerge:1221` + `HashCausalDot:1580`): set-union modulo causal-dot identity is a join-semilattice by construction.

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

(* Invariant: Replicas eventually converge to the supremum of all replica states *)
EventualConvergence ==
    \A A, B \in Replicas : (networkBuffer = {}) => (replicaState[A] = replicaState[B])
=============================================================================
```

---

## 3. Deterministic Chaos Simulator Constraints

The `internal/chaos/supervisor.go` component guarantees system survival and transaction durability across un-catchable process faults (e.g. `SIGSEGV` triggered during off-heap manipulation).

The primary safety invariant is: **The client listener must remain alive, and all unacknowledged or written WAL payloads must be durably replayed upon worker recovery.**

### Supervisor/Worker Isolation — Design-Level Specification

This is a **design-level TLA+ specification** of the supervisor/worker isolation invariants, not a model-checked proof (no `.tla` file is checked in; no TLC run has been executed — see the honesty caveat above). The invariants it names are **mechanically enforced by Go tests**:

- `TestStage6SIGSEGVSurvival` (`internal/chaos/survival_test.go:56`) — the listener-survival + worker-reboot invariant under an un-catchable `SIGSEGV`.
- `TestStage6WALRecoveryDeterminism` (`internal/chaos/wal_test.go:42`) — WAL replay determinism across a worker crash/recovery.
- `TestRecoveryDeterminism_KillRebuildMerkleEqual` (`pkg/durability/bridge_test.go:90`) — kill → rebuild yields a Merkle-equal recovered state.
- `TestSnapshot_Determinism_PreVsPostCheckpoint_MerkleEqual` (`pkg/durability/snapshot_test.go:259`) — pre- and post-checkpoint recovery are Merkle-equal (snapshot determinism).

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

(* Client submits a transaction to the Supervisor's open socket *)
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

(* Invariant 1: The Supervisor's TCP listener socket is NEVER closed by a crash *)
ListenerNeverClosed ==
    listenerState = "Listening"

(* Invariant 2: No committed transaction in the WAL is ever lost *)
NoCommittedDataLoss ==
    \A i \in 1..Len(wal) :
        (workerState = "Alive" /\ supervisorState = "Normal") => wal[i] \in dbState
=============================================================================
```

These design-level specifications model the intended runtime logic of the Supremum Engine under edge-triggered network partitions and off-heap execution environments. They are not machine-checked; their invariants are enforced by the Go tests cited in §2 and §3.

---

## What is NOT formally verified

To state the boundary precisely, the following are **not** mechanically proven for this engine:

- **No TLA+ / TLC.** No `.tla` file is checked into the repository (`find . -name '*.tla'` returns zero hits), and no TLC model-checker run has been executed against the engine, ever. Every TLA+ block in this document is a hand-authored design-level specification — design prose, not an extracted or checked artifact. The "formal verification" the engine actually performs is by Go test, not by model checker.

- **No mechanical proof of the (now-deleted) 7-dimensional total order.** The `CompareEvents` cascade over `(SystemTime, PayloadDigest, ValidTimeStart, AssertionTime, ValidTimeEnd, H3Index, EntityID)` modeled a `LWWOperator` in `internal/temporal_store/toki.go` that no longer exists (ADR-0033, Day 28). It was never extracted to `.tla`; it is now deleted dead code, and wiring its eager-lossy `Resolve` into `Join` was explicitly rejected as a CRDT convergence-law regression. The real read-path pick is the 2-dimensional `selectLatestDot` (`gossip.go:531`) — see §1.

- **Convergence is enforced by Go property tests + mesh loopback teeth, not a model checker.** The join-semilattice axioms are property-tested (`TestCRDTJoinCommutativity` / `Associativity` / `Idempotence`, §2). Cross-replica root-equality is enforced by the mesh loopback teeth — `TestDay36_T_LOOP_Converges100` and `TestDay36_T_LOOP_Converges10K` (`pkg/mesh/day36_loopback_test.go:681` / `:829`) assert that all nodes converge to one Merkle root (with a `RED CONTROL` that proves the tooth is not a tautology), and `TestPQ_HybridE2EConverges` (`pkg/mesh/day32_hybrid_test.go:359`) covers the hybrid-PQ transport. These are the mechanically-enforced convergence proofs.

- **The 3/5-node convergence tests check cardinality and key-presence, NOT Merkle-root equality.** `TestCRDTEngine_ThreeNodeConvergence` and `TestCRDTEngine_FiveNodeConvergence` (`pkg/sync/crdt_test.go:293` / `:351`) assert only `state.Len()` and `state.Get(key) != nil` per node — i.e. that every node ends up holding every key. They do **not** assert that the nodes' Merkle roots are equal. Merkle-root equality across replicas is enforced by the mesh loopback teeth named above, not by these unit tests. This document does not claim root-equality for the 3/5-node tests.

- **No mechanical proof of the durability invariants beyond the Go tests.** The supervisor/WAL/snapshot invariants of §3 are enforced solely by `TestStage6SIGSEGVSurvival`, `TestStage6WALRecoveryDeterminism`, `TestRecoveryDeterminism_KillRebuildMerkleEqual`, and `TestSnapshot_Determinism_PreVsPostCheckpoint_MerkleEqual` (cited in §3). There is no model-checker or theorem-prover artifact backing them.
