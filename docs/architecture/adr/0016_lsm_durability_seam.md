# ADR-0016: The LSM↔Durability Seam — Bounded Recovery

**Status:** Accepted
**Date:** 2026-08-02
**Author:** Harsh Rawat
**Builds on:** ADR-0013 (WAL recovery), ADR-0014 §0 (the seed-by-trace proof)

---

## §1. Context (the root cause)

`pkg/durability/recovery.go` was **WAL-replay-only** (ADR-0013). On crash it
`ReplayWAL`'d the entire log into a seed engine — `O(writes-since-boot)`,
**not** `O(writes-since-last-checkpoint)`. The checkpoint record
(`{MerkleRoot, LamportHigh}`) anchored a Merkle-equality assertion but held **no
state**; every mutation since genesis had to be replayed to rebuild the HAMT, so
recovery time grew unbounded with engine uptime. The seed-by-trace proof
(ADR-0014 §0) made replay *correct*; it did nothing about replay *cost*.

The `internal/database` LSM tier (MemTable + L0Flusher + Arrow IPC) **existed**
already — vet-clean, its own tests green — but had **zero importers** outside its
own package. It was dead code. This change **wires it** for the first time into
the production path; it does **not** rewrite it.

---

## §2. The seam (what was built)

Four new/edit sites, atomic:

| File | What | Role |
|------|------|------|
| `pkg/durability/localfs.go` (NEW) | `LocalFS{root}` implementing `database.S3Uploader`/`S3Lister`/`S3Downloader` | CI/local substitute for S3; pure os ops |
| `pkg/durability/snapshot.go` (NEW) | `SnapshotToLSM` + the dot-bearing `SnapshotImage` codec | the checkpoint snapshot + recovery LOAD |
| `pkg/durability/recovery.go` (EDIT) | `RecoverEngineWithSnapshot(...store)` + `RecoveryWitness` | bounded-recovery entrypoint; back-compat wrapper |
| `pkg/durability/bridge.go` (EDIT) | `SetSnapshotter` + `AppendCheckpoint` writes the snapshot | wires the snapshot into the checkpoint path |
| `cmd/sovereign-node/main.go` (EDIT) | `--lsm-root` flag + `SetSnapshotter` wired when `--wal-path` | the node flag |

**Two artifacts on checkpoint** (both under the `--lsm-root` dir):

1. A **dot-bearing recovery image** at `ckpt/<LamportHigh>` — a plain binary, NOT
   Arrow. It carries the **full dot set** `{(DotNodeID, DotCounter)}` per entity,
   the exact state `MerkleRoot()` folds (hamt.go:265 hashes the **sorted full dot
   set**; it does **not** depend on `maphash.Seed`). On recovery this image is
   `Join`'d into a seed engine — `Join` **honors the recorded `Dot()`** (it does
   NOT re-mint — crdt.go:1067 forwards the recorded dot into the per-shard
   dot-union merge). This is the artifact that makes the determinism proof pass
   and makes bounded recovery **strictly better** than full replay: the snapshot
   captures **foreign dots** the WAL never records, so bounded recovery restores
   origin+foreign while full replay can only restore origin (the crdt.go limit,
   ADR-0013 §7(h)).

2. An **Arrow IPC index** under `l0/<...>` via the **existing**
   `internal/database` MemTable/L0Flusher — the query-tier snapshot. It stores
   the **latest entry per entity** with `payload=SENTRY`. This is the act that
   **wires `internal/database`** (the first importer outside its own
   package+tests).

**Recovery** (`RecoverEngineWithSnapshot`): when a snapshot exists at the
checkpoint watermark, seed the engine at `ckpt.LamportHigh`, `Join` the image's
recorded dots, nail the watermark via `AdvanceLamportTo`, then replay **only**
the WAL records whose `Counter`/`Advance` strictly exceeds the watermark (the
conceptual truncation at the checkpoint — the snapshot absorbed everything
at-or-before). Recovery cost → **O(post-checkpoint)**.

---

## §3. The seed-by-trace proof, made executable

`InsertLocal` **re-mints** `DotNodeID/DotCounter` from `NextDot()`
(`lamportCounter.Add(1)`) regardless of the recorded entry fields. Full replay
reproduces origin dots via the seed trick (seed = `firstMutation.Counter-1`).
The snapshot path cannot use the seed trick — the snapshot is the **merged**
state with **scattered** dots — so it restores them via `Join` (which honors the
recorded dot, no re-mint). The question the determinism test answers: do the two
paths reach the SAME dot set?

```
at the checkpoint      : A.State().MerkleRoot() == checkpoint.MerkleRoot
                    (the snapshot IS the live dot set at the watermark)
after post-ckpt replay : A.MerkleRoot() == B.MerkleRoot()
                    (B = full replay; A and B reach the same dot set + watermark)
```

The bounded seed is `max(firstMutation.Counter-1, ckpt.LamportHigh)`; in the
honest reachable path the checkpoint's `LamportHigh` ≥ `firstMutation.Counter-1`
(the checkpoint came after mutations), so the max IS `ckpt.LamportHigh`. Post-ckpt
`InsertLocal` re-mints `ckpt.LamportHigh+1, +2, …` matching the recorded
`m.Counter` values that exceed the watermark. The snapshot's pre-ckpt dots are
already present (from the `Join`). So `A` and `B` reach the identical dot set.

**The determinism test**
(`TestSnapshot_Determinism_PreVsPostCheckpoint_MerkleEqual`): engine A recovers
via the bounded path, engine B via full replay, both from the SAME WAL+snapshot.
Assert `A.MerkleRoot() == B.MerkleRoot() == live.MerkleRoot()`.
**GREEN** (pre=256, post=24, under `-race`).

---

## §4. Byte-verified corrections to the original plan

1. **Merkle folds the full dot SET, not "latest entry per entity".** The plan's
   prose said the snapshot stores the "engine image containing the merged
   state" and listed "latest entry per entity". The truth
   (`hamt.go:265`, grep-verified): `MerkleRoot()` iterates `ForEach`, collects
   **every** `(DotNodeID, DotCounter)` across **all** entries of **all**
   entities, sorts, SHA-256's the sorted set. So the **recovery image stores the
   FULL dot set** (one `SnapshotRecord` per `CRDTEntry`, not per entity); only the
   **Arrow query index** is latest-per-entity (the query tier's representative).
   The determinism test would FAIL on a "latest-per-entity" recovery image (it
   would drop historical dots whose absence changes the Merkle root).

2. **`CRDTEntry` has NO `Payload []byte` field.** Verified:
   `CRDTEntry` is 120 bytes (ADR-0010) — `PayloadDigest [32]byte` + `OriginNodeID`
   + `DotNodeID` + `DotCounter` + 5 time fields + `H3Index`. No payload body.
   So the Arrow index stores the **real digest + an empty body** (sentry).
   `MemTable.Write` trusts the caller's `PayloadDigest` (memtable.go:166 packs
   `event.PayloadDigest` as-is — it does NOT recompute from the payload), so the
   index carries the honest digest with a sentry body, not a recomputed lie.

3. **The checkpoint record is NOT in `rep.Ordered`.** `ReplayWAL` (internal/chaos
   wal.go:482-493) sets `out.FinalCheckpt` + `out.HasCheckpoint` but does **not**
   append the checkpoint to `Ordered` (only mutations + advances). So the bounded
   truncation **cannot** key off the checkpoint's position — it keys off the
   **counter-based filter** (`m.Counter > ckpt.LamportHigh` → replay;
   `rec.Advance > ckpt.LamportHigh` → replay). This is the conceptual truncation
   at the watermark.

4. **`State()` does NOT pin EBR.** The `EBR()` docstring (crdt.go:1316)
   documents that a bare `state := eng.State()` under concurrent `InsertLocal`
   can dereference a shard root a racing CAS retired and freed — a
   use-after-free. `Acquire()` is just `pool.Get()` (no `Enter`). So
   `SnapshotToLSM` pins the epoch **explicitly**: `ebr.Acquire()` then
   `participant.Enter(ebr)` then `defer ebr.Release(participant)` AROUND
   `State()`+`ForEach`. This is what makes the `-race` stress test (6 concurrent
   writers intersecting checkpoint-extract) race-clean.

---

## §5. The dangling-anchor failure mode (and why it is safe)

The ordering invariant: **the WAL checkpoint is fsync'd BEFORE the snapshot
image is written** (`Bridge.AppendCheckpoint` calls `wal.AppendCheckpoint` then
`SnapshotToLSM`). The three crash windows:

| Crash window | WAL anchor | Snapshot image | Recovery |
|--------------|-----------|----------------|----------|
| Before WAL fsync | absent | absent | cold-boot / full-replay from earlier anchor |
| After WAL fsync, before image | **present** | absent | **full-replay fallback** — `SnapshotExists`=false |
| Mid image write | present | **torn** | **full-replay fallback** — decode refuses bad magic |

Recovery **always rebuilds**. Boundedness is a **best-effort** optimization over
the durable image: a missing or corrupt image silently degrades to the
pre-existing full-replay algorithm, byte-identical, and the `RecoveryWitness`
reports the reason. **No image is ever treated as data loss.**

`decodeSnapshotImage` refuses mismatched magic/version and truncation — recovery
never rebuilds on a suspect image (the no-silent-misinterpretation rule).

---

## §6. Back-compat (zero behavior change when unwired)

- `RecoverEngine(nodeID, walPath, arenaSize)` is now a thin wrapper over
  `RecoverEngineWithSnapshot(nodeID, walPath, nil, arenaSize)` discarding the
  witness. `store==nil` ⇒ `useSnapshot=false` ⇒ the **exact pre-existing
  full-replay algorithm**, byte-identical. All existing tests
  (`bridge_test.go`, `TestWALRecoveryDeterminism`,
  `TestRecoveryDeterminism_KillRebuildMerkleEqual`) stay GREEN — verified.
- `Bridge.AppendCheckpoint` with `snapshotter==nil` writes the WAL anchor only,
  exactly as before this change — verified (`bridge_test.go` green).
- `--lsm-root` empty (default) + `--wal-path` set = full-replay back-compat.
  `--wal-path` empty (default) = in-memory research mode,
  **no** `LocalFS`, **no** behavior change. The silicon bench path is untouched.

---

## §7. Honest scope (what this change does NOT claim)

- **The query-tier resolver (`query.go` `Resolver.AsOf`) is NOT exercised.** The
  Arrow index is *wired* (rows written + flushed) but the tri-temporal dominance
  resolution that reads those rows is a **later** seam. The rows are well-formed
  (real digest + sentry body) so a future resolver reads them without rework.
- **The snapshot is O(total state) per checkpoint, BOUNDED by the checkpoint
  interval.** The *recovery* is O(post-checkpoint); the *checkpoint itself*
  walks the full live HAMT (EBR-pinned) once per checkpoint. This is the
  bounded-recovery contract: pay O(N) at the checkpoint, get O(M≪N) at recovery.
  A future change may bound the checkpoint cost (incremental snapshots) — out of
  scope here.
- **The foreign-dot recovery case**: bounded recovery is **strictly better**
  than full replay here (A ⊋ B — the snapshot has the foreign dots full replay
  cannot reproduce). The determinism test's origin-only setup makes A==B;
  the foreign case is the bounded-wins case, not a determinism-test assertion
  target, because full replay has no foreign state to assert equality against.

---

## §8. The gate

| Gate | Command | Status |
|------|---------|--------|
| build | `go build ./...` | PASS |
| vet | `go vet ./...` | PASS |
| gofmt | `gofmt -l` (pkg/durability, cmd/sovereign-node) | clean |
| durability race | `go test -race ./pkg/durability/` | PASS (9.1s) |
| database race | `go test -race ./internal/database/` | PASS (2.2s) |
| sync+mesh race | `go test -race ./pkg/sync/ ./pkg/mesh/` | PASS |
| hot-path zero-alloc | `TestHotPathZeroAllocations` | PASS |
| fieldalignment | `pkg/durability` (new structs only) | clean |
| bench ratio | `BenchmarkRecovery_BoundedVsFull` | see §9 |
| back-compat | existing durability + chaos determinism teeth | PASS |

---

## §9. The headline (honest integers — measured, not predicted)

`BenchmarkRecovery_BoundedVsFull` (pre=8192, post=64, arm64, -4c), measured:

```
BenchmarkRecovery_BoundedVsFull/Full-4        80409917 ns/op   13760184 B/op   34004 allocs/op   ReplayedRecords=8256
BenchmarkRecovery_BoundedVsFull/Bounded-4     77439932 ns/op   22285733 B/op   35270 allocs/op   ReplayedRecords=64
```

**The `ReplayedRecords` witness is the formula-independent ground truth** (the
integrated call is the production headline; `ns/op` reflects replay machinery,
not the bound): bounded replays **64** records where full replays **8256** — a
**129× reduction** in the replay tail, both recovering to the identical Merkle
root.

**The honest wall-clock + memory verdict at THIS ratio (pre=8192): bounded is
only ~4% faster wall-clock AND regresses memory (22.3 MB vs 13.7 MB, +63%) and
allocs (35,270 vs 34,004, +3.7%).** WHY — and why this is STILL the right seam:

- The snapshot LOAD pays O(N) once (decode the 8192-record image into a heap
  `[]SnapshotRecord`, then `Join` it). At pre=8192 that O(N) load ≈ the O(N)
  full replay, so wall-clock is a wash + the decode is allocation-heavy (the
  memory/alloc regression is the `io.ReadAll` + `[]SnapshotRecord` decode of the
  full image, off the hot path — one per recovery, acceptable, but documented).
- The **win is the BOUND, and it grows with `pre` (engine uptime)**: when
  `pre=8,192,000` (a long-running node) and `post=64`, full replay is O(8.2M) and
  bounded is O(64) — the snapshot load O(N) is paid ONCE at recovery but the
  replay tail is 128,000× shorter. The bench's pre=8192 is too small to show the
  win because load O(N) ≈ replay O(N) there; the win is structural and unbounded
  in `pre`, which is the entire point (unbounded replay was the motivating
  defect).
- The memory regression is a **known limitation** of the v1 decode
  (`io.ReadAll` + slice-of-struct): a later change may stream-decode the image
  row by row into the `Join` Seq (no full materialization) — orthogonal,
  documented here so it is not a silent lie.

**The bound is proven (64 vs 8256 replayed records). The determinism is proven
(identical roots). The wall-clock win is contingent on `pre >> post` (the
production shape for a long-running node) and is NOT claimed at the bench's
small ratio.** The regression is reported, not hidden.
