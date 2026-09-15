# ADR-0021: The L0 Reaper + the Land-Mine Closures — Reclaim the Superseded-L0 Backstop (closing ADR-0020 §6c) and Close the MaxValidTime + eng.DataDir Landmines (ADR-0020 §6 tail)

**Status:** Accepted
**Date:** 2026-08-03
**Author:** Harsh Rawat
**Builds on:** ADR-0020 (the Level-2 prune — the (C1)&&(C2)&&(C3) SAFE-DROP + txTime GC floor; §6c deferred the L0 reaper, §6 tail carried the MaxValidTime + DataDir landmines), ADR-0019 (L0→L1 compaction — writes the manifest that lists the superseded L0s; keeps them as the backstop), ADR-0017 (the resolver read-half — AsOf over L1+tail; the L0 reaper preserves the L1 the resolver queries), ADR-0015 §7 (the comment-only frozen-edit precedent this change follows).

---

## §0. The three things this change closes

This ADR closes the three items ADR-0020 §6 left open — one deferred follow-up plus two latent landmines:

- **§0.a (ADR-0020 §6c, the deferred follow-up) — the L0 reaper.** ADR-0019's compaction write path writes a manifest at `compaction/{hex8}/{sysNs}.manifest` listing the L0 files it merged into the L1, but KEEPS the L0 files forever as the crash-recovery backstop (delete-after-read-safety was deferred). The `l0/` directory grows monotonically — every compaction leaves N L0 files plus the manifest. The reaper deletes the manifest-listed L0 files AFTER verifying the L1 still exists (the Stage C safety guard), then deletes the manifest. The backstop is reclaimed, not leaked.

- **§0.b (ADR-0020 §6 tail landmine #1) — `MaxValidTime.UnixNano()` int64 overflow.** `var MaxValidTime = time.Date(9999,12,31,23,59,59,0,UTC)` was conceptually an open-ended valid-interval endpoint, but `.UnixNano()` overflows int64: year 9999 → ~633e9 s → ~6.33e20 ns, negative when truncated (the high bit is set). Every `_test.go` call site that passed `MaxValidTime.UnixNano()` as `ValidTimeEnd` sent a garbage negative into the Arrow index — a half-open interval `[vs,ve<0)` is empty for every positive `validTime`, so the row is silently invisible to `AsOf`'s `Filter3`. The mesh's `OpenEndedValidEndNs` (pkg/mesh/control.go) has always used the concrete-const-`9e18` pattern; this change closes the write-schema side to match. Zero production callers existed (every caller was a `_test.go`); the `var` is deleted, replaced by `const MaxValidTimeEndNs int64 = 9_000_000_000_000_000_000` (year ~2253, comfortably below `MaxInt64 ~9.22e18`).

- **§0.c (ADR-0020 §6 tail landmine #2) — `eng.DataDir` global bypass.** `pkg/sync.DataDir` is a package-level `var`; `newEngineAt` (pkg/durability/recovery.go) sets it directly to the scratch dir. The hazard: a bare global mutation the caller races a concurrent apply against. This change keeps the pre-constructor global write (load-bearing — the frozen constructor reads the global mid-construction) AND adds a post-constructor `engine.SetDataDir(scratchDir)` so the instance's `dataDir` field is routed through the `persistMu`-guarded setter for its lifetime. The residual global race (two concurrent `newEngineAt` calls) is disclosed honestly — never reachable on the sequential boot path, blocked from full closure only by the frozen crdt.go constructor's global read.

The design rule: **the reaper is opt-in** (`--compaction-reap-enable`, default false) and never auto-on. Byte-identical prior behavior is the default: the superseded L0 files stay as the backstop. The reaper's safety contract is the Stage C **verify-the-L1-exists-before-any-L0-delete** guard — a filesystem layer that ever reports a present L1 as missing would also be one the compactor trusted to write the L1; the reaper should be turned on only once the storage layer is trusted.

---

## §1. The one frozen file this change touches (comment-only)

This change touches ONE frozen file: `pkg/sync/crdt.go`. The change is comment-only — a warning doc placed above `var DataDir` in crdt.go (the §0.c landmine's own surface). No byte of executable code changed; the three contracts (determinism / EBR / the 57.6M hot path) are byte-identical (a comment edit provably cannot touch the CAS line, the retire order, or the zero-alloc gates).

The other four frozen files (crdt_apply.go / schema.capnp / schema.capnp.go / envelope.go) are unchanged — this change touches none of them.

---

## §2. The land-mine closures (honest, with disclosed residuals)

### §2.1 MaxValidTime → MaxValidTimeEndNs (closed, no residual)

`internal/database/l0_flusher.go` replaces `var MaxValidTime = time.Date(9999,...)` with:

```go
const MaxValidTimeEndNs int64 = 9_000_000_000_000_000_000
```

Eight call sites updated (all in `_test.go`: two in `l0_flusher_test.go`, six in `memtable_test.go`) — `MaxValidTime.UnixNano()` → `MaxValidTimeEndNs`. The `time` import dropped from l0_flusher.go (no remaining use). The `var` deletion is safe: zero production callers existed (grep-verified — `MaxValidTime` appears in production code only inside l0_flusher.go's own declaration; the write path reads `validTimeEndNs` from the packed value bytes directly, never via `MaxValidTime.UnixNano()`). The write schema now matches the mesh's read-side `OpenEndedValidEndNs` (pkg/mesh/control.go) — one int64-safe sentinel on both sides. **No residual.**

### §2.2 eng.DataDir → engine.SetDataDir (partially closed — residual disclosed)

`pkg/durability/recovery.go newEngineAt` keeps the pre-constructor `eng.DataDir = scratchDir` global write (load-bearing — see §0.c) and adds a post-constructor `engine.SetDataDir(scratchDir)`:

```go
eng.DataDir = scratchDir                 // pre-ctor: the frozen ctor copies this into e.dataDir; recoverLamport reads no stale file
engine, err := eng.NewDeltaCRDTEngine(nodeID, initialCounter, arenaSize)
...
engine.SetDataDir(scratchDir)            // post-ctor: instance field via the persistMu-guarded setter
```

**Why the pre-constructor global write is load-bearing and cannot be removed:** the frozen constructor (`NewDeltaCRDTEngine` in crdt.go) copies `DataDir` into `e.dataDir` and calls `recoverLamport()`, which reads `e.dataDir` to find `<dataDir>/lamport_<nodeID>.dat` — a persisted Lamport override that, if present, lifts `initialCounter` above the caller's seed. Pointing the global at the fresh scratch dir before the constructor makes `recoverLamport` read no stale file → returns 0 → honors the WAL-derived determinism seed exactly (ADR-0013 §4). Removing the global write means the frozen constructor reads `/data/crdt`, and a stale `lamport_<nodeID>.dat` overrides the WAL seed — re-introducing the determinism defect ADR-0013 closed. The global write is the only channel for the scratch-dir seed trick through the frozen constructor.

**What the post-constructor `engine.SetDataDir` closes:** the instance's `dataDir` field for its lifetime is routed through the `persistMu`-guarded setter, not a bare global mutation the caller races a concurrent apply/persist against. `SetDataDir` acquires `persistMu`; `persistLamport` also takes `persistMu`; so the instance sees the same ordering edge the setter establishes.

**The disclosed residual:** two concurrent `newEngineAt` calls still race on the package global `sync.DataDir` — a real-but-never-reached hazard. The production boot path is sequential (one `RecoverEngine` per process at boot; `cmd/sovereign-node` constructs exactly one engine). The test paths serialize too. The global race is blocked from closure only by the frozen crdt.go constructor reading the global mid-construction; full closure requires a constructor that takes an explicit `dataDir` argument. I report the residual rather than claim the trap is fully closed.

---

## §3. The reaper (the §0.a closure — the load-bearing safety contract)

### §3.1 The seam

The reaper adds a fourth narrow S3 interface: `S3Deleter` (internal/database/query.go):

```go
type S3Deleter interface {
    Delete(ctx context.Context, bucket, key string) error
}
```

`pkg/durability/localfs.go *LocalFS.Delete` implements it — `os.Remove` with the idempotent contract: `os.IsNotExist` returns `nil` (not an error). A file already reclaimed by a prior sweep or a manual cleanup returns nil, so the reaper's partial-reap retry loop makes forward progress across sweeps. The compile-time interface assertion `_ S3Deleter = (*LocalFS)(nil)` catches a signature drift.

### §3.2 The reaper (internal/database/l0_reaper.go — new file)

`L0Reaper` holds the three read/delete seams (`S3Lister` + `S3Downloader` + `S3Deleter`) — it never holds an `S3Uploader` (it never writes). `NewL0Reaper(lister, downloader, deleter, bucket)` constructs it; `Reap(ctx) ReapResult` runs one cross-entity sweep in stages A–F:

- **Stage A** — list all keys under `compaction/` (uncapped — the reaper reaps every entity, not one at a time); skip non-`.manifest` keys (defense in depth).
- **Stage B** — `Download` + `ParseManifest` each manifest → `(l1Key, l0Keys)` via the existing parser (one parser, one truth — the same function AsOf + SupersededL0Keys use).
- **Stage C** — **the safety guard**: `Download(l1Key)` to verify the L1 still exists. The probe is a Download (the S3 surface has no Head/Stat; the reaper is off the hot path — one probe per manifest per 5-minute sweep, bounded by the manifest count). A manifest with no `l1Key` (malformed) cannot be verified → preserve (orphan). Any download failure (a genuine 404, an S3 outage, a permission error) → the L0s are preserved (the backstop) and the manifest is skipped → `SkippedOrphan++`. Treating any download failure as "preserve" is the safest reading — a transient outage degrades the reaper to a no-op for one interval (harmless); deleting an L0 whose L1 is actually gone loses the sole durable copy (catastrophic).
- **Stage D** — delete each `l0Key` via the `S3Deleter`. If a single delete fails (a real IO/permission error — not a missing file, which is idempotent nil), stop → the manifest is retained → `SkippedError++`. The already-deleted L0s stay deleted (monotone forward progress); the next sweep retries (idempotent nil on the gone ones, and the failed one real).
- **Stage E** — delete the manifest, only after every listed-L0 delete succeeded. A manifest-delete failure → `SkippedError++` (the L0s are already gone; the manifest retries next sweep — forward-progress-safe).
- **Stage F** — tally `ReapedManifests++`. The L0-delete count accumulates in `ReapedL0` during Stage D.

`ReapResult` carries four per-sweep tallies (disclose the counts, not adjectives): `ReapedManifests` / `ReapedL0` / `SkippedOrphan` / `SkippedError`.

### §3.3 The telemetry (4 counters — observable)

`internal/telemetry/registry.go` adds:

- `supremum.compaction.l0_reap_sweeps` — sweeper runs
- `supremum.compaction.l0_reap_l0_files_deleted` — successful Delete calls (includes the idempotent already-absent path — see T3 sweep 3)
- `supremum.compaction.l0_reap_manifests_reaped` — manifests fully reaped (L0s + manifest)
- `supremum.compaction.l0_reap_manifests_skipped_orphan` — manifests skipped (L1 gone/sick; the backstop preserved — the operational signal)

A non-zero `skipped_orphan` is the operational signal that an L1 was lost (or the store is reporting it gone). A non-zero `skipped_error` is the signal that the store is rejecting deletes.

### §3.4 The wiring (cmd/sovereign-node/main.go)

Two flags: `--compaction-reap-enable` (default false) + `--compaction-reap-interval` (default 5m). The reaper is constructed in the `--lsm-root` block (alongside the compactor + resolver) sharing the same `*LocalFS` for all three seams (one FS root, one keyspace — the established wiring discipline). `reaperLoop` runs alongside `compactionSchedulerLoop`, gated on `meshCtx` so SIGINT/SIGTERM cancels it; a nil reaper (--reap false, or no --lsm-root) makes it a no-op (byte-identical to the pre-reaper default). The reaper runs less often than the compactor (default 5m vs 30s) — the superseded L0s are a safety net with zero urgency to delete; the slower cadence amortizes the manifest-list + L1-probe cost over more compactions.

The reaper is the complement of the per-entity compaction scheduler: the compactor drives new L1s + manifests; the reaper reclaims the L0s the compactor superseded.

---

## §4. The teeth (T1–T4 + the scope-hygiene guard)

Two test locations (an internal/database test cannot import pkg/durability because snapshot.go imports internal/database — the established import-cycle constraint):

- **`pkg/durability/l0_reaper_test.go`** — T1/T2/T3/T4, driven against a real `*LocalFS` (drive the route, not the seam). It reuses the existing helpers (`newLocalFS`, `writeNCheckpoints`, `makePackedValue`, `putBE64`).
  - **T1 — the headline** (`TestReapDeletesSupersededL0AndManifestRedThenGreen`): write N=8 per-entity checkpoints → compaction (manifest + L1 written, L0s stay) → Reap → every superseded L0 deleted, manifest deleted, L1 untouched, and a non-manifest bystander entity's L0 (no compaction ran for it) untouched; AsOf still 200 via the L1 (truth preserved). RED-then-GREEN over a real FS.
  - **T2 — the safety guard (load-bearing)** (`TestOrphanL1SafetyGuardPreservesL0AndManifest`): delete the L1 a manifest points at, Reap → the reaper must not delete the L0s nor the manifest; `SkippedOrphan=1`. The L0s are the sole durable copy → preserved.
  - **T3 — idempotent reaper** (`TestIdempotentSecondSweepIsCleanNoOp`): Reap twice. Sweep 1 reaps fully; sweep 2 is a clean no-op (the manifest already gone → not re-listed; 0/0/0/0). Sweep 3 re-creates the manifest (pointing at L0s already gone) → reaps it (Stage D's Deletes return idempotent nil on the already-gone L0s, counted as N successful Deletes; Stage E deletes the manifest). Forward progress on an already-reaped keyspace.
  - **T4 — partial reap** (`TestPartialReapDeleteFailureRetainsManifest`): a fault-injecting `*LocalFS` wrapper makes the second L0 delete fail → Stage D stops → manifest retained, first L0 deleted (forward progress), `SkippedError=1`; a resume sweep against the real FS reaps the rest. The `faultyDeleter` satisfies `database.S3Deleter` at compile time.

- **Scope hygiene** (`TestReaperDeadCompactorScopeHygiene`, in `internal/database`): the dead `EpochCompactor` (ADR-0018 §6) stays dead. The reaper is a new type over `S3Deleter`, not a `SetCompactor`/`InsertTombstone`/`NewEpochCompactor`/`PruneTombstones` importer. The tooth greps the production trees (internal/pkg/cmd, excluding _test.go and the dead symbol's own definition files) and asserts zero callers for each.

---

## §5. What stayed out

This change does not touch the receive/mesh transport-hardening, service-thread-pool, or io_uring work — those remain gated behind their own flags, not unconditionally shipped. The scope here is the durability/disk-reclaim layer only.

---

## §6. Residuals (disclosed, honestly)

- **§6.1 the eng.DataDir global race** (§2.2) — closed at the instance level (`engine.SetDataDir`); the package-global race (two concurrent `newEngineAt`) remains, never reachable on the sequential boot path, blocked from closure by the frozen crdt.go constructor's mid-construction global read. Full closure = a frozen-crdt.go constructor that takes an explicit `dataDir` argument — future work.
- **§6.2 the L0 files of an entity with no manifest** — the reaper deletes only manifest-listed L0s. An L0 whose entity was never compacted (no manifest) is never deleted by the reaper — it is the live L0 the resolver reads. Correct by design (the reaper reclaims superseded L0s, not live ones); disclosed for completeness.
- **§6.3 the `L0ReapL0Deleted` inflation under re-run** — the counter counts every successful Delete call, including the idempotent already-absent path (a re-created manifest pointing at already-gone L0s re-counts them: see T3 sweep 3). A pre-Stat per L0 could distinguish "physically removed this sweep" from "already absent," but that is an IO the safety contract does not require; the per-sweep `ReapedManifests` is the cleaner forward-progress signal. Disclosed in the metric description.
- **§6.4 ADR-0020 §6a (T_gc auto-inference) + §6b (O(N²)→O(N·H) interval sweep)** — unchanged, still ADR-0020's deferred Level-3 prune refinements.

---

## §7. What this proves

The L0 reaper is a provably-safe opt-in disk-reclaim sweep with a byte-identical default to the pre-reaper behavior (the backstop kept forever). It closes the cross-entity monotonic-L0 disk leak ADR-0020 §6c deferred, at the honest cost of an opt-in flag (`--compaction-reap-enable`) gated on storage trust (the Stage C L1-exists guard). The L1 is verified before any L0 delete; a missing/sick L1 preserves the backstop (SkippedOrphan, the operational signal). The reaper is idempotent (Delete returns nil for missing files; partial reaps resume cleanly) and best-effort (one sick manifest does not stall reaping for the rest). The two landmines are closed honestly: MaxValidTime fully (no residual); eng.DataDir partially (instance-level closed, the global residual disclosed, blocked by the frozen crdt.go constructor). The comment-only crdt.go edit follows the ADR-0015 §7 precedent (disclosed openly, never slipped in silently). The dead `EpochCompactor` stays dead. The default engine behavior (no flags) is byte-identical to before.
