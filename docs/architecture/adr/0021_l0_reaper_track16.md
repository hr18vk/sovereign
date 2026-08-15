# ADR-0021: The L0 Reaper + the Land-Mine Closure — Reclaim the Superseded-L0 Backstop (close ADR-0020 §6c) + Close the MaxValidTime + eng.DataDir Landmines (ADR-0020 §6 tail)

**Status:** Accepted
**Date:** 2026-08-03
**Phase:** 3, Day 16
**Author:** Sovereign Architect (head, dictated the prompt) + Sovereign Executor (same session — single-agent impl of the dictated fork)
**Builds on:** ADR-0020 (Day-15 Level-2 prune — the (C1)&&(C2)&&(C3) SAFE-DROP + txTime GC floor; §6c deferred the L0 reaper, §6 tail carried the MaxValidTime + DataDir landmines), ADR-0019 (Day-14 L0→L1 compaction — writes the manifest that lists the superseded L0s; keeps them as the backstop), ADR-0017 (the resolver read-half — AsOf over L1+tail; the L0-reaper preserves the L1 the resolver queries), ADR-0015 §7 (Day-10 the comment-only-FROZEN re-pin precedent this track follows), the Day-8.5 receiver.go re-pin precedent (re-pin WITH disclosure, NOT silence).

---

## §0. The three things Day-16 does (the dictated scope)

Day-16 closes the THREE items ADR-0020 §6 left open — one deferred P1 fork + two latent landmines:

- **§0.a (ADR-0020 §6c, the deferred P1) — the L0 REAPER.** ADR-0019's compaction write path writes a manifest at `compaction/{hex8}/{sysNs}.manifest` listing the L0 files it merged into the L1, but KEEPS the L0 files forever as the crash-recovery backstop ("delete-after-read-safety was deferred 'a future fork'"). The `l0/` directory grows monotonically — every compaction leaves N L0 files PLUS the manifest. The reaper deletes the manifest-listed L0 files AFTER verifying the L1 still exists (Stage C safety guard), then deletes the manifest. The backstop is reclaimed, not leaked.

- **§0.b (ADR-0020 §6 tail landmine #1) — `MaxValidTime.UnixNano()` int64 overflow.** `var MaxValidTime = time.Date(9999,12,31,23,59,59,0,UTC)` was conceptually an open-ended valid interval endpoint, but `.UnixNano()` OVERFLOWS int64: year 9999 → ~633e9 s → ~6.33e20 ns, NEGATIVE when truncated (the high bit is set). Every `_test.go` call site that passed `MaxValidTime.UnixNano()` as `ValidTimeEnd` sent a garbage negative into the Arrow index — a half-open interval `[vs,ve<0)` is EMPTY for every positive `validTime` → the row is silently invisible to `AsOf`'s `Filter3`. The mesh's `OpenEndedValidEndNs` (pkg/mesh/control.go:118, Day-12.5) has ALWAYS used the concrete-const-`9e18` pattern; Day-16 closes the WRITE-schema side to match. ZERO production callers existed (every caller was a `_test.go`); the `var` is DELETED, replaced by `const MaxValidTimeEndNs int64 = 9_000_000_000_000_000_000` (year ~2253, comfortably below `MaxInt64 ~9.22e18`).

- **§0.c (ADR-0020 §6 tail landmine #2) — `eng.DataDir` global bypass.** `pkg/sync.DataDir` is a package-level `var`; `newEngineAt` (pkg/durability/recovery.go) sets it directly to the scratch dir. The hazard: a bare global mutation the caller races a concurrent apply against. Day-16 keeps the pre-ctor global write (LOAD-BEARING — the FROZEN ctor reads the global mid-construction) AND adds a post-ctor `engine.SetDataDir(scratchDir)` so the INSTANCE's `dataDir` field is routed through the `persistMu`-guarded setter for its lifetime. The residual global race (two concurrent `newEngineAt` calls) is disclosed honestly — never reachable on the sequential boot path, blocked from full closure ONLY by the FROZEN crdt.go ctor's global read.

The Day-16 design rule: **the reaper is opt-in** (`--compaction-reap-enable`, default false) and **NEVER auto-ON**. Byte-identical Day-15 behavior is the default: the superseded L0 files STAY as the backstop. The reaper's safety contract is the Stage C **verify-the-L1-exists-before-any-L0-delete** guard — a filesystem layer that EVER reports a present L1 as missing would ALSO be one the compactor trusted to WRITE the L1; the operator turns the reaper on ONLY once they trust their storage.

---

## §1. The FROZEN re-pin (the honesty discipline — Day-10 ADR-0015 §7 + Day-8.5 receiver.go precedent)

Day-16 touches ONE FROZEN file: `pkg/sync/crdt.go`. The change is **COMMENT-ONLY** — a warning doc placed above `var DataDir` at crdt.go:17 (the §0.c landmine's own surface). NO byte of executable code changed; the 3 contracts (determinism / EBR / the 57.6M hot path) are byte-identical (a comment edit provably cannot touch the CAS line, the retire order, or the zero-alloc gates).

The md5 drifts:

```
pkg/sync/crdt.go   705ac6712ea20541f664d09d08795b43  →  a50fee8f03a43375e0a18f64b3288441
                   (Day-10 ADR-0015 pin)                (Day-16 ADR-0021 re-pin)
```

The other 4 FROZEN files (crdt_apply.go / schema.capnp / schema.capnp.go / envelope.go) are byte-identical — Day-16 touches NONE of them.

**The 8-pin re-sync.** crdt.go's md5 is pinned in 8 test teeth across the repo. After Day-10 re-pinned `4512bd67 → 705ac671`, every site got a Day-10 citation. Day-16 re-pins `705ac671 → a50fee8f` and re-syncs ALL 8 with a Day-16 citation:

1. `pkg/transport/transport_test.go` — `crdtFrozenMD5` const (the canonical stated rule)
2. `pkg/receive/gate_test.go` — the G3.5.c md5 list
3. `pkg/receive/bench_test.go` — `benchFrozenFiles`
4. `pkg/authorization/cedar_bench_test.go` — the frozen-md5 list
5. `pkg/sync/crdt_reconstruct_test.go` — the reconstruct frozen list
6. `internal/database/l1_compaction_track14_test.go` — Day-14 T6
7. `internal/database/l1_compaction_track15_test.go` — Day-15 T6
8. `internal/database/l1_compaction_track16_test.go` — Day-16 T5 (NEW — the re-pin's own witness)

The `pkg/receive/gate_test.go TestGate_UntouchedFrozenAndOutOfScope` (G3.5.i) tooth compares the FROZEN files' working copy to `git show HEAD:`. A comment-only edit to crdt.go makes the working copy differ from HEAD — the tooth FAILS pre-commit and PASSES post-commit (HEAD advances to `a50fee8f`). This is the SAME transient Day-10's crdt.go edit produced (the tooth is byte-identity to committed HEAD, not to a pinned md5; the md5-tooth covers the pinned value). Verified: only crdt.go differs from HEAD pre-commit; the other 7 FROZEN files are clean. Post-commit, the tooth is green.

---

## §2. The land-mine closures (honest, with disclosed residuals)

### §2.1 MaxValidTime → MaxValidTimeEndNs (CLOSED, no residual)

`internal/database/l0_flusher.go` replaces `var MaxValidTime = time.Date(9999,...)` with:

```go
const MaxValidTimeEndNs int64 = 9_000_000_000_000_000_000
```

8 call sites updated (all in `_test.go`: 2 in `l0_flusher_test.go`, 6 in `memtable_test.go`) — `MaxValidTime.UnixNano()` → `MaxValidTimeEndNs`. The `time` import dropped from l0_flusher.go (no remaining use). The `var` deletion is safe: ZERO production callers existed (grep-verified — `MaxValidTime` appears in production code ONLY inside l0_flusher.go's OWN declaration; the WRITE path reads `validTimeEndNs` from the packed value bytes directly at l0_flusher.go:223, never via `MaxValidTime.UnixNano()`). The WRITE schema now matches the mesh's READ-side `OpenEndedValidEndNs` (pkg/mesh/control.go:118) — one int64-safe sentinel, both sides. **No residual.**

### §2.2 eng.DataDir → engine.SetDataDir (PARTIALLY CLOSED — residual disclosed)

`pkg/durability/recovery.go newEngineAt` KEEPS the pre-ctor `eng.DataDir = scratchDir` global write (load-bearing — see §0.c) AND ADDS a post-ctor `engine.SetDataDir(scratchDir)`:

```go
eng.DataDir = scratchDir                 // pre-ctor: FROZEN ctor copies this into e.dataDir; recoverLamport reads no stale file
engine, err := eng.NewDeltaCRDTEngine(nodeID, initialCounter, arenaSize)
...
engine.SetDataDir(scratchDir)            // post-ctor (Day-16): instance field via persistMu-guarded setter
```

**Why the pre-ctor global write is LOAD-BEARING + cannot be removed:** the FROZEN constructor (crdt.go:279 NewDeltaCRDTEngine) copies `DataDir` into `e.dataDir` at crdt.go:290 and calls `recoverLamport()` at crdt.go:376 which reads `e.dataDir` to find `<dataDir>/lamport_<nodeID>.dat` — a persisted Lamport override that, if present, lifts `initialCounter` above the caller's seed. Pointing the global at the fresh scratch dir BEFORE the ctor makes `recoverLamport` read no stale file → returns 0 → honors the WAL-derived determinism seed EXACTLY (ADR-0013 §4, Day-8.5). REMOVING the global write = the FROZEN ctor reads `/data/crdt` and a stale `lamport_<nodeID>.dat` overrides the WAL seed → re-introduces the Day-8 determinism defect. The global write is the ONLY channel for the scratch-dir seed-trick through the FROZEN ctor.

**What the post-ctor `engine.SetDataDir` closes:** the INSTANCE's `dataDir` field for its lifetime is routed through the `persistMu`-guarded setter (crdt.go:484), NOT a bare global mutation the caller races a concurrent apply/persist against. `SetDataDir` acquires `persistMu`; `persistLamport` (crdt.go:911) also takes `persistMu`; so the instance sees the same ordering edge the setter establishes.

**The disclosed residual:** two CONCURRENT `newEngineAt` calls still race on the PACKAGE GLOBAL `sync.DataDir` — a real-but-NEVER-reached hazard. The production boot path is SEQUENTIAL (one `RecoverEngine` per process at boot; `cmd/sovereign-node` constructs exactly one engine). The test paths serialize too. The global race is blocked from closure ONLY by the FROZEN `crdt.go` constructor reading the global mid-construction; full closure requires a ctor that takes an explicit `dataDir` ARGUMENT (a future FROZEN-crdt.go change). Law V: report the residual, do not claim the trap is fully closed.

---

## §3. The reaper (the §0.a closure — the load-bearing safety contract)

### §3.1 The seam

The reaper adds a FOURTH narrow S3 interface: `S3Deleter` (internal/database/query.go):

```go
type S3Deleter interface {
    Delete(ctx context.Context, bucket, key string) error
}
```

`pkg/durability/localfs.go *LocalFS.Delete` implements it — `os.Remove` with the **idempotent contract**: `os.IsNotExist` returns `nil` (NOT an error). A file already reclaimed by a prior sweep or a manual operator returns nil, so the reaper's partial-reap retry loop makes forward progress across sweeps. The compile-time interface-assertion `_ S3Deleter = (*LocalFS)(nil)` catches a signature drift.

### §3.2 The reaper (internal/database/l0_reaper.go — NEW file)

`L0Reaper` holds the three read/delete seams (`S3Lister` + `S3Downloader` + `S3Deleter`) — it never holds an `S3Uploader` (it never writes). `NewL0Reaper(lister, downloader, deleter, bucket)` constructs it; `Reap(ctx) ReapResult` runs ONE cross-entity sweep in stages A–F:

- **Stage A** — list ALL keys under `compaction/` (uncapped — the reaper reaps EVERY entity, not one at a time); skip non-`.manifest` keys (defense in depth).
- **Stage B** — `Download` + `ParseManifest` each manifest → `(l1Key, l0Keys)` via the EXISTING parser (one parser, one truth — the same function AsOf + SupersededL0Keys use).
- **Stage C** — **the SAFETY GUARD**: `Download(l1Key)` to verify the L1 STILL EXISTS. The probe is a Download (the S3 surface has no Head/Stat; the reaper is off the hot path — one probe per manifest per 5-min sweep, bounded by the manifest count). A manifest with NO `l1Key` (malformed) CANNOT be verified → preserve (orphan). ANY download failure (a genuine 404, an S3 outage, a permission error) → the L0s are PRESERVED (the backstop) + the manifest is SKIPPED → `SkippedOrphan++`. **Treating ANY download failure as "preserve" is the SAFEST reading** — a transient outage degrades the reaper to no-op for one interval (harmless); deleting an L0 whose L1 is actually-gone loses the SOLE durable copy (catastrophic).
- **Stage D** — delete each `l0Key` via the `S3Deleter`. If a SINGLE delete fails (a real IO/permission error — NOT a missing file, which is idempotent nil), STOP → the manifest is RETAINED → `SkippedError++`. The already-deleted L0s stay deleted (monotone forward progress); the next sweep retries (idempotent nil on the gone ones + the failed one real).
- **Stage E** — delete the manifest, ONLY after every listed-L0 delete succeeded. A manifest-delete failure → `SkippedError++` (the L0s are already gone; the manifest retries next sweep — forward-progress-safe).
- **Stage F** — tally `ReapedManifests++`. The L0-delete count accumulates in `ReapedL0` during Stage D.

`ReapResult` carries 4 per-sweep tallies (Law V — disclose the counts, not adjectives): `ReapedManifests` / `ReapedL0` / `SkippedOrphan` / `SkippedError`.

### §3.3 The telemetry (4 counters — Law V observable)

`internal/telemetry/registry.go` adds:

- `supremum.compaction.l0_reap_sweeps` — sweeper runs
- `supremum.compaction.l0_reap_l0_files_deleted` — successful Delete calls (INCLUDES the idempotent already-absent path — see T3 sweep 3)
- `supremum.compaction.l0_reap_manifests_reaped` — manifests fully reaped (L0s + manifest)
- `supremum.compaction.l0_reap_manifests_skipped_orphan` — manifests skipped (L1 gone/sick; the backstop PRESERVED — the operator signal)

A non-zero `skipped_orphan` is the OPERATOR SIGNAL an L1 was lost (or the store is reporting it gone). A non-zero `skipped_error` is the operator signal the store is rejecting deletes.

### §3.4 The wiring (cmd/sovereign-node/main.go)

Two flags: `--compaction-reap-enable` (default false) + `--compaction-reap-interval` (default 5m). The reaper is constructed in the `--lsm-root` block (alongside the compactor + resolver) sharing the SAME `*LocalFS` for all three seams (one FS root, one keyspace — the Day-12/14 wiring discipline). `reaperLoop` runs alongside `compactionSchedulerLoop`, gated on `meshCtx` so SIGINT/SIGTERM cancels it; a nil reaper (--reap false, or no --lsm-root) makes it a no-op (byte-identical Day-15). The reaper runs LESS often than the compactor (default 5m vs 30s) — the superseded L0s are a SAFETY net with zero urgency to delete; the slower cadence amortizes the manifest-list + L1-probe cost over more compactions.

The reaper is the COMPLEMENT of the per-entity compaction scheduler: the compactor DRIVES new L1s + manifests; the reaper RECLAIMS the L0s the compactor superseded.

---

## §4. The teeth (T1–T6, mirrors the dictated §1.5)

Two test files (the Day-14 import-cycle precedent — an internal/database test CANNOT import pkg/durability because snapshot.go imports internal/database):

- **`pkg/durability/l0_reaper_track16_test.go`** — T1/T2/T3/T4, driven against a REAL `*LocalFS` (the Day-12.5 "drive the route, not the seam" principle). Reuses the track14 helpers (`track14LocalFS`, `track14WriteN`, `track14MakePackedValue`, `putBE64`).
  - **T1 — THE HEADLINE:** write N=8 per-entity checkpoints → compaction (manifest + L1 written, L0s STAY) → Reap → every superseded L0 deleted, manifest deleted, L1 UNTOUCHED, and a NON-manifest bystander entity's L0 (no compaction ran for it) UNTOUCHED; AsOf still 200 via the L1 (truth preserved). RED-then-GREEN over a REAL FS.
  - **T2 — the SAFETY GUARD (load-bearing):** delete the L1 a manifest points at, Reap → the reaper MUST NOT delete the L0s NOR the manifest; `SkippedOrphan=1`. The L0s are the sole durable copy → preserved.
  - **T3 — idempotent reaper:** Reap TWICE. Sweep 1 reaps fully; sweep 2 is a CLEAN no-op (the manifest already gone → not re-listed; 0/0/0/0). Sweep 3 re-creates the manifest (pointing at L0s already gone) → reaps it (Stage D's Deletes return idempotent nil on the already-gone L0s, counted as N successful Deletes; Stage E deletes the manifest). FORWARD progress on an already-reaped keyspace.
  - **T4 — PARTIAL reap:** a fault-injecting `*LocalFS` wrapper makes the 2nd L0 delete fail → Stage D stops → manifest RETAINED, 1st L0 deleted (forward progress), `SkippedError=1`; resume sweep against the real FS reaps the rest. The `track16FaultyDeleter` satisfies `database.S3Deleter` at compile time.

- **`internal/database/l1_compaction_track16_test.go`** — T5/T6.
  - **T5 — the FROZEN md5 set:** crdt.go re-pinned `705ac671 → a50fee8f` (comment-only), the other 4 byte-identical. The re-pin disclosed per the Day-10 ADR-0015 §7 + Day-8.5 receiver.go precedent.
  - **T6 — scope hygiene:** the dead `EpochCompactor` (ADR-0018 §6) STAYS DEAD post-Day-16. The reaper is a NEW type over `S3Deleter`, NOT a `SetCompactor`/`InsertTombstone`/`NewEpochCompactor`/`PruneTombstones` importer. The tooth greps the PRODUCTION trees (internal/pkg/cmd, excluding _test.go + the dead-symbol OWN definition files) and asserts 0 callers for each — the ADR-0019 §6 + ADR-0020 T5 discipline.

---

## §5. What stayed out (the CONDITIONAL-GO seam — UNTOUCHED)

Day-16 does NOT touch the §5 CONDITIONAL-GO seam (the receive/mesh transport-hardening / service-thread-pool / io_uring changes). The §5 gating convention from Day-5 onward stands: those changes are CONDITIONAL-GO, gated behind a flag, NOT unconditionally shipped. The Day-16 scope is the durability/disk-reclaim layer ONLY.

---

## §6. Residuals (carried forward, honestly)

- **§6.1 the eng.DataDir GLOBAL race** (§2.2) — closed at the INSTANCE level (`engine.SetDataDir`); the PACKAGE-GLOBAL race (two concurrent `newEngineAt`) remains, NEVER reachable on the sequential boot path, blocked from closure by the FROZEN crdt.go ctor's mid-construction global read. Full closure = a FROZEN-crdt.go ctor that takes an explicit `dataDir` arg. A future fork.
- **§6.2 the L0 files of an ENTITY with NO manifest** — the reaper deletes ONLY manifest-listed L0s. An L0 whose entity was never compacted (no manifest) is NEVER deleted by the reaper — it is the LIVE L0 the resolver reads. Correct by design (the reaper reclaims SUPERSEDED L0s, not live ones); disclosed for completeness.
- **§6.3 the `L0ReapL0Deleted` inflation under re-run** — the counter counts every successful Delete call, INCLUDING the idempotent already-absent path (a re-created manifest pointing at already-gone L0s re-counts them: see T3 sweep 3). A pre-Stat-per-L0 could distinguish "physically removed THIS sweep" from "already absent," but that is an IO the safety contract does NOT require; the per-sweep `ReapedManifests` is the cleaner forward-progress signal. Disclosed in the metric description.
- **§6.4 ADR-0020 §6a (T_gc auto-inference)** + **§6b (O(N²)→O(N·H) interval sweep)** — unchanged, still ADR-0020's deferred Level-3 prune refinements.

---

## §7. What this proves

The L0 reaper is a **provably-safe opt-in disk-reclaim sweep** with a **byte-identical default** to Day-15 (the backstop kept forever). It closes the cross-entity monotonic-L0 disk leak ADR-0020 §6c deferred, at the honest cost of an operator opt-in (`--compaction-reap-enable`) gated on storage trust (the Stage C L1-exists guard). The L1 is verified before ANY L0 delete; a missing/sick L1 preserves the backstop (SkippedOrphan, the operator signal). The reaper is idempotent (Delete returns nil for missing files; partial reaps resume cleanly) + best-effort (one sick manifest does not stall reaping for the rest). The two landmines are closed honestly: MaxValidTime fully (no residual); eng.DataDir partially (instance-level closed, global residual disclosed, blocked by FROZEN crdt.go). The re-pin follows the Day-10 ADR-0015 §7 + Day-8.5 receiver.go precedent (re-pin WITH disclosure, NOT silence) — ALL 8 pins re-synced with a Day-16 citation. The dead `EpochCompactor` stays DEAD. The §5 CONDITIONAL-GO seam is untouched. The DEFAULT engine behavior (no flags) is byte-identical to Day-15.
