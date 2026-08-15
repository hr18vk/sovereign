# PHASE 2.5a — PARALLEL-JOIN CAS-STORM CLOSURE — EXECUTOR REPORT

Branch: `feat/phase25a-sharded-root-cas` off `main @ 785bdc5`. Production change:
`pkg/sync/crdt.go` only (the first production-code phase since 2g). New tooth:
`pkg/sync/phase25a_test.go`. Necessary diagnostic compat: a 10-line field-ref
refresh in `pkg/sync/layout_analysis_test.go` (print-only Phase-1 layout dumper;
no assertions). All other `pkg/sync/*` files are byte-identical to 785bdc5 (R4).

## §1 The edit (R1 — sharded-root CAS)

`pkg/sync/crdt.go` replaces the single root-state CAS with a per-entityID shard
array. Concretely:

- **Shard array decl**: `shards []shardRoot` on `DeltaCRDTEngine`, replacing
  `state atomic.Pointer[HAMT]` + its two `CacheLinePad`s. `shardRoot` wraps
  `ptr atomic.Pointer[HAMT]` between `_padHead`/`_padTail` `CacheLinePad` so two
  hot shards mutated by different cores do not share an L1 line (the Phase 1/2
  false-sharing discipline, now per-shard).
- **Routing helper**: `func (e *DeltaCRDTEngine) routeShard(entityID string) int`
  — `maphash.String(e.routeSeed, entityID) & (N-1)` (power-of-two N → bitmask
  route, no modulo). Pure in `entityID` so the same entityID always lands in the
  same shard — the load-bearing property Join's per-shard CAS relies on.
- **Per-shard CAS in InsertLocal**: route `entityID` → `shardIdx`, CAS ONLY
  `e.shards[shardIdx].ptr` in the lock-free retry loop. The rest of
  InsertLocal's merge (insertion-sort-last-entry, MANDATE 4 fresh backing
  array, EBR Retire on the previous shard root, maybeAdvanceEpoch) is unchanged.
- **Per-shard CAS in Join**: `incoming` (already sorted by entityID) is
  partitioned into per-shard `blockRange` runs grouped by `routeShard`. Each
  shard that receives ≥1 block is CAS'd INDEPENDENTLY: load the shard root,
  run the same dot-merge (the `perShardMerge` closure, lifted verbatim from the
  single-root Join) over all of that shard's blocks into one modified HAMT, CAS
  just that shard's pointer; on success Retire the previous shard root, on fail
  retry against a freshly-loaded shard root. `maybeAdvanceEpoch` is called
  ONCE per Join (outside the per-shard driver) — preserving the Phase 2g/2l
  Reclamation contract (R2 §4). `sort.Ints(shardOrder)` keeps the retire order
  deterministic for the Merkle-root determinism contract.
- **LamportSnapshot across-shards reader**: UNCHANGED. `LamportSnapshot` reads
  `e.lamportCounter` (a single shared `atomic.Uint64`), the EWMA bits, and the
  persistMu-guarded knobs — exactly as before. Sharding the HAMT root does NOT
  shard the LamportClock (R2 §3); the clock is one atomic shared across all
  shards just as it was shared across all workers on the single root.
- **EBR retire/AdvanceEpoch adaptation**: each successful per-shard CAS
  `e.ebr.Retire(unsafe.Pointer(current))` (the previous shard root).
  `maybeAdvanceEpoch` once per Join/InsertLocal. The Phase 2l static tooth
  (`Retire(prev)` + `AdvanceEpoch()` in `BenchmarkHAMT_Set`) is byte-identical
  and still matches — it audits the raw HAMT bench, not the engine.
- **SetShardCount(n int)**: runtime-tunable knob (mirrors the
  `SetLamportAbsoluteSlack`/`SetDataDir` pattern). Re-roots the engine into a
  different power-of-two cardinality: re-emit every live (entityID, entries)
  pair from the old shards into the new shards via `Set`, Retire the old roots
  through EBR (3-epoch grace). Asserts `n` is a positive power of two.
- **State() merged view**: the engine root is sharded, but `State()` keeps
  returning `*HAMT` (production API surface — `internal/chaos/probe.go` /
  `partition.go` call `.RootPtr()`/`.MerkleRoot()`). `State()` builds a fresh
  merged `*HAMT` from all shards via `Set`, Retires the PREVIOUS merged view via
  EBR (3-epoch grace, mirroring the single-root publish profile), and returns
  the new one. Bounds the live merged-view hold to ONE wrapper per engine.
  OFF the Join hot path (Join never calls `State()`).
- **Generator adaptation**: `GenerateDigestWithSeed`/`GenerateStrataEstimator`
  iterate every shard root under the EBR pin. `GenerateDelta`/
  `GenerateDeltaStratified` snapshot `allShardRoots()` under the pin and the lazy
  `Entries` Seq iterates that frozen view; the delta carries `rootRef=0`/
  `arenaRef=nil` and `Release()` skips DecRef via its guard (the EBR pin is the
  load-bearing protection per the C4 FIX comment; IncRef/DecRef is N-rooted at
  sharded scale). `CRDTDelta.MerkleRoot` — which has NO consumer (the
  authoritative convergence check is `eng.State().MerkleRoot()`, preserved via
  the merged `State()` view) — is left zeroed; honest carry-forward.

## §2 Why this is architecturally pure (R2)

1. **Textbook migration, not invention.** Sharding a CRDT by entityID is the
   known-correct shape at planetary scale (Riak / Antidote / Redis-CRDT). The
   single root CAS was the Phase 1/2 simplification that eased the
   linearizability proof; Phase 2.5a graduates to the production shape now that
   the integrity teeth (2c-2g) pin the contract.
2. **Per-shard linearizability.** Each `shardRoot.ptr` is its own
   `atomic.Pointer[HAMT]`, so the per-shard CAS loop is linearizable
   INDEPENDENTLY. The cross-shard model is "last-writer-per-shard" — exactly
   the CRDT Join contract (for each entityID, merge the delta's entries into
   the existing set; the merge is per-entityID, therefore per-shard). All
   integrity teeth (dot attribution 2f, skew bound 2g, version mismatch 2b,
   digest 2c) operate per-entity → unchanged by sharding.
3. **LamportClock shared across shards.** `lamportCounter`, the EWMA, and the
   persistMu-guarded knobs are SINGLE shared values across all shards (R2 §3).
   `LamportSnapshot` reads them byte-identically to Phase 2g; sharding the HAMT
   root does not shard the clock. Tooth B runs the full 2c-2g bite suite on the
   sharded engine and they all PASS.
4. **EBR contract preserved.** Each per-shard CAS success Retires the previous
   shard root; `maybeAdvanceEpoch` once-per-Join keeps the Phase 2g/2l
   Reclamation contract. The Phase 2l static tooth (regex on
   `BenchmarkHAMT_Set`'s `Retire(prev)` + `AdvanceEpoch()`) is byte-identical
   and STILL MATCHES — it audits the raw HAMT bench, which does not use the
   sharded engine.

## §3 Gates — literal output (Tier 1, GOMAXPROCS=4 / runtime.NumCPU()==4)

This sandbox is a 4-core `c7g.xlarge` Tier-1 dev box (`runtime.NumCPU()==4`).
The 32-core Tier-2 (`c7g.8xlarge`, `runtime.NumCPU()==32`) ratification was NOT
run on this sandbox — the prompt's "NEVER claim a 32-core number without the
literal 32-core run" rule forbids fabricating it. The 4-core run proves the
RATIO collapse (CPU-count-invariant per the prompt); the ≥10× absolute gate and
the ≥50% CAS-share gate are 32-core publication numbers.

| Gate | Tier 1 (NumCPU=4) literal | Verdict |
|---|---|---|
| G2 throughput (pre-R1 ns/op@4 baseline) | `JoinParallel-4  350061  7878 ns/op` (count=2: 7997, 7878); pre-bench-table also 7473, 7758 ns/op | pre-R1 storm ≈ 7.8k ns/op@4 |
| G2 throughput (post-R1 ns/op@4) | `JoinParallel-4  1330866  2755 ns/op` (count=2: 2755, 2913); also 2608, 2640, 2689 ns/op | **≈2.85× collapse at 4 cores; ≥10× is the 32-core gate** |
| G2b contention curve (pre-R1) | `Tooth C: ratio ns/op@4 / ns/op@1 = 8151 / 6177 = 1.32` — NOT-CORROBORATED (storm mild at 4 cores; the prompt's "lower-core-noise" caveat) | pre-R1 ratio 1.32× |
| G2b contention curve (post-R1) | `Tooth C: ratio ns/op@4 / ns/op@1 = 2426 / 5139 = 0.47` — NOT-CORROBORATED; parallel-Join now ACCELERATES with cores (embarrassing-parallelism signature) | **ratio collapsed 1.32× → 0.47×** |
| G3 pprof top-frame (pre-R1) | top: `Join 96.65%` → `HAMT.Set 49.5%` → `NodePtr.set 45.5%` → `maybeAdvanceEpoch 37.7%` → `AdvanceEpoch 37.6%`; `atomic.(*Uint64).CompareAndSwap` 16.09% + `atomic.CompareAndSwapPointer` 9.48% + `Pointer[HAMT].CompareAndSwap` 0.77% (the single-root CAS frame) ≈ 26% | single-root CAS frame present |
| G3 pprof top-frame (post-R1) | top: `Join 93.57%` → `Join.func3 54.1%` → `HAMT.Set 47.2%` → `NodePtr.set 43.5%`; `atomic.(*Uint64).CompareAndSwap` 11.08% + `atomic.CompareAndSwapPointer` 3.27% ≈ 14.4%; the `Pointer[HAMT].CompareAndSwap` single-root frame GONE from top-30 (spread across 256 shard pointers) | **single-root CAS frame eliminated; CAS share ~26%→~14% (≈45% drop at 4 cores; ≥50% drop is the 32-core gate)** |
| G4 build ./... | clean | GREEN |
| G5 go vet ./... | 26 `unsafe.Pointer` notices = baseline (23 `pkg/sync` + 3 `internal/chaos`); zero NEW vet warnings introduced | GREEN (baseline) |
| G6 R4 byte-identical scope | `hamt.go, hamt_arena.go, hamt_test.go, crdt_reconstruct.go, crdt_reconstruct_skew.go, crdt_apply.go, crdt_apply_batch.go, physics_test.go, race_enabled_test.go, race_enabled_off_test.go, phase2j_test.go, crdt_test.go, + 2c-2g teeth files` all `git diff 785bdc5` IDENTICAL | GREEN |
| G7 crdt.go md5 before/after | before `64dad041890b1566038622de70cf0022`; after `74aa2a41c4b19b9684f8167a4db7f5a0` (CHANGED — this is a production-code phase) | honest (see §6 (i)) |
| G8 race-sweep (-race full pkg/sync) | `go test -race ./pkg/sync/ -count=1` → `ok ... 43.361s` (incl. rapid property + EBR ring + concurrency teeth + Phase 2g lamport coherence) | GREEN |
| G9 concurrency teeth on sharded root | `TestConcurrentInsertLocalRace`, `TestConcurrentJoinRace`, `TestCRDTEngine_ConcurrentInsertAndJoin`, `TestPhase2g_LamportSnapshotCoherence` → all PASS under -race | GREEN |
| G10 Phase 2l/2m tooth under -race | `TestPhase2L_HAMTSetReclamationTooth` → `--- SKIP` (raceEnabled guard load-bearing; tooth's static guard still PASSED) | SKIP (unchanged) |
| G11 Phase 2j tooth verdict flip | pre-R1 1.32× NOT-CORROBORATED (mild at 4c) → post-R1 0.47× NOT-CORROBORATED (parallel-Join accelerates) | ratio collapsed (0.59× recorded in Tooth A runtime drive) |

**XPath 2 (Tooth A runtime drive, post-R1 GOMAXPROCS=4):**
```
Tooth A row: GOMAXPROCS=1    ns/op=5069.00 ... ; GOMAXPROCS=4   ns/op=2608.00 ...
Tooth A: ratio ns/op@4 / ns/op@1 = 2608 / 5069 = 0.51   (ratio-COLLAPSE gate PASS, < 1.5x)
Tooth A (cardinality): N=1 single-shard ns/op@4=7121.00 ; N=256 sharded ns/op@4=2516.00 ; speedup=2.83x   (EFFECTIVE-CARDINALITY gate PASS, >= 1.5x)
```

**Pre-R1 ns/op@4 (Tooth A from the single-root state) ≈ 7780 ns/op (≈ 2.95× the
post-R1 ≈ 2640). On a 4-core box the CAS storm is mild (single-root ratio 1.32×
already < 1.5×), so the ABSOLUTE ns/op collapse at 4 cores is ≈ 2.85–2.95×, NOT
≥10× — the ≥10× absolute gate is the 32-core Tier-2 gate (the prompt's "4-core
gate is the engineering gate; the 32-core gate is the publication gate").**

**Pre/post pprof diff (Tier 1):** the single-root `atomic.Pointer[HAMT].CompareAndSwap`
frame (0.77% pre-R1, present in the symbol table) disappears from the post-R1
top profile; total CAS cum drops from ≈ 26% → ≈ 14% (≈ 45% reduction at 4 cores).
At 32 cores the authoritative reduction is ≥ 50% (the prompt's G3 Whitepaper
number — not run on this 4-core sandbox per the tier discipline).

## §4 Scope discipline (R4)

- **Sanctioned change**: `pkg/sync/crdt.go` (production, the first since 2g) +
  `pkg/sync/phase25a_test.go` (new tooth) + a necessary 10-line field-ref
  refresh in `pkg/sync/layout_analysis_test.go` (the Phase-1 layout analyzer is
  a print-only diagnostic that introspects `unsafe.Offsetof(DeltaCRDTEngine{}.…)`
  fields; removing the `state` field for the shard array required updating those
  field names so the package still compiles — no assertions changed).
- **Byte-identical (verified `git diff 785bdc5 -- <path>` empty for each)**:
  `hamt.go, hamt_arena.go, hamt_test.go, crdt_reconstruct.go,
  crdt_reconstruct_skew.go, crdt_apply.go, crdt_apply_batch.go, physics_test.go,
  race_enabled_test.go, race_enabled_off_test.go, phase2j_test.go, crdt_test.go,
  crdt_apply_test.go, crdt_apply_batch_test.go, crdt_dot_origin_test.go,
  crdt_lamport_skew_test.go, crdt_reconstruct_test.go,
  crdt_capnp_roundtrip_test.go, crdt_capnp_teeth_test.go,
  phase2l_staticaudit_test.go`.
- **crdt.go md5**: before `64dad041890b1566038622de70cf0022`; after
  `74aa2a41c4b19b9684f8167a4db7f5a0`. CHANGED — this is the honest graduation
  from Phase 2's test-harness discipline to production-code work.

## §5 Carry-forwards (one line each)

- **CONFOUNDER 2 (persistMu disk-mutex serialization)**: NOT closed by 2.5a;
  pprof post-R1 no longer has the single-root CAS drowning out the top-30, so
  the wall-time `persistLamport`/`persistMu` frames may now bubble up. Phase
  2.5c closes it. Untouched here (no edit to `persistLamport` or the persistMu
  call site).
- **Phase 2.5b Delta-gen Zero-GC (300KB/delta + 6.5ms)**: UNTOUCHED in 2.5a;
  its own prompt. The sharded root does not change the per-delta allocation
  profile (the bench's `allocs/op` even dropped 11→9 from fewer merged-state
  retries per Join).
- **Phase 2g A2/A3 (per-peer EWMAs + authenticated clocks)**: UNCHANGED;
  sharding the HAMT root does not affect A1/A4 closure at the wire nor advance
  A2/A3.
- **26-pointer vet baseline**: `go vet ./...` = 26 `unsafe.Pointer` notices =
  baseline (filed under "off-heap arena; pre-existing"). No new vet warnings.

## §6 Honest limitations

(i) This IS a production-code phase. R4's byte-identical set is the TEST
files, not the production files. `crdt.go`'s md5 changed (§4). The integrity
teeth (2c-2g) are the regression net; `layout_analysis_test.go`'s field-ref
refresh is the only test-file edit outside the byte-identical set, and it is a
print-only diagnostic (no assertions) — a necessary compat for removing the
`state` field.

(ii) The ≥10× ns/op gate uses the verifier's SAME-sandbox measured pre-R1
baseline. On this 4-core sandbox the pre-R1 ns/op@4 ≈ 7780 and post-R1 ≈ 2640
(≈ 2.85× collapse). The ≥10× absolute improvement is the 32-core Tier-2
publication number (NOT run on this sandbox per the tier discipline — never
claim a 32-core number without the literal 32-core run). The RATIO collapse
(1.32× → 0.47× at GOMAXPROCS=4) is CPU-count-invariant evidence the storm
collapsed.

(iii) GOMAXPROCS=4 / runtime.NumCPU()==4 declared on every §3 measurement above
(this is a Tier-1 c7g.xlarge). The Tier-2 c7g.8xlarge (NumCPU=32) G2/G2b/G3
ratification is the verifier's role per the two-tier discipline; NOT claimed here.

(iv) Default N=256 is reasoned (≥ GOMAXPROCS, power of two, fits L1 cache ×
cache-line-pad); a real-traffic Phase 3 would surface different right values.
`SetShardCount` is the runtime-tunable knob (verified by M3's
`SetShardCount(1)` mutation being caught by Tooth A's cardinality drive).

## §7 THE VERDICT — LEFT BLANK (verifier rules)

(the verifier writes ACCEPTED/REJECTED here and on ACCEPT lands the atomic
--ff-only merge to main and re-bites M1+M2+M3 on the post-merge tree)
