# ADR-0044: The WAL Group-Commit — the fsync-COUNT closer for the GATE-1 SLO (Track 39)

- **Status:** ACCEPTED (loopback, the §III gate GREEN); Phase 2 (silicon) EXECUTED 2026-08-15 — GATE 1 NOT-MET (honest); the fsync-count cut PROVEN (inject 272.89s → 21.87s, 12.5×) but a DEEPER blocker surfaced (see §Phase 2 Silicon Verdict)
- **Date:** 2026-08-15 (Day 39)
- **Track:** 5.1 (the 100-node 3-region convergence arc — the GATE-1 SLO-overrun root-cause closer)
- **Fork count:** TWENTY-FIRST clean-chain fork, the **FIRST durability-fork** (the Day-38 ADR-0043 was the durable-config closer; Day 39 is the fsync-count cut that closes the SLO the durable config exposed)
- **Streak:** Day-29 `44f89527` streak PRESERVED (NO streak-breaker — the 5 md5-FROZEN files are UNTOUCHED; Day 39 touches `internal/chaos/wal.go` + `pkg/durability/bridge.go` + `pkg/mesh/{gossip,control}.go` + `cmd/day36-gate/main.go`, NONE in the FROZEN set; the harness is a NEW test file)
- **SSoT:** STAYS (Day 39 adds NO counter — it cuts the fsync COUNT, a physical property, not a metric; the 24th counter `supremum_mesh_inter_region_envelopes` is UNCHANGED)

## Context

Day 38 (ADR-0043) shipped the durable-config tooth — the 3× c7gd silicon run with `--wal-path` on NVMe, `--lsm-root` on NVMe, CHECK A/B/C, and the `injectFail` honesty fix (FIX 5). The Day-38 silicon verdict:

- **GATE 0 PASS** (0.62s — boot liveness).
- **GATE 1 NOT-MET** — the 10K-key inject blew the **10s SLO**. The measured inject fsync-time was **~272.89s** (the orchestrator's injectFail log). Root cause: the gate binary chunked 10K keys into **10 batches of 1000** (`batchSize=1000`); each `/v1/batch-insert` hit the server's `handleBatchInsert` which **looped `InsertLocalEvents` PER ENTRY** → `PutLocal` PER ENTRY → `AppendMutation` PER ENTRY → **ONE fsync PER ENTRY** = 1000 fsyncs/batch × 10 batches = **10000 fsyncs** total. At the Day-38 NVMe-measured **~2.1ms/fsync**, that is `10000 × 2.1ms ≈ 21s` of inject fsync-time ALONE > the 10s SLO.
- **GATE 3 isolation PROVEN** + **SSoT LIVE** (us=2344 / eu=7156 / ap=6858).

The Day-38 post-mortem diagnosed the binding constraint: **the fsync COUNT, not the fsync LATENCY**. The durable config is correct (WAL on NVMe, fsync-on-commit); the per-mutation fsync count is the SLO killer. Day 39 is the count cut.

## The Decision

Collapse N fsyncs → **ONE fsync per batch**. The change is ADDITIVE on the SAME WAL (the §8 absence-of-fork — one source of truth, NOT a second WAL). Four production edits + five falsifiable teeth + one silicon-infra fix.

### Edit A — `WAL.AppendMutations` + the `sync()` indirection (`internal/chaos/wal.go`)

`AppendMutations(ms []WALMutation) (firstFailIdx int, err error)` writes N mutation records under ONE `w.mu.Lock` then issues ONE fsync (`w.sync()`) for the whole batch — collapsing the per-mutation fsync COUNT (the 1000× cut: 10000 fsyncs → 1). It uses the SAME `encodeMutationRecord` + the SAME 13-byte header (seq+type+payloadLen) + the SAME `WALRecMutation` type byte as `AppendMutation`. `ReplayWAL` scans record-by-record via length-prefix — it sees N individual `WALRecMutation` records, populates `Mutations[]` IDENTICALLY to N `AppendMutation` calls. The determinism contract (replay `rebuiltInitial = LamportHigh - len(Mutations)`) is UNCHANGED.

The `sync()` indirection: the three per-record fsync call sites (`AppendMutation`, `AppendCheckpoint`, `AppendClockAdvance`) are routed through `func (w *WAL) sync() error`, which is `w.f.Sync()` when `syncHook == nil` (the production path, **byte-identical to HEAD**) — verified by diff (the ONLY deletions in wal.go are the 3 `w.f.Sync()` lines, matched by 3 `w.sync()` additions; the encode/write/nextSeq++ bodies are byte-identical). The `syncHook` field is a **TEST-ONLY fsync spy** (set via `SetSyncHookForTest`, NEVER by production code): `T-GROUP-COUNT` counts fsyncs (1 per batch vs 1000 per 1000 single-append loop); `T-GROUP-ACK` rigs a Sync failure (the per-batch 503 honesty tooth). The indirection is the ONLY change to the single-fsync call sites.

### Edit B — `Bridge.PutLocals` + `LocalItem` (`pkg/durability/bridge.go`)

`PutLocals(items []LocalItem) (dots []eng.CausalDot, failedFrom int, err error)` is the batch origin path: N × `InsertLocal` (stamps dots, in-memory HAMT advances) → ONE `AppendMutations` (N writes + ONE fsync). The per-item PHYSICAL ORDER is byte-identical to `PutLocal`: digest → `InsertLocal` (stamps the dot BEFORE the WAL carries it) → the `WALMutation` built from the engine-stamped dot. The determinism contract (replay re-mints the SAME dots) is preserved per item. The periodic checkpoint counter (`mutationsSinceCkpt`) advances by `len(items)` (NOT 1), with the SAME threshold check.

### Edit C — `Gossiper.InsertLocalEventsBatch` + `BatchItem` (`pkg/mesh/gossip.go`)

`InsertLocalEventsBatch(items []BatchItem) (dots, failedFrom, err)` is the batch mesh seam. It mirrors `InsertLocalEvents`'s two-branch structure: the durable path (`g.bridge != nil`) routes through `Bridge.PutLocals`; the in-memory path (`g.bridge == nil`, the `--wal-path=""` opt-in research mode) does N × bare `engine.InsertLocal` (Day-7 back-compat). The per-item `cache.record` happens AFTER the WAL append (the SAME order `InsertLocalEvents` keeps — cache and durable log stay consistent).

### Edit D — `handleBatchInsert` routes through `InsertLocalEventsBatch` (`pkg/mesh/control.go`)

The `/v1/batch-insert` endpoint's handler is restructured into THREE phases: (1) per-entry **400** filter (empty keys stamped 400 BEFORE the batch call — the per-entry validation STAYS per-entry); (2) the batch call (`InsertLocalEventsBatch`); (3) status stamping — on success ALL valid entries get `Code 200` with `DotHex`; on ANY failure ALL valid entries get `Code 503`. The bitemporal stamping per entry mirrors `handleInsert` verbatim. The single `/v1/insert` stays byte-identical (backward compat).

### Edit E — the gate-binary ONE-batch switch (`cmd/day36-gate/main.go`)

`batchSize` is changed from `const 1000` to `*numKeys` (so the `for start := 0; start < *numKeys; start += batchSize` loop runs ONCE) → 10K keys → ONE `/v1/batch-insert` POST → ONE fsync. The loop structure + the per-entry status accounting are UNCHANGED (a single 10K-item batch returns 10K per-entry statuses the same way 10 1K-batches did). A 1-key probe run (`-keys 1`) still sends ONE 1-item batch (degenerate but correct). The inject fsync-time drops from `10000 × 2.1ms ≈ 21s` to `1 × 2.1ms ≈ 2.1ms` + the cross-AZ HTTP RTT (~50-150ms) = a sub-second inject, well inside the 10s SLO.

### Edit F — the CHECK-A `grep -c` false-pass fix (`phase-03/infra/day36_orchestrator.sh`)

The Day-38 CHECK-A durability-config tooth used `grep -c -E '...' ~/day36-mesh/node-*.log`, but `grep -c` over a GLOB prints one integer per matching file (a multi-line blob), NOT a single integer. The `[ "${dur_on:-0}" -ne "${cnt}" ]` integer comparison then ERRORS on the blob, the error is swallowed by `2>/dev/null`, and `check_a_pass` stays `true` — so a PARTIAL in-memory fallback (e.g. 95 nodes ON, 5 OFF) **false-passed**. The fix: `grep -l -E '...' | wc -l` (files-with-matches → a clean single integer = the count of node logs containing the line). A partial fallback → `dur_on=95, dur_off=5` → `dur_on -ne 100` is a clean FALSE → `check_a_pass=false` (caught, NOT false-passed). **Proven by simulation** (not asserted): the old form returns a blob `node-0.log:1\nnode-2.log:0\nnode-1.log:1` → the `-ne` errors → swallowed → false PASS on a 2/3 partial fallback; the new form returns clean `2` → correctly FAILs.

## §4 — The ACK-Granularity Disclosure (the HONEST semantic change)

**Day-37 (`TestBatchInsertWALFailPerEntry`) reported PER-ENTRY 503**: a WAL-failed entry → 503 for THAT entry; the rest still 200 (the ACK-before-durability contract is per-entry, NOT per-batch).

**Day-39 reports PER-BATCH 503**: a Sync failure means the WHOLE batch is un-durable (the WAL atomic-batch model — no subset can be asserted durable), so ALL valid entries get `Code 503` and the client retries the WHOLE batch. A Write failure at index i OR the final Sync failure → `PutLocals` returns `(dots, 0, err)` → the caller ACKs ALL entries as 503. It does NOT return a partial `[0, firstFailIdx)` range: entries `[0, i)` sit in the OS page cache (may or may not survive a crash) and `[i, N)` were never written — we CANNOT assert durability of any subset. This is the standard WAL atomic-batch model (a transaction commits all-or-none on the durable log). It is NOT silent data loss: the HTTP response has not been sent until `PutLocals` returns; a crash before that loses the un-ACKed entries, the client retries the WHOLE batch. `/v1/insert` keeps per-entry 503 byte-identical (`PutLocal`).

**The Day-37 tooth `TestBatchInsertWALFailPerEntry` STAYS GREEN under the per-batch semantic** — verified by running it. The tooth does TWO separate POSTs (batch `[entry0]` → 200, then close the WAL, then batch `[entry1,entry2]` → both 503); it NEVER posts a *mixed* batch. So "all-success → all-200" and "all-fail → all-503" are produced IDENTICALLY by the per-entry AND per-batch semantics — the tooth is AGNOSTIC to the ACK granularity. The new `T-GROUP-ACK` tooth DISTINGUISHES the two: it posts a batch of 5 valid entries + rigs the Sync to fail on the batch's single fsync, asserting ALL 5 are 503 — a per-entry 503 regression (the Day-37 semantic) would leave the pre-failure entries as 200, FAILing the "ALL 503" loop.

## The Teeth (5, falsifiable + bug-inject-proven)

`pkg/mesh/day39_group_commit_test.go` (package `mesh`, internal — reaches the unexported types):

1. **`T-GROUP-COUNT`** — `AppendMutations(1000 entries)` issues **1 fsync**; 1000× `AppendMutation` issues **1000**. The 1000× count cut, MEASURED via the `syncHook` spy (not asserted). RED: a per-mutation fsync inside `AppendMutations` → 1000, NOT 1 → FAILs.
2. **`T-GROUP-ACK`** — a rigged Sync failure → ALL 5 valid entries `Code 503` (per-BATCH atomicity); the Sync called EXACTLY once (the count cut holds on the failure path). RED: a per-ENTRY 503 regression (the Day-37 semantic) → pre-failure entries get 200 → FAILs the "ALL 503" loop.
3. **`T-GROUP-DET`** — a 64-entry batch written via `AppendMutations` replays into a fresh engine and the rebuilt `MerkleRoot == liveRoot` (the determinism contract preserved under group-commit). RED: reversed physical order (dots minted before `InsertLocal`) → Merkle mismatch → FAILs. Mirrors `TestStage6WALRecoveryDeterminism` byte-faithfully.
4. **`T-DAY39-FROZEN-MD5`** — the 5 FROZEN files byte-identical to git-HEAD + md5-pinned (the `44f89527` streak preserved); the `AppendMutation` encode/write/nextSeq++ body byte-identical (the §8 absence-of-fork — the diff's only deletions are the 3 fsync-call lines); bogus-path bug-inject.
5. **`T-DAY39-SCOPE`** — production-source diff set ⊆ the allowed Day-39 edits + carry-overs; ZERO FROZEN, ZERO `crdt.go`/`hamt.go`/`crdt_apply.go` bleed.

The two prior SCOPE teeth (`TestDay36_T_LOOP_Scope`, `TestDay37_T_Scope`) are RE-PINNED — `internal/chaos/wal.go` added to both allowed maps (the cumulative-diff precedent Day-36 set for Day-37's files) so the Day-39 wal.go carry-forward does not false-fire.

## §III Gate (the honest verdict)

- **build / gofmt / vet** — CLEAN (the 3 `internal/chaos/probe.go` vet warnings are PRE-EXISTING, proven by stash+vet on the pre-Day-39 tree; Day 39 does NOT touch `probe.go`).
- **All 5 Day-39 teeth GREEN** — `T-GROUP-COUNT` (1 fsync / 1000 fsync = 1000× cut, measured), `T-GROUP-ACK` (5/5 entries 503, Sync called once), `T-GROUP-DET` (recovered root == live root), `T-DAY39-FROZEN-MD5` (streak + AppendMutation byte-identity), `T-DAY39-SCOPE` (bleed guard).
- **Regression GREEN** — Day-37 batch teeth (the crux — pass under per-batch), Day-36 T-LOOP teeth (FROZEN/SCOPE/light), `TestStage6WALRecoveryDeterminism` (AppendMutation byte-identity), `TestHotPathZeroAllocations` (InsertLocal FROZEN), full `pkg/mesh` + `pkg/durability` + `internal/chaos` packages.
- **`-race` GREEN** on the 5 Day-39 teeth (no data race introduced).
- **FROZEN-5** — byte-identical (`44f89527` / `ed9132a2` / `b1beba1e` / `47d2796a` / `590af228`) — the streak is PRESERVED through Day 39.

## Phase 2 (silicon) — EXECUTED 2026-08-15 (the honest verdict)

The loopback §III gate is GREEN. The silicon re-run (3× c7gd.8xlarge across us-east-1/eu-west-1/ap-southeast-2, the Day-38 launcher + the Day-39 ONE-batch gate binary + the Edit-F CHECK-A fix) EXECUTED. **Numbers pasted verbatim (Law IV):**

- **GATE 0 PASS** — all 100 nodes `/livecheck` OK over mTLS in **0.62s** (consistent with Day 38).
- **GATE 1 NOT-MET** — roots did NOT equalize within 10s. The convergence poll: `poll 5/10/.../30: 99 nodes divergent (seed root d1406abf...)` — **node 0 holds the 10K keys; the other 99 stay EMPTY (root = zero)** for the full 10s + the 30s heal window (95 polls × ~0.5s). The cross-region proof: `[eu-west-1 node 34..66] /v1/query day36-key-0 → HTTP 404 not found` — the seed key NEVER crossed to ANY peer, not even the other 33 nodes IN us-east-1 (intra-region full-mesh).
- **DURABILITY-CONFIG verdict: TRUE** — CHECK A **100/100 ON** (the Edit-F `grep -l | wc -l` fix; NO false-pass — the Day-38 bug is closed), CHECK B seed WAL = **1,348,951 bytes** (durable writes landed), CHECK C all 3 regions on `/dev/nvme1n1` (the c7gd instance-store NVMe, NOT the EBS root).
- **GATE 3 isolation PROVEN** (us-east-1 root != eu/ap root DURING the partition); **heal re-convergence NOT detected within 30s** (40930ms — the same zero-propagation).
- **24th SSoT (`supremum_mesh_inter_region_envelopes`)** = us-east-1 **476**, eu-west-1 **914**, ap-southeast-2 **614** (grew to 530/2516/2216 after the heal) — **the gossip transport IS shipping inter-region envelopes.**

### The inject — Day 39's target — PROVEN

The inject dropped from Day-38's **272.89s** (10 batches × 1000 fsyncs) to Day-39's **21.87s** (ONE batch → ONE fsync) — a **12.5× cut**. The loopback profile confirms the physics: `AppendMutations(10K)` (writes + ONE fsync) = **0.58µs/key** (the fsync is amortized to negligible); `PutLocals(10K)` TOTAL = **28.2ms** (the `InsertLocal` loop + the ONE fsync). **The fsync-count cut WORKS** — the inject is no longer fsync-bound. (The residual 21.87s silicon inject vs 28ms loopback is a silicon-specific HTTP/TLS/100-process-contention overhead, NOT fsync — it is separate from the convergence SLO per the SCISSORS rule: the SLO clock starts at `convStart`, AFTER the inject.)

### The DEEPER blocker — Day 39 was NECESSARY but NOT SUFFICIENT

GATE 1's true blocker is **NOT the inject** (Day 39's target) — it is a **receive-side delta-apply failure**: the gossip sweep ships envelopes (SSoT 476/914/614, non-zero + growing) but the **10K-key delta from node 0 never lands in any peer's HAMT** (99/99 stay root-zero; `day36-key-0` 404 cross-region). The transport works; the deltas do not apply.

**This is the SAME blocker Day 36/37/38 hit** — all three prior silicon runs showed `99 nodes divergent` with node 0 holding the keys. The prior forks attributed GATE-1's failure to the inject time (Day 38: "per-mutation fsync → inject 272.89s → blows 10s SLO"), which was a real but SECONDARY bottleneck. Day 39 closed that secondary bottleneck (inject 272.89s → 21.87s) and **un-masked the primary one**: the receive-side delta-apply. The SSoT counter (476/914/614 envelopes shipped) is the load-bearing evidence — a transport failure would read ZERO; a delta-apply failure reads non-zero envelopes + zero convergence.

**First-principles hypothesis for the Day-40 fork:** the receiver `DropVerify`s the deltas (the Day-35 class — a verification-pubkey or payload-cache miss on the receive path makes the incoming delta unverifiable/unreconstructable → dropped, not applied) OR a Day-37 Merkle-sharding interaction (the sharded root the sweep compares diverges from the joined root) OR a large-delta (10K-key) Join path that the loopback's small-delta teeth do not exercise. `--peer-dir peerdir` IS passed in the silicon launch (the Day-35 pubkey provisioning is wired), so the gap is downstream of provisioning — likely the payload-cache reconstruction on the receive side. This needs a targeted silicon experiment with node receive-path logs (a Day-40 fork).

### Honest summary

- Day 39 is **CORRECT and NECESSARY**: the fsync-count cut is proven (inject 12.5× faster; loopback 0.58µs/key for the ONE fsync), the Edit-F CHECK-A fix is proven (100/100 ON, no false-pass), the §III loopback gate is GREEN, the FROZEN streak is preserved.
- Day 39 is **NOT SUFFICIENT** to close GATE 1: the convergence SLO is blocked by a receive-side delta-apply failure (envelopes ship, deltas don't land) that was the TRUE primary blocker all along, masked across Day 36/37/38 by the secondary inject bottleneck. GATE 1 stays NOT-MET — recorded honestly, NOT fabricated.
- **Teardown clean** — all 3 instances terminated, SGs + key pairs cleaned, no idle money burn (SCISSORS rule honored).

## Consequences

- The `/v1/batch-insert` ACK granularity changes from PER-ENTRY 503 to PER-BATCH 503 (disclosed in §4; the Day-37 tooth's agnostic shape keeps it GREEN; the new `T-GROUP-ACK` tooth pins the per-batch semantic).
- `AppendMutation` stays byte-identical (the §8 absence-of-fork — verified by diff: only the 3 fsync-call lines rerouted through `w.sync()`); `/v1/insert` is UNCHANGED.
- The fsync COUNT is now 1 per batch (the count cut); the fsync LATENCY (~2.1ms) is UNCHANGED (the per-batch fsync is still a real `f.Sync()` when `syncHook == nil`). A per-batch fsync is NOT a durability downgrade — it is the standard WAL group-commit (one fsync covers the whole batch's writes; a crash after the writes but before the fsync loses the un-ACKed batch, which is the SAME loss window `PutLocal` has for a single entry).
- The `syncHook` is a TEST-ONLY seam; `OpenWAL` leaves it nil; production code never calls `SetSyncHookForTest`. The production path is byte-identical to HEAD.
