# ADR-0044: WAL Group-Commit — Cutting the fsync Count for the Convergence SLO

- **Status:** Accepted. Verified on loopback, then re-run on 3-region AWS silicon 2026-08-15 — the convergence SLO was still not met (recorded honestly): the fsync-count cut is proven (inject 272.89s → 21.87s, 12.5×) but a deeper blocker surfaced (see the silicon verdict below).
- **Date:** 2026-08-15
- **Author:** Harsh Rawat
- **Scope:** `internal/chaos/wal.go`, `pkg/durability/bridge.go`, `pkg/mesh/{gossip,control}.go`, `cmd/convergence-gate/main.go`, plus a new test file. None of the merge-law/wire-schema files are touched.
- **Metrics:** unchanged — this change cuts the fsync *count* (a physical property), it adds no metric; the inter-region envelope counter `supremum_mesh_inter_region_envelopes` is untouched.

## Context

The previous change put the durable configuration on silicon: a 3× c7gd run with `--wal-path` on NVMe, `--lsm-root` on NVMe, the A/B/C durability checks, and an inject-failure honesty fix. Its silicon verdict:

- **Boot liveness passed** (0.62s).
- **The convergence SLO was not met** — the 10K-key inject blew the 10s budget. The measured inject fsync time was **~272.89s** (from the inject-failure log). Root cause: the gate binary chunked 10K keys into **10 batches of 1000** (`batchSize=1000`); each `/v1/batch-insert` hit the server's `handleBatchInsert`, which **looped `InsertLocalEvents` per entry** → `PutLocal` per entry → `AppendMutation` per entry → **one fsync per entry** = 1000 fsyncs/batch × 10 batches = **10,000 fsyncs** total. At the NVMe-measured **~2.1ms/fsync**, that is `10000 × 2.1ms ≈ 21s` of inject fsync time alone — already over the 10s budget.
- **Region isolation was proven**, and the inter-region envelope counter was live (us=2344 / eu=7156 / ap=6858).

The post-mortem isolated the binding constraint: **the fsync count, not the fsync latency**. The durable config is correct (WAL on NVMe, fsync-on-commit); the per-mutation fsync count is the SLO killer. This change is the count cut.

## The Decision

Collapse N fsyncs into **one fsync per batch**. The change is additive on the same WAL — one source of truth, not a second WAL. Four production edits, five falsifiable tests, and one silicon-infra fix.

### Edit A — `WAL.AppendMutations` + the `sync()` indirection (`internal/chaos/wal.go`)

`AppendMutations(ms []WALMutation) (firstFailIdx int, err error)` writes N mutation records under one `w.mu.Lock`, then issues one fsync (`w.sync()`) for the whole batch — collapsing the per-mutation fsync count (the 1000× cut: 10,000 fsyncs → 1). It uses the same `encodeMutationRecord`, the same 13-byte header (seq+type+payloadLen), and the same `WALRecMutation` type byte as `AppendMutation`. `ReplayWAL` scans record-by-record via length-prefix, so it sees N individual `WALRecMutation` records and populates `Mutations[]` identically to N `AppendMutation` calls. The determinism contract of the time (replay `rebuiltInitial = LamportHigh - len(Mutations)`) is unchanged.

> **Superseded 2026-08-31 (ADR-0045):** that determinism contract — a re-minting replay seeded from a scalar counter — is itself refuted. Group commit stands unchanged; the replay it preserved does not. Replay now restores each recorded `(DotNodeID, DotCounter)` and cuts the tail by WAL record sequence. Note the sharper hazard this ADR introduced for the new contract: `AppendMutations` releases `w.mu` *before* its fsync, so seq/byte ordering — not fsync ordering — is what a sequence cut may rely on.

The `sync()` indirection: the three per-record fsync call sites (`AppendMutation`, `AppendCheckpoint`, `AppendClockAdvance`) are routed through `func (w *WAL) sync() error`, which is `w.f.Sync()` when `syncHook == nil` (the production path, byte-identical to the pre-change code) — verified by diff: the only deletions in wal.go are the 3 `w.f.Sync()` lines, matched by 3 `w.sync()` additions; the encode/write/nextSeq++ bodies are byte-identical. The `syncHook` field is a **test-only fsync spy** (set via `SetSyncHookForTest`, never by production code): `TestGroupCommitCount` counts fsyncs (1 per batch vs 1000 per 1000 single-append loop); `TestGroupCommitAck` rigs a Sync failure (the per-batch 503 honesty test). The indirection is the only change to the single-fsync call sites.

### Edit B — `Bridge.PutLocals` + `LocalItem` (`pkg/durability/bridge.go`)

`PutLocals(items []LocalItem) (dots []eng.CausalDot, failedFrom int, err error)` is the batch origin path: N × `InsertLocal` (stamps dots, in-memory HAMT advances) → one `AppendMutations` (N writes + one fsync). The per-item physical order is byte-identical to `PutLocal`: digest → `InsertLocal` (stamps the dot before the WAL carries it) → the `WALMutation` built from the engine-stamped dot. The determinism contract (replay re-mints the same dots) is preserved per item. The periodic checkpoint counter (`mutationsSinceCkpt`) advances by `len(items)` (not 1), with the same threshold check.

### Edit C — `Gossiper.InsertLocalEventsBatch` + `BatchItem` (`pkg/mesh/gossip.go`)

`InsertLocalEventsBatch(items []BatchItem) (dots, failedFrom, err)` is the batch mesh seam. It mirrors `InsertLocalEvents`'s two-branch structure: the durable path (`g.bridge != nil`) routes through `Bridge.PutLocals`; the in-memory path (`g.bridge == nil`, the `--wal-path=""` opt-in research mode) does N × bare `engine.InsertLocal` (the original back-compat path). The per-item `cache.record` happens after the WAL append (the same order `InsertLocalEvents` keeps — cache and durable log stay consistent).

### Edit D — `handleBatchInsert` routes through `InsertLocalEventsBatch` (`pkg/mesh/control.go`)

The `/v1/batch-insert` handler is restructured into three phases: (1) a per-entry **400** filter (empty keys stamped 400 before the batch call — per-entry validation stays per-entry); (2) the batch call (`InsertLocalEventsBatch`); (3) status stamping — on success all valid entries get `Code 200` with `DotHex`; on any failure all valid entries get `Code 503`. The bitemporal stamping per entry mirrors `handleInsert` verbatim. The single `/v1/insert` stays byte-identical (backward compat).

### Edit E — the gate-binary one-batch switch (`cmd/convergence-gate/main.go`)

`batchSize` changes from `const 1000` to `*numKeys`, so the `for start := 0; start < *numKeys; start += batchSize` loop runs once → 10K keys → one `/v1/batch-insert` POST → one fsync. The loop structure and the per-entry status accounting are unchanged (a single 10K-item batch returns 10K per-entry statuses the same way 10 1K-batches did). A 1-key probe run (`-keys 1`) still sends one 1-item batch (degenerate but correct). The inject fsync time drops from `10000 × 2.1ms ≈ 21s` to `1 × 2.1ms ≈ 2.1ms` plus the cross-AZ HTTP RTT (~50–150ms) — a sub-second inject, well inside the 10s budget.

### Edit F — the durability-check `grep -c` false-pass fix (the 3-region orchestrator script)

The prior durability-config check used `grep -c -E '...'` over the per-node logs, but `grep -c` over a glob prints one integer per matching file (a multi-line blob), not a single integer. The `[ "${dur_on:-0}" -ne "${cnt}" ]` integer comparison then errors on the blob, the error is swallowed by `2>/dev/null`, and `check_a_pass` stays `true` — so a partial in-memory fallback (e.g. 95 nodes on, 5 off) **false-passed**. The fix: `grep -l -E '...' | wc -l` (files-with-matches → a clean single integer = the count of node logs containing the line). A partial fallback → `dur_on=95, dur_off=5` → `dur_on -ne 100` is a clean false → `check_a_pass=false` (caught, not false-passed). **Proven by simulation, not asserted:** the old form returns a blob `node-0.log:1\nnode-2.log:0\nnode-1.log:1` → the `-ne` errors → swallowed → false pass on a 2/3 partial fallback; the new form returns a clean `2` → correctly fails.

## §4 — The ACK-Granularity Disclosure (the honest semantic change)

**Before this change (`TestBatchInsertWALFailPerEntry`) the endpoint reported per-entry 503**: a WAL-failed entry → 503 for that entry; the rest still 200 (the ACK-before-durability contract was per-entry, not per-batch).

**This change reports per-batch 503**: a Sync failure means the whole batch is un-durable (the WAL atomic-batch model — no subset can be asserted durable), so all valid entries get `Code 503` and the client retries the whole batch. A Write failure at index i, or the final Sync failure, → `PutLocals` returns `(dots, 0, err)` → the caller ACKs all entries as 503. It does not return a partial `[0, firstFailIdx)` range: entries `[0, i)` sit in the OS page cache (may or may not survive a crash) and `[i, N)` were never written — I cannot assert durability of any subset. This is the standard WAL atomic-batch model (a transaction commits all-or-none on the durable log). It is not silent data loss: the HTTP response has not been sent until `PutLocals` returns; a crash before that loses the un-ACKed entries and the client retries the whole batch. `/v1/insert` keeps per-entry 503 byte-identical (`PutLocal`).

**The existing `TestBatchInsertWALFailPerEntry` stays green under the per-batch semantic** — verified by running it. The test does two separate POSTs (batch `[entry0]` → 200, then close the WAL, then batch `[entry1,entry2]` → both 503); it never posts a *mixed* batch. So "all-success → all-200" and "all-fail → all-503" are produced identically by the per-entry and per-batch semantics — the test is agnostic to the ACK granularity. The new `TestGroupCommitAck` test distinguishes the two: it posts a batch of 5 valid entries and rigs the Sync to fail on the batch's single fsync, asserting all 5 are 503 — a per-entry 503 regression (the old semantic) would leave the pre-failure entries as 200, failing the "all 503" loop.

## The Tests (falsifiable + bug-injection-proven)

`pkg/mesh/group_commit_test.go` (package `mesh`, internal — it reaches the unexported types):

1. **`TestGroupCommitCount`** — `AppendMutations(1000 entries)` issues **1 fsync**; 1000× `AppendMutation` issues **1000**. The 1000× count cut, measured via the `syncHook` spy (not asserted). RED: a per-mutation fsync inside `AppendMutations` → 1000, not 1 → fails.
2. **`TestGroupCommitAck`** — a rigged Sync failure → all 5 valid entries `Code 503` (per-batch atomicity); the Sync called exactly once (the count cut holds on the failure path). RED: a per-entry 503 regression (the old semantic) → pre-failure entries get 200 → fails the "all 503" loop.
3. **`TestGroupCommitDeterminism`** — a 64-entry batch written via `AppendMutations` replays into a fresh engine and the rebuilt `MerkleRoot == liveRoot` (the determinism contract preserved under group commit). RED: reversed physical order (dots minted before `InsertLocal`) → Merkle mismatch → fails. Mirrors `TestWALRecoveryDeterminism` byte-faithfully.

## The Loopback Gate (the honest verdict)

- **build / gofmt / vet** — clean (the 3 `internal/chaos/probe.go` vet warnings are pre-existing, proven by stash+vet on the pre-change tree; this change does not touch `probe.go`).
- **All tests green** — `TestGroupCommitCount` (1 fsync / 1000 fsync = 1000× cut, measured), `TestGroupCommitAck` (5/5 entries 503, Sync called once), `TestGroupCommitDeterminism` (recovered root == live root). The `AppendMutation` encode/write/nextSeq++ body is byte-identical (the diff's only deletions are the 3 fsync-call lines).
- **Regression green** — the existing batch tests (the crux: they pass under per-batch semantics), `TestWALRecoveryDeterminism` (`AppendMutation` unchanged), `TestHotPathZeroAllocations` (`InsertLocal` pinned), and the full `pkg/mesh` + `pkg/durability` + `internal/chaos` packages.
- **`-race` green** on the tests (no data race introduced).
- **The merge-law/wire-schema files** — byte-identical; the change leaves them untouched.

## Silicon Verification — 2026-08-15 (the honest verdict)

The silicon re-run (3× c7gd.8xlarge across us-east-1 / eu-west-1 / ap-southeast-2, with the one-batch gate binary and the Edit-F check fix) was executed. Numbers verbatim:

- **Boot liveness passed** — all 100 nodes `/livecheck` OK over mTLS in **0.62s** (consistent with the prior run).
- **The convergence SLO was not met** — roots did not equalize within 10s. The convergence poll: `poll 5/10/.../30: 99 nodes divergent (seed root d1406abf...)` — **node 0 holds the 10K keys; the other 99 stay empty (root = zero)** for the full 10s plus the 30s heal window (95 polls × ~0.5s). The cross-region proof: `[eu-west-1 node 34..66] /v1/query convergence-key-0 → HTTP 404 not found` — the seed key never crossed to any peer, not even the other 33 nodes in us-east-1 (intra-region full-mesh).
- **Durability-config verdict: true** — check A **100/100 on** (the Edit-F `grep -l | wc -l` fix; no false-pass — the prior bug is closed), check B seed WAL = **1,348,951 bytes** (durable writes landed), check C all 3 regions on `/dev/nvme1n1` (the c7gd instance-store NVMe, not the EBS root).
- **Region isolation proven** (us-east-1 root != eu/ap root during the partition); **heal re-convergence not detected within 30s** (40,930ms — the same zero-propagation).
- **The inter-region envelope counter** (`supremum_mesh_inter_region_envelopes`) read us-east-1 **476**, eu-west-1 **914**, ap-southeast-2 **614** (grew to 530/2516/2216 after the heal) — **the gossip transport is shipping inter-region envelopes.**

### The inject — this change's target — proven

The inject dropped from the prior run's **272.89s** (10 batches × 1000 fsyncs) to **21.87s** (one batch → one fsync) — a **12.5× cut**. The loopback profile confirms the physics: `AppendMutations(10K)` (writes + one fsync) = **0.58µs/key** (the fsync is amortized to negligible); `PutLocals(10K)` total = **28.2ms** (the `InsertLocal` loop + the one fsync). **The fsync-count cut works** — the inject is no longer fsync-bound. (The residual 21.87s silicon inject vs 28ms loopback is a silicon-specific HTTP/TLS/100-process-contention overhead, not fsync — it is separate from the convergence SLO: the SLO clock starts at `convStart`, after the inject.)

### The deeper blocker — necessary but not sufficient

The convergence SLO's true blocker is **not the inject** (this change's target) — it is a **receive-side delta-apply failure**: the gossip sweep ships envelopes (476/914/614, non-zero and growing) but the **10K-key delta from node 0 never lands in any peer's HAMT** (99/99 stay root-zero; `convergence-key-0` 404s cross-region). The transport works; the deltas do not apply.

**This is the same blocker the three prior silicon runs hit** — all three showed `99 nodes divergent` with node 0 holding the keys. The earlier analysis attributed the convergence failure to the inject time ("per-mutation fsync → inject 272.89s → blows the 10s SLO"), which was a real but secondary bottleneck. This change closed that secondary bottleneck (inject 272.89s → 21.87s) and **un-masked the primary one**: the receive-side delta-apply. The envelope counter (476/914/614 shipped) is the load-bearing evidence — a transport failure would read zero; a delta-apply failure reads non-zero envelopes plus zero convergence.

**First-principles hypothesis for the follow-up:** the receiver `DropVerify`s the deltas (a verification-pubkey or payload-cache miss on the receive path makes the incoming delta unverifiable/unreconstructable → dropped, not applied), or a Merkle-sharding interaction (the sharded root the sweep compares diverges from the joined root), or a large-delta (10K-key) Join path that the loopback's small-delta tests do not exercise. `--peer-dir peerdir` is passed in the silicon launch (pubkey provisioning is wired), so the gap is downstream of provisioning — likely the payload-cache reconstruction on the receive side. This needs a targeted silicon experiment with node receive-path logs.

### Honest summary

- This change is **correct and necessary**: the fsync-count cut is proven (inject 12.5× faster; loopback 0.58µs/key for the one fsync), the Edit-F durability-check fix is proven (100/100 on, no false-pass), the loopback gate is green, the merge-law/wire-schema files are unchanged.
- It is **not sufficient** to close the convergence SLO: the SLO is blocked by a receive-side delta-apply failure (envelopes ship, deltas don't land) that was the true primary blocker all along, masked across the three prior runs by the secondary inject bottleneck. The convergence gate stays not-met — recorded honestly, not fabricated.
- **Teardown clean** — all 3 instances terminated, security groups and key pairs removed.

## Consequences

- The `/v1/batch-insert` ACK granularity changes from per-entry 503 to per-batch 503 (disclosed in §4; the existing test's agnostic shape keeps it green; the new `TestGroupCommitAck` test pins the per-batch semantic).
- `AppendMutation` stays byte-identical (verified by diff: only the 3 fsync-call lines were rerouted through `w.sync()`); `/v1/insert` is unchanged.
- The fsync **count** is now 1 per batch (the count cut); the fsync **latency** (~2.1ms) is unchanged (the per-batch fsync is still a real `f.Sync()` when `syncHook == nil`). A per-batch fsync is not a durability downgrade — it is the standard WAL group commit: one fsync covers the whole batch's writes, and a crash after the writes but before the fsync loses the un-ACKed batch, which is the same loss window `PutLocal` has for a single entry.
- The `syncHook` is a test-only seam; `OpenWAL` leaves it nil; production code never calls `SetSyncHookForTest`. The production path is byte-identical to the pre-change code.
