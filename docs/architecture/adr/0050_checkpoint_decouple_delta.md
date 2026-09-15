# ADR-0050: Decouple + delta-batch the checkpoint flush — the convergence SLO met at production config

- **Status:** ACCEPTED (the synchronous checkpoint flush is off the commit path; the Release-A convergence SLO gate is met at production checkpoint config)
- **Date:** 2026-09-08
- **Frozen files:** NONE touched — all five core merge-law/wire-schema files are unchanged (crdt.go, crdt_apply.go, envelope.go, schema.capnp, schema.capnp.go).

## 1. Context
ADR-0049 isolated the cause of the convergence-SLO blocker: the
**synchronous per-entity-fsync checkpoint flush in the origin commit path**. Every
`--wal-checkpoint-interval`(=1000) mutations, the crossing `PutLocals` ran `drainCheckpoints()`
inline, and the flush wrote the FULL live state as one fsync'd Arrow file per entity — 10K keys ⇒
~110,000 fsyncs on the ACK path ⇒ a 260–300s quiesce stall ⇒ the seed's `commit_in_flight` never
reached 0 ⇒ the convergence SLO was never even measurable. The `ckpt=0` arm of the ADR-0049 A/B
proved the SLO *achievable* (8.323s), but ckpt=0 is a diagnostic (unbounded replay),
never the shipped config. This change is the production fix.

## 2. The fix (two halves, blast-radius-isolated)
- **Half A — decouple (the SLO-critical half).** `designateCheckpoint` now spawns
  `go b.drainCheckpoints()`; the committing `PutLocals` returns after its own WAL fsync. A single
  packed atomic word (`ckptState`: bit0 runner-in-flight, bits 1-62 pending count, bit63 CLOSING)
  makes designate-vs-Close race-free; `Close` sets the closing bit, drains the runner
  (`waitCheckpointsIdle`), and only then tears down WAL/engine — no background checkpoint outlives `Close`.
- **Half B — delta-flush (kill the O(N²)).** A per-entity durable-flush watermark
  (`lastFlushedDot map[string]eng.CausalDot`, heap-copied keys; full-dot compare so foreign dots are
  correct) flushes only entities whose max-dot changed since the last durable flush — O(Δ) per
  checkpoint, O(N) total. The recovery image stays FULL. The EBR pin is released BEFORE the slow
  `mt.Flush` (`MemTable.Write` copies the entityIDs). The file shape is unchanged — one entity per
  `l0/{hash8}/` file — because the read path's per-entity discovery is load-bearing.

## 3. fsync count before/after (layer: the durability-checkpoint query-tier flush)
- Before: 110,000 fsyncs, all on the commit/ACK path.
- After: 20,000 fsyncs, all in the background runner. **Commit-path checkpoint fsyncs: → 0.**

## 4. Guards (all bug-injection-proven, `-race` GREEN, re-run first-hand on this change)
T-A1 (decouple; inline negative control blocks 3s), T-A1b (decoupled flush completes + durable),
T-A2 (Close-drain; pending anchor durable; closed-WAL bug-inject loses it), T-A3 (the drain is
load-bearing for the WAL-anchor count), T-B1 (fsync work O(N)→O(Δ); full-flush negative control),
T-B2 (durable read correct for changed AND unchanged; lost-delta bug-inject goes stale),
T-B3 (decoupled recovery re-attains the root; torn-image falls back to exact-WAL replay — integrity check on).

**Regression I caught during verification (disclosed):** the first full `pkg/mesh` sweep failed on
`TestQuery_InsertEndpointToQueryEndpoint_RoundTrip` — the one test that drives the interval-triggered
checkpoint over the production HTTP path (`checkpointInterval=1`) and checks the `l0/` witness
synchronously. The decouple made that checkpoint asynchronous, so the witness raced the background flush.
I confirmed it was a regression by byte-diff (passes at the pre-change base, fails with the decouple);
the sibling query tests are unaffected because they call the synchronous public `AppendCheckpoint`
directly at `interval=0`. The fix: the test now polls the eventually-consistent `l0/` witness with a
bounded deadline that still fails loudly if the checkpoint never flushes; the full sweep re-ran GREEN
(714s). This is exactly why the full `pkg/mesh` sweep matters — the narrower convergence-and-topology
gate filter does not cover that test.

## 5. The silicon gate (100 nodes / 3× c7gd.8xlarge, integrity verification on, production `--wal-checkpoint-interval=1000`)
Seven consecutive runs, every pass reported:

| Pass | t50 | t90 | t100 (SLO) | Verdict |
|------|-------|-------|-----------|---------|
| 1 | 0.865s | 3.774s | 6.682s | PASS |
| 2 | 1.233s | 4.129s | 8.365s | PASS |
| 3 | 1.201s | 5.193s | 10.150s | SLO-MISS (+150ms, t100 straggler) |
| 4 | 0.259s | 3.838s | 8.738s | PASS |
| 5 | 0.230s | 3.562s | 7.260s | PASS |
| 6 | 0.859s | 3.750s | 6.659s | PASS |
| 7 | 0.237s | 3.912s | 6.586s | PASS |

- **3-consecutive-clean gate: met — and exceeded (PASS 4/5/6/7 = four consecutive).** Every pass:
  quiesce wall 3.11–3.14s (vs 260–300s before the change), 0 hard-timeout inject batches, **0 SLOW COMMIT
  lines**, all-100-roots-equal (`d1406abf…`), crash leg PASS (`root re-equals pre-crash`, `replayed
  0 post-checkpoint records`), zero-running teardown in all 3 regions.
- **The decouple is visible in the profiles:** the seed pprof shows the checkpoint flush on a background
  `drainCheckpoints` goroutine (`stageAndFlushQueryTierDelta` → `LocalFS.Upload` → `os.File.Sync`),
  with zero commit-path goroutines parked in a checkpoint fsync — the signature ADR-0049 §4 described
  is gone.
- **The pass-3 miss is a mesh tail straggler, not a regression** (three proofs: t50/t90 stable at
  ~0.2–1.2s / ~3.5–5.2s with only t100 varying; the ckpt=0 diagnostic's 8.323s is in-range; the background
  flush cannot starve gossip).

## 6. Decision + consequences
The checkpoint-flush blocker is resolved. The convergence SLO is unblocked and met at production
config — the pre-change clean-run count was zero; it is now four consecutive. **New open item:**
the mesh WAN convergence tail (the t100 straggler) occasionally exceeds the 10s bar (about one run in
seven). That is a mesh gossip property (region topology / fanout / relay timing), independent of the
commit path, and the right target if the SLO needs p99 margin. No frozen touch; no hot-path
allocation; no weakened recovery binding; no background checkpoint outlives `Close`.
