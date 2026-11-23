# Sovereign Engine — The Engineering Post-Mortem & Journey Log

**Author:** Harsh Rawat
**Journey span:** 2026-07-17 → 2026-11-06
**Scope:** The engineering arc of Sovereign Engine, from the zero-GC substrate through the allocator rewrite, crash recovery, and multi-region convergence. I wrote it from test output, race runs, source changes, and fleet logs. It records the failures and false trails as well as the results. I built this engine on my own, set the architecture, made the design decisions, and checked the measurements quoted here.

> **Reading contract:** The measurements below come from `go test`, `go test -race`, `RUN_CRUCIBLE=1`, and dated fleet runs on Linux/arm64 AWS Graviton hosts. The early allocation and cache experiments used 8 cores; the scaling benchmark used 32 cores with `GOMAXPROCS` tiers 4/8/16/32. The final fleet runs spanned multiple AWS regions. These are different measurement layers, not one throughput claim. Where runs varied, I give the range and its conditions.

---

## Prologue: The Mandate

The initial target was a ledger sustaining 50 million operations per second without Go heap allocation on its hot path, built on AWS Graviton. The design used a lock-free, off-heap δ-CRDT engine over a path-copying HAMT, with Epoch-Based Reclamation and hazard pointers. I also wanted recovery and replication to preserve correctness over a long service life. The risk was letting a design document substitute for evidence, so I made each important claim a test that could fail.

Three principles guided the work:

1. **Measure the event that matters.** A cache line is 64 bytes. A major page fault is a kernel event. A `SIGSEGV` is an MMU trap below the Go runtime. Each has a measurable signature; a test should observe that signature rather than a proxy that host scheduling can distort.
2. **Let the test arbitrate.** I encoded cache-line offsets, linearizability, and byte-equal Merkle roots as assertions. The tests caught defects that my own reading missed.
3. **Report the margin.** A gate passing by 1.5% has little headroom. Ranges and failed targets matter as much as the passing figures, because they tell a maintainer what the result does not establish.

What follows is the journey in the order that the work exposed those constraints.

---

## The Zero-GC Substrate

Before optimizing across cores, I had to establish the memory and convergence invariants. Those tests later told me whether the allocator rewrite had broken earlier work.

### The Zero-GC Microscope

**Objective:** prove that the measured `HAMT.Set` hot path performs zero Go heap allocations. Other engine paths can allocate and trigger GC, but allocation on this path would add GC pauses to every write-heavy workload.

**Method:** `testing.AllocsPerRun` isolates the allocation count of `HAMT.Set` from benchmark framework noise. The defense was structural — every HAMT node, leaf, string, and CRDT entry array lives in a `mmap`'d C-space arena, *invisible to the Go GC*, allocated by a segregated slab allocator with 17 size classes and lock-free Treiber free-lists.

```
=== RUN   TestHotPathZeroAllocations
--- PASS: TestHotPathZeroAllocations (0.00s)

BenchmarkHAMTInsertZeroAlloc-8    415088   4350 ns/op   0 B/op   0 allocs/op
BenchmarkHAMTInsertZeroAlloc-8    413342   4349 ns/op   0 B/op   0 allocs/op
BenchmarkHAMTInsertZeroAlloc-8    412203   4359 ns/op   0 B/op   0 allocs/op
```

**Result:** the benchmark reported 0 allocs/op and 0 B/op. Single-threaded throughput was about 230,000 ops/sec in these runs. Arena consumption per `Set` was 1,153 bytes, then 1,344 bytes for the next thousand deeper keys; `TestArenaUsagePerSet` records both. Structural tests fixed the layouts: `HamtNode` was 72 bytes with `nextFree` at offset 64, `CRDTEntry` was 120 bytes with no internal padding, and `hamtLeaf` was 32 bytes. The allocation result came from placing those objects outside the Go heap, not from tuning the collector.

### ABA Immunity

**Objective:** test the fixed-size node free-list for the ABA (A→B→A) problem under goroutine preemption, with the race detector enabled.

**Method:** the ABA test yields after an explicit read of `arena.freeHeads[0].head`, then makes a separate `AllocNode` call while other goroutines allocate and retire nodes. `AllocNode` reads and CASes a head in the sharded `nodeFreelist`, so that explicit yield does not sit between its actual head load and CAS. The test stresses concurrent allocation and EBR reclamation under the race detector; it is not a direct proof of that specific ABA window. In production, `AllocNode` holds an EBR participant across its head read and CAS, preventing a node observed as head from being recycled during that interval. The later variable-size lists took different free paths and needed a separate fix, described below.

An early environment could not run the race detector because it lacked CGo and gcc. Once that limitation was removed, `-race` reported no data races across the nine tests listed below. They exercise `HamtArena` allocation and EBR, concurrent CRDT/HAMT operations, and an atomic counter; none exercises `ShardedStack` or `ElimNodePool`. The run checks those paths for data races, not the SEC allocator's ABA behavior or scaling. A property is not tested by a tool that could not run.

```
=== RUN   TestTreiberStackABAImmunity            --- PASS
=== RUN   TestEBRHazardPointerSequencing         --- PASS
=== RUN   TestConcurrentAllocFree                --- PASS
=== RUN   TestConcurrentInsertLocalRace           --- PASS
=== RUN   TestConcurrentJoinRace                 --- PASS
=== RUN   TestEpochStateMachineFuzz              --- PASS
=== RUN   TestConcurrentSetGet                   --- PASS
=== RUN   TestAtomicCounterStress                --- PASS (1.73s)
=== RUN   TestHEBRDetachAllowsEpochAdvance       --- PASS
```

### Algebraic CRDT Convergence

**Objective:** test the δ-CRDT merge function for the three join-semilattice axioms — commutativity, associativity, and idempotence — and check that multi-node topologies converge to identical state.

**Method:** property-based testing with `pgregory.net/rapid` at `-rapid.checks=100`, plus a Merkle-root convergence harness using IBLT (Invertible Bloom Lookup Table) anti-entropy and a Strata Estimator for set-difference sizing. Five property tests each passed 100 randomized checks; engine-level tests covered 3-node and 5-node meshes.

```
=== RUN   TestCRDTJoinCommutativity      [rapid] OK, passed 100 tests   --- PASS
=== RUN   TestCRDTJoinAssociativity      [rapid] OK, passed 100 tests   --- PASS
=== RUN   TestCRDTJoinIdempotence       [rapid] OK, passed 100 tests   --- PASS
=== RUN   TestCRDTConvergenceMultiNode  [rapid] OK, passed 100 tests   --- PASS
=== RUN   TestCRDTJoinMonotonicGrowth   [rapid] OK, passed 100 tests   --- PASS
```

The IBLT tests (`InsertAndPeel`, `Subtract`, `ZeroFalsePositives`, and `IncompletePeel`) and Strata Estimator tests (`IdenticalSets`, `SmallDifference`, and `LargeDifference`) covered decoding, subtraction, empty differences, and incomplete peels. Their test vectors produced no false positives and sized the tested differences correctly. All five algebraic properties passed, and the 3-node and 5-node topologies converged after δ-CRDT synchronization. At that point I had a single-machine result; the fault-injection and fleet work came later.

---

## Cache Coherence and the Allocator Collapse

The substrate tests established correctness and zero Go heap allocation on the measured HAMT path. They did not establish throughput across cores. Cache-coherence traffic became the next constraint.

### False Sharing

I measured the hot struct layouts with `unsafe.Offsetof` and added tests for the offsets, then compared padded and unpadded atomics. The goal was to keep hot atomics on separate 64-byte L1 cache lines and measure whether the padding changed throughput.

The pre-sharding layout placed `DeltaCRDTEngine.state` at offset 64, `lamportCounter` at 216, and `epochCounter` at 440. Four write-only metrics counters shared a line because they were read infrequently through `Stats()`. `DeltaCRDTEngine` grew from 168 to 680 bytes with eight cache-line pads; `EBRManager` grew from 120 to 376 bytes with four. `EBRManager.globalEpoch`, `Participant.active`, and the free-list heads likewise received separate lines. These figures describe that historical layout: the current engine shards state into padded `shardRoot` slots rather than retaining the old `state` field. The padding was a one-time memory cost, not an allocation on each operation.

`TestFalseSharingProof` compared two goroutines updating adjacent atomics, with and without padding:

```
Unpadded (false sharing):    34,526,310.0 ns/op
Padded   (no false share):    5,495,223.0 ns/op
Speedup ratio:                     6.28x
```

Other runs of the two-counter test measured 6.78× (37,229,586 → 5,491,824 ns/op); the engine-proxy test measured 2.07× and 1.88×. The proxy performed more work per operation, so coherence invalidations represented a smaller fraction of its runtime. The measurements showed that two frequently written atomics on one cache line could dominate this microbenchmark. That gave me a concrete mechanism to investigate when throughput later fell as core count increased.

### The Single-Locus Collapse

#### A correct stack that became slower with more cores

I had treated the SEC (Sharded Elimination) stack as complete. The code existed, but `TestScalingGate` showed that it did not scale:

| Tier | Throughput | Efficiency | Linearizable |
|------|------------|------------|--------------|
| 4c   | 19.4M ops/s | 100.0%   | OK           |
| 8c   | 12.0M ops/s | 30.8%    | OK           |
| 16c  | 6.5M ops/s  | 8.4%     | OK           |
| 32c  | 4.0M ops/s  | 2.6%     | OK           |

At 32 cores, parallel efficiency was 2.6%, below the recorded plain-Treiber baseline of 3.4%. Adding cores reduced throughput from 19.4M to 4.0M ops/s. Linearizability held (`drained == surplus` at every tier), but the implementation did not meet its scaling purpose.

#### The diagnosis: contention moved to the allocator

The sharded `stackTop` (64 × 128-byte `secShard`) distributed stack-head CAS operations, but each `secDeepCache` refill made a series of `pool.allocIndex()` calls against the single global `pool.free` head. The burst workload (mean 64, cap 512) repeatedly emptied and refilled the 128-slot cache, concentrating cores on that one free-list line. The retired `TestEliminationCrucibleScalingGate` records the earlier design at 1.1M ops/s at 32 cores and 1.6% parallel efficiency, failing identically on the unmodified baseline.

#### The architectural pivot: the Home-Shard SEC Allocator

I replaced the single free-list head with `freeShards [64]ElimPoolShard`. Each `ElimPoolShard` was 128 bytes: an atomic head plus padding, keeping adjacent heads out of the same 128-byte prefetch pair. Two routing rules distributed the work:

- **Free by home shard:** `freeIndexHome(idx)` pushed to shard `idx % 64`, rather than the executing thread's PID. Under skew, consumers scattered frees across the home shards and refilled producers' local shards.
- **Allocate locally, then probe:** `allocIndexSharded(pid)` popped from the caller's shard, then linearly probed `(pid+1, pid+2, ...)` when it was empty.

This was the design that removed the single-locus collapse. The current `ShardedStack` has one later refinement: `deepFreeLocal` spills to the popper's local shard, matching `deepAlloc`'s local-first refill. `freeIndexHome` remains on the raw-index path. That change addressed a later 16-core dip caused by the two routing directions contending on the same heads.

#### The three bugs the pivot surfaced

The allocator rewrite introduced three defects. Linearizability assertions, the drain walker, sequential tests, and the race detector caught them.

**Bug 1 — sentinel collision (`drained=0`, `surplus=790,823`).** `allocIndexSharded` returned `NullOffset64` (0) when every shard was exhausted. Index 0 also meant "empty", so linking it onto `stackTop` made a nonempty shard look empty. The drainer returned zero nodes and left 790,823 pushed values unreachable. I changed allocation to keep probing and yield rather than return the sentinel.

**Bug 2 — producer/consumer live-lock.** The original `pop` stayed on the caller's P-shard. With about 25% pure consumers and random routing across 32 PIDs, a consumer could spin on a shard with no producer while producers exhausted the pool. The gate timed out after 50s with producers in `Gosched`. I made `pop` probe beyond the local shard; a bounded diagnostic with 30 producers and 2 consumers then recorded 0% empty pops.

**Bug 3 — `freeNext` aliasing.** The home-shard seed loop wrote `p.nodes[i].freeNext`, the same field used by the legacy single free-list. `ElimStack` and `flatCombStack` therefore followed shard links as though they were legacy links and became unreachable after about 16 nodes. `TestEliminationSequentialCorrectness` hung in allocation. I made the legacy allocation and free functions delegate to the sharded API so `ElimNode.freeNext` has one owner.

The design looked straightforward before implementation. The failures came from the shared sentinel and mutable link field, and the tests found them before my reading did.

#### The regression sweep

Because the change replaced a core memory primitive, I re-ran the earlier checks without further edits:

- **Allocation and layout:** `TestHotPathZeroAllocations`, arena usage, HAMT offsets, struct alignment, and layout analysis passed. The 128-byte `ElimPoolShard` preserved cache-line isolation; `TestFalseSharingProof` still measured 6.78×.
- **Concurrency under `-race`:** the nine tests listed above reported no data races in their HamtArena, EBR, CRDT/HAMT, and atomic-counter coverage. They did not exercise `ShardedStack` or `ElimNodePool`; the SEC stack's linearizability evidence comes separately from `TestScalingGate` below.
- **CRDT and HAMT behavior:** the selected suite reported 40 passes, no failures, and no skips with `-rapid.checks=100`. All five property tests passed their 100 checks.

#### The result and its limits

Command: `RUN_CRUCIBLE=1 go test -v -run TestScalingGate ./pkg/sync/`

```
  core   throughput      speedup  efficiency   lin-ok?   pushed       drained     surplus
  4        25,797,287      1.00x      100.0%     OK        12,877,120    2,364       2,364
  8        35,014,884      1.36x       67.9%     OK        17,502,891   17,451      17,451
  16       34,746,270      1.35x       33.7%     OK        17,418,434   43,137      43,137
  32       50,736,038      1.97x       24.6%     OK        25,448,950   63,939      63,939
  NumCPU=32, candidate=SEC-sharded

--- PASS: TestScalingGate (4.03s)
```

The 32-core result rose from 4.0M ops/s to 50,736,038 ops/s, about 13× at the gate floor. A later run on a c8g.8xlarge with Go 1.26.1 measured 68,278,197 ops/s, about 17× the collapsed result. The recorded range is therefore 50.7M–68.3M ops/s. This is the in-process SEC stack push/pop benchmark: it does not include signature verification, networking, TLS, or persistence, and it is not the production ingest rate. The later run is preserved in the [core benchmark receipt](../evidence/core-crucible.txt).

Linearizability held across repeated runs, including `-race`, but the throughput curve did not scale near-linearly. The recorded 16-core result, 34,746,270 ops/s, was slightly below the 8-core result of 35,014,884 ops/s, and the gate run reached 24.6% relative efficiency at 32 cores.

#### Two targets and the one that passed

- **85% relative parallel efficiency at 32 cores — not met.** The gate run measured 24.6%. This was the original target; I moved to an absolute throughput target during the work.
- **50,000,000 ops/s at 32 cores — met**, with about 1.5% headroom at the recorded floor.

The workload was about 25% pure producers, 25% pure consumers, and 50% mixed. Under that skew, the spanning pop probe can inspect O(shards) and generate coherence traffic. This explains part of the efficiency cost, but it does not prove that 85% was unattainable. The absolute target is useful for this workload; it does not erase the missed scaling target.

#### Why I cite a range

Some early notes rounded the result to 58M ops/s. The gate output did not support that figure: its passing run measured 50,736,038 ops/s, and the later receipt measured 68,278,197 ops/s under the conditions named above. I cite 50.7M–68.3M with the benchmark layer and machine class rather than rounding a measurement into a margin it did not have.

#### Keeping hardware tests opt-in

The 50M ops/s threshold depends on the machine. `TestScalingGate` skips in short mode and unless `RUN_CRUCIBLE=1` is set. `TestFalseSharingProof` and `TestEngineProxyFalseSharingProof` also skip in short mode, and the longer linearizability stress tests are gated as well.

At that point in the work, `go test -short ./pkg/sync/` recorded 62 passes, no failures, and 11 skips in about 2.6s. Those are historical counts, not the size of the current suite. The expensive tests remained available through their explicit options.

#### Test cleanup

I removed print-only diagnostics and dead probe counters from `sharded.go`. The behavioral tests stayed: ABA, arena usage, CRDT properties, HAMT layout, cache coherence, reclamation, sharding, and scaling all had assertions that could fail. Diagnostic output was useful while isolating the allocator defects, but it was not a substitute for a regression test.

---

## The Chaos Layer

The allocator tests covered atomic concurrency and throughput. The next work tested operating-system faults, process crashes, and network partitions. It did not add throughput; it tested whether the engine preserved state when those faults occurred.

### OS Page Faults and `mmap`

#### The threat

The arena is a `mmap`'d region. A dereference normally needs no syscall, but accessing a nonresident page can trap into the kernel and block the OS thread while the page is restored. That is a major page fault, and ordinary pointer access does not tell the caller that it occurred.

Three consequences mattered:

- **Faults occupy OS threads.** Go cannot preempt a thread blocked in uninterruptible disk I/O. Enough concurrent faults during an arena scan can therefore reduce scheduler capacity and stall unrelated goroutines.
- **`recover()` does not report a major fault.** Execution continues after the page is restored. An unresolved fault on an unmapped page instead delivers `SIGSEGV`, which the next section covers.
- **Latency alone is an unreliable test on a shared host.** The inherited 10µs predicate could fail because of scheduling noise or pass because the kernel happened not to evict pages. Neither outcome isolated the residency property.

There was a second failure mode: applying `MADV_DONTNEED` to a `MAP_PRIVATE` anonymous page discards its modifications. If that page holds the HAMT `seed` or a control node, the next access reads zeroes; in the test, the next `Get` panicked with `maphash: use of uninitialized Seed`.

#### The diagnosis: gating the wrong thing

`TestResidencyPageFaultGate` initially used a wall-clock latency predicate. On a shared host, that could not distinguish pinned pages from pages the kernel had simply left resident. I replaced it with an assertion that no major fault occurred during the measured traversal.

#### Chunked `mlock` and a fault-counter gate

The helpers in `pkg/sync/residency.go` implement bounded pinning and fault injection without changing the allocator hot path.

**Chunked, degradation-tolerant `mlock`.** `LockHotPages` pins one page at a time and returns a `ResidencyStatus`. `UnlockHotPages` releases the selected range one page at a time, while `UnlockAllPages` issues one `Munlock` for the whole arena. Both unlock helpers discard errors and return no status:

- **Page boundaries are explicit.** `LockHotPages` and `UnlockHotPages` align addresses and lengths to whole pages, avoiding ambiguity about partial-page coverage. `LockHotPages` reports `PagesPinned` against `PagesRequested`.
- **`EPERM` is nonfatal.** Without `CAP_IPC_LOCK`, the first `mlock` can fail. `LockHotPages` records `PermDenied: true` and returns its status instead of refusing to run.
- **`ENOMEM` is nonfatal.** When `RLIMIT_MEMLOCK` stops further pinning, `LockHotPages` records `Truncated: true` and reports how many requested pages were pinned.

The lock status makes partial residency visible to the caller. It does not claim that the whole arena is locked.

**The deterministic gate.** `osMajorFaultCount()` reads `majflt` from `/proc/self/stat`, and the test asserts that its delta is zero across the post-pin traversal. Scheduling delays without a major fault do not fail this assertion. If `/proc` is unavailable, the test falls back to a P99 traversal ceiling of 100µs. The original 10µs per-thread objective remains in `ResidencyTraceRecipe` as a manual `go tool trace` check rather than the CI predicate.

```
=== RUN   TestResidencyPageFaultGate
--- PASS: TestResidencyPageFaultGate (0.11s)
=== RUN   TestResidencyAdviceConstantsExist
--- PASS: TestResidencyAdviceConstantsExist (0.00s)
PASS
ok   github.com/hr18vk/sovereign/pkg/sync   0.116s
```

The negative control applies `EvictPages` to the live control pages, zeroes `seed`, and reproduces the `maphash: use of uninitialized Seed` panic on the next `Get`. That shows the test can detect the corruption. With the control region pinned, the measured traversal incurred no major faults; without the required capability or limit, the helper reports partial or denied pinning.

These helpers are not called automatically during node startup in this tree. The tests exercise `LockHotPages`, `EvictPages`, and `PrefaultPages`; production code calls `UnlockAllPages` from `HamtArena.Free`. Residency pinning is therefore an available embedding operation, not a default guarantee for every running node.

The lesson was to test the kernel event directly when a counter is available, while keeping a separate fallback for systems that cannot expose it.

### SIGSEGV Survival and the Supervisor-Worker Split

#### The threat

The arena uses `unsafe.Pointer` arithmetic on `mmap`'d memory, outside Go's bounds checks and write barrier. A bad offset can access an unmapped page and deliver `SIGSEGV`; `recover()` cannot restore the process. If the listener and engine share that process, client connections die with it.

The crash probe in `internal/chaos/probe.go` makes that failure reproducible:

```go
const unmappedFaultAddr uintptr = 0xDEADDEAD_DEADDEAD
```

`WorkerExecuteCrashProbe` corrupts an off-heap child pointer and dereferences it; the empty-engine path dereferences this synthetic address directly. On the supported arm64 test environment, setting the top bit moves the pointer outside user-space mappings. The child dies, its stdout pipe closes, and the supervisor observes EOF.

#### Process isolation

I isolated the unsafe arena in a worker process and reconstructed its logical state from the WAL after a crash. `internal/chaos/supervisor.go` implements the supervisor side of this test harness. The companion `chaos-worker` command is not shipped in this tree. `TestSIGSEGVSurvival` skips when `CHAOS_WORKER_BIN` is unset, but setting it does not make the end-to-end test runnable here: the test ignores the supplied path, attempts `go build ./cmd/chaos-worker/`, and fails because that directory is absent. This section describes the harness contract, not crash/recovery coverage that ran from this tree or a supervisor wired into the production daemon:

- **The listener stays outside the worker.** The test process owns a real TCP listener and connection. The worker owns only the engine, so its `SIGSEGV` cannot close the listener's socket.
- **Stdout EOF signals the crash.** The worker acknowledges successful operations on stdout. A fatal signal closes the pipe without an acknowledgment, and the supervisor's read returns `io.EOF`.
- **Recovery creates a new worker.** The supervisor discards the dead address space, starts a pristine worker, and replays the WAL rather than trying to salvage corrupted memory.
- **The test checks connection survival.** It pings the same TCP connection before and after recovery, with a timeout on the post-crash ping. The listener belongs to the test, not to `Supervisor` itself; the assertion covers socket survival across child recovery, not TLS termination or production listener integration.

A length-prefixed binary stream (`internal/chaos/protocol.go`, with a 9-byte header: `op(1)` + `payloadLen(4)` + `frameSeq(4)`) carries requests over stdin and acknowledgments over stdout. Closing the stdout pipe provides the supervisor's crash signal.

#### The WAL — durability before acknowledgment

`internal/chaos/wal.go` defines the on-disk magic:

```go
walMagic   uint32 = 0x57414C00 // "WAL\0"
```

`verifyHeader` and `OpenWAL` reject files without this magic instead of interpreting a foreign file as a WAL. In the harness, the worker calls `fsync` before acknowledging an operation, so an acknowledged mutation has a durable record. Current mutation records carry the full 120-byte `CRDTEntry`, including its causal dot. `WALRecChecksummed` wraps records with CRC32C, and versioned checkpoints carry a `CutSeq` horizon and state fingerprint. `HamtArena.Free()` calls `UnlockAllPages()` before unmapping the arena.

#### The boot bug the gate caught

The first recovery test caught a real dot-identity bug, but my first two fixes answered the wrong question. On 2026-08-31 I replaced that approach with exact-dot restoration; [ADR-0045](adr/0045_mesh_transport_invariants.md) records the decision.

Both early fixes kept replay through `InsertLocal` and changed only the initial counter. That relied on WAL append order matching counter-minting order. Concurrent writers can reserve counters and append in a different order, and a non-quiescent checkpoint can include dots after its watermark. In a later multi-node run, replay produced 10,800 live dots for 10,000 keys, diverging from the root held by the other 99 peers.

The current law is to restore the recorded `(DotNodeID, DotCounter)` through `Join`, never mint a replacement. The checkpoint's WAL sequence cut selects the post-checkpoint tail. The initial clock is seeded from the durable high-water mark so later writes cannot reuse counters, not by subtracting mutations from it.

The earlier gate also exposed a measurement gap: `MerkleRoot` folds causal dots, not the full entry bytes. An old 80-byte WAL record could lose other fields while roots still matched. Current records carry the full 120-byte entry, and checkpoints with a fingerprint let recovery compare the pre-tail image's complete state as well as its root.

The original worker initialized a recovered engine at `LamportHigh` and replayed mutations through `InsertLocal`. Because `InsertLocal` assigns a fresh `(DotNodeID, DotCounter)`, replay created a new causal history instead of restoring the old one. The test failed with `got 105, want 41` at replay index 33: the initial counter was 7, and the 34 replayed mutations should have ended at 41.

My first fix initialized the engine at `LamportHigh - len(Mutations)`. I later tried `firstMutation.Counter - 1` to handle counter gaps from `AdvanceLamportTo`. Those formulas could reproduce a sequential test's dots, but both still assumed that replay should mint again. The later concurrent-checkpoint failure showed why that assumption was invalid.

Current recovery in `pkg/durability/recovery.go` replays full entries through `Join` in bounded chunks. `Join` preserves each recorded dot and advances the Lamport clock without re-minting. A versioned checkpoint supplies the pre-walk `CutSeq`; records at or above that sequence form the tail. The legacy checkpoint path has a separate repair pass for durable dots missing from its image.

`TestWALRecoveryDeterminism` now checks that each WAL record preserves the live-minted dot before joining the records into a fresh engine. Its constructor counter is not an inverse function of the log. The test then compares the recovered root and checks that the Lamport clock reaches the replay high-water mark.

The lesson was broader than an off-by-one error: recovery must restore causal identity, not infer it from a scalar clock. A successful process restart alone says nothing about whether the recovered state is correct.

#### The survival and recovery gates

`TestSIGSEGVSurvival` is intended to cover a real child-process crash, WAL recovery with a matching pre-crash root, and a ping on the same TCP connection before and after recovery. It cannot run from this tree because its unconditional `chaos-worker` build fails even when `CHAOS_WORKER_BIN` is set, so those assertions are not current end-to-end results. Four WAL tests cover the other properties:

| Test | Property checked |
|:---|:---|
| `TestWALRecoveryDeterminism` | WAL records preserve the live-minted dots; `Join` restores them into a fresh engine with the same Merkle root and advances the clock to the replay high-water mark. |
| `TestWALTornTailTruncation` | A partial trailing record does not corrupt the valid prefix; replay returns the complete records. |
| `TestWALSequenceMonotonic` | Reopening a log preserves `nextSeq` (3→3→4), so later appends do not reuse pre-crash sequence numbers. |
| `TestWALForeignFileRejected` | `OpenWAL` and `ReplayWAL` reject a bad magic header. |

The chaos package needed only read-only accessors: `HamtArena.Base()`, `HamtArena.Size()`, `DeltaCRDTEngine.Arena()`, and `HAMT.RootPtr()`. These expose the fault target without opening the allocator's internals.

### Network Partition and Merkle Convergence

#### The correctness question

The partition test split 32 nodes into two groups that could not communicate, accepted writes on both sides, healed the partition, and checked whether all 32 nodes reached byte-equal Merkle roots. A counterexample would invalidate convergence for that history. A passing run is a randomized witness for the tested configuration, not a proof for every network and workload.

#### The in-memory fabric

`internal/chaos/mesh_test.go` configures the 32-node partition run as follows:

| Parameter | Value | Purpose |
|-----------|-------|---------|
| `Drop` | `0.05` (5%) | Ambient loss; later gossip rounds can retransmit. |
| `Duplicate` | `0.20` (20%) | Duplicate delivery; this run enables receiver-side deduplication. |
| `ReorderMaxJitter` | `8ms` | Reordered delivery. |
| Partition | A={0..15} ↔ B={16..31}, both directions blackholed | 512 cross-group edges severed. |

The edge count is `2*(numNodes/2)*(numNodes/2) = 2·16·16 = 512`. `VirtualNet` provides mailbox goroutines, delayed delivery, ambient drops, duplicates, and explicit partitions; `SetPartitions(nil)` heals them. Full mailboxes and queues drop messages, which later gossip can retry. The separate determinism run disables deduplication so that duplicate deltas reach `Join` itself.

I had also planned Kubernetes fault injection with Chaos Mesh, but this repository does not contain those manifests and I did not run that variant. The results here come from the in-process `VirtualNet` and partition harness, not from OS-level network fault injection.

#### The convergence run

While the partition was active, gossip continued and each side accepted events. The test did not require convergence between the separated groups; it observed different cross-group roots. After `SetPartitions(nil)` restored the 512 edges, gossip continued until all roots matched.

The recorded run converged after 18 post-heal rounds. That is an observation for this run, not a convergence bound.

```
=== RUN   TestMerkleConvergenceAfterPartition
    partition active across 512 edges; 64 events into each side
    intra-group deliveries observed: groupA=true groupB=true
    intra-group convergence A=false B=false; cross-group roots differ=true
    partition healed; running gossip rounds to convergence
    PASS — all 32 nodes converged to root d5af3535...3dfd50 after 18 post-heal rounds
--- PASS: TestMerkleConvergenceAfterPartition (3.05s)
```

Three consecutive `-count=3` runs passed in about 9.7s total.

#### The determinism contract

Two additional checks limit what a single successful run can mean.

**Independent-run determinism.** `MerkleRoot()` sorts and hashes `(DotNodeID, DotCounter)` pairs with SHA-256. It does not hash the Go map seed or insertion order. The test invokes `runOnce` with labels 1 and 2 and requires the same root, but the current `seed` parameter is used only in failure text; it does not configure a random generator. The test therefore checks two independent runs, not controlled seed independence. Because keys and values are not part of the root, it is also not a complete state-integrity check.

**Idempotent `Join` under `Dedup:false`.** A separate 8-node determinism run uses 10% duplicate delivery and disables receiver deduplication. Duplicate deltas therefore reach `Join`, and both independent runs must converge to the same root. This differs from the 32-node partition run, which uses 20% duplicates with deduplication enabled.

```
=== RUN   TestConvergenceDeterminismAcrossRuns
    PASS: two independent runs converged to the same deterministic root 50283482...f78003
--- PASS: TestConvergenceDeterminismAcrossRuns (0.35s)
```

The 32-node test demonstrated root convergence after the recorded symmetric 512-edge partition with 5% loss, 20% duplication, and 8ms reorder jitter. The separate 8-node test compared roots across two runs with 10% duplicate delivery configured and `Dedup:false`. Together the tests exercised causal merge behavior in memory; neither used the production TLS transport or established a fleet-scale convergence time.

#### Retaining the retired benchmark

`TestEliminationCrucibleScalingGate` remains skipped with a recorded reason. It measures the retired single-locus SEC stack: 1.1M ops/s at 32 cores and 1.6% parallel efficiency, failing identically on the unmodified baseline. That was not a regression introduced by the sharded allocator. I kept the test as a record of why the allocator changed rather than deleting the unfavorable result.

---

## What Changed at Fleet Scale

On 2026-11-06, multi-region fleet runs exposed two failures that smaller tests had not covered. [ADR-0074](adr/0074_var_freelist_aba_and_v2_digest_requests.md) records the resulting design changes and test evidence.

### The variable-size free-list failed differently

My earlier ABA result covered the fixed-size node list, whose reclamation was EBR-deferred. The variable-size lists also received direct non-EBR frees. Their untagged byte-offset heads allowed an A→B→A sequence to allocate the same block twice, while a non-atomic header write could make a list head look like a small size-class index. Under fleet preemption, that produced unaligned `SIGBUS` failures and overwritten entries.

The fix packs a 32-bit generation tag and a 32-bit word offset into each head and updates the packed next-offset and size-class header atomically. `TestVarFreelist_ABARaceDoesNotCorruptBlocks` covers the race with a negative control.

### Digest requests carried buckets the receiver discarded

A versioned digest request carried the requester's bucket table even though the responder read only the scheme-and-size header and discarded the bucket body. On cold inter-region sockets, those unused bytes delayed the exchange.

The request now carries only that header. The requester rebuilds its local IBLT when the response arrives. A responder root announcement and a two-strike gateway timeout policy changed at the same time, so I do not attribute the fleet's reduced request traffic or improved convergence to the request shrink alone.

The lesson from both fixes was that small-scale tests had not exercised the failing combination: direct variable-size frees under fleet preemption, and large requests on cold wide-area sockets. Scale changed which assumptions mattered.

---

## Epilogue: Lessons Learned

The core benchmark crossed 50M ops/s, but the gate run reached only 24.6% relative efficiency at 32 cores. Recovery required more than counter arithmetic, and the fleet runs exposed defects that smaller tests had not covered. These are the lessons I retained:

1. **Measure contention before redesigning for it.** The 6.78× two-counter result identified cache-line sharing as a substantial cost in that microbenchmark. It gave the allocator investigation a concrete mechanism to test.
2. **Moving contention is not removing it.** Distributing `stackTop` while refilling from one `pool.free` head reduced throughput from 19.4M to 4.0M ops/s as core count grew. The allocator and the stack both needed distributed heads.
3. **Tests catch implementation assumptions.** Linearizability, drain, sequential, and race tests found the sentinel collision, producer/consumer live-lock, and `freeNext` aliasing. My reading of the home-shard design had not found them.
4. **Report the target that failed as well as the one that passed.** The workload did not meet 85% relative efficiency. Reaching 50M ops/s was useful, but it did not establish near-linear scaling or prove that the original target was impossible.
5. **Observe the kernel event when possible.** A latency-only test could not distinguish scheduling noise from page faults. The `majflt` delta isolated the event, with a documented P99 fallback when `/proc` was unavailable.
6. **Report partial residency and its wiring.** `EPERM` and `ENOMEM` produce explicit status rather than a boot failure. The helpers make pinning available to an embedder; they do not pin every production node automatically.
7. **Process isolation needs a separate address space.** The harness keeps the listener outside the crashing worker, detects stdout EOF, and rebuilds from the WAL. Its intended connection-survival check does not establish production-daemon integration, and the end-to-end test cannot run from this tree because the worker command is absent and the test's build step fails.
8. **Recovery restores identity, not just liveness.** Replay applies each recorded dot through `Join`; it does not derive new dots from `LamportHigh` or the first mutation counter. `CutSeq` identifies the checkpoint tail, and fingerprint-enabled checkpoints cover entry bytes that the dot-only Merkle root cannot check.
9. **Name what a convergence check compares.** The in-memory tests checked causal-dot roots under their stated network settings. They did not exercise production TLS or compare every entry byte. Fleet runs added state-fingerprint equality under their own conditions.
10. **Preserve failed measurements.** The retired benchmark's 1.6% efficiency explains the allocator rewrite. Keeping it skipped with that reason retains evidence that a successful redesign should not erase.

11. **Reclamation guarantees are path-specific.** EBR protected the fixed-size list, but direct variable-size frees bypassed the assumption on which its ABA argument rested. Tagged heads and atomic packed headers addressed the actual path that failed at fleet scale.
12. **Send only what the receiver consumes.** The digest responder needed the scheme-and-size header, not the requester's bucket table. Removing the unused body reduced request traffic in the compared fleet runs.

The common lesson is scope. A test establishes a property for a particular path, machine, workload, and measurement layer. The most damaging mistakes came from extending a correct local result to a path it did not cover: counter-derived replay, EBR-protected variable frees, and digest exchanges on cold wide-area sockets.
