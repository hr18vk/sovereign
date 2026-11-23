# 5. Benchmarks and Limits

## 5.1 Core Stack Throughput

[`TestScalingGate`](../../pkg/sync/stack_scaling_gate_test.go) is an opt-in,
in-process benchmark of [`ShardedStack`](../../pkg/sync/sharded.go). With
`RUN_CRUCIBLE=1`, it drives asymmetric producer, consumer and mixed bursts
through `Push` and `Pop` at `GOMAXPROCS` tiers $\{4, 8, 16, 32\}$. Tiers above
the host's `NumCPU` are omitted, and the test is skipped in short mode.

At every tier, the test walks the surviving stack and checks that its node
count equals pushes minus successful pops. The walk also rejects cycles,
duplicate nodes and out-of-pool indices. This is a conservation check, not a
complete linearizability proof. The reported ops/s counts every push and pop
attempt, including empty pops. The highest eligible tier must reach at least
50,000,000 ops/s; the test does not require a minimum parallel efficiency.

The benchmark does not call `HAMT.Set`. It omits Ed25519 verification,
envelope decoding, network I/O, TLS and WAL persistence.

The published per-tier receipt is
[`core-crucible.txt`](../evidence/core-crucible.txt), recorded on 2026-09-03
on an AWS c8g.8xlarge (Graviton4, arm64) with Go 1.26.1:

```bash
RUN_CRUCIBLE=1 go test -v -run TestScalingGate -cpu=32 -count=1 ./pkg/sync/
```

| `GOMAXPROCS` | Throughput (ops/s) | Speedup vs 4c | Parallel efficiency | Conservation |
|---:|---:|---:|---:|:---|
| 4 | 45,722,911 | 1.00× | 100.0% | OK |
| 8 | 59,481,186 | 1.30× | 65.0% | OK |
| 16 | 85,096,809 | 1.86× | 46.5% | OK |
| 32 | 68,278,197 | 1.49× | 18.7% | OK |

All four tiers passed the conservation check in this run. The 32-core tier
reached 68,278,197 ops/s with 18.7% parallel efficiency, while the 16-core
tier reached the higher aggregate rate. These are measurements of this
benchmark on the named host, not a throughput guarantee for other machines.

### 5.1.1 Per-Core Decomposition

The table reports aggregate attempts across all goroutines. Dividing that rate
by the core count gives an average per-core operation interval, not a request
latency:

- At 4 cores, 45,722,911 ops/s is 11.43M ops/s per core, or approximately
  87 ns per operation.
- At 16 cores, 85,096,809 ops/s is 5.32M ops/s per core.
- At 32 cores, 68,278,197 ops/s is 2.13M ops/s per core, or approximately
  469 ns per operation.

The falling per-core rate and the 16-core-over-32-core inversion show that
adding cores does not provide linear scaling for this workload.

### 5.1.2 In-Process Receive Path

[`BenchmarkBatchedVerifyParallel`](../../pkg/receive/bench_silicon_test.go)
measures a different layer. Its timed loop calls `Receiver.HandleBatchFrame`,
which performs origin lookup, Ed25519 verification, batch-envelope decoding
and CRDT application. It does not include network I/O, TLS, WAL persistence
or ingest metrics.

The benchmark constructs and signs each frame before timing and warms the
engine with one application. Timed iterations then reapply the same deltas,
so the CRDT joins are idempotent. The result is an in-process receive-path
measurement, not networked or durable production ingest throughput.

The [receive-path receipt](../evidence/ingest-ed25519.txt), recorded on
2026-09-15 on the same instance type, reports the shared single-origin path at
5,681,818 deltas/sec with N=100 and 6,024,096 deltas/sec with N=256. Each
figure appears in two measured samples. These rates count deltas, while the
core benchmark counts stack operation attempts; neither rate can be substituted
for the other.

## 5.2 Scaling Limits

### 5.2.1 Cache-Coherence Traffic

`ShardedStack` has 64 stack shards with a 128-byte stride. A push normally uses
the caller's P-local shard. A pop starts there but can probe other shards when
the local stack is empty. Per-goroutine caches hold recycled node indices;
cache refills and overflow drains use the caller's local pool shard, probing
others when necessary.

This layout disperses contention, but cross-shard probes and pool spills still
transfer cache-line ownership between cores. On Graviton4 those transfers use
the CMN-700 interconnect. The recorded 16-core-over-32-core inversion is
consistent with coherence traffic growing faster than useful work. The receipt
contains no hardware-counter breakdown, so it does not quantify the separate
contributions of the interconnect and memory system.

### 5.2.2 Arena and Residency Boundaries

`TestScalingGate` measures `ShardedStack` over an `ElimNodePool`; it does not
allocate HAMT nodes in the mmap-backed `HamtArena`. The 128-byte value above is
the stack-shard stride, not an arena allocation size.

For HAMT storage, cache misses and page faults can add DRAM traffic and stalls,
but the core table does not measure either effect. `HamtArena` provides
`LockHotPages`, `PrefaultPages` and `PrefaultHot` helpers in
[`residency.go`](../../pkg/sync/residency.go). The first two are exercised by
residency tests; none of the three is called by production node startup. The
published throughput therefore does not depend on a production `mlock` or
prefault phase, and it does not establish a major-page-fault bound for a
running node.

### 5.2.3 Historical Single-Locus Baseline

[`TestEliminationCrucibleScalingGate`](../../pkg/sync/elimination_test.go) is
the retired single-locus scaling test. It remains in the tree but is skipped
because `TestScalingGate` covers the current sharded implementation. The
[engineering post-mortem](6_ENGINEERING_POST_MORTEM.md) records its historical
result as 1.1M ops/s at 32 cores with 1.6% parallel efficiency.

That baseline explains why the allocator was sharded; it is not a current
performance result. Dispersing stack and free-list contention across 64 loci
removes the single shared head, but it does not eliminate cross-shard
coherence traffic or memory-bandwidth limits.

## 5.3 Latency Scope

The design includes several latency-related mechanisms, but the throughput
tables do not measure end-to-end or tail latency:

- The sharded stack has zero-allocation tests for its push/pop hot path. That
  result does not extend to the receive benchmark, whose receipt reports heap
  allocations.
- The stack uses atomic compare-and-swap operations rather than a mutex. Other
  parts of the receive path do take locks, so the stack's design is not a
  lock-free claim for the whole engine.
- Batch envelopes use Cap'n Proto struct-level access rather than reflection.
  Envelope decoding is included in the receive benchmark; network transport is
  not.
- Delta-CRDT joins do not require a synchronous quorum. Convergence, read
  freshness and WAL durability are separate properties with their own tests.

A sub-millisecond tail remains a design target, not a result established by
these benchmarks. The per-core intervals in §5.1.1 are arithmetic averages and
must not be quoted as request-latency measurements.

## 5.4 Reproduction and Interpretation

Run the receive-path benchmark with the command recorded in its receipt:

```bash
go test -run '^$' -bench=BenchmarkBatchedVerifyParallel -benchmem \
  -count=3 -cpu=32 ./pkg/receive/
```

Use the instance type and toolchain named in each receipt when comparing
absolute rates. A host with fewer than 32 cores does not reproduce the full
core table: `TestScalingGate` omits unsupported tiers and applies its absolute
throughput threshold to the highest eligible tier. Host load and a different
processor or memory system can change both results.

The core command and the receive command measure different operations. Neither
one measures a client-observed, networked, durable write rate.

## 5.5 Fault-Injection Scope

The partition tests use [`VirtualNet`](../../internal/chaos/virtualnet.go) and
its [orchestrator](../../internal/chaos/partition.go) to drop, duplicate, delay
and reorder messages in memory, then compare Merkle roots after healing. They
do not inject operating-system network or filesystem faults. No external
Kubernetes fault-injection result is claimed here.
