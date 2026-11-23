# ADR-0012: Measure batched ingest on Graviton4

- **Status:** Accepted
- **Date:** 2026-07-29; corrected 2026-07-30
- **Predecessors:** [ADR-0010](0010_batched_delta_wire_v1.md), [ADR-0011](0011_sdk_control_port.md)

---

## Context

ADR-0010 amortizes one Ed25519 verification over a batch of deltas. Its
four-core measurements showed per-delta latency falling by 26× at N=100, but
the one-million-deltas-per-second target remained an extrapolation. An earlier
32-core estimate of roughly 533K/sec for unbatched frames likewise came from
an approximately 60us verification cost, not an aggregate-throughput
measurement.

`BenchmarkVerifyCRDTFrame_32c` and `BenchmarkBatchedVerify` each run a single
timed loop. Their `ns/op` results describe one goroutine even when `-cpu`
allows more operating-system threads; multiplying that latency by the core
count does not measure aggregate throughput. The new measurement therefore had
to exercise concurrent receivers and report the total work completed per unit
of wall-clock time.

---

## Decision

Add `BenchmarkBatchedVerifyParallel` in `pkg/receive/bench_silicon_test.go`.
It uses `b.RunParallel` to drive `(*Receiver).HandleBatchFrame`, including
identity lookup, Ed25519 verification, envelope decoding, and
`ApplyCRDTDeltaBatch`. The existing `buildBenchBatchWire` helper constructs N
events with distinct entity IDs and monotonic dot counters. Signing and
envelope marshaling happen before the timed loop.

Each N in {1, 10, 100, 256} has two configurations:

- **shared:** all goroutines use one receiver, engine, identity directory, and
  origin. They contend on the same `PeerBucket` shard in the admission path,
  as frames from one origin do on a node.
- **ceiling:** each goroutine has its own receiver, engine, and directory.
  This removes rate-bucket contention and isolates verification and apply
  scaling. It is an upper-bound configuration, not a single-origin node's
  receive rate.

The reported rate is `1e9 / nsPerDelta`, where `nsPerDelta = ns/op / N`.
Under `b.RunParallel`, `b.N` counts iterations across all goroutines and
`b.Elapsed()` is wall-clock time. Thus `ns/op` already represents elapsed time
divided by total completed batches; multiplying by `GOMAXPROCS` would count
the cores twice. The initial report made that error and inflated its aggregate
column by 64× on the 64-core host. `reportAggregate` now uses the formula
above, and the first run's rates below were recomputed from its unaffected
`ns/delta` column.

The apply path reaches `ReconstructEntryWithSkewBound` and the sharded
compare-and-swap loop in `(*DeltaCRDTEngine).Join`; it does not construct the
merged view guarded by `stateViewMu`. The admission bucket's shard mutex is a
deliberate point of contention in the shared configuration.

Each receiver gets its persistence directory through
`(*DeltaCRDTEngine).SetDataDir` during setup. The temporary directory is chosen
before `b.RunParallel` starts, avoiding concurrent writes to the package-level
`DataDir` default. The timed loop performs no persistence and does not call
`RecordIngest`; those costs are outside this benchmark.

Run the sequential reference benchmarks and the new parallel benchmark with
`-cpu=<nproc> -benchtime=3s -count=3`. Record the instance type, CPU part,
architecture, Go version, `GOMAXPROCS`, and kernel beside the results. The
historical runs used a 64-core c8g.16xlarge with Graviton4 CPU part `0xd4f`.
The four-core development run is only a construction check and is not included
in the throughput claim.

## Consequences

The target is met on this host for the shared configuration at N=256: all six
counts in the first run exceed one million deltas/sec. At N=100 the shared
counts range from 862,812 to 1,883,239 deltas/sec; four of six exceed the
target. The result is therefore specific to batch size and run, rather than a
guarantee that every shared-path run at N=100 exceeds one million deltas/sec.
The ceiling configuration measures scaling without bucket contention and must
not be substituted for the shared result.

These are in-process verification-and-apply measurements. The benchmark reuses
frames after their initial insertion, so steady-state operations do not add new
state. The measurements also omit network I/O, TLS, persistence, and ingest
telemetry. The rates are not end-to-end durable-ingest measurements and apply
only to the measured 64-core host; no 96-core result is claimed.

---

## Evidence

### Host and benchmark configuration

The first run recorded the following host details through instance metadata
and `/proc/cpuinfo`:

```
 instance-type : c8g.16xlarge
 nproc         : 64
 arch          : aarch64
 CPU part      : 0xd4f (Graviton4 / Neoverse V2)
 go version    : go1.26.1 linux/arm64
 GOMAXPROCS    : 64
 kernel        : 6.1.176-221.367.amzn2023.aarch64
```

### Sequential per-verification latency, `-cpu=64`

```
BenchmarkVerifyCRDTFrame_32c-64    59605   59814 ns/op   3.61 MB/s   2672 B/op   12 allocs/op
BenchmarkVerifyCRDTFrame_32c-64    60230   60006 ns/op   3.60 MB/s   4720 B/op   13 allocs/op
BenchmarkVerifyCRDTFrame_32c-64    59239   60499 ns/op   3.57 MB/s   2672 B/op   12 allocs/op
```

The three verification counts are 59,814 / 60,006 / 60,499 ns/op, close to
the earlier 60.19us reference. This remains a sequential latency measurement.

### Sequential batched latency, `-cpu=64`

```
BenchmarkBatchedVerify/N=1-64     56312   67058 ns/op   67057 ns/delta
BenchmarkBatchedVerify/N=10-64   34692  108549 ns/op   10854 ns/delta
BenchmarkBatchedVerify/N=100-64  10000  308140 ns/op    3081 ns/delta
BenchmarkBatchedVerify/N=256-64   5521  626165 ns/op    2445 ns/delta
```

Per-delta latency falls from 67us at N=1 to 10.8us at N=10, 3.08us at N=100,
and 2.44us at N=256. This reproduces the amortization pattern from ADR-0010
on the Graviton4 host.

### Parallel aggregate throughput, `-cpu=64`

The first run executed the `-count=3` parallel block twice, giving six counts
per configuration. The aggregate column uses `1e9 / ns/delta`, correcting the
erroneous 64× multiplier described above. The retained `ns/op` and `ns/delta`
values are copied from the raw output. One inherited `ns/op` transcription is
omitted below because it conflicts with that output. The cold and warm labels
distinguish the first count of each invocation from the remaining two.

**N=100 (the batched claim — one Ed25519 verify amortized over 100 deltas):**

| sub-bench | count | ns/op | ns/delta | aggregate_deltas/sec |
|---|---|---|---|---|
| shared/N=100-64 | 1 (cold) | 53,120 | 531 | 1,883,239 |
| shared/N=100-64 | 2 (warm) | 115,920 | 1,159 | 862,812 |
| shared/N=100-64 | 3 (warm) | 81,845 | 818 | 1,222,493 |
| shared/N=100-64 | 4 (cold) | 53,954 | 539 | 1,855,287 |
| shared/N=100-64 | 5 (warm) | — | 1,137 | 879,507 |
| shared/N=100-64 | 6 (warm) | 76,664 | 766 | 1,305,483 |
| ceiling/N=100-64 | 1 (cold) | 17,283 | 172 | 5,813,953 |
| ceiling/N=100-64 | 2 (warm) | 12,747 | 127 | 7,874,015 |
| ceiling/N=100-64 | 3 (warm) | 12,994 | 129 | 7,751,937 |
| ceiling/N=100-64 | 4 (cold) | 17,016 | 170 | 5,882,352 |
| ceiling/N=100-64 | 5 (warm) | 13,204 | 132 | 7,575,757 |
| ceiling/N=100-64 | 6 (warm) | 12,951 | 129 | 7,751,937 |

**N=256 (the batched claim at higher amortization — one verify over 256 deltas):**

| sub-bench | count | ns/op | ns/delta | aggregate_deltas/sec |
|---|---|---|---|---|
| shared/N=256-64 | 1 (cold) | 84,250 | 329 | 3,039,513 |
| shared/N=256-64 | 2 (warm) | 183,634 | 717 | 1,394,700 |
| shared/N=256-64 | 3 (warm) | 117,289 | 458 | 2,183,406 |
| shared/N=256-64 | 4 (cold) | 83,342 | 325 | 3,076,923 |
| shared/N=256-64 | 5 (warm) | 184,111 | 719 | 1,390,820 |
| shared/N=256-64 | 6 (warm) | 120,590 | 471 | 2,123,142 |
| ceiling/N=256-64 | 1 (cold) | 36,119 | 141 | 7,092,198 |
| ceiling/N=256-64 | 2 (warm) | 30,420 | 118 | 8,474,576 |
| ceiling/N=256-64 | 3 (warm) | 29,778 | 116 | 8,620,689 |
| ceiling/N=256-64 | 4 (cold) | 36,465 | 142 | 7,042,253 |
| ceiling/N=256-64 | 5 (warm) | 30,502 | 119 | 8,403,361 |
| ceiling/N=256-64 | 6 (warm) | 30,244 | 118 | 8,474,576 |

**N=10 (lower amortization — one verify over 10 deltas):**

| sub-bench | count | ns/op | ns/delta | aggregate_deltas/sec |
|---|---|---|---|---|
| shared/N=10-64 | 1 (cold) | 13,799 | 1,379 | 725,163 |
| shared/N=10-64 | 2 (warm) | 14,762 | 1,476 | 677,506 |
| shared/N=10-64 | 3 (warm) | 13,188 | 1,318 | 758,725 |
| shared/N=10-64 | 4 (cold) | 13,302 | 1,330 | 751,879 |
| shared/N=10-64 | 5 (warm) | 14,750 | 1,474 | 678,426 |
| shared/N=10-64 | 6 (warm) | 14,686 | 1,468 | 681,198 |
| ceiling/N=10-64 | 1 (cold) | 2,399 | 239 | 4,184,100 |
| ceiling/N=10-64 | 2 (warm) | 2,410 | 240 | 4,166,666 |
| ceiling/N=10-64 | 3 (warm) | 2,208 | 220 | 4,545,454 |
| ceiling/N=10-64 | 4 (cold) | 2,416 | 241 | 4,149,377 |
| ceiling/N=10-64 | 5 (warm) | 2,203 | 220 | 4,545,454 |
| ceiling/N=10-64 | 6 (warm) | 2,194 | 219 | 4,566,210 |

**N=1, without batching:**

The first-run shared results span 110K–368K deltas/sec and the ceiling results
span 672K–846K. Neither configuration reaches one million deltas/sec at N=1.

### Second 64-core run

A second c8g.16xlarge run on 2026-07-30 used the corrected `reportAggregate`
directly rather than recomputing the aggregate column. Its ranges were:

| configuration | aggregate_deltas/sec | counts above 1,000,000 |
|---|---|---|
| shared/N=256 | 1.38M–3.06M | 6/6 |
| shared/N=100 | 848K–1.89M | 4/6 |
| ceiling/N=100 | 5.71M–7.69M | 6/6 |

The second run agrees with the recomputed first-run ranges. In both runs the
N=100 shared results straddle the target and every N=256 shared count exceeds
it.

A later 32-core run on a c8g.8xlarge recorded 5.7M–6.0M deltas/sec for the
shared configuration at N=100–256 and 12.5M–14.7M for the ceiling
configuration. Those measurements have their own date and hardware conditions
in [the ingest receipt](../../evidence/ingest-ed25519.txt); they are not part
of the 64-core tables above.

### Reproduction

```bash
go test -run='^$' -cpu=<nproc> -bench=BenchmarkBatchedVerifyParallel \
  -benchtime=3s -count=3 ./pkg/receive/
```

A short construction check can use `-benchtime=200ms -count=1` without the
`-cpu` override. Its output describes the local machine, not the Graviton4
results in this record.

### Measurement limits

Before timing, `makeSignedFrame` applies the batch to a warm-up receiver. The
shared configuration reuses that receiver. In the ceiling configuration, each
fresh receiver inserts the frame on its first operation. Subsequent operations
rejoin the same dots, so CRDT deduplication leaves state unchanged while the
Ed25519 verification still runs in full. Reusing the frame bounds arena growth;
it also means these tables do not measure steady-state insertion of fresh state.

The shared configuration retains admission-bucket contention. The ceiling
configuration removes it by constructing independent receivers, so the two
results answer different questions. At N=1, neither configuration reaches one
million deltas/sec; the target depends on batching.

The corrected figures also retract the earlier claim of a large per-core
speedup under parallel load. The shared configuration's per-core rate is below
the sequential reference, consistent with contention and garbage collection
costs; the benchmark does not isolate those causes. Cold and warm counts
differ, and the shared configuration varies more. The tables retain every
count rather than selecting a warm result.

`-cpu=64` sets `GOMAXPROCS` for the benchmark; it does not describe a
production deployment setting. The 3-second counts did not record processor
temperature, so these results do not establish sustained thermal behavior.
