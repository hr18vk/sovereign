# ADR-0060: Size the scaling-gate pool for parked surplus

- **Status:** Accepted
- **Date:** 2026-09-26

## Context

`TestScalingGate` measures the in-process CRDT core. One run reached a
600.008 s `go test` timeout with the workload stalled in
`(*secDeepCache).deepAlloc` and `allocIndexSharded`; three of five later
fresh attempts at 32 cores stalled with the same stack signature. A gate
that hung in roughly 40-60% of fresh runs could not support the throughput
claim, and promotion of the SEC stack to a request path remained blocked
pending a root cause.

The investigation separated ABA corruption, lost indices, and whole-pool
exhaustion. It changed only the test workload's pool sizing and added an
allocator liveness and conservation harness; production allocator behavior
was left unchanged.

## Decision

1. Reproduce the gate workload in `allocator_tripwire_test.go`: a 25/25/50
   producer/consumer/mixed split, capped-geometric bursts up to `BurstMax`,
   jitter, and independent value streams. Register every goroutine's cache
   before it starts and snapshot it at exit so the census includes cached
   indices. Use a fresh pool and stack for every attempt.
2. Poll `runtime.Stack` every 250ms and report a stall only after the same
   `allocIndexSharded` signature remains for 10s, approximately 40 consecutive
   observations. A healthy claim takes nanoseconds and a 64-index refill takes
   microseconds, so the empty-pool `Gosched` loop is distinguishable from
   normal allocation.
3. Walk the 64 sharded free lists, 64 stack chains, and registered caches into
   one visited bitmap of `poolCap/8` bytes. Cap each walk above `poolCap` to
   detect cycles, and classify mutation during a snapshot as unstable rather
   than walking it again. Recover mid-refill claims from the cache arrays.
   Allow one in-flight index per live goroutine during a run and zero after
   it. Report corrupt links, duplicates, cycles, instability, stranded
   indices, or an exact reconciliation.
4. Prove the census with fault-injection controls through the real allocator
   entry points: a double free, three leaked claims, and constructed pool
   exhaustion must produce their respective failures.
   `TestAllocatorConservation_Always` also requires an exact post-run census;
   its measured run took 0.16s. An early harness that reused a stack across
   attempts demonstrated why fresh stacks matter: the census caught a
   duplicate four steps into a shard walk, with `count=−17,472`.
5. Size the gate pool with
   `gatePoolCap(goroutines) = goroutines*BurstMax*2 + elimTestPoolSize*16 + 1`.
   At the 1s tier this provides 1,048,576 spare indices, approximately 10σ;
   at 32 goroutines the total is 1,081,345 indices, approximately 26 MiB of
   `ElimNode` storage. Both the gate and tripwire call this helper. Allocation
   still costs one CAS per claimed index. Because σ grows with the square
   root of duration, a longer tier requires re-deriving the spare.

## Consequences

The captured stall was whole-pool exhaustion, not allocator corruption. The
census reconciled every index, and all stalled goroutines were trying to
push. At exhaustion, producer bursts park values that only a pop can release,
while mixed goroutines stall before their pop halves. The allocator's
never-return-zero spin cannot terminate when no recycler remains.

Increasing only the benchmark pool therefore addresses the measured demand
envelope without weakening conservation checks or changing production code.
The separate ABA generation-tag hazard remains open and still requires its
own regression test before SEC promotion. The liveness watchdog, census, and
fault-injection controls remain in the test suite.

## Evidence

On attempt 4 of 20 at 32 cores, with three clean attempts before it and the
unmodified allocator using `SOVEREIGN_TEST_POOL_ATTEMPT_MS=1000`, the watchdog
fired at 10.000000013s. The census found:

| Store | Unique indices |
|---|---:|
| Free lists, all 64 shards | 0 |
| Stack shards, parked surplus | 97,216 |
| Mid-refill spinner claims | 1,088 |
| All 32 live caches, each empty | 0 |
| Total | 98,304 = `poolCap−1` = `pool.count` |

`availableLie` was +0 and `shortfall` was −32, exactly the in-flight
allowance for the 32 goroutines waiting before their claims. There were no
duplicates, cycles, corrupt links, or stranded indices. The three earlier
attempts also reconciled exactly over approximately 223M operations. All 32
stalled goroutines were in push loops: 14 producers and 18 mixed-operation
pushers, with none in a pop loop.

The workload's parked surplus behaves as a zero-drift random walk reflected
at zero. Bursts have mean size approximately 64 and a capped tail of 512;
about 1.2M bursts at the 1s tier give
`σ ≈ sqrt(1.2M) × 128 ≈ 99K` indices. The old supply of 98,304 indices, with
65,536 spare beyond twice the working set, was only about 1σ above the
working demand. The measured pre-fix stall counts were 2 of 2, 3 of 5, and 1
of 4 across the recorded fresh-run groups. The enlarged pool had 0 stalls in
20 runs at 32 cores and 6 clean runs at 4 cores. An initial undersized-pool
control stalled in 1 of 4 runs; a later control reproduced the stall on
attempt 4 of 10.

The liveness hunt is disabled unless `SOVEREIGN_TEST_POOL_TRIPWIRE=1` is set.
`SOVEREIGN_TEST_FAULT_POOL=DUP`, `LEAK`, and `WEDGE` select the double-free,
leak, and exhaustion controls through the real allocator entry points.
`SOVEREIGN_TEST_FAULT_UNDERSIZED_POOL=1` restores the smaller pool for the
load-bearing sizing control. These fault-injection cases are expected to fail
and are not part of a normal passing run. `TestAllocatorConservation_Always`
runs unconditionally and requires zero post-run discrepancy.

Three fresh `-count=1` core runs at 32 cores on c8g.8xlarge with Go 1.26.1
were linearizable at every tier and measured 81,071,364 / 76,506,555 /
75,444,142 ops/s. Each exceeded the 50,736,038 ops/s floor; the earlier
passing runs measured 69,267,509 and 57,882,136 ops/s. These are
core-microbenchmark results, with no network, TLS, or persistence. They are
not receive-path ingest measurements.

