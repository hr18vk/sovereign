# ADR-0061: Parallelize the race-test suite and gate ingest throughput

- **Status:** Accepted
- **Date:** 2026-09-27

## Context

The independent `-race` package tests ran serially. Their durations summed to
about 8,256s even though the 64-core c8g.16xlarge test machine could run two
32-core lanes. Separately, the 5.7M-6.0M deltas/sec receive-path result at 32
cores had been measured on 2026-09-15 and then reused without a recurring
check. The test suite needed shorter wall-clock runs and a way to detect an
ingest regression rather than continuing to cite a stale result.

## Decision

1. Pack the race-enabled packages into two lanes from their measured
   durations. Keep the `pkg/sync` tests sequential within their lane because
   they share temporary paths. Give every package an explicit timeout and
   `GOMAXPROCS=32`, so parallel execution does not change the concurrency
   environment used by the serial 32-core runs.
2. Move result classification into the parent shell after `wait`. Background
   subshells cannot update the parent's pass and fail counters; leaving the
   tally in those subshells could omit a failed lane and print a passing
   summary. Preserve the serial report order.
3. Run `BenchmarkBatchedVerifyParallel` separately, without `-race`, after the
   solo core benchmark. Use five fresh processes and discard each process's
   first result as warmup. Gate the stable shared rows on measured latency
   floors, report ceiling rows without gating them, and reject any result
   whose `GOMAXPROCS` token is not 32.00.
4. Keep the core and receive-path measurements at 32 lanes even when the test
   machine has 64 cores. The core benchmark retains its 50,736,038 ops/s
   floor. A floor is derived from pooled measurements and changed only after a
   demonstrated environment shift, not retuned to fit an individual run.

## Consequences

- The package-test block approaches the longest lane's duration: about 4,180s
  instead of 8,256s serially, a 1.98× reduction. The full suite gains less,
  approximately 1.6-2.0×, because the measurement jobs still run alone and
  non-test checks do not parallelize.
- Core and ingest throughput are measured again on each suite run. A floor
  trip first requires an isolated rerun and an explanation of the changed
  conditions. A demonstrated environment shift requires a new floor derived
  from pooled data, not a per-run adjustment.

## Evidence

- Lane A measured 4,179.9s and lane B 4,076.1s. Lane A contained the
  sequential `pkg/sync` pair, chaos, receive, filtered mesh, attribution,
  admission, and index tests; lane B contained the full mesh, durability, and
  database tests.
- A shimmed `--- FAIL:` result in a background lane reached the parent tally,
  demonstrating that a parallel failure could not be dropped from the summary.
- The receive-path command was
  `go test -run='^$' -cpu=32 -bench=BenchmarkBatchedVerifyParallel -benchtime=3s -count=3 ./pkg/receive/`.
  Five fresh processes each contributed three iterations, with iteration one
  discarded as warmup.
- The initial floors were shared/N=100 at 5,000,000 deltas/sec with a 200 ns
  ceiling, and shared/N=256 at 5,524,861 deltas/sec with a 181 ns ceiling.
  Each floor was `ceil(worst_observed_stable_ns × 1.05)`: the factor covered
  the paired relative standard deviations of 4.0%/3.0%, plus one
  integer-nanosecond quantization step.

