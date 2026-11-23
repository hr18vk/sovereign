# ADR-0065: Reconciliation scale-test design

**Status:** Accepted  
**Date:** 2026-10-04

## Context

Before measuring reconciliation across multiple machines, four assumptions
needed in-process tests: partial-view rotation had to cover large registries without
censoring peers; IBLT placement and sizing had to be measured at their peel
thresholds; the test harness had to fit in memory and file descriptors; and
the digest wait had to cover wide-area response times without hiding slow
exchanges.

These tests used the real selector, peel, mesh, and network-emulation paths.
Their results are simulation and loopback measurements, not a substitute for
a multi-machine run. The original record also mixed early interpretations
with later corrections; this version states the corrected results directly.

## Decision

### Selector coverage and in-degree

Drive `(*TopologyManager).Select` rather than a reimplementation. Measure
coverage until every peer has been selected, and use enough rounds to avoid
censoring the coupon-collector tail. Model multi-hop spread synchronously:
nodes infected during a round cannot infect another node until the next
round. A one-hop starvation control must not be described as a partition on
a three-region mesh, because inter-region picks can still reach the victim.

Judge in-degree by its distribution and a family-wise uniformity check, not
by requiring every static-round maximum to stay below the concurrent
responder bound. Those quantities describe different conditions.

### IBLT peel envelope

Run Monte Carlo trials through the real peel over bucket counts B from
1,024 through 21,845 and k values 3, 4, 5, and 7. Measure the 1% crossings
at load margins β=1.05 and 1.15, and compare legacy double hashing with v2
placement at D=400 with B=1,024 buckets and k=4. Use higher seed counts to resolve
residual failure probabilities rather than treating a small clean sample as
proof of a lower bound.

### Harness density and network waits

Scale the in-process census in separate measured arms, retaining the actual
connection and memory counts. Do not divide cumulative anonymous RSS by the
last arm's node count when earlier engines and arenas remain live. Exercise
the digest timeout across emulated RTTs with `tc-netem`, including a timeout
below the network delay as a negative control.

For wide-area test configurations, use `--digest-wait-timeout=1500ms` when
the measured RTT requires it. This does not change the command's 500 ms
default, and each configuration must be justified by its own RTT and defer
measurements.

## Consequences

The selector and peel tests supplied the design constraints for IBLT v2 and
partial-view operation; they did not make either option default. Sweep phase
jitter was subsequently implemented in [ADR-0066](0066_sweep_phase_jitter.md),
and hierarchical gateways in
[ADR-0073](0073_hierarchical_gateway_topology_and_boot_dial.md). The proposed
reverse-batch byte counter is now exposed as
`CounterSnapshot.RelayBatchReverseBytes`; compact v2 requests are recorded in
[ADR-0074](0074_var_freelist_aba_and_v2_digest_requests.md).

The k=5 and k=7 samples establish an upper bound of 3e-5 at their tested
margins, not the desired 1e-5 failure probability. Rateless reconciliation
beyond D=16.8K remains unbuilt. `--defer-handler` remains false by default.

## Evidence

### Selector results

At N=3,333 with R=20,000 rounds, the direct-pick tail completed with mean
coverage 9,595 against an analytic mean of about 9,203 and zero censored
peers in sixty-five trials. The worst chi-square and Bonferroni ratios were
0.983 and 0.936. The corrected 10K layout is 3,333/3,333/3,334. R=10,000
censored all sixty-five coverage trials; R=60,000 completed with mean 30,903
against the analytic 31,275 (−1.2%), maximum 39,151, and zero censored
trials in sixty-five.

The 64-core selector runs took 7,052 s and 8,119 s. Their tightest uniformity
and colocation ratios were 0.969 and 0.951. At 10K nodes, the measured
full-mesh selection cost was 208.4× the 16-slot responder bound.

After the synchronous frontier correction, rumor coverage took 4 rounds at
N=1,000 against a bound of 29. At N=3,333 it took 5 rounds against a bound of
35. These results are consistent with branching 8^k. The first distributional
check accepted a worst maximum of 20 under kCap=27; the later 10K grid
accepted maxima of 22–24 under the same cap. The inter-region maximum was 11
under kCap=15. A frozen zero-seed control produced p99=377. The measured 10K
p99 was 16 under the tail convention, at but not above the responder cap; the
inf-CDF convention gives 15 for Poisson(8).

For isolation analysis, the multi-hop rumor instrument derives a reachability
bound of about 2–3 rounds. Direct inter-region selection derives about 1 round
from 6,667 foreign picks across 3,333 candidates, approximately 2 picks per
victim per round. These are derivations for different instruments, not a
measured one-round partition-healing claim.

### Peel results

The measured 2-core coefficients c3/c4/c5/c7 were
1.222/1.295/1.425/1.721. The D=400 case with B=1,024 buckets and k=4 produced a legacy failure
probability of 0.2642 against a model of 0.262; v2 failed with probability
0.00025, approximately a 10^3 difference in failure rate.

The 10^4-seed run took 73.4 s on the 64-core machine and recorded 11 nonzero
margin rungs. Their counts by bucket rung were:

| k | Counts |
|---|---|
| 3 | 19; 11; 6; 1; 1; 1 |
| 4 | 7; 8; 7; 1; 0; 1 |

Thus the earlier interpretation that every margin was zero was incorrect.
The 10^5-seed run took 712 s. At β=2.0, every k=3 and k=4 rung exceeded 1e-5.
Across the B ladder, the subtract-shape run's counts fell from 143 to 9 for
k=3 and from 111 to 5 for k=4; every k=5 and k=7 rung had zero failures in
10^5 seeds.

At k=4, the residual floor decreased approximately as 1/B: about 1.11e-3 at
B=1,024; 5e-5 at B=16,384; and 8e-5 at B=21,845 (8 failures in the
10^5-seed run). Sizing within that ladder therefore did not reach 1e-5. Zero
failures in 10^5 seeds gives a binomial 3/N bound of 3e-5; resolving 1e-5 at
the same confidence requires about 3×10^5 seeds.

`seedWord` is a pure function of `(trial,B,k,d)`. The insert-only and
subtract-shape runs therefore execute the same deterministic cases and yield
the same rung counts. Their agreement checks reproducibility and the
`Subtract` path, not an independent physical experiment. The false-pure class
retains its approximately 2^-64 bound and was not newly exercised.

### Harness and network results

The region-tag-based harness has a 2,550-node-per-region ceiling. On the
local machine, N=133 completed; the kernel killed the N=200 arm at 39,800
connections with 8.5 GB cumulative anonymous RSS. Earlier arms were still
retained, so these data do not support a per-node memory estimate.

On the 64-core machine, the smaller and larger ladder arms (N=333/666)
completed in 445 s with 110,556/442,890 connections respectively. Their mean
sweep walls were 24–1846/95–2271 ms, with p99 tails reaching 5.6 s; roots
became equal in both arms. The raised-descriptor run supported about 888K
live file descriptors with zero `EMFILE` errors. The retained logs do not
establish the machine's original descriptor limit.

The starvation negative control uses a 600-node single-region layout, where
removing intra-region selection does isolate the victim. Convergence checks
must drive rounds after fresh divergence: one synchronized round is one
gossip hop, and a poll-only wait cannot substitute for the required exchanges.

With the RTT clamped to 400 ms, a 1,500 ms digest wait produced zero defers,
while the 500 ms default produced one. A 50 ms negative-control wait produced
two defers and zero fallback dumps. The corrected 64-core `tc-netem` test
duration is 5.72 s.

The current guards are `TestSelectorScaleGrid`,
`TestSelectorScaleNegativeControl`, `TestIBLT_PeelEnvelopeMonteCarlo`,
`TestIBLT_V2VsV1FloorGuard`, `TestCensusScalingSmoke`,
`TestCensusNeverJoinedNegativeControl`, `TestNetemSweep`, and their micro
smoke variants. Heavy grids remain explicitly enabled test runs; the smoke
variants do not reproduce their resolution or scale.
