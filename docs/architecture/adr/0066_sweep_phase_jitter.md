# ADR-0066: Sweep phase jitter

**Status:** Accepted  
**Date:** 2026-10-05

## Context

With phase-aligned ticks, nodes select their intra-region peers at the same
instant. At fan-out f=8, a responder can receive a Poisson(8) burst against
its concurrency bound of 16; the modelled probability of at least 17 arrivals
is approximately 3.7e-3 per victim-round. Increasing the tick rate would
repeat the same alignment more often.

A fixed per-node phase spreads requests across the tick without changing the
number of peers selected per round. For response window W and tick T, the
probability that two independent phases overlap is
`w_eff = 2W/T - (W/T)^2`. The desynchronised arrival model is therefore
Poisson(`f*w_eff`), not the one-sided Poisson(`f*W/T`) model.

## Decision

Add `--sweep-phase-jitter`, disabled by default.
`SOVEREIGN_SWEEP_PHASE_JITTER=1` also enables it. Startup always logs whether
the option is enabled, including when the environment variable supplies it.

`(*Gossiper).SweepLoop` derives the phase on every entry as:

```go
rand.NewPCG(
    binary.LittleEndian.Uint64(nodeID[:8]),
    0x5EED0FF5EED0FF5E,
).Uint64() % uint64(tick)
```

The offset is in `[0, tick)`. Its PCG stream is distinct from the inter-region
stream 0 and the intra-view stream `0x1D5EED5EEDB5EED`. Re-deriving on loop
entry applies the active tick after a restart or tick change. The phase stays
constant within one loop; per-tick randomness is unnecessary because each
node already has its own anchor.

On the enabled path, a warm timer fires at `tick + phase`. The loop creates
its ticker immediately before calling `sweepOnce(ctx)` for that first fire,
so later ticks retain the warm timer's epoch at `k*T + phase`. A slow sweep
can drop ticker events but cannot add its own duration to the phase.

On the disabled path, no phase is derived and `sweepPhaseDerives` remains
zero. Extracting `sweepOnce` does not change the ordinary sweep body, its
converged roots, or its base log format. Configuration is completed before
the sweep goroutine starts.

## Consequences

Jitter changes arrival overlap, not the per-round pick count. It complements
`digestRespondMaxConcurrent`; the semaphore still bounds concurrent digest
builds and can drop excess responses. A static offset is reproducible from
the node ID, which also means equally keyed nodes are not guaranteed to have
distinct phases.

The measurements 258/578/3152 ms cited during this design are per-region
convergence p50s measured since quiescence. They are not inter-region RTTs
and must not be used as RTT evidence for digest-wait sizing.

## Evidence

For the concurrent in-degree model with W=2 ms and T=100 ms,
`w_eff=0.0396` and the modelled mean is `8*0.0396=0.317` arrivals per
window. The measured mean was 0.320. The fraction of windows with at least
two overlapping requests fell from 0.997 with aligned phases to 0.042 with
jitter, approximately a 24× reduction. These are model-harness measurements,
not a multi-machine latency result.

The first-fire check measured `ON-OFF-phase = -425 µs` against a ±100 ms
band. An early implementation created the ticker after the first sweep and
shifted later fires by +28.056 ms. Creating it before `sweepOnce` reduced the
observed offsets to +0.622 ms and +0.333 ms in two verification runs, about
30× inside the epoch band.

The current guards are `TestOutboundSweepJitterDeterminism`,
`TestOutboundSweepJitterSpread`, `TestOutboundSweepJitterIndegreeModel`,
`TestOutboundSweepJitterOffByteIdentity`, and
`TestOutboundSweepJitterSelectChainInvariant`. They include forced phase
alignment, stream reuse, and seed contamination as negative controls.
