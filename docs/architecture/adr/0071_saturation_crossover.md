# ADR-0071: Bounded saturation crossover

- **Status:** Accepted; `--defer-crossover` remains opt-in and is off by
  default. Later exchange changes appear in
  [ADR-0072](0072_ebr_hoist_mesh_dial_and_digest_gating.md),
  [ADR-0073](0073_hierarchical_gateway_topology_and_boot_dial.md), and
  [ADR-0074](0074_var_freelist_aba_and_v2_digest_requests.md).
- **Date:** 2026-10-22

## Context

The defer handler prevents repeated full-keyset fallback by sending bounded
rotating slices after digest failures. The earlier fleet measurement used 30
machines across three AWS regions, with fan-out `f=8-of-332`; a particular pair
met about every 41.5 rounds. That cadence made recovery from bulk saturation
much slower than the six full-keyset oversend runs, which converged all
fingerprints in 284–590 seconds.

A full-keyset ship is useful when one capacity failure represents a large true
diff, but repeating it on every failure recreates the cascade the defer handler
was designed to avoid. The crossover therefore needs a failure-class check, a
keyset bound, and a per-episode limit.

## Decision

Add `--defer-crossover`, disabled by default and valid only with
`--defer-handler`. The command rejects the orphan configuration during startup.
`Gossiper.SetDeferCrossover` is configured before sweeps begin.

Only `ErrIncompletePeel` is eligible. A nil or malformed digest, a timeout, a
publish failure, or a marshal failure continues through the existing defer
path. On an eligible failure, `deferCrossoverTry` counts the local keyset if no
estimate is available and permits the existing oversend path only when its size
is at most 20,000 entries. It does not add another publication mechanism.

The size bound derives from the 30-node full-mesh measurement: approximately
408 bytes per entry per pair, or 4.08 MB for a 10,000-key ship. The bound keeps
one crossover within twice that per-pair budget. Together with the per-episode
limit, it prevents unbounded repeated oversend.

`crossoverServed` permits one full-keyset ship per divergence episode, and
`resetDeferPeer` clears it only after a clean peel. A failed publication clears
the once-marker and records `crossoverAt`; another crossover is unavailable for
180 seconds while the defer ladder owns retries. A later clean peel clears the
cooldown with the episode marker.

## Consequences

Small and medium keysets can recover from a capacity peel failure in one ship
instead of waiting for a complete rotating-window cycle. Larger keysets and all
other failure classes retain the defer handler's bandwidth bound.

The option does not change the default configuration. Enabling it trades a
bounded increase in per-pair traffic for faster recovery; it is not evidence
that full-keyset fallback is safe on every sweep or at larger keysets.

## Evidence

The unit tests use a two-node in-process loopback mesh or direct state
inspection. They do not make a larger-fleet timing claim.

- `TestCrossoverSelection` drives a 10,000-key divergence, observes one
  crossover ship and convergence, then checks that a clean peel permits a later
  episode to cross over again.
- `TestCrossoverOnceMarker` adds divergence before a clean peel and requires
  the defer ladder to handle it without another full-keyset ship.
- `TestCrossoverCooldown` checks rejection immediately after a failed publish
  and eligibility after the 180-second cooldown.
- `TestCrossoverTimeoutDoesNotShip` separates a digest timeout from
  `ErrIncompletePeel`; `TestCrossoverKeysetBound` rejects a keyset above 20,000
  entries while preserving its size estimate for the defer ladder.
- `TestCrossoverDisabledUsesDeferLadder` converges the same 10,000-key
  two-node divergence through bounded slices with crossover disabled.

The earlier fleet measurement exposed a separate limit. In one partial run,
the US region reached `t50 = 156 s`, with all 34 nodes on the first machine
holding 10,000 entries and one fingerprint. The EU and AP regions did not
converge by the 1,800-second cap: the 1,500 ms digest wait expired while roughly
10 draws occupied a roughly 15-second round. EU first receipt improved from 762
to 411 seconds, a 1.854-fold reduction, but response latency still prevented
fleet-wide convergence. That run does not support a completed 1,000-node
convergence claim. ADR-0072 addresses declined-connection and digest-role
handling, ADR-0073 changes the gateway topology, and ADR-0074 reduces the v2
request to its header.
