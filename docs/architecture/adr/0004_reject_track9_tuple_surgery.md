# ADR-0004: Reject Track 9.0 Tuple Surgery

> Status: REJECTED (BLOCKED BY POLICY)     Date: 2026-07-26     Track: Phase 3 Track 9.0

## Context
Track 9.0 of the Phase 3 Roadmap proposes replacing the existing 16-byte `DotNodeID` with a massive physical time tuple `(PhysicalMs + Logical + NodeID)` within the CRDT state structure. The theoretical intent of the track was to provide absolute physical time precision on every piece of data.

## CEO Directive and Rationale
The CEO has explicitly directed that Track 9.0 remain **permanently locked and blocked by policy**.

The engineering and strategic rationale for this rejection is:
1. **Performance Degradation:** The CRDT core microbenchmark (the in-process `HAMT.Set` crucible, `TestStage5ScalingGate` — NOT the production ingest path) passes the 50M ops/s absolute mandate at 32c with a gate-passing run of 50,736,038 ops/s (range 50.7M-57.6M; the 57.6M is a residency high-end, NOT sustained). Bloating the CRDT memory layout with a massive time tuple will cause devastating CPU cache misses and destroy the 2.5ns/op baseline speed limit.
2. **Mathematically Unnecessary:** The engine's security and convergence are already mathematically sound. The roadmap itself notes that Track 9.0 was "superseded by the scalar-cap wrapper" (Track 3.0), which achieves necessary causality defenses without the memory tax.
3. **World No. 1 Commitment:** The engine does not negotiate with physics. Extreme performance and zero-allocation memory integrity take precedence over theoretical, high-cost features.

## Decision
Do **NOT** implement Track 9.0. 
The core data structures (`crdt.go` and the `DotNodeID` references) will remain frozen in their optimal, lock-free, cache-aligned state.

## Override Condition
This track may only be unlocked if a massive enterprise customer strictly requires physical timestamping for legal or compliance reasons, and the CEO explicitly provides signed authorization acknowledging the inevitable loss of the 50.7M-57.6M core-microbenchmark throughput range. Until such an authorization exists, this track is dead.
