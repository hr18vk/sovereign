# ADR-0034: Stratified Anti-Entropy Mesh Wiring — the Phase-5 Track-5.1 FIRST Stake (Day 29)

**Status:** ACCEPTED (Day 29, 2026-08-11) — the TWELFH clean-chain fork (the SECOND deletion-bearing fork; the FIRST streak-breaker since Day-13).

**Date:** 2026-08-11

**Tracks:** Phase-5 Track-5.1 (the stratified anti-entropy FIRST stake).

## §1 — The Decision

WIRE stratified anti-entropy into the mesh sweep: a peer-to-peer StrataEstimator + full-IBLT digest-exchange phase before the per-peer `GenerateDelta`, replacing the O(N×M) oversend (EVERY entry to EVERY peer) with a minimal delta proportional to |A−B|. The dormant primitive mold (Day-23 SkipList.Seek) demanded a wiring that ships the bandwidth cut as a NUMBER (Law V), converges the SAME MerkleRoot the oversend path does in the SAME rounds OR FEWER (Law II), and discloses the fallback honestly (the 19th SSoT counter, M5).

**THE ARCHITECT'S AMENDMENT (the load-bearing mid-audit refutation).** The premise-audit M2 ("the diff is a strict subset → byte-identity + bandwidth cut") was REFUTED by direct read of the dormant primitive `GenerateDeltaStratified` (crdt.go:1934, pre-deletion): it created `remoteIBLT := NewDynamicIBLT(dEst, 4, seed)` then NEVER populated it — the shard-root loop filled only the LOCAL IBLT. The `localIBLT.Subtract(remoteIBLT)` subtracted an EMPTY IBLT → the diff was the FULL local IBLT → the peel yielded ALL local keys → the iterator shipped EVERY entry. The stratified delta was byte-identical to oversend for ANY non-empty remote overlap (NO bandwidth cut — the fork's entire M3 value absent). The dormant unit test (`TestCRDTEngine_GenerateDeltaStratified`) only covered the EMPTY-remote case (where oversend==stratified by coincidence), so the defect never fired — the primitive was wiring-dormant.

**The fundamental obstacle:** the StrataEstimator is a LOSSY digest (XOR-based KeySum, not invertible to the key set); the remote's FULL IBLT MUST come from the wire, NOT be reconstructed from the estimator. The primitive's signature `GenerateDeltaStratified(remoteEstimator *StrataEstimator)` could not supply the remote IBLT — it had only the lossy estimator.

**The fix (the amendment):** the mesh's digest exchange sends the remote's FULL IBLT digest on the wire (alongside the SE used only for the dEst sizing hint), and the sweep calls `GenerateDelta(remoteIBLT)` (crdt.go:1603 — the FROZEN, CORRECT set-reconciliation primitive that subtracts the POPULATED remote IBLT + peels the real diff) instead of the broken `GenerateDeltaStratified`. `GenerateDelta` has ALWAYS set `participantPoolPtr` (crdt.go:1736), so the D2 EBR-pool leak (the stratified sibling's only real artifact) does not exist on this path — the leak was an artifact of the now-deleted primitive, not the wiring.

## §2 — The Premise Audit (M1–M6, verified BEFORE code)

- **M1 (primitive exists + tested + dormant):** `GenerateDeltaStratified` existed at crdt.go:1934, unit-tested GREEN, ZERO prod callers — the Day-23 SkipList.Seek mold. ✅ (then REFUTED in M2 + deleted.)
- **M2 (the diff is a strict subset → byte-identity + bandwidth cut):** REFUTED by direct read — the primitive subtracted an EMPTY remote IBLT (it created `remoteIBLT` then never populated it) → the stratified delta was byte-identical to oversend for any non-empty overlap. The amendment KILLS the primitive + wires `GenerateDelta(remoteIBLT)` (the remote IBLT from the wire). The `GenerateDelta` path IS byte-identity-by-construction (the diff is a strict subset of the full set; `Join` is MERGE-UNION, FROZEN crdt.go:1089) + delivers the REAL bandwidth cut (proven: T-STRUCE-BANDWIDTH-CUT, 150 vs 600, a 75.0% cut).
- **M3 (digest-exchange is a new phase, not inline):** ✅ — the digest exchange is a peer-TLS data-plane round-trip BEFORE the per-peer `GenerateDelta` (a self-diff is a no-op; the exchange is the load-bearing operand supplier). Rides the peer TLS data-plane (NOT the control port — M4).
- **M4 (transport FROZEN-touch):** the recon agent's `/v1/strata-digest` control-port recommendation was REFUTED by direct read of `gossip_test.go` + `partition_test.go` (both build ONLY PeerSet+Gossiper — NO ControlServer, NO HTTP listener; the mesh is pure peer-TLS data-plane). The digest exchange rides the peer TLS data-plane: a new mesh-internal digest frame (length-prefix + `WireDigestMagic` discriminator in `wire_v1.go` + `MarshalStrataEstimator`/`UnmarshalStrataEstimator` siblings in `iblt_wire.go` + `HandleDigestFrame` sink in `pkg/receive` + `SetDigestSink` on `PeerSet`). ✅
- **M5 (fallback honest):** ✅ — a digest timeout / malformed digest / peel failure falls back to oversend (CRDT-idempotent `Join` — the convergence holds) + fires the 19th SSoT counter `StratifiedAntiEntropyFallback` (the Law V disclosure). The D2 leak (the stratified sibling's `participantPoolPtr` omission) was surfaced as a load-bearing decision; the amendment makes it MOOT by deleting the primitive (the leak's only host).
- **M6 (SSoT 18→19):** ✅ — `StratifiedAntiEntropyFallback` (modeCounter) in all 4 registry sites (var block + `allCounters()` + `init()` + `rebuildCounters()`); the bridge auto-surfaces it (§0.f — ZERO bridge edit).

## §3 — The D2 EBR-Pool Leak (the streak-breaker's first artifact)

**ROOT CAUSE:** `GenerateDeltaStratified` (crdt.go:1934, pre-deletion) set `ebrPart: participant` but did NOT set `participantPoolPtr`. `GenerateDelta` (crdt.go:1736) sets `delta.participantPoolPtr = &e.participantPool`. `Release()` (crdt.go:1508-1513) does `pp := d.participantPoolPtr; d.ebrPart.Exit(); if pp != nil { pp.Put(d.ebrPart) }` — so the stratified path Exited the participant but never Put it back → the pool dries → per-call heap alloc of a fresh `Participant`.

**WHY THE STREAK-BREAKER:** the leak was pre-existing (the primitive was wiring-dormant), but Day-29 wires the primitive into the sweep, ACTIVATING the leak on every stratified round. The first D2 unfreeze (this session) added `participantPoolPtr: &e.participantPool,` at both Return A (crdt.go:1959) + Return B (crdt.go:2024). The M2 amendment then DELETED the primitive (the leak's only host), making the D2 fix MOOT by construction — the wiring's path (`GenerateDelta`) has ALWAYS recycled (crdt.go:1736). The D2 fix + the primitive deletion are the TWO crdt.go changes this unfreeze carries (the single re-pin, 835350a8 → 44f89527). The Day-18 "no re-pin since Day-13" streak is BROKEN for this physical defect (Architect-authorized).

## §4 — The 10 Teeth (GATED + GREEN)

1. **T-STRUCE-OFF-IS-BYTE-IDENTICAL** — OFF (oversend, the default) converged 1000 events in 1 round, byte-identical to HEAD oversend, fallback silent. The opt-IN zero-value (`stratified=false`) is byte-identical Day-28.
2. **T-STRUCE-BYTE-IDENTITY** — ON root A == OFF root A (Law II byte-identity); ON 1 round vs OFF 1 (converges-never-breaks); cardinality ON A=1000 B=1000 == OFF A=1000 B=1000.
3. **T-STRUCE-BANDWIDTH-CUT** — the stratified delta yielded 150 entries vs the oversend delta's 600 (a 450-entry cut, 75.0% of oversend) — Law V NUMBER, not an adjective (|A−B|=150 of a 600-entry set, 1024-bucket digest at 0.59 load, direct primitive measurement, loopback 4c, NOT silicon).
4. **T-STRUCE-FALLBACK-COUNTER-FIRES** — mixed-mode (A ON, B OFF): A fell back 1 time (digest timeout → oversend), converged anyway (the M5 honest path); the 19th SSoT counter is the Law V DISCLOSURE.
5. **T-STRUCE-SSOT-19** — `Counters()` carries 19 DISTINCT; the 19th is `supremum.mesh.stratified_fallback` (modeCounter, the M5 disclosure); the bridge auto-surfaces it (§0.f).
6. **T-STRUCE-FROZEN-REPIN** — the 5-file FROZEN set holds: crdt.go re-pinned to 44f89527 (D2 leak fix + M2 primitive deletion, ADR-disclosed streak-breaker); the other 4 byte-UNCHANGED (crdt_apply.go ed9132a2, envelope.go b1beba1e, schema.capnp 47d2796a, schema.capnp.go 590af228).
7. **T-STRUCE-RACE** — ON converged 1000 events in 1 round race-clean (the `digestRecv` mutex + the per-peer channel + the EBR pin are goroutine-safe; run under `-race` in the gate).
8. **RED-NEUTER (the D2 bug-inject control)** — 2000 `GenerateDelta(remoteIBLT)`+`Release` cycles (the M2-fixed wiring path) completed; the FROZEN primitive recycles the EBR participant (Release → Exit + Put back via `participantPoolPtr` at crdt.go:1736); the pool does NOT dry; the engine stays usable. The RED arm (a parallel Get-without-Put control) proves the deleted primitive's D2 leak was REAL; the amendment makes the fix MOOT by deleting the primitive (the leak's only host).
9. **T-STRUCE-M2-CUT-PROVEN (the M2 bug-inject control)** — GREEN (the M2 fix, populated remote IBLT) yielded 150 entries vs OFF 600 (a 450-entry cut, 75.0%); RED (the injected bug — the deleted primitive's empty-subtract defect) yielded 600 == OFF (the cut VANISHES under the bug) — the M2 fix (populating the remote IBLT from the wire) is the LOAD-BEARING artifact; the bug it closes is REAL.
10. **T-STRUCE-WIRE-COST (the honest-overhead disclosure)** — the digest frame is 72311 bytes/peer/round (SE 51789 + IBLT 20498 + header 24); the cut wins at 75% overlap (NET=2689 B); the saturation limit (~750 entries/node, the FROZEN 1024-bucket digest) + the near-empty-diff net cost are DISCLOSED.

**The M2 unit test** (`TestCRDTEngine_GenerateDeltaWithRemoteIBLT`, pkg/sync) re-proves the 3 core contracts pre-and-post: (a) empty remote IBLT → delta == full set (oversend); (b) populated remote IBLT (3-of-5 overlap) → delta == the 2 |A−B| diff ONLY (the bandwidth cut); (c) identical remote IBLT → delta == empty (perfect sync).

## §5 — The Saturation Limit (the honest physical bound)

The FROZEN `GenerateDelta` builds its LOCAL digest at a FIXED 1024 buckets (crdt.go:1610); the remote IBLT MUST match (Subtract requires identical bucket counts, iblt.go:377). The 1024-bucket IBLT saturates past ~750 keys (the peel success rate collapses past ~0.7 load — XOR-based KeySum collisions stop canceling → the subtract's diff IBLT inherits impure buckets → the peel fails → `GenerateDelta` falls back to oversend = NO bandwidth cut). The probe (T-STRUCE-WIRE-COST) measured: total=750 overlap=562 diff=188 YIELDS 188 (the cut holds); total=800 OVERSENDS (saturated).

**This is the honest physical limit of the FROZEN primitive's FIXED local-digest sizing.** Above ~750 entries per node, the stratified path falls back to oversend (the fallback counter fires, the M5 honest path) until a future fork unfreezes `GenerateDelta`'s local-digest builder to size DYNAMICALLY by the remote's bucket count (the dEst-sized dynamic digest — a SEPARATE fork, NOT this one). The bandwidth tooth sizes under the threshold (total=600, 0.59 load) to prove the cut; T-STRUCE-WIRE-COST discloses the limit.

## §6 — The §III Gate (green)

- `go build ./...` exit 0.
- `gofmt` clean on ALL Day-29 files.
- `go vet` clean on `pkg/mesh` + `pkg/sync` + `internal/telemetry` + `pkg/receive` (the edited seams are vet-safe; the `go vet ./...` `unsafe.Pointer` warnings are ALL pre-existing in `pkg/sync` FROZEN CRDT — UNCHANGED).
- `fieldalignment`: `pkg/mesh` + `pkg/sync` + `internal/telemetry` + `pkg/metrics` add ZERO new debt (the `Gossiper.stratified` + `digestRecv` + `digestWaitTimeout` fields, the `peerDigest` struct, the `StratifiedAntiEntropyFallback` counter are fieldalignment-clean; the 11/1/0 baseline holds).
- **5-FILE FROZEN md5:** crdt.go re-pinned 835350a8 → 44f89527 (the D2 + M2 combined re-pin, ADR-disclosed streak-breaker); the other 4 byte-UNCHANGED (crdt_apply.go ed9132a2, envelope.go b1beba1e, schema.capnp 47d2796a, schema.capnp.go 590af228). `TestGate_FrozenMD5` + `TestBench_FrozenMD5` GREEN (the authoritative `pkg/receive` gate, re-pinned to 44f89527 across 14 test sites).
- `TestGate_UntouchedFrozenAndOutOfScope` GREEN (crdt.go EXEMPT — the Day-29 streak-breaker, disclosed in the gate; the other 7 untouched files byte-identical to HEAD).
- `TestGate_GearHonesty` GREEN (4c, the honest SCISSORS label — the teeth run loopback 4c, NOT silicon).
- `TestHotPathZeroAllocations` GREEN (Day 29 is the mesh sweep + the digest exchange — the digest frame is a per-round allocation OFF the hot path; the write path is untouched).
- The 10 Day-29 teeth GREEN across `pkg/mesh` + the M2 unit test GREEN in `pkg/sync`.
- `-race` per-package clean (the 4-core box constraint).

## §7 — Carry-Forwards (disclosed, NOT closed)

- **The dEst-sized dynamic digest** (the saturation-limit lift): unfreeze `GenerateDelta`'s local-digest builder to size DYNAMICALLY by the remote's bucket count (the `GenerateDigestDynamicWithSeed` + `Cardinality` primitives were probed this fork but REVERTED — the FROZEN `GenerateDelta` requires a matching bucket count; the dynamic sizing is a SEPARATE fork that unfreezes the local-digest builder). OPEN.
- **The silicon-scale 100-node bandwidth gate** (the prompt's explicit "NO AWS this turn"): the bandwidth cut is measured in-process (loopback 4c); the named-silicon 100-node gate is the NEXT-NEXT fork. OPEN.
- **The SE wire-cost** (51789 bytes/round, 32 strata IBLTs): the SE is the dominant digest-frame overhead; a future fork could send ONLY the remote IBLT (the load-bearing operand) + skip the SE (the dEst sizing hint is dispensable if the digest is sized by the engine's cardinality, not dEst). OPEN.
- The live cross-entity tail mega-fork (ADR-0032 §6.b), the O(1) per-entity live-cursor (ADR-0032 §6.a), the upper-bound `maxSys` sidecar (ADR-0030 §6.b), the Fenwick sweep balance (ADR-0025 §6), the inferrer backoff auto-tuning (ADR-0027 §6.3), the NEXT ZERO-ALLOC JOIN fork (ADR-0022 §8) remain OPEN.

## §8 — Enforcement

Enforced by the 10 teeth (`pkg/mesh/day29_stratified_test.go`) + the M2 unit test (`pkg/sync/crdt_test.go`) + `TestGate_FrozenMD5`/`TestGate_UntouchedFrozenAndOutOfScope`/`TestGate_GearHonesty`/`TestBench_FrozenMD5` (the `pkg/receive` gate, re-pinned to 44f89527) + `TestGate_UntouchedFrozenAndOutOfScope_Day19` (the `pkg/mesh` gate, crdt.go exempted) + `TestTrack36_ScopeTooth` (the per-track scope gate, the Day-29 edited set exempted with disclosure) + `TestHotPathZeroAllocations` (the zero-alloc gate) + `-race` per-package.
