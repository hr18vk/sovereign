# ADR-0034: Stratified Anti-Entropy Mesh Wiring

**Status:** Accepted
**Date:** 2026-08-11

## §1 — The Decision

I wired stratified anti-entropy into the mesh sweep: a peer-to-peer StrataEstimator + full-IBLT digest-exchange phase before the per-peer `GenerateDelta`, replacing the O(N×M) oversend (every entry shipped to every peer) with a minimal delta proportional to |A−B|. The engine already had the primitive — unit-tested, with zero production callers — and an earlier wiring of a dormant primitive (`SkipListArena.Seek`) had set the pattern I held this to: ship the bandwidth cut as a measured number, converge the same Merkle root the oversend path converges in the same number of rounds or fewer, and disclose every fallback honestly through a new telemetry counter.

**The amendment that reshaped the change.** My premise going in was "the diff is a strict subset, so byte-identity plus a bandwidth cut." A direct read of the dormant primitive `GenerateDeltaStratified` (crdt.go:1934, pre-deletion) refuted it: it created `remoteIBLT := NewDynamicIBLT(dEst, 4, seed)` and then never populated it — the shard-root loop filled only the local IBLT. So `localIBLT.Subtract(remoteIBLT)` subtracted an empty IBLT, the diff came back as the full local set, the peel yielded all local keys, and the iterator shipped every entry. The stratified delta was byte-identical to oversend for any non-empty overlap — the bandwidth cut did not exist. The dormant unit test (`TestCRDTEngine_GenerateDeltaStratified`) only covered the empty-remote case, where oversend and the stratified path coincide, so the defect never fired.

**The fundamental obstacle:** the StrataEstimator is a lossy digest (XOR-based KeySum, not invertible back into the key set), so the remote's full IBLT must come from the wire — it cannot be reconstructed from the estimator. The primitive's signature `GenerateDeltaStratified(remoteEstimator *StrataEstimator)` could never supply the remote IBLT; no edit to its body could fix what its signature left out.

**The fix:** the mesh digest exchange sends the remote's full IBLT digest on the wire (alongside the StrataEstimator, kept only as the dEst sizing hint), and the sweep calls `GenerateDelta(remoteIBLT)` (crdt.go:1718 — the correct set-reconciliation primitive, which subtracts the populated remote IBLT and peels the real diff) instead of the broken `GenerateDeltaStratified`. `GenerateDelta` has always set `participantPoolPtr` (crdt.go:1851), so the EBR-pool leak described in §3 does not exist on this path — the leak was an artifact of the deleted primitive, not of the wiring.

## §2 — The Premise Audit

I verified each premise against the code before writing the change:

- **The primitive exists, is tested, and is dormant.** `GenerateDeltaStratified` existed at crdt.go:1934, unit-tested green, zero production callers. (Then refuted by the next premise, and deleted.)
- **The diff is a strict subset → byte-identity plus a bandwidth cut.** Refuted by direct read, as above: the primitive subtracted an empty remote IBLT, so the stratified delta was byte-identical to oversend for any non-empty overlap. The amendment deletes the primitive and wires `GenerateDelta(remoteIBLT)` with the remote IBLT arriving on the wire. That path is byte-identity-by-construction (the diff is a strict subset of the full set; `Join` is merge-union, crdt.go:1173) and delivers the real cut (measured: 150 vs 600 entries, a 75.0% cut — §4).
- **The digest exchange is a new phase, not inline.** Confirmed: it is a peer-TLS data-plane round-trip before the per-peer `GenerateDelta` (a self-diff is a no-op; the exchange is the load-bearing operand supplier). It rides the peer TLS data-plane, not a control port.
- **Transport impact.** An early sketch put the exchange on a `/v1/strata-digest` HTTP control port; reading `gossip_test.go` and `partition_test.go` refuted that — both build only a PeerSet and a Gossiper, with no control server and no HTTP listener; the mesh is a pure peer-TLS data-plane. So the exchange is a new mesh-internal digest frame: length-prefix plus a `WireDigestMagic` discriminator in `pkg/attribution/wire_v1.go`, `MarshalStrataEstimator`/`UnmarshalStrataEstimator` siblings in `iblt_wire.go`, a digest-frame dispatch sink (`DispatchFrame` routing to `DigestSink.DeliverDigest` in `pkg/mesh/digest.go`), and `SetDigestSink` on `PeerSet`.
- **The fallback is honest.** A digest timeout, a malformed digest, or a peel failure falls back to oversend (the CRDT-idempotent `Join` means convergence still holds) and fires the new telemetry counter `StratifiedAntiEntropyFallback`, so the degradation is visible rather than silent.
- **Counter registration.** `StratifiedAntiEntropyFallback` (a modeCounter) is registered in all four registry sites (the var block, `allCounters()`, `init()`, and `rebuildCounters()`); the telemetry bridge auto-surfaces it with no bridge edit.

## §3 — The EBR-Pool Leak

**Root cause:** `GenerateDeltaStratified` (crdt.go:1934, pre-deletion) set `ebrPart: participant` but never set `participantPoolPtr`. `GenerateDelta` (crdt.go:1851) sets `delta.participantPoolPtr = &e.participantPool`. `Release()` (crdt.go:1605) does `pp := d.participantPoolPtr; d.ebrPart.Exit(); if pp != nil { pp.Put(d.ebrPart) }` — so the stratified path exited the participant but never returned it to the pool: the pool drains, and every call heap-allocates a fresh `Participant`.

The leak was pre-existing but harmless only because the primitive was dormant; wiring it into the sweep would have activated it on every stratified round. My first fix added `participantPoolPtr: &e.participantPool,` at both return sites (crdt.go:1959 and crdt.go:2024). The §1 amendment then deleted the primitive outright — the leak's only host — making the fix moot by construction: the shipped path (`GenerateDelta`) has always recycled (crdt.go:1851). The pool-pointer fix and the primitive deletion are the two crdt.go changes in this decision.

## §4 — The Tests (all green)

1. **`TestStratifiedOffIsByteIdentical`** — with the flag off (oversend, the default), 1000 events converged in 1 round, byte-identical to the pre-change oversend path, fallback silent. The opt-in zero value (`stratified=false`) changes nothing.
2. **`TestStratifiedOnConvergesByteIdentity`** — on-root A == off-root A (byte-identity); on converged in 1 round vs off in 1; cardinality on A=1000 B=1000 == off A=1000 B=1000.
3. **`TestStratifiedBandwidthCut`** — the stratified delta yielded 150 entries vs the oversend delta's 600: a 450-entry cut, 75.0% of oversend (|A−B|=150 of a 600-entry set, 1024-bucket digest at 0.59 load, direct primitive measurement, loopback on 4 cores, not silicon).
4. **`TestStratifiedFallbackCounterFires`** — mixed mode (A on, B off): A fell back once (digest timeout → oversend) and still converged; the new counter is the disclosure.
5. **`TestStratifiedFallbackCounter`** — the registry carries the new counter (`supremum.mesh.stratified_fallback`); the telemetry bridge auto-surfaces it with no bridge edit.
6. **`TestStratifiedRace`** — on, 1000 events converged in 1 round race-clean (the `digestRecv` mutex, the per-peer channel, and the EBR pin are goroutine-safe; run under `-race`).
7. **`TestPooledBufferNoLeak`** (the leak bug-injection control) — 2000 `GenerateDelta(remoteIBLT)`+`Release` cycles on the fixed path completed; the primitive recycles the EBR participant (Release → Exit + Put back via `participantPoolPtr` at crdt.go:1851); the pool never dries. The red arm (a parallel Get-without-Put control) proves the deleted primitive's leak was real; deleting the primitive makes the fix moot.
8. **`TestStratifiedCutProven`** (the bug-injection control for the cut) — green (populated remote IBLT) yielded 150 entries vs off 600 (the 450-entry, 75.0% cut); red (the injected bug — the deleted primitive's empty-subtract defect) yielded 600 == off: the cut vanishes under the bug. Populating the remote IBLT from the wire is the load-bearing artifact, and the bug it closes is real.
9. **`TestStratifiedWireCost`** (the honest-overhead disclosure) — the digest frame is 72311 bytes/peer/round (SE 51789 + IBLT 20498 + header 24); the cut wins at 75% overlap (NET=2689 B); the saturation limit (~750 entries/node, the fixed 1024-bucket digest) and the near-empty-diff net cost are disclosed in §5.

The focused unit test (`TestCRDTEngine_GenerateDeltaWithRemoteIBLT`, pkg/sync) re-proves the three core contracts: (a) empty remote IBLT → delta == full set (oversend); (b) populated remote IBLT (3-of-5 overlap) → delta == only the 2-entry |A−B| diff (the cut); (c) identical remote IBLT → delta == empty (perfect sync).

Of the merge-law/wire-schema files, only `crdt.go` changed in this decision (the §3 pool-pointer fix plus the primitive deletion); `crdt_apply.go`, `envelope.go`, `schema.capnp`, and `schema.capnp.go` are unchanged.

## §5 — The Saturation Limit (the honest physical bound)

`GenerateDelta` builds its local digest at a fixed 1024 buckets (via `GenerateDigestWithSeed`, crdt.go:1952), and the remote IBLT must match (`Subtract` requires identical bucket counts, iblt.go:381). A 1024-bucket IBLT saturates past ~750 keys: the peel success rate collapses past ~0.7 load (XOR-based KeySum collisions stop canceling → the subtract's diff IBLT inherits impure buckets → the peel fails → `GenerateDelta` falls back to oversend, and the bandwidth cut is gone). The probe measured: total=750 overlap=562 diff=188 yields 188 (the cut holds); total=800 oversends (saturated).

That is the honest physical limit of the fixed local-digest sizing. Above ~750 entries per node the stratified path falls back to oversend (the fallback counter fires, and convergence still holds) until future work lets `GenerateDelta` size its local digest dynamically from the remote's bucket count. The bandwidth test therefore sizes under the threshold (total=600, 0.59 load) to prove the cut, and `TestStratifiedWireCost` discloses the limit.

## §6 — The Gate (green)

- `go build ./...` exit 0.
- `gofmt` clean on every file this change touched.
- `go vet` clean on `pkg/mesh`, `pkg/sync`, `internal/telemetry`, and `pkg/receive` (the edited seams are vet-safe; the `go vet ./...` `unsafe.Pointer` warnings are all pre-existing in the frozen `pkg/sync` CRDT and unchanged).
- `fieldalignment`: `pkg/mesh`, `pkg/sync`, `internal/telemetry`, and `pkg/metrics` add zero new debt (the `Gossiper.stratified`, `digestRecv`, and `digestWaitTimeout` fields, the `peerDigest` struct, and the `StratifiedAntiEntropyFallback` counter are fieldalignment-clean).
- `TestHotPathZeroAllocations` green (the change is the mesh sweep plus the digest exchange; the digest frame is a per-round allocation off the hot path; the write path is untouched).
- The §4 tests green across `pkg/mesh`, plus the contract test green in `pkg/sync`.
- `-race` per-package clean (the 4-core box constraint).

## §7 — Known Limitations / Future Work

- **The dEst-sized dynamic digest** (the saturation-limit lift): let `GenerateDelta` size its local digest dynamically by the remote's bucket count. A dynamically-sized digest builder plus an estimator-cardinality primitive were probed here but reverted — the frozen `GenerateDelta` requires a matching bucket count, so dynamic sizing is separate work that unfreezes the local-digest builder. Open.
- **The silicon-scale 100-node bandwidth gate:** the bandwidth cut is measured in-process (loopback, 4 cores); a named-silicon 100-node gate is later work. Open.
- **The SE wire cost** (51789 bytes/round, 32 strata IBLTs): the StrataEstimator is the dominant digest-frame overhead; a future change could send only the remote IBLT (the load-bearing operand) and skip the estimator — the dEst sizing hint is dispensable if the digest is sized by the engine's cardinality rather than by dEst. Open.
- The live cross-entity tail work (ADR-0032 §6.b), the O(1) per-entity live cursor (ADR-0032 §6.a), the upper-bound `maxSys` sidecar (ADR-0030 §6.b), the Fenwick sweep balance (ADR-0025 §6), the inferrer backoff auto-tuning (ADR-0027 §6, item 3), and the next zero-alloc join work (ADR-0022 §8) remain open.

## §8 — Enforcement

Enforced by the §4 tests (`pkg/mesh/stratified_antientropy_test.go`) + the contract test (`pkg/sync/crdt_test.go`) + `TestHotPathZeroAllocations` + per-package `-race`.
