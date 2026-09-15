# ADR-0037: Hybrid Post-Quantum Sign Wire — ShipBatchHybrid (Ed25519 + ML-DSA-65) Batch Sign, the HybridEnvelope Frame, the 4-Way Dispatch, and the Hybrid-Accept Telemetry Counter

**Status:** ACCEPTED

**Date:** 2026-08-11

**Context:** the second post-quantum step. ADR-0036 wired the VERIFY half of the hybrid moat and disclosed an honest not-yet: under `--hybrid-verify` every v1 frame is rejected because the v1 wire carries one Ed25519 signature and the Directory carries one `ed25519.PublicKey`. This change closes that gap by wiring the SIGN half.

## §1 — The Decision

Wire the sign half of the hybrid post-quantum moat. `ShipBatchHybrid` signs the marshaled `CRDTDeltaBatch` wire under BOTH Ed25519 and ML-DSA-65 over the same 120-byte SHAKE256 pad (the amortized pad — one PQ sign per BATCH, not per delta), the `HybridEnvelope` frame carries both signatures, the identity Directory is provisioned with both public keys (`RegisterPQ` + `LookupBoth`), the `DispatchFrame` 4-way router routes the hybrid magic to `HandleHybridFrame`, `VerifyBatchHybrid` is the both-required batch verify gate, and the `HybridFrameAccepted` counter is a new telemetry counter — the externally visible proof the moat is in use, not just wired. The change is opt-in, following the established opt-in precedent for mesh features: the `--hybrid-sign` flag (default false) keeps the self-originated delta path on the v1 `BatchEnvelope` — byte-identical to the prior behavior (no hybrid frame is produced or accepted; the counter stays 0); the `--hybrid-verify` flag (ADR-0036, default false) keeps the receive path on the classical `VerifyCRDTFrame` seam. None of the merge-law/wire-schema files is touched — `crdt.go` is byte-identical; the hybrid-sign layer is a mesh/identity/attribution addition, not a CRDT/data-layer change.

**The SHAKE256-pad amortization (the load-bearing mechanism).** The hybrid sign does not sign `batchWire` twice (the 64-byte Ed25519 plus the 3309-byte ML-DSA-65 over the raw capnp wire would double the per-batch sign cost and triple the wire). Instead `SignCRDTFrame_Hybrid` derives a fixed 120-byte SHAKE256 pad of `batchWire` (the `HashBatchWireToFrame120` helper — the same 120-byte frame the `pq_preview` `SignCRDTFrame_PostQuantum` already used), then signs the pad under both keys: `ed25519.Sign(edPriv, pad120)` + `mldsa65.Sign(pqPriv, pad120)`. The verify re-derives the pad and checks both signatures over it. The amortization is the point: one PQ sign per batch of N deltas (the `--batch-size` knob, default `DefaultBatchSize`), not one PQ sign per delta. A per-frame hybrid would sign the 120-byte pad of a one-delta "batch" per frame (no amortization — the 73.7µs PQ sign per delta, not per batch); the batch is the load-bearing shape, so `--hybrid-sign` forces the `shipBatchedDelta` path even when `--batch-size <= 1` (the §4 wiring detail the tests caught — see §6).

**The both-gate (defense in depth, carried from ADR-0036).** `VerifyBatchHybrid` checks both the Ed25519 signature and the ML-DSA-65 signature over the same pad; either failure rejects the frame. The both gate (return `edOK && pqOK`) is the load-bearing choice — the either-or gate (return `pqOK || edOK`) is the defense-in-depth inversion: a classical break (a future Ed25519 fault) would compromise a PQ frame under either-or (the PQ sig still verifies, so the frame accepts), but under both, the classical break rejects. The `TestPQ_HybridEitherOrControl` bug-inject test (ADR-0036) proves the both gate is load-bearing; this change carries the same gate to the batch verify (`VerifyBatchHybrid`).

**The strict-mode symmetry (the orthogonality).** The hybrid moat is strict in both directions:
- a hybrid verifier (`--hybrid-verify=ON`) never accepts a classical-only v1 frame (the v1 wire carries one Ed25519 signature and no PQ sig, so the Directory lookup yields a nil PQ pubkey; the both gate rejects — `TestPQ_HybridNilPQReject`)
- a non-hybrid verifier (`--hybrid-verify=OFF`) never accepts a both-sig hybrid frame (it cannot fall back to the classical single-sig verify on a both-sig frame — `TestPQ_HybridSignVerifyOff`)

The symmetry is the orthogonality: the two flags are independent (sign + verify), and each side rejects the cross-class frame. A hybrid frame is only accepted when both `--hybrid-sign` (send) and `--hybrid-verify` (receive) are armed — the moat-in-use posture.

**The honest not-yet (the load-bearing scope disclosure).** Out-of-band peer-pubkey provisioning is future work — this change assumes a statically provisioned Directory (the test harness registers the peer's PQ public key via `RegisterPQ` at construction; the production node registers its own PQ public key via `RegisterPQ` at boot, but does not yet gossip peer public keys). A node whose Directory does not carry a peer's ML-DSA-65 public key gets a `nil pqPub` from `LookupBoth`, so the hybrid verify rejects (the strict mode). Directory gossip (peer-pubkey propagation) is the next PQ change. The node's mesh peer-dial loop is a pre-existing stub (the node log still prints "dial loop pending ") — a pre-existing codebase gap, not a defect introduced here; the two-node binary mesh cannot converge until that lands, so the runtime verification is single-node (presence of the new counter) and the end-to-end proof that the counter fires (`>=1`) is the in-process `pqHarness` (6/6 checks green).

## §2 — The Premise Audit (verified before code)

- **Substrate exists:** confirmed — `SignCRDTFrame_PostQuantum` + `VerifyCRDTFrame_PostQuantum` exist at `pkg/identity/pq_mldsa.go` (promoted from the `pq_preview` build tag to the default build by ADR-0036, so the hybrid sign can call them without a build tag). `SignCRDTFrame` (classical, circl Ed25519) is at `pkg/identity/sign.go`. The `filippo.io/mldsa` dependency is pinned (ADR-0036). The 120-byte SHAKE256-pad helper (`HashBatchWireToFrame120` / `frame120`) was probed and reverted in an earlier dynamic-digest experiment; this change re-uses the same pad shape for the hybrid sign.
- **The hybrid sign amortizes over the batch, not the frame:** confirmed empirically — the tests caught the wiring defect: `g.hybridSign` on the `shipDelta` (per-frame) path was a no-op because the sweep's `if g.batchSize > 1` guard took the per-frame path when `batchSize == 0` (the harness default). `TestPQ_HybridE2EConverges` failed (roots static, accept=0 — the hybrid frames were never produced because `shipDelta` ignores `hybridSign`) and `TestPQ_HybridSignVerifyOff` failed (the mesh converged via the v1 per-frame path, ignoring `hybridSign`). Fix: `--hybrid-sign` forces `shipBatchedDelta` (the batch path) regardless of `batchSize` — the hybrid frame is a batch shape (it carries the marshaled `CRDTDeltaBatch` wire plus both signatures amortized over N deltas). After the fix, `TestPQ_HybridE2EConverges` passed (converged 1000 events in 1 round, acceptA=5 acceptB=5) and `TestPQ_HybridSignVerifyOff` passed (hybrid frames DropVerify'd, no convergence — the symmetric strict mode).
- **Hybrid = both-required:** confirmed — `VerifyBatchHybrid` returns `edOK && pqOK` (short-circuit AND — the cheap classical gate first; the 73.7µs PQ verify runs only if classical passed). The `TestPQ_HybridEitherOrControl` test (ADR-0036) proves the both gate is load-bearing; the `TestPQ_HybridPQReject` + `TestPQ_HybridClassicalReject` tests prove an either-sig-corrupt frame is rejected.
- **Honest 4-core bench:** carried from ADR-0036 — `BenchmarkMLDSA65_Verify_120B-4` = 73,662 ns/op (~73.7µs < 100µs), 0 allocs, 4-core loopback. The hybrid sign cost is ~73.7µs per batch (amortized over N deltas — the `--batch-size` knob); the 32-core gate is future AWS work. The hybrid verify is the same 73.7µs per batch (the verify re-derives the pad and checks both signatures).
- **Strict-mode symmetry:** confirmed — `TestPQ_HybridNilPQReject` (a hybrid verifier rejects a frame with no PQ sig) + `TestPQ_HybridSignVerifyOff` (a non-hybrid verifier rejects a both-sig hybrid frame) prove the orthogonality — the two flags are independent and each side rejects the cross-class frame.
- **Byte-identity — the hybrid frame carries the verbatim batchWire:** confirmed — `TestPQ_HybridE2EByteIdentity` proves the hybrid mesh's MerkleRoot equals the v1 mesh's MerkleRoot (the same 1000-event split, the same nodeIDs) — the `HybridEnvelope` carries the verbatim `CRDTDeltaBatch` wire (the signatures are over the pad; the wire is unchanged), so the merge `Join` produces a byte-identical state. `TestPQ_HybridOffIsByteIdentical` proves the default (sign=OFF, verify=OFF) keeps the v1 path — byte-identical to the prior behavior (no hybrid frame produced or accepted; counter stays 0).
- **Honesty — the counter is the disclosure, not the mechanism:** confirmed — the `HybridFrameAccepted` counter fires on a hybrid-frame accept (the `SetHybridAcceptReporter` seam → `telemetry.HybridFrameAccepted.Inc`); the counter does not gate the accept (a nil reporter leaves the receiver's gate stack unchanged — the `SetStratifiedFallbackReporter` + `SetPQHandshakeReporter` precedent). The counter is the externally visible proof the moat is in use.

## §3 — The Teeth (all green under -race, including the two review-fix regression teeth)

**Mesh + receiver end-to-end (`pkg/mesh/pq_hybrid_test.go`):**
- `TestPQ_HybridE2EConverges` — a 2-node mesh with `--hybrid-sign` + `--hybrid-verify` converges the same 1000-event split the v1 path does, via hybrid frames (acceptA=5 acceptB=5 — the moat is useful).
- `TestPQ_HybridE2EByteIdentity` — the hybrid mesh's MerkleRoot equals the v1 mesh's MerkleRoot (the hybrid frame carries the verbatim batchWire, so the join is byte-identical).
- `TestPQ_HybridOffIsByteIdentical` — `--hybrid-sign=false` + `--hybrid-verify=false` (the default) keeps the v1 path — byte-identical to the prior behavior (no hybrid frame produced or accepted; counter stays 0).
- `TestPQ_HybridSignVerifyOff` — under `--hybrid-sign` + `--hybrid-verify=OFF` a hybrid frame is rejected (the symmetric strict mode — a non-hybrid-verify receiver cannot fall back to the classical single-sig verify on a both-sig frame).
- `TestPQ_HybridDispatch4Way` — `DispatchFrame` routes a hybrid frame to `HandleHybridFrame` (the 4th arm); a batch, a digest, and a relay frame route to their respective arms (the 4-way dispatch is unambiguous).
- `TestPQHybridCounter` — the new telemetry counter is `HybridFrameAccepted` (a modeCounter, not a gauge — the gauge count is unchanged at 3), named `supremum.hybrid.frame_accepted`, and the bridge auto-surfaces it.
- `TestPQ_HybridAcceptDispatchParity` (§5.5 finding 1) — the production accept-side inline dispatch (digest → batch → hybrid → else→HandleFrame) routes a hybrid frame to `HandleHybridFrame`, not `HandleFrame` (the review defect: a hybrid frame on an inbound conn was DropMalformed'd; the arm parity with `DispatchFrame` is regression-guarded).
- `TestPQ_HybridRateGateOrdering` (§5.5 finding 3) — an unarmed receiver (`hybridVerify=false`) rejects a hybrid frame (`DropVerify`) without decrementing the origin's rate budget (the DoS-amplifier close — the config gate precedes the rate gate and the Directory lookup).

**Identity hybrid-sign (`pkg/identity/hybrid_sign_test.go`):**
- `TestPQ_HybridSignThenVerify` — a both-sig frame over a real batchWire verifies under both signatures.
- `TestPQ_HybridSignClassicalReject` — a classical-sig-corrupt frame is rejected (the Ed25519 gate).
- `TestPQ_HybridSignPQReject` — a PQ-sig-corrupt frame is rejected (the ML-DSA-65 gate).
- `TestPQ_HybridPadDeterministic` — the SHAKE256 pad is deterministic (the same batchWire → the same pad).
- `TestPQ_HybridPadDistinct` — distinct batchWires → distinct pads (no collision).
- `TestPQ_HybridPadLen` — the pad is exactly 120 bytes (the `frame120` shape).
- `TestPQ_HybridSignBadSeed` / `TestPQ_HybridSignNilPQSk` / `TestPQ_HybridSignNilBatchWire` — the nil/bad-input guards fire (no hybrid sign on a nil PQ key or a nil batchWire).

**Identity hybrid-verify (`pkg/identity/hybrid_verify_test.go`, ADR-0036 re-run):**
- `TestPQ_HybridVerifyDual` / `TestPQ_HybridVerifyNilPQPub` / `TestPQ_HybridClassicalReject` / `TestPQ_HybridPQReject` / `TestPQ_HybridNilPQReject` / `TestPQ_HybridLenMismatch` / `TestPQ_HybridEitherOrControl` — the both-required gate (ADR-0036, re-run green after this change).

**Identity Directory both-pubkey (`pkg/identity/directory_pq_test.go`):**
- `TestPQ_DirRegisterPQBoth` / `TestPQ_DirLookupBothClassicalOnly` / `TestPQ_DirLookupBothMiss` / `TestPQ_DirRegisterPQNilReject` / `TestPQ_DirRegisterLookupUnchanged` — the `RegisterPQ` + `LookupBoth` provisioning (the classical `Register`/`Lookup` byte-identical to the prior behavior).

**Attribution wire-shape (`pkg/attribution/wire_hybrid_test.go`):**
- `TestPQ_HybridFrameWireShape` / `TestPQ_HybridFrameMarshal` / `TestPQ_HybridFrameIsHybrid` — the `HybridEnvelope` codec (`MarshalHybridFrame` + `UnmarshalHybridFrame` + `IsHybridFrame` + `WireHybridPQMagic`) — a new magic, not a touch of the core `envelope.go` (the same mold the digest frame used).

## §4 — The Wiring

**`pkg/identity/hybrid_sign.go` (new):** `SignCRDTFrame_Hybrid(edSeed, pqPriv, batchWire) → (edSig [64]byte, pqSig []byte, pad120 []byte)` — derives the 120-byte SHAKE256 pad via `HashBatchWireToFrame120`, signs under both Ed25519 and ML-DSA-65. `VerifyBatchHybrid(edPub, pqPub, batchWire, edSig, pqSig) → bool` — re-derives the pad and returns `edOK && pqOK` (the both gate). `HashBatchWireToFrame120(batchWire) → [120]byte` — the SHAKE256 pad helper (re-used from the earlier dynamic-digest probe).

**`pkg/identity/directory.go`:** the `mPQ map[[16]byte]*mldsa.PublicKey` field + `RegisterPQ(nodeID, pqPub)` + `LookupBoth(nodeID) → (edPub, pqPub)` — the hybrid-sign provisioning layer. The classical `Register`/`Lookup` are byte-identical to the prior behavior (the `mPQ` map is independent — a peer that registered only the classical key leaves `mPQ` unpopulated, so `LookupBoth` returns a nil `pqPub` and the hybrid verify rejects: the strict mode).

**`pkg/attribution/wire_v1.go`:** the `HybridEnvelope` struct + `MarshalHybridFrame` + `UnmarshalHybridFrame` + `IsHybridFrame` + `WireHybridPQMagic` — a new magic and a new frame shape (a new magic in `wire_v1.go`, not a touch of the core `envelope.go`). The `HybridEnvelope` carries the `originNodeID`, the `edSig`, the `pqSig`, the `originSeq`, the `batchCount`, and the verbatim `batchWire` (the same wire the v1 `BatchEnvelope` carries — byte-identity).

**`pkg/mesh/peer.go`:** the `NodeIdentity.PQPriv`/`PQPub` fields + `NewNodeIdentityHybrid(seed) → (*NodeIdentity, error)` (the PQ keypair derived from the same seed) + the `frameSink.HandleHybridFrame` interface arm.

**`pkg/mesh/gossip.go`:** the `hybridSign` opt-in knob + `SetHybridSign(bool)` + the sweep's `if g.batchSize > 1 || g.hybridSign` branch (the §2 fix — `--hybrid-sign` forces the batch path).

**`pkg/mesh/batch.go`:** `ShipBatchHybrid(ctx, peerID, events) → (shipped, entries, err)` + the `shipBatchedDelta` hybrid branch (`if g.hybridSign { b, e, err = g.ShipBatchHybrid(...) }`).

**`pkg/mesh/digest.go`:** `DispatchFrame`'s 4th arm (`IsHybridFrame → HandleHybridFrame`).

**`pkg/receive/receiver.go`:** the `SetHybridAcceptReporter(func())` seam (the `HybridFrameAccepted` counter fire on a both-verify accept). `HandleHybridFrame` verifies both signatures via `VerifyBatchHybrid` and fires the reporter on accept.

**`internal/telemetry/registry.go`:** the new counter `HybridFrameAccepted` (`supremum.hybrid.frame_accepted`, modeCounter — the gauge count is unchanged at 3) in all 4 sites (the field, `allCounters()`, `init()`, `rebuildCounters()` — the registry fill discipline).

**`cmd/sovereign-node/main.go`:** the `--hybrid-sign` flag (default false) + the `NewNodeIdentityHybrid` conditional (`if cfg.hybridSignEnable`) + `RegisterPQ(ident.NodeID, ident.PQPub)` + `gossiper.SetHybridSign(cfg.hybridSignEnable)` + `recv.SetHybridAcceptReporter(telemetry.HybridFrameAccepted.Inc)`.

## §5 — The Gates

- **build / gofmt / vet:** green (`go build ./...` + `go vet` clean; gofmt clean across the edited set).
- **Merge-law/wire-schema files:** `crdt.go` byte-identical (the hybrid-sign layer is a mesh/identity/attribution addition, not a CRDT/data-layer change). The other core files are byte-unchanged.
- **fieldalignment:** zero new hot-path debt — the new structs (`HybridEnvelope`, `Directory.mPQ`, `NodeIdentity.PQPriv/PQPub`, `Gossiper.hybridSign`, `Receiver.onHybridAccept`, `pqHarness`) are all off the per-delta hot path with no contended atomics (the cache law — contended atomics on one cache line at 32 cores produce a HITM storm — is unchanged; the off-hot-path size findings are disclosed and accepted).
- **`TestHotPathZeroAllocations`:** green (the hybrid sign/verify and the frame codec are off the per-delta hot path; the PQ sign is per-batch, amortized over N deltas).
- **The new tests:** green under `-race` (no data race — the `hybridSign`/`hybridVerify`/`onHybridAccept` seams are race-free; the single-writer-before-reader discipline holds).
- **The distinct-counter tests:** green, updated for the new counter.
- **`go.sum` neutrality:** green — the build is `go.sum`-neutral (an earlier gratuitous 71-line stale-checksum cleanup modified `go.sum` unnecessarily; it was reverted to HEAD and the build passes `go.sum`-clean).
- **Runtime verification:** pass 6/6 (a harness driving the real binary): the moat-armed binary (`--hybrid-sign` + `--hybrid-verify`) boots and the read-your-writes seam is byte-identical (insert → immediate query → 200 + immediate range → 200 + delete → 404 + `supremum_query_live_source_reads` == 3 + durable tier empty) + `supremum_hybrid_frame_accepted` present on /metrics (the new counter auto-surfaced with zero bridge edit — presence, not value; the counter is 0 single-node by construction, and the counter firing is proven by the `TestPQ_HybridE2EConverges` in-process test, acceptA=5 acceptB=5). The ADR-0036 harness re-run on this binary passes 7/7 (the read seam, the PQ-KEM proof, and the KEM counter unchanged — no regression).

## §5.5 — The Review Fixes (production accept-path parity + the DoS-amplifier close)

A code review pass over the change (15 findings, each verified against the source) surfaced 4 load-bearing production defects that the in-process tests and the single-node runtime verification had masked (the tests use `DispatchFrame`, the 4-way router; the production accept side had its own inline dispatch). All fixed and regression-guarded:

1. **The accept-side dispatch asymmetry** (`cmd/sovereign-node/main.go serveConnWithDigest`): the production accept-side inline dispatch was 3-way (digest → batch → else→HandleFrame) with no `IsHybridFrame` arm, so a hybrid frame on an inbound connection fell through to `HandleFrame`: the RelayEnvelope parser saw `WireHybridPQMagic` (`SHYB`) rather than the `0x02/0x03` version prefix → `DropMalformed` → the hybrid delta was silently dropped on the accept side and `HybridFrameAccepted` never fired on inbound conns. The dial-side `readLoop` (peer.go) and the test `serveTestConn` both call `DispatchFrame` (which has the arm), so the tests and the in-process harness masked it. Fix: added the `IsHybridFrame → HandleHybridFrame` arm to the inline dispatch (4-way parity with `DispatchFrame`). Regression test: **`TestPQ_HybridAcceptDispatchParity`** (replicates the exact production inline-dispatch order and asserts a hybrid frame routes to `HandleHybridFrame`, not `HandleFrame`).

2. **The `HybridAcceptCount` gap** (`pkg/receive/batch_handle.go`): `BatchAcceptCount` parses `UnmarshalBatchEnvelope` (WireV1Magic) and returns 0 on a hybrid frame (WireHybridPQMagic mismatch). There was no `HybridAcceptCount` sibling, so even after fix #1 the per-delta verdict counter `sovereign_ingest_verdicts_total` would record 0 deltas per accepted hybrid batch, undercounting hybrid ingest by Nx. Fix: added `HybridAcceptCount` (parses `UnmarshalHybridFrame` and returns `env.BatchCount()` — the same per-delta accounting the v1 batch path uses, on the hybrid frame shape). Wired into the new accept-side `IsHybridFrame` arm.

3. **The rate-gate-before-config-reject DoS amplifier** (`pkg/receive/receiver.go HandleHybridFrame`): the `!r.hybridVerify` reject ran after the `preAdvance` engine read, the rate gate (`r.bucket.Accept`, which mutates the per-origin budget), the `LookupBoth` RLock, and two map reads, so a `--hybrid-sign` peer dialing a `--hybrid-verify=OFF` (the default) peer drained the origin's rate budget on a guaranteed-reject frame — in a mixed-fleet rolling deploy a hybrid-sign node would burn every not-yet-hybrid-verify peer's budget while converging nothing. Worse, a spoofed hybrid frame with a forged victim `originNodeID` drained the victim's budget on a default-config node with zero crypto work. Fix: hoisted the config gate to step 0 (the very top of `HandleHybridFrame`, before the `preAdvance` engine read, the unmarshal, the rate gate, and the lookup) — an unarmed receiver rejects a hybrid frame with zero side effects. Regression test: **`TestPQ_HybridRateGateOrdering`** (a real `admission.PeerBucket`, pre-seeded; asserts an unarmed receiver returns `DropVerify` without decrementing the origin's budget — `before == after`).

4. **The gratuitous `go.sum` modification:** an earlier 71-line stale-checksum cleanup modified `go.sum` when the change needed no dependency add/remove. The build is go.sum-neutral (passes with `go.sum` reverted to HEAD). Fix: reverted `go.sum` to HEAD. (Separately, pre-existing: `go.mod` marks `golang.org/x/crypto` `// indirect` despite the direct `sha3` import — a `go mod tidy` produces a 23-line diff; shipping `go.mod` unchanged is fine, but it is a latent drift a CI `go mod tidy -diff` would catch — disclosed as future work, not fixed here, to keep the diff scoped.)

**Plus the honesty fixes** (report numbers, not adjectives; verify before claiming):

5. **The sign-vs-verify cost conflation** (`pkg/mesh/batch.go` + `gossip.go`): the comments cited "73.7µs PQ sign", but 73.7µs (73,662 ns/op) is the ML-DSA-65 **verify** bench; the real **sign** is ~585.8µs (585,837 ns/op) — the hybrid send path is ~8x more expensive than the comments claimed. Fixed to cite the 585.8µs sign cost (the 73.7µs verify is named separately).

6. **The nonexistent sign-cost test cite** (`pkg/identity/hybrid_sign.go` + `pkg/attribution/wire_v1.go`): the comments claimed the 585,837 sign cost was re-recorded in a dedicated test, but no such test or bench exists in the test set (the E2E tests are convergence / byte-identity / strict-mode / dispatch). Fixed: the 585,837 number is an honest ADR-0036-era cited measurement, not a fresh measurement.

7. **The `LookupBoth` ok-semantics doc/code mismatch** (`pkg/identity/directory.go`): the doc claimed a RegisterPQ-only peer returns `(nil, pqPub, true)`, but the code sources `ok` exclusively from the classical map (`d.m`), so a RegisterPQ-only peer returns `ok=false` (a Directory miss). Fixed the doc to match the code (a RegisterPQ-only peer is an unsupported posture that reports `ok=false`).

8. **The unchecked type assertion** (`pkg/mesh/peer.go NewNodeIdentityHybrid`): `pqPriv.Public().(*mldsa.PublicKey)` was an unchecked assertion on the `crypto.PublicKey` interface; a future KMS/HSM-backed `mldsa.PrivateKey` (future work) could return a non-`*mldsa.PublicKey` from `Public()` and panic at boot. Fixed: use the concrete `pqPriv.PublicKey()` getter (mldsa.go:139 — returns `*PublicKey` directly, no assertion).

9. **The stale receiver.go line cites** (`cmd/sovereign-node/main.go` + `pkg/receive/receiver.go` + `batch_handle.go`): three comment blocks cited stale `HandleFrame`/`HandleBatchFrame` line numbers after the hybrid fields shifted the lines. Fixed all cites.

**Findings disclosed, not fixed here** (lower severity / pre-existing / out of scope): the ~60µs wasted classical verify on v1 frames under `--hybrid-verify` (efficiency — the simpler `if r.hybridVerify { DropVerify }` for a v1 frame is future work); the asymmetric `Register`/`RegisterPQ` error handling (the classical error-discard is pre-existing; the `RegisterPQ` `log.Fatalf` is the addition here — making Register fatal too is a separate hardening change); the shared-seed Ed25519+ML-DSA-65 derivation (a documented design choice, "one identity space flat" — the key-compromise independence is overstated, the sig-forgery independence holds; a separate-seed change is future work); the HybridEnvelope header duplication of the BatchEnvelope header (simplification, latent drift risk; a `writeBatchHeader` helper is a future refactor); the batchSeq-hole-on-Publish-failure (pre-existing, matches ShipBatch's behavior, not a regression introduced here).

## §6 — Known Limitations / Future Work

- **Out-of-band peer-pubkey provisioning** (directory gossip — peer-pubkey propagation via the mesh; this change assumes a statically provisioned Directory).
- **The node's mesh peer-dial loop** (the pre-existing stub — the boot log still prints "dial loop pending "; the two-node binary mesh cannot converge until that lands; the in-process `pqHarness` drives the dial via `psA.Dial` directly, bypassing the stub).
- **The silicon-scale 100-node hybrid-mesh bandwidth gate** (future AWS work — the 585.8µs ML-DSA-65 sign per batch at 32 cores, the 73.7µs verify per batch, and the 3309-byte ML-DSA-65 signature wire cost, 51.7x vs Ed25519's 64 bytes; the sign-vs-verify cost distinction is the §5.5 honesty fix).
- **The production-path hybrid sign via a KMS/HSM minter** (the `RotationMinter` precedent from ADR-0035 — the PQ private key in an HSM, not on disk).
- **The delta-CRL/Bloom fast path for PQ cert revocation** (the ADR-0035 future work extended to the PQ layer).
- **The hybrid sign on the relay/foreign path** (the self-origin boundary — a relayer cannot re-origin-sign a foreign delta under either signature; the hybrid sign is self-origin only).

## §7 — The Counter

The new telemetry counter `HybridFrameAccepted` (`supremum.hybrid.frame_accepted`, modeCounter) is the externally visible proof the moat is in use. The bridge auto-surfaces it (zero bridge edit; the bridge enumerates `telemetry.Counters()` and maps the name via dots → underscores). The counter is 0 on a single-node run (no mesh peers); the counter firing is proven by the `TestPQ_HybridE2EConverges` in-process test (the 2-node loopback mesh-dial proof, acceptA=5 acceptB=5). The gauge count is unchanged at 3 (the counter is a modeCounter, not a gauge). The distinct-counter tests across the affected packages are updated for the new counter.
