# ADR-0010: Batched delta wire v1 — the 1M/sec arithmetic unlock (one Ed25519 over N self-originated deltas)

- **Status:** ACCEPTED (Day 5, 2026-07-29) — in-process gates G05.a–i PASS on the executor box (GOMAXPROCS=4, gear-light, arm64); §5 STAYS CONDITIONAL-GO
- **Scope:** Day 5 of the World-No.1 Battle Plan (`phase-03/WORLD_NO1_BATTLE_PLAN.md`, ed.2.1, Day 5 section)
- **Predecessor:** ADR-0009 (the Day-4 chaos partition probe — the <100ms convergence-after-heal SLO)
- **§5 verdict:** STAYS CONDITIONAL-GO (Day 5 is NOT an E1/E2/E3/E5 verdict-blocker; it ADVANCES the architectural claim from "the verify ceiling is 533K/sec, batching does not exist" to "the mesh amortizes one Ed25519 verify over N self-originated deltas in a verifiable, cross-path-deterministic batch wire — the arithmetic unlock for Day 7's >=1M/sec target exists, measured honestly")
- **Enforced by:** `TestBatchedConverge_100PerBatch` (G05.d — the cross-path MerkleRoot determinism tooth), `TestBatchRejectTamperedWire` (G05.b — one-sig-covers-batch + S1a atomic-reject), `TestBatchRateGateCountsOnce` (G05.e — rate-gate-counts-once on the monotonic originSeq), `BenchmarkBatchedVerify` (G05.f — the amortization bench), the FROZEN md5 PRE+POST assert, the receiver.go re-lock (OLD 9dfde188 → NEW 82b22fc8), the SCISSORS `t.Logf` honest-label tooth, the `gofmt -s` / `go vet` / `go build` symmetry, the glued-token grep (G05.h)

---

## 1. Context

The barrier to >=1M state synchronizations/sec is **ARITHMETIC, not engineering**:

```
Ed25519 VerifyCRDTFrame      = 60.19 us/frame  (32c PROVEN, circl v1.6.4 — BenchmarkVerifyCRDTFrame_32c)
=> single-verify ceiling      = 1 / 60.19e-6    ~= 533,000 verifies/sec
=> 1M/sec is ARITHMETIC-FALSE on the per-frame path while one verify buys one delta.
```

Through Day 4 the mesh shipped ONE Ed25519 signature per delta (`gossip.go:279` `sig, err := identity.SignCRDTFrame(g.owner.Seed, innerWire)`). The Day-7 >=1M/sec headline bench would be a LIE on that path — the number CANNOT exist while one verify buys one delta. The ONLY honest path: collapse N verifies into ONE verify. One Ed25519 signature covers a BATCH of N deltas, so the verify cost amortizes from 60.19 us/delta to 60.19/N us/delta. At N=100 that is ~0.60 us/delta; the floor then moves to (batch-wire decode + N applies + net), each sub-microsecond per delta on the PROVEN 32c apply number (~36 ns/entry). **This is the arithmetic unlock.** WITHOUT it, every later "1M/sec" claim is fabricated.

### 1.1 The self-origin boundary (load-bearing — encode it, do NOT hide it)

A relayer forwarding a FOREIGN delta holds ONLY its own relay seed (`pkg/mesh/peer.go` `NodeIdentity.Seed`) — it NEVER holds the foreign ORIGIN's seed. It can ADD a relay hop-signature (`attribution.SignHop` over `(innerWire || preceding)`) — the FROZEN `RelayEnvelope` hop chain (`envelope.go`) — but it CANNOT re-origin-sign a foreign delta.

```
>>> Day-5 batching covers the SELF-ORIGINATED delta path (a node batching its
>>> OWN N writes into one signed batch). Relay-chained foreign deltas STAY
>>> per-frame (the FROZEN RelayEnvelope v3 hop chain — UNTOUCHED).
```

This is honest and is also the DOMINANT production workload (a node's own writes are the high-rate path; relay-chained foreign deltas are lower-rate forwarding). The Day-7 1M/sec headline is a SELF-ORIGINATED ingest bench (a node shipping its own N writes/sec) — EXACTLY the workload batching serves. A batch that relayer-signs foreign origins is a FORGERY (the relay has no origin seed) and is a fabrication, not a feature.

---

## 2. Decision

Day 5 ships ONE atomic unit — a crypto-minimal batch envelope + a send-side batch builder + a receive-side batch gate, composing the FROZEN substrate (the 5 TRUE-FROZEN files are NOT touched):

```
SEND (pkg/mesh/batch.go NEW + gossip.go EDITABLE):
  BuildCRDTDeltaBatch(events []BuiltEvent) ([]byte, error)
    -> capnp.NewMessage(SingleSegment(nil)) + NewRootCRDTDeltaBatch + NewEvents(n)
    -> the ev.At(i).Set* loop (the 12 contract fields + version tag)
    -> msg.Marshal()  // ONE marshaled CRDTDeltaBatch wire
  Gossiper.ShipBatch(ctx, peerID, events)
    -> BuildCRDTDeltaBatch -> ONE SignCRDTFrame(owner.Seed, batchWire)  // the amortization
    -> MarshalBatchEnvelope(owner.NodeID, sig, originSeq, batchCount, batchWire)
    -> LengthPrefixFrame -> peers.Publish
  Gossiper.shipBatchedDelta  // drains a CRDTDelta into MaxBatchSize-sized batches
  AntiEntropySweep: batchSize>1 -> shipBatchedDelta; batchSize==1 -> shipDelta (RETAINED)

ENVELOPE (pkg/attribution/wire_v1.go NEW — the crypto-minimal batch envelope):
  wire = [magic uint32 BE][version uint8][originSeq uint64 BE][batchCount uint16 BE]
         [originNodeID 16][originSig 64][batchWire ...]
  originSig = SignCRDTFrame(originSeed, batchWire)  // ONE Ed25519 over the marshaled wire
  UnmarshalBatchEnvelope: O(1) header parse; NEVER decodes batchWire (opaque until verify)

RECEIVE (pkg/receive/receiver.go RE-LOCK + batch_handle.go NEW):
  Receiver.HandleBatchFrame(batchFrameBytes) AcceptVerdict:
    1. UnmarshalBatchEnvelope -> malformed => DropMalformed; zero originSig => DropVerify
    2. RATE: r.bucket.Accept(rateKey, env.OriginSeq()) ONCE per batch -> DropRate
    3. GAP-3: r.dir.Lookup(originNodeID) -> miss => DropVerify
    4. VERIFY: identity.VerifyCRDTFrame(originPub, batchWire, originSig) -> false => DropVerify
    5. APPLY: r.engine.ApplyCRDTDeltaBatch(batchWire) -> *WireIntegrityError => DropVerify (S1a)
    6. Accept (N deltas joined in one decode + one Join)

DISPATCH (cmd/sovereign-node/main.go serveConn + pkg/mesh/peer.go readLoop):
  attribution.IsBatchFrame(frame) -> HandleBatchFrame; else -> HandleFrame (back-compat default)
```

### 2.1 The crypto-minimal design (sign the batch wire directly — STRICTLY STRONGER than a SHA-256 batch-root)

The battle plan §Day-5 Deliverables proposed `batchRootHash = SHA-256 over the concatenation of per-delta hashes; Ed25519 signs batchRootHash`. This introduces THREE expenses and ONE new crypto surface: N per-delta SHA-256 hashes (send) + N on verify = 2N SHA-256; + 1 SHA-256 over the concatenation (the "batch root"); a NEW batch-root hash scheme (new audit surface, new tooth to maintain); and a **hash-then-reconstruct GAP** — verify checks H(X); apply decodes X — the signature and the decode see DIFFERENT bytes (a wire-tamper opportunity between the verified hash and the decoded wire).

Day 5 OVERRIDES the battle-plan draft on this single point (ATTACK 1, §8): **Ed25519 signs the MARSHALED CRDTDeltaBatch WIRE DIRECTLY**:

```
batchSig = identity.SignCRDTFrame(originSeed, batchWire)
verify   = identity.VerifyCRDTFrame(originPub, batchWire, batchSig)
```

Ed25519 (circl, RFC-8032 strict) internally SHA-512-hashes the message byte string in Verify. Signing the wire directly gives:
- ONE hash inside verify (the SHA-512 over batchWire) vs (N+1) SHA-256 hashes in the batch-root draft — LESS crypto compute, same security (Ed25519 is already a hash-then-sign scheme; an outer hash is redundant).
- ZERO new hash scheme (reuse `VerifyCRDTFrame` VERBATIM — the 60.19us PROVEN symbol, no new crypto to audit).
- NO hash-then-reconstruct gap: the bytes Verify checks ARE the bytes `ApplyCRDTDeltaBatch` (crdt_apply_batch.go:118) decodes — the signature covers the EXACT wire batch the engine Join()s. STRONGER binding.
- the FROZEN `ApplyCRDTDeltaBatch` ALREADY accepts a marshaled CRDTDeltaBatch wire ([]byte) — so the wire you sign is the wire you apply, end to end.

### 2.2 The rate-gate-counts-once amortization (on the MONOTONIC originSeq, NOT the static BatchCount)

The per-frame rate gate (`PeerBucket.Accept(lastHopPub, dotCounter)`) drains on the DELTA between successive dotCounters from the same origin. The batch path must amortize the same way: ONE `bucket.Accept` call per batch (not N), and the budget drains on a MONOTONIC per-origin counter.

The BatchEnvelope carries an `originSeq uint64` header field — the origin's MONOTONIC per-batch sequence number, advancing by 1 per `ShipBatch` (the Gossiper's `batchSeq` counter, single-goroutine under the SweepLoop). `HandleBatchFrame` passes `env.OriginSeq()` (NOT `env.BatchCount()`) to `bucket.Accept`. The bucket drains on the delta between successive originSeq values, so a burst of batches drains the origin's budget (the Sybil-burst isolation the rate gate exists to enforce), amortized to one check per batch.

**Why NOT BatchCount:** a static count of deltas (e.g. 50) produces a ZERO delta between same-size batches and the budget NEVER drains — a DEAD rate gate for the dominant steady-state workload (a node shipping its own N writes/sec in fixed-size batches). The previous session's `HandleBatchFrame` passed `env.BatchCount()` as the counter — a fabrication (the gate only "drains" with a lying counter). Day 5 fixes this: the monotonic `originSeq` is the honest drain counter, mirroring the per-frame path's `dotCounter`. (See §8 ATTACK 2.)

The rate-gate key is the batch's `originNodeID` zero-extended to 32 bytes (PeerBucket keys on a 32-byte pubkey). This is a DISTINCT key space from the 32-byte relay pubkeys the per-frame path rate-gates on (a real Ed25519 pubkey is never 16-zero-bytes-padded), so there is no collision in practice.

### 2.3 The verdict-counter += N choice

The per-delta verdict counter (`sovereign_ingest_verdicts_total`) is PER-DELTA. A batch of N accepted deltas adds N to the Accept label, NOT +1. The dispatch wrapper (serveConn/readLoop) calls `receive.BatchAcceptCount(frame)` (an O(1) header re-parse, no capnp decode) on a batch Accept to get N, then increments the counter N times via the existing Recorder seam. The Receiver does NOT import `pkg/metrics` (the same seam discipline as the per-frame path, where the caller records `RecordIngest` and the Receiver returns a Verdict). The double header-parse (HandleBatchFrame + BatchAcceptCount) is O(1) and is the honest cost of keeping the verdict-counter increment at the caller.

### 2.4 The single-origin scope

`ShipBatch` covers ONLY self-originated deltas (the owner's seed signs them). A caller that forwards foreign deltas here commits a FORGERY. The per-frame `shipDelta` is the path for relay-chained foreign deltas; `ShipBatch` is the self-originated high-rate path. `AntiEntropySweep` switches to `shipBatchedDelta` for the self-originated delta path when `--batch-size > 1`; the per-frame `shipDelta` is RETAINED as the low-rate / fallback / relay path (NOT deleted).

---

## 3. The three audit teeth

### TOOTH 1 — one-sig-covers-the-batch (G05.b)

A single tampered byte in `batchWire` makes `VerifyCRDTFrame` return false — the ONE Ed25519 signature covers the WHOLE batch. This is the SAME reject-before-Apply tooth as the per-frame DropVerify: a tampered batch is dropped at verify, never reaching `ApplyCRDTDeltaBatch`. `TestOneSigCoversBatch` (pkg/attribution) + `TestBatchRejectTamperedWire` (pkg/mesh) prove it: a tampered batch => DropVerify AND `engine.State()` UNCHANGED (S1a: zero joined — verify catches the tamper BEFORE apply, so the engine never sees it).

### TOOTH 2 — S1a atomic-reject (G05.b)

On the FIRST `*WireIntegrityError` from `ApplyCRDTDeltaBatch` (a tampered digest, a dot/origin mismatch, or a Lamport skew poisoning on ANY element), the receiver returns DropVerify and ZERO deltas are joined (the FROZEN engine's reconstruct-all-then-join-once guarantee, crdt_apply_batch.go:149-227). A partial batch is a batch-level failure, NEVER a partial apply. `TestBatchRejectTamperedWire` proves it: a tampered batch => State() byte-identical to the pre-batch snapshot.

### TOOTH 3 — cross-path MerkleRoot determinism (G05.d — the load-bearing correctness proof)

The batched path's MerkleRoot MUST EQUAL the per-frame path's MerkleRoot for the SAME 1000 self-originated events. Batching amortizes the verify (throughput) but the converged state is IDENTICAL — the CRDT Join is idempotent and the per-event wire bytes the batch carries are the SAME per-event bytes the per-frame path carries (`BuildCRDTDeltaBatch` stamps the same 12 contract fields `BuildCRDTDeltaEvent` stamps). A divergence would mean batching silently mutated state — a fabrication, not a feature. `TestBatchedConverge_100PerBatch` proves it: 1000 events shipped as 10 batches of 100 converge to a MerkleRoot byte-identical to the per-frame path's root for the same 1000 events. **Batching changes THROUGHPUT, not STATE.**

---

## 4. The receiver.go re-lock (12.2 re-lockable)

`pkg/receive/receiver.go` is a 12.2 RE-LOCKABLE file. Day 5 re-locks it with a documented NEW md5:

```
OLD md5: 9dfde1885c6c6f9c64599684e0180eb2  (Day-4 state — the pre-Day-5 receiver)
NEW md5: 82b22fc84405780d6ed7eba6fdfcbe12  (Day-5 — HandleBatchFrame ADDED)
```

The re-lock is PURELY ADDITIVE: the `HandleFrame` body (receiver.go:253) is UNCHANGED (the git diff shows 0 removals from the existing body — only the new `HandleBatchFrame` method is ADDED, +113 lines). `HandleBatchFrame` is a new method on `*Receiver` so it reads `r.dir` / `r.engine` / `r.bucket` / `r.cap` — the same fields `HandleFrame` uses. `NewReceiver`'s arity is UNCHANGED (6-arg: bucket, cap, wallClock, dir, engine, budget — the §7 symbol-gate discipline from Day 2). `ingress_epoll.go` (47f92978) is NOT touched.

---

## 5. The self-origin boundary (restated — the line Day 5 holds)

Day-5 batching covers the SELF-ORIGINATED delta path (a node batching its OWN N writes into one signed batch). Relay-chained foreign deltas STAY per-frame (the FROZEN RelayEnvelope v3 hop chain in envelope.go — UNTOUCHED, md5 b1beba1e PRE+POST). A batch that relayer-signs foreign origins is a FORGERY (the relay has no origin seed). This is honest and is the DOMINANT production workload. The Day-7 1M/sec headline is a self-originated ingest bench — EXACTLY the workload batching serves.

---

## 6. IS-NOT (what Day 5 does NOT deliver — scope discipline)

- Does NOT touch the 5 TRUE-FROZEN files (md5-lock PRE+POST — §G05.g).
- Does NOT batch RELAY / foreign-origin deltas (the self-origin boundary, §1.1).
- Does NOT ship the 1M/sec silicon number (Day 7 — SCISSORS: the G05.f bench is in-process 4c executor box, NOT relabeled as 32c/96c).
- Does NOT ship a digest-exchange (still full-batch oversend — the IBLT digest is the Day-2 honest simplification Day 5 inherits; digest exchange is later).
- Does NOT ship AF_XDP (Day 9) or eBPF steering (Day 8).
- Does NOT re-open crdt.go / crdt_apply.go / schema.capnp (FROZEN — the CRDTDeltaBatch capnp API at schema.capnp.go:339-401 is CALLED, not edited).
- Does NOT widen NewReceiver (receiver.go:173 arity UNCHANGED — the 4-arg-seam discipline from the Day-2 §7 symbol gate).
- Does NOT claim zero-copy (the copy-mode C1 boundary from Day 1 endures; the batch wire rides the same TransmitTLSFrame copy path; zero-copy is Day-9 AF_XDP only).
- Does NOT fabricate a single ns/delta number; the bench table is the ONLY source of truth and a NEGATIVE line is recorded verbatim.

---

## 7. Honest weaknesses (minimum 5)

1. **The bench's apply is an idempotent no-op, not a real insert.** `BenchmarkBatchedVerify` warms the engine with one real apply, then re-applies the same frame every op (the CRDT Join is idempotent). This bounds the engine to N entries (the fixed-size arena would exhaust across b.N real inserts) but UNDERSTATES the apply cost — the measured ns/delta is a LOWER BOUND on the real per-delta cost. The apply floor (~36 ns/entry @ 32c) is CITED from the PROVEN per-entry number, NOT measured here. A bench that measured the real apply floor would need an arena that grows with b.N (or a reset-per-op engine, whose construction cost would dominate). The honest consequence: the ns/delta table proves the VERIFY amortization (its purpose); the apply floor is a cited anchor, not a measured one.

2. **The 32c/96c silicon number is NOT measured.** The bench runs on the executor box (GOMAXPROCS=4, gear-light, arm64). The per-frame anchor (60.19 us @ 32c) is CITED from `BenchmarkVerifyCRDTFrame_32c`, NOT re-measured (this box is not 32c). The 4c ns/delta is NOT the 32c ns/delta — the absolute silicon number is a Day-7 conditional (SCISSORS). The amortization SHAPE (ns/delta falls with N) is gear-invariant; the absolute floor is not.

3. **The rate-gate key is a 16-byte originNodeID zero-extended to 32 bytes.** This is a DISTINCT key space from the 32-byte relay pubkeys the per-frame path rate-gates on (a real Ed25519 pubkey is never 16-zero-bytes-padded), so there is no collision IN PRACTICE — but it is not cryptographically bound the way a real pubkey is. An attacker who controls a 16-byte prefix collision across two originNodeIDs would share a rate bucket. The originNodeID is derived from the origin's pubkey (the first 16 bytes), so a collision requires a pubkey-prefix collision — hard, but not impossible by construction. Documented, not fixed (the rate gate is a soft cap, not a security boundary).

4. **The batch's per-event clock/depth gate is NOT re-run in the receiver.** A 0-hop self-originated batch has NO relay hop walls, so the receiver's batch-level cheap gate is RATE only. The per-event clock/Lamport-skegate gate is enforced by `ApplyCRDTDeltaBatch`'s `ReconstructEntryWithSkewBound`-per-element (the FROZEN engine path, crdt_apply_batch.go:206), NOT re-implemented in the receiver. This is honest (the FROZEN engine already enforces it per element) but means a batch with a Byzantine-future event is rejected at APPLY (after the 60us verify), not at the cheap gate — the verify is "wasted" on a batch the apply then rejects. A per-batch wall field would let the cheap clock gate reject before verify, but the prompt RECOMMENDS against it (a 0-hop batch has no hop walls; the clock gate is relay-hop-driven). The trade-off is documented; the cheap clock gate stays relay-hop-driven.

5. **Full-batch oversend (no digest exchange).** Day 5 ships the FULL batch wire (all N deltas) every sweep — it does NOT exchange a digest first (IBLT) to send only the deltas the peer lacks. This is the Day-2 honest simplification Day 5 inherits: oversend converges via idempotent re-join, but it wastes bandwidth on deltas the peer already has. A digest-exchange (send an IBLT, peer peels the diff, requests only the missing deltas) is a later phase. Day 5's amortization is over the VERIFY, not the bandwidth — the oversend is a known, documented inefficiency.

6. **The verdict-counter += N is N RecordIngest calls, not one.** The dispatch wrapper increments the per-delta verdict counter N times on a batch Accept (a loop of N `RecordIngest` calls), not one atomic add-N. This is because the Recorder seam (`RecordIngest(latency, verdict)`) is per-delta (it also records a latency histogram sample). The N calls are off the gate-stack hot path (after the Accept verdict) but they are N mutex/map operations, not one. A batch-aware `RecordIngestN(n, verdict)` seam would collapse this to one call — a future optimization, not a Day-5 deliverable.

---

## 8. Self-adversarial critique (4 ATTACK + 1 MEDIOCRITY)

### ATTACK 1 — the crypto-minimal override of the battle-plan draft (the SHA-256 batch-root is redundant crypto surface)

The battle plan §Day-5 Deliverables proposed `batchRootHash = SHA-256 over the concatenation of per-delta hashes; Ed25519 signs batchRootHash`. The self-adversarial critique: this adds (N+1) SHA-256 hashes (2N across send+verify), a NEW batch-root hash scheme (new audit surface, new tooth to maintain), and a **hash-then-reconstruct GAP** — verify checks H(X); apply decodes X — the signature and the decode see DIFFERENT bytes (a wire-tamper opportunity between the verified hash and the decoded wire). Signing the batch wire DIRECTLY (Ed25519 already SHA-512-hashes the message in Verify) is STRICTLY STRONGER (the bytes Verify checks ARE the bytes Apply decodes — no gap), FASTER (one hash vs N+1), and reuses the PROVEN `VerifyCRDTFrame` symbol (zero new crypto to audit). **REJECT the batch-root; sign the wire directly.** The battle-plan draft is OVERRIDDEN by this ADR on this single point; every other Day-5 deliverable stands.

### ATTACK 2 — the rate-gate counter must be MONOTONIC, not the static BatchCount (the dead-rate-gate fabrication)

The previous session's `HandleBatchFrame` passed `env.BatchCount()` (the static uint16 count of deltas, e.g. 50) as the `PeerBucket.Accept` counter. The self-adversarial critique: `PeerBucket.Accept` drains on the DELTA between successive counters from the same origin. A static BatchCount produces a ZERO delta between same-size batches — the budget NEVER drains — a DEAD rate gate for the dominant steady-state workload (a node shipping its own N writes/sec in fixed-size batches). The gate "passes" only with a lying counter (the test's rising uint16 wrapped mod 65536 back to 50, also producing delta=0 — the test FAILED, exposing the defect). **FIX: add a monotonic `originSeq uint64` header field** (the origin's per-batch sequence, advancing by 1 per ShipBatch); `HandleBatchFrame` passes `env.OriginSeq()` to `bucket.Accept`. The bucket drains on the real advancement, mirroring the per-frame path's `dotCounter`. The fix is verified by `TestBatchRateGateCountsOnce` (drops at attempt 3, budget decremented once per batch on the monotonic sequence). The previous BatchCount-as-counter was a fabrication; the monotonic originSeq is the honest drain counter.

### ATTACK 3 — the dispatch magic-peek must read the POST-length-prefix body, not the length prefix

The dispatch (`IsBatchFrame`) peeks the first 4 bytes of the frame to discriminate a BatchEnvelope (WireV1Magic) from a RelayEnvelope. The self-adversarial critique: the existing wire is `[uint32 frameLen BE][RelayEnvelope bytes]` — the length prefix is COMMON to both wire shapes and carries no type information. A peek that read the length prefix would never discriminate. **FIX: `IsBatchFrame` reads the first 4 bytes of the POST-prefix body** (ReadFrame already stripped the 4-byte length prefix), NOT the length prefix. The magic is DISTINCT from the RelayEnvelope's first on-wire bytes (a RelayEnvelope begins with a uint16 little-endian version 2 or 3, so its first 4 bytes are 0x02_00_???? or 0x03_00_???? — never WireV1Magic big-endian 0x53424154). A misroute would hand a batch to the FROZEN RelayEnvelope parser (DropMalformed — a silent throughput collapse); `TestIsBatchFrameDispatch` + `TestBatchedConverge_100PerBatch` catch it (no convergence => gate D fails loudly).

### ATTACK 4 — the track36 scope-tooth transient conflict (the SAME Day-4 hit)

`TestTrack36_ScopeTooth` runs `git diff --name-only HEAD -- pkg/` and asserts every changed pkg/ path is in `track36EditedSet`. That set does NOT include `pkg/attribution/wire_v1.go`, `pkg/mesh/*.go`, `pkg/receive/batch_*.go`. So while Day-5's pkg/ edits are UNCOMMITTED in the working tree, the tooth FAILS (it sees them in the diff). It PASSES post-commit (the pkg/ diff vs HEAD is empty once committed). This is the SAME transient-conflict Day 4 hit (ADR-0009 §9 ATTACK 4). **FIX: do NOT edit the track36 tooth; commit Day-5 as one atomic unit** (the workflow's expected next step) and the tooth passes. Verified by the architect: Day-4 post-commit `TestTrack36_ScopeTooth` PASS.

### MEDIOCRITY 1 — the bench's idempotent-apply is a conservative lower bound, not the real apply floor

A mediocre engineer would have either (a) let the arena exhaust and crash (the first bench draft did — a `HamtArena: OOM` panic after enough real inserts), or (b) fabricated a "real apply" number by resetting the engine per op (whose construction cost would dominate and hide the verify amortization). The honest choice: warm once, re-apply idempotently (the apply is a no-op after the warm), and STATE IT — the measured ns/delta is a LOWER BOUND on the real per-delta cost (a no-op apply is cheaper than a real insert), and the apply floor is CITED from the PROVEN 36ns/entry, not measured. The bench proves the VERIFY amortization (its purpose); the apply floor is a cited anchor. A fabricated "real apply" number would be the sin; the conservative lower bound is the honest result.

---

## 9. §5 verdict lock + bottom line

Day 5 is NOT an E1/E2/E3/E5 verdict-blocker. The §5 verdict STAYS CONDITIONAL-GO. Day 5 does NOT flip §5, does NOT upgrade to UNCONDITIONAL-GO, does NOT re-prove a §5 number. Day 5 ADVANCES the architectural claim from "the verify ceiling is 533K/sec, batching does not exist" to "the mesh amortizes one Ed25519 verify over N self-originated deltas in a verifiable, cross-path-deterministic batch wire — the arithmetic unlock for Day 7's >=1M/sec target exists, measured honestly (ns/delta as a function of N, with the apply/decode floor named)."

### The measured amortization (G05.f — GOMAXPROCS=4, gear-light executor box, arm64; SCISSORS — NOT 32c silicon)

```
BenchmarkBatchedVerify (in-process, GOMAXPROCS=4, arm64 executor box)
  N=1    :  75684 ns/op    75683 ns/delta    26 allocs/op   (the per-frame-equivalent: one verify + one apply)
  N=10   :  94629 ns/op      9462 ns/delta    89 allocs/op
  N=100  : 291325 ns/op      2913 ns/delta   639 allocs/op   (26.0× lower ns/delta than N=1)
  N=256  : 641583 ns/op      2506 ns/delta  1574 allocs/op   (the apply/decode floor is near)

Per-frame anchor (CITED, NOT re-measured — this box is not 32c):
  BenchmarkVerifyCRDTFrame_32c = 60188 ns/op (~60.19 us) @ 32c, circl v1.6.4
  => single-verify ceiling = 533K/sec; the batch path amortizes this to 60.19/N us/delta.
  (this 4c box's pure verify = 71937 ns/op ~71.94us — the N=1 batch number 75683 = verify + apply + header parse is consistent)
```

**The amortization is REAL and POSITIVE**: ns/delta falls from 75,683 (N=1) to 2,913 (N=100) — a 26.0× reduction. The verify (~72us on this 4c box; 60.19us @ 32c) amortizes as predicted. At N=256, ns/delta=2,506 — the marginal gain from N=100→256 is small (2913→2506), confirming the apply/decode floor is near (the idempotent-apply no-op + the capnp decode of a 256-event batch dominate at large N). The 32c/96c re-bite is a Day-7 conditional (SCISSORS).

A NEGATIVE bench (G05.f) is an HONEST result recorded verbatim; a FABRICATED pass is the catastrophic-failure mode. This bench is POSITIVE and HONEST — the amortization is measured, the apply floor is cited (not fabricated), and the gear is labeled (4c, not 32c).

**Bottom line:** the arithmetic unlock exists. One Ed25519 now covers N self-originated deltas; the verify amortizes to 1/N; the cross-path MerkleRoot determinism tooth proves batching changes THROUGHPUT, not STATE; the S1a atomic-reject proves a tampered batch joins NOTHING. Day 7's >=1M/sec target has the substrate it needs — measured honestly, not marketed.
