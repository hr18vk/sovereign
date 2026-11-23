# ADR-0010: Batched delta wire v1

- **Status:** Accepted; subset admission and acceptance accounting are amended by
  [ADR-0069](0069_trust_quintet.md).
- **Date:** 2026-07-29
- **Predecessor:** [ADR-0009](0009_chaos_partition_probe.md)

---

## Context

The mesh originally signed and verified every delta separately. The recorded
`BenchmarkVerifyCRDTFrame_32c` result was 60.19 µs per verification with circl
v1.6.4 on a 32-core host. Thirty-two concurrent verifications at that latency
imply an aggregate ceiling of about 533,000 verifications/sec when each
verification admits only one delta.

Signing one batch of N self-originated deltas changes the verification component
to 60.19/N µs per delta. At N=100 that component is approximately 0.60 µs; batch
decoding, N CRDT applications, and network costs remain. The earlier 32-core
in-process apply measurement of approximately 36 ns/entry is a different layer
and does not include those receive-path costs.

This decision supplies a batch wire and receive path. It does not itself
establish the later >=1M deltas/sec target on multi-core hardware.

### Self-originated deltas only

A relayer has its own seed, not the seed of the origin whose delta it forwards.
It can add `attribution.SignHop` over `(innerWire || preceding)` to a
`RelayEnvelope`, but it cannot produce a valid origin signature for that delta.

`BatchEnvelope` therefore covers only deltas originated and signed by one node.
Relay-chained foreign deltas retain the per-frame `RelayEnvelope` v3 path. A
batch signature produced by a relayer for somebody else's origin would be a
forgery, not an alternative batching mode.

---

## Decision

### Batch construction and framing

`BuildCRDTDeltaBatch(events []BuiltEvent)` serializes the same 12 event fields
as `BuildCRDTDeltaEvent` into one Cap'n Proto `CRDTDeltaBatch`.
`Gossiper.ShipBatch` signs those marshaled bytes once with the owner's seed,
adds the origin identity, monotonic sequence, and declared count, then publishes
the result through the ordinary length-prefixed transport.

The version 1 envelope has this layout:

```
[magic uint32 BE][version uint8][originSeq uint64 BE][batchCount uint16 BE]
[originNodeID 16][originSig 64][batchWire ...]
```

`UnmarshalBatchEnvelope` parses the fixed header but leaves `batchWire` opaque
until signature verification. `IsBatchFrame` reads the first four bytes after
the transport has removed the length prefix. Its big-endian magic `0x53424154`
cannot be confused with the little-endian version 2 or 3 prefix of a relay
frame.

`AntiEntropySweep` uses the batched path when `--batch-size > 1` and retains
`shipDelta` for relay, fallback, and `--batch-size=1` operation. The default
batch size is 100 and `MaxBatchSize` is 256.

### Receive path

`Receiver.HandleBatchFrame` performs these steps:

1. Parse the header; malformed input returns `DropMalformed`, and an unsigned
   batch returns `DropVerify`.
2. Charge `PeerBucket.Accept` once using the zero-extended origin node ID and
   `OriginSeq`.
3. Resolve the origin through `Directory.Lookup` and verify one Ed25519
   signature over `batchWire`.
4. Commit the rate-gate high-water mark after authentication, then call
   `ApplyCRDTDeltaBatch` on exactly the verified bytes.
5. Return `AcceptVerdict.Accepted` with the number of elements actually joined.

Directory and signature failures refund the pre-authentication charge. Strict
`--hybrid-verify` mode rejects this classical-only envelope because it does not
carry the required ML-DSA-65 signature.

### Sign the batch bytes directly

An earlier design hashed each delta, hashed the concatenation into a batch root,
and signed that root. Across sending and verification this required 2N per-delta
SHA-256 operations plus the root calculation. It also introduced a gap between
the bytes covered by the signature and the bytes later decoded for application.

The adopted design calls the existing functions on the marshaled batch itself:

```
batchSig = identity.SignCRDTFrame(originSeed, batchWire)
verify   = identity.VerifyCRDTFrame(originPub, batchWire, batchSig)
```

Ed25519 already hashes the message with SHA-512 as specified by RFC 8032. Direct
signing avoids the extra hash construction, reuses `VerifyCRDTFrame`, and binds
the signature to the exact bytes passed to `ApplyCRDTDeltaBatch`.

### Charge once per batch with a monotonic sequence

`PeerBucket.Accept` charges the difference between successive counters. A fixed
`BatchCount`, such as 50 for every batch, produces a zero difference and would
never drain the budget. `originSeq uint64` therefore advances by one for every
`ShipBatch`, and `HandleBatchFrame` passes that value to `Accept` once per
batch.

The bucket key is the 16-byte `originNodeID` zero-extended to 32 bytes. The
trailing zeroes distinguish this key space from relay public keys in practice,
although the rate key is not a cryptographic replacement for origin signature
verification. Directory and signature failures refund the charge; a verified
batch that fails during application remains charged.

### Count joined deltas, not the declared batch size

`sovereign_ingest_verdicts_total` remains a per-delta counter. The dispatcher
uses `AcceptVerdict.Accepted`, which contains `BatchApplyResult.Joined`, rather
than reparsing the header's declared count. Held or otherwise unjoined elements
do not inflate the accept count. The former `BatchAcceptCount` and
`HybridAcceptCount` helpers were removed by [ADR-0069](0069_trust_quintet.md).

The receiver still returns a verdict rather than importing `pkg/metrics`; the
caller performs the metrics recording.

---

### Preserve integrity and state equivalence

One signature covers every byte of `batchWire`, so tampering fails verification
before application. Digest, attribution, version, and wire-read integrity errors
retain whole-batch atomic rejection: no accumulated element joins.

[ADR-0069](0069_trust_quintet.md) changes only the treatment of
`WireIntegrityLamportSkewPoisoning`. An over-bound element is held while the
in-window subset joins through one `Join` call. A fully held non-empty batch
returns `DropVerify`; an empty batch is an accepted no-op. A partially held
batch is not retained for relay because its single signature cannot be split to
cover only the joined subset.

Batching must not change the converged state. `BuildCRDTDeltaBatch` stamps the
same 12 event fields as `BuildCRDTDeltaEvent`, and the regression suite compares
the batched and per-frame Merkle roots for the same 1000 self-originated events.

---

## Consequences

- Batching applies to self-originated deltas only. Relay envelopes and the
  per-frame fallback remain available.
- `NewReceiver` keeps its existing constructor signature. `HandleBatchFrame`
  uses the same directory, engine, rate bucket, and clock cap as `HandleFrame`.
- The batch wire uses the existing copy-mode TLS transmission path. This
  decision does not add zero-copy transport, AF_XDP, or eBPF steering.
- The 32-core and 96-core throughput targets were not measured by the four-core
  in-process benchmark. Verification amortization does not remove decode,
  application, allocation, or network costs.
- The rate key is a zero-extended 16-byte origin ID. Two origins with the same
  16-byte public-key prefix would share a bucket; the rate gate is a soft cap,
  not the origin authentication boundary.
- A bad per-event clock or Lamport value is detected during application after
  signature verification. There is no relay-hop wall field on a zero-hop batch
  that would support an equivalent earlier clock check.
- The original sender shipped full batches without a digest exchange, allowing
  idempotent re-join at the cost of duplicate bandwidth. Verification
  amortization did not address that oversend.

---

## Evidence

### Correctness and admission tests

- `TestOneSigCoversBatch` in `pkg/attribution/wire_v1_test.go` checks that
  changing signed batch bytes invalidates the signature.
  `TestIsBatchFrameDispatch` checks recognition after length-prefix removal.
- `TestBatchRejectTamperedWire` in `pkg/mesh/batch_test.go` checks rejection
  before state changes. `TestBatchRateGateCountsOnce` checks one budget charge
  per batch on the monotonic sequence.
- `TestBatchedConverge_100PerBatch` sends 1000 events as 10 batches of 100 and
  compares the resulting Merkle root with the per-frame path for the same 1000
  events.
- `TestSubsetAdmission_NonSkewDigestPreserved` in
  `pkg/receive/admission_trust_test.go` checks that digest corruption still
  rejects the whole batch with zero joins after subset skew admission was
  introduced. `TestSubsetAdmission_AdversarialBatch` checks that valid elements
  join while over-bound elements are held.

### Recorded verification benchmark

`BenchmarkBatchedVerify` was recorded in-process with `GOMAXPROCS=4` on a
four-core arm64 development host:

| N | ns/op | ns/delta | allocs/op |
|---:|---:|---:|---:|
| 1 | 75,684 | 75,683 | 26 |
| 10 | 94,629 | 9,462 | 89 |
| 100 | 291,325 | 2,913 | 639 |
| 256 | 641,583 | 2,506 | 1,574 |

At N=100 the recorded ns/delta was 26.0× lower than at N=1. The smaller gain
from N=100 to N=256 is consistent with decode and idempotent application taking
a larger share of the remaining time.

These are not 32-core or 96-core results. The separately recorded
`BenchmarkVerifyCRDTFrame_32c` anchor was 60,188 ns/op, approximately 60.19 µs,
with circl v1.6.4. The four-core host's pure verification result was 71,937
ns/op, approximately 71.94 µs.

The benchmark warms the engine with one real application and then reapplies the
same frame. This keeps the fixed-size arena from exhausting across benchmark
iterations, but subsequent applications are idempotent no-ops. The table
therefore establishes verification amortization and is a lower bound on real
per-delta receive cost, not a measurement of new-insert application cost. The
separate ~36 ns/entry figure is a cited 32-core in-process apply measurement,
not a result from this four-core benchmark. Resetting the engine for every
iteration would instead put construction cost into the measurement.
