# ADR-0014: Ingest-path allocation hardening: value-return seam and zero-copy payload read

Status: Accepted
Date: 2026-08-01

## 1. Context

The receive path verifies an Ed25519 signature, decodes a Cap'n Proto envelope,
reconstructs each CRDT entry, and joins the batch. This decision concerns the
in-process `BenchmarkBatchedVerifyParallel/shared/N=100` benchmark, measured on
four cores with `-cpu=4 -count=3`. It does not concern the CRDT core benchmark
or multi-node convergence.

Two allocation hypotheses needed separate measurements. A proposed rate-gate
change had been credited with a roughly 7× throughput increase, but that
comparison also changed the batch size from N=1 to N=100 and moved from 31K to
966K deltas/sec. It therefore measured verification amortization as well as the
rate gate. With batch size held at N=100 on four cores, the shared benchmark
reached 966,183 deltas/sec and the ceiling sub-benchmark reached 761,614
deltas/sec. The latter also changes engine construction and cache behavior, so
it does not isolate the cost of the rate-gate mutex.

The other hypothesis attributed a 15.7% allocation reduction to hashing the
payload through `ev.PayloadBytes()` instead of `ev.Payload()` followed by
`[]byte(payload)`. An isolated run with the zero-copy read and the old pointer
return measured 638 allocs/op and 126,305 B/op, against a baseline of 638
allocs/op and 126,260 B/op. Go's escape analysis showed that the old conversion
inside the `sha256.Sum256` argument did not escape. It was already
stack-allocated; the zero-copy accessor did not remove a heap allocation.

A flat `alloc_objects` profile at N=100 located the measured allocations as
follows:

| Source | Share | Reason |
|---|---:|---|
| `Join.func3` | 35% | closure append in `(*DeltaCRDTEngine).Join` |
| `capnp.Ptr.Text` | 27% | string copies: 12% for `EntityId`, 15% for `Payload` |
| `ReconstructEntry` | 13% | returned `*ReconstructedEntry` |
| circl `ed25519.Verify` | 2.22% | amortized over the batch |

The entity ID remains in Join's `Seq`; the payload is checked and then discarded
by the production apply paths. Signature verification was not the allocation
driver in this profile.

## 2. Decision

### Hash the payload through the zero-copy accessor

`ReconstructEntry` uses `ev.PayloadBytes()`, which reaches Cap'n Proto's
`Ptr.TextBytes()` and returns a slice backed by the message segment.
`sha256.Sum256` consumes those bytes directly. The returned `Payload` field is
still materialized once with `string(payloadBytes)` before the function returns.

This change makes the copy boundary explicit and provides the seam for later
arena-backed work. It is not credited with an allocation reduction: the
isolated A/B measurement found none.

### Return reconstructed entries by value

`ReconstructEntry` and `ReconstructEntryWithSkewBound` return
`ReconstructedEntry` rather than `*ReconstructedEntry`. Errors return
`ReconstructedEntry{}`. The apply paths read `rec.Entry.OriginNodeID`,
`rec.EntityID`, and `rec.Entry` directly, without a pointer or nil check.
Tests compare against the zero value; the struct is comparable because it
contains two strings and an all-value `CRDTEntry`.

This removed the returned-pointer allocation and accounts for the measured
integrated reduction from 638 to 538 allocs/op. The per-call probe fell from 4
to 2 allocs/op. The two measurements are at different layers, so the per-call
reduction cannot be multiplied by the batch size to predict the integrated
result.

### Retain the rate-gate mutex

The proposal to pack the budget and counter into one atomic word was rejected.
The per-shard mutex keeps the budget and full-width counter coherent; section 5
records the correctness failures of the proposed alternatives. At N=100 the
gate runs once per batch, and its measured cost was 0.035% of per-delta cost
with 0 allocations.

## 3. Evidence and verification

The integrated benchmark used:

```bash
go test -run '^$' -bench=BenchmarkBatchedVerifyParallel -benchmem \
  -count=3 -cpu=4 ./pkg/receive/
```

`testing.AllocsPerRun` ran the per-call probe 100 times and observed 2.00
allocs/op for this decision. The current regression test is
`TestZeroCopyPayloadAllocReduction`: it requires fewer than the old baseline of
4 allocs/op and compares the reconstructed payload and digest with the source
payload. The decision's negative control restored the pointer return and
returned the probe to 4 allocs/op.

The integrity behavior was exercised under `-race -count=1 -cpu=4` by
`TestReconstructEntryRejects`, `TestApplyCRDTDeltaEventRejects`,
`TestApplyCRDTDeltaBatchRejects`, `TestLamportSkewBoundRejects`, and
`TestLamportSnapshotCoherence`. Build, vet, formatting, and escape-analysis
checks accompanied those tests. `go build -gcflags="-m"` showed the old
`&ReconstructedEntry{...}` escape disappear; the retained
`string(payloadBytes)` still escapes as expected.

The original rate-gate test glob did not name a real test. Current coverage of
budget saturation, peer isolation, and concurrent admission is provided by
`TestPeerBucket_HonestPeerKeepsBudget`, `TestPeerBucket_AttackerDrainsToZero`,
`TestPeerBucket_SybilIsolation`, and `TestPeerBucket_ConcurrentAdmitNoRace`.

These are the checks recorded for the decision, not a new benchmark run on the
v0.2.0 tree.

## 4. Remaining allocations at the decision point

At the time of this decision, 47% of the baseline 638 allocs/op remained in
Join and its input accumulator: 35% in `Join.func3` and 12% in
`make([]batchPair, 0, n)`. The `EntityId` string retained by `Seq` and the
payload string retained by `ReconstructedEntry` also remained. This change did
not make ingest allocation-free.

That historical Join limit was subsequently addressed by
[ADR-0015](0015_join_unfreeze_pool.md), which pooled Join buffers and merge
scratch, and [ADR-0022](0022_zero_alloc_join.md), which replaced the reflective
sort with `slices.SortFunc` and a non-capturing comparator. The current code
contains both changes. For a later, separate measurement, the
[Ed25519 ingest receipt](../../evidence/ingest-ed25519.txt) records 327
allocs/op for `shared/N=100` on a 32-core c8g.8xlarge on 2026-09-15. That result
has different code and hardware conditions and is not a rerun of this ADR's
four-core comparison.

## 5. Why the rate-gate CAS proposal was rejected

The proposed single `atomic.Uint64` packed the budget into its high 32 bits and
`lastCounter` into its low 32 bits. `lastCounter` represents a 64-bit
`DotCounter`; truncation wraps after 2^32 counter values. That is approximately
75 seconds at 57M ops/s, or 71 minutes at 1M dots/s.

After a wrap, `counter <= prev` can produce a zero delta and admit a peer
without charging its budget. A truncated previous value can instead produce a
large false delta and spuriously drop the peer. Losing the high counter bits is
thus a correctness and admission-control failure, not a precision trade-off.

Using separate atomic words for `budget` and `lastCounter` does not solve the
problem. Concurrent callers in one shard can observe or update one without the
other, losing budget deductions and breaking linearizability. A coherent paired
update would require a 128-bit CAS, which Go does not provide natively. An
`atomic.Pointer` to replacement state would add allocation, garbage-collection,
and memory-barrier costs to remove a mutex measured at 0.035% of per-delta cost
and 0 allocations on the N=100 path.

The mutex therefore stayed. Later changes added authenticated watermark commits
and refunds through `CommitHWM` and `Refund`; they retain the same per-shard
coherence requirement rather than adopting the rejected packed representation.

## 6. Measured result

The four-core, N=100 comparison produced these allocation results:

| Measurement | Baseline | Zero-copy read only | Zero-copy read and value return |
|---|---:|---:|---:|
| Allocations | 638 allocs/op | 638 allocs/op | 538 allocs/op |
| Bytes | 126,260 B/op | 126,305 B/op | 110,256–112,371 B/op |

The combined post-change runs averaged approximately 111,657 B/op; one recorded
run was 110,273 B/op. Relative to baseline, the combined change removed 100
allocs/op (15.7%) and 14,603 B/op (11.6%). The isolated measurements attribute
the allocation reduction to the value return, not the zero-copy read.

Baseline throughput across three runs was 707,714–771,604
aggregate_deltas/sec, with a median of approximately 748K. After both changes,
three runs covered 807,754–928,505 aggregate_deltas/sec, with a median of
approximately 829K. The apparent 11% median increase is not claimed as a
throughput improvement. Across all six runs, the approximately ±15% variation
associated with cache warmth is larger than that difference. The decision rests
on allocation counts, not throughput.

## 7. Consequences and limitations

(a) The original 47% Join-and-accumulator share was a residual of this change,
not a permanent ceiling. ADR-0015 and ADR-0022 supersede that part of the
analysis.

(b) The `EntityId` string allocation, 12% of the original flat profile, remains
because Join's `Seq` retains the key. The zero-copy payload read does not address
it.

(c) circl verification accounted for 2.22% of allocations in the original
profile and is amortized across a batch. Pooling verify buffers was not
justified by that profile.

(d) The rate-gate mutex remains on the admission path. Its measured cost does
not justify a representation that truncates counters or loses paired updates.

(e) The ceiling sub-benchmark changes engine construction and cache behavior in
addition to admission behavior. It is not a clean measurement of mutex removal.

(f) `PayloadBytes` aliases the Cap'n Proto segment. The message must remain
alive while the hash is computed. `ReconstructEntry` finishes the hash and
copies the payload into an independently owned string before returning, so the
returned entry does not retain a segment alias. Callers keep their deferred
`msg.Release()`.

(g) `ReconstructedEntry.Payload` remains a string even though the production
apply paths discard it after validation. Reconstruction tests use the field to
check payload fidelity. Removing that copy requires a separate API and test
change; this decision does not make one.

The value-return and zero-copy reconstruction contracts remain in v0.2.0. Later
Join and admission changes do not alter the attribution of the original
four-core measurement.

## 8. Safety and measurement analysis

**Attribution requires isolation.** Measuring only the combined changes would
have incorrectly credited the zero-copy read with the value return's reduction.
The zero-copy-only A/B run and the old-code escape analysis independently
explain why its allocation count stayed at 638 allocs/op.

**A value return still depends on escape analysis.** A returned value can escape
when its size or use requires it. The compiler output for this implementation
showed no `ReconstructedEntry` success-path escape; the retained payload string
was the expected remaining escape. The per-call probe corroborated the result.

**Validation still precedes Join.** Returning a value changes ownership, not the
wire-integrity contract. Reconstruction checks field reads, dot attribution,
and the payload digest before the apply path calls Join. The skew-bound variant
then checks the inbound counter against the caller's snapshot. Errors return a
zero value and do not become partially valid entries.

**Probe and benchmark granularity differ.** The per-call reduction of 2
allocs/op over 100 probe runs and the integrated reduction of 100 allocs/op at
N=100 measure different layers. Join closures, accumulator behavior, and
batch-level allocation effects prevent a linear extrapolation between them.
The integrated benchmark determines the ingest allocation claim; the probe
confirms the reconstruction mechanism.
