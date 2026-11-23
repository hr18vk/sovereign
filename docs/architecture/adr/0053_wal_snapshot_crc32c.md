# ADR-0053: WAL + snapshot CRC32C integrity that fails loud

**Status:** Accepted  
**Date:** 2026-09-11

## Context

The durability layer had no content-integrity check. A WAL record was guarded
only by sequence contiguity and a length bound; a snapshot image had no content
check at all. A flipped byte inside a complete, length-consistent record or image
could therefore be decoded and replayed as valid state.

Sequence contiguity and the length bound catch a missing or truncated record.
They cannot detect a record that is present, structurally valid, and wrong. A
content checksum closes that gap without changing replay semantics.

A read-only probe against the pre-change implementation demonstrated the problem:

- Flipping one payload byte in a WAL mutation made `ReplayWAL` return `err == nil`
  and apply the corrupted mutation.
- Flipping one snapshot body byte made `decodeSnapshotImage` accept the image,
  which recovery then used.
- Truncating the final WAL record cleanly discarded that record while preserving
  the leading records. The checksum design had to retain this crash-boundary
  behavior rather than report a torn append as corruption.

## Decision

Add Castagnoli CRC32C checksums to new WAL records and snapshot images. Reject a
corrupt authoritative WAL, but discard a corrupt snapshot and rebuild from the
WAL because the snapshot is only a derived cache.

### WAL framing

Use one new record type, `WALRecChecksummed = 0x06`, rather than separate new
type bytes such as `0x06/0x07/0x08` for mutations, checkpoints, and clock
advances. One wrapper covers every record kind, reuses the existing decode arms
through inner-type dispatch, and leaves the legacy set `0x01–0x05` unchanged.

In `internal/chaos/wal.go`, a framed payload is:

```
innerType(1) || innerPayload || crc32c(innerType || innerPayload, 4, big-endian)
```

The checksum is metadata. It does not change `walVersion`, `walEntryLen`, or the
meaning of any replayed record. It covers the inner type and payload, not the
outer `seq` or `payloadLen`. Those header fields remain protected by the length
bound and sequence checks. `ReplayWAL` also requires the first record to have
sequence zero, since pairwise contiguity cannot check the first record and the
CRC does not cover its sequence.

`castagnoliTable` is package-level, so checksum calculation does not construct a
new hash for each record. The test-only `walCRC32Skip` fault-injection switch
leaves verification enabled by default and lets tests show that the comparison
is responsible for rejecting corrupt bytes.

`frameChecksummed` allocates one complete record. The shared `put*Payload`
writers define the byte layout for both bare and framed forms, preventing the
two encoders from drifting apart. The four production append methods,
`AppendMutation`, `AppendMutations`, `AppendCheckpoint`, and
`AppendClockAdvance`, emit `0x06` by default; integrity protection is not
opt-in.

Test-only helpers still produce bare records for compatibility and corruption
tests: `AppendMutationV1ForTest` writes `0x01`, `AppendMutationV2ForTest` writes
`0x04`, and `AppendCheckpointRawForTest` writes `0x05`. Production append paths
do not use these helpers.

During replay, `unwrapChecksummed` separates the trailing four-byte checksum,
recomputes it over the inner type and payload, and returns `ErrWALCorrupt` on a
mismatch or short frame. A matching frame is dispatched to the same decoders
used by bare `0x01/0x04/0x03/0x02/0x05` records. Unwrapping happens only after
the complete payload has been read, so a torn final record is discarded before
checksum verification.

`pkg/durability/wal.go` re-exports `WALRecChecksummed` and `ErrWALCorrupt` from
the engine-side WAL package, allowing `errors.Is` to work across the package
boundary.

### Snapshot checksums

`pkg/durability/snapshot.go` retains `snapshotVersionV2 = 2` for legacy images
and introduces `snapshotVersionV3 = 3` for new images. `encodeSnapshotImage`
keeps the existing 61-byte header and record stream, then appends a four-byte
big-endian CRC32C over the entire header and records.

`decodeSnapshotImage` requires a v3 image to contain at least the four-byte
trailer and to match a checksum computed over all but those final four bytes.
A mismatch or short trailer returns `ErrSnapshotCorrupt`. Version 2 images still
decode without a checksum, while any other version returns an unsupported-
version error.

A snapshot is uploaded as one complete buffer, so it has no torn-append state.
Any v3 checksum mismatch or incomplete trailer is treated as corruption. The
package-level `snapshotCastagnoliTable` and test-only `snapshotCRC32Skip` switch
play the same roles as their WAL counterparts.

### Recovery behavior

The WAL is authoritative; a snapshot is a recoverable cache. Their corruption
handling is therefore deliberately different.

`ReplayWAL` has two production callers. `recoverEngineWithFeeder` propagates a
replay error other than `os.ErrNotExist`, refusing the boot; a missing WAL is a
cold boot and is handled separately. `(*Supervisor).recover` likewise aborts
supervised recovery on a replay error. Neither caller substitutes snapshot
state for a corrupt WAL.

For snapshots, `recoverEngineWithFeeder` calls `LoadSnapshotImage`, which decodes
the stored image. `ErrSnapshotCorrupt` causes recovery to discard the suspect
image, log an exact-WAL fallback, set `witness.ExactWALFallback=true` and
`witness.Bounded=false`, and rebuild state from the WAL. A corrupt cache image
must not prevent a node with an intact WAL from recovering, and it must never be
used as valid state.

### Checksums and state fingerprints

The two integrity checks detect different failures and both remain necessary:

- The snapshot CRC detects changed bytes at decode time. A mismatch returns
  `ErrSnapshotCorrupt` and selects exact-WAL fallback.
- The state fingerprint detects a well-formed but incorrect image during
  recovery. If decoded state differs from the checkpoint's recorded fingerprint,
  recovery returns `ErrRecoveryFingerprintMismatch`. A swapped or deliberately
  rewritten image can have a valid CRC for the wrong content, so the checksum
  cannot replace this comparison.

`TestValidCRCSwapStillCaughtByFingerprint` changes `ValidTimeEnd` and recomputes
the CRC. The Merkle root folds only `(DotNodeID, DotCounter)`, so this temporal
change leaves the root unchanged. The checksum passes, but the state fingerprint
fails. In the recorded test, the error reported rebuilt fingerprint prefix
`6642884a…`, checkpoint prefix `59a72208…`, and `CutSeq=6`; the test requires
`ErrRecoveryFingerprintMismatch`, not `ErrSnapshotCorrupt`.

### Compatibility

Existing unframed WAL records `0x01–0x05` still replay without checksums, and a
log may mix them with new `0x06` records. Existing bytes cannot gain retroactive
integrity protection, so legacy records remain unprotected; only newly written
frames are checksummed.

Version 2 snapshots likewise remain readable without a CRC and are not rejected
for lacking one. New images use v3. An older binary encountering `0x06` or v3
returns an unknown-record-type or unsupported-version error rather than
misinterpreting the new format. Downgrading across these formats is refused.

## Consequences

### Existing tests had to understand the new formats

Changing the default WAL writer to `0x06` and snapshots to v3 affected tests
that walked raw WAL records or damaged an image expecting it to reach a later
check. The test adaptations preserved the property each test exercised:

- `walRecordAtForTest` in `pkg/durability/collision_helpers_test.go` verifies a
  `0x06` checksum and unwraps the inner record. The raw WAL scanners in
  `checkpoint_concurrency_test.go` (`countCheckpoints`) and
  `checkpoint_posttail_test.go` (`ckptWatermarks` and the post-tail path) use
  this helper, reading watermarks and `CutSeq` from the inner payload.
- The ClockHigh clamp tests in `clock_high_clamp_test.go` append a bare `0x05`
  checkpoint through `appendMirroredRawCheckpointForTest` before damaging its
  ClockHigh field. Damaging a framed checkpoint would trip the CRC first and
  leave the legacy clamp untested.
- Fingerprint, image-binding, and duplicate-detection tests downgrade captured
  images to v2 before damaging them, allowing the intended downstream check to
  run instead of the v3 CRC. These cases are in `integrity_oracle_test.go`,
  `image_binding_test.go`, and `duplicate_detection_test.go`.
- `UnknownTypeHardErrors` in `wal_v2_format_test.go` originally combined
  sequence 1 with unknown type `0x7F` in the first record. The first-record
  sequence guard would mask the type error, so the fixture now uses sequence 0
  and isolates the unknown-type refusal.
- The shared scanner repair also fixed `TestAsyncCheckpointRequiresDrain`.
  Before the repair, `countCheckpoints` returned zero for framed records, and a
  scanner failure left cleanup busy-waiting. The async-checkpoint tests passed
  under `-race` in 4.8s on the local test machine.

### Coverage boundaries

Legacy WAL records and v2 snapshots remain unprotected because their existing
bytes contain no checksum. The CRC on a new WAL frame excludes `seq` and
`payloadLen`; damage limited to those fields is handled by the first-record,
sequence-contiguity, and length checks instead. Neither the checksum nor the
Merkle root replaces the full-state fingerprint check.

Tracing both `ReplayWAL` callers and the snapshot loading path found no recovery
branch that continues with partial state after these errors: WAL corruption
refuses recovery, and snapshot corruption selects exact-WAL replay.

## Evidence

### Pre-change reproduction and negative controls

The pre-change probe showed that damaged WAL and snapshot content was accepted,
while a torn WAL tail was cleanly discarded. The integrity tests retain negative
controls through `walCRC32Skip` and `snapshotCRC32Skip`: with checksum comparison
disabled, the same damaged bytes pass the decoding stage. The rejection therefore
depends on the new comparison rather than on an incidental decoder error.

### WAL tests

`internal/chaos/wal_crc_integrity_test.go` covers the format and replay contract:

- `TestWALCorruptDetect` changes a `0x06` payload and requires `ErrWALCorrupt`;
  with the comparison disabled, the same bytes replay.
- `TestWALFormatEvolution` replays a six-record mixed log containing
  `0x01/0x04/0x05/0x06×3`.
- `TestWALTornTailPreserved` distinguishes a cleanly truncated final record from
  a complete record with corrupt content.
- `TestWALReplayDeterminism` requires identical `Replayed` values for bare and
  framed forms. Their on-disk sizes were 937 and 967 bytes respectively; the
  checksum changes storage, not replayed content.
- `TestWALCRCZeroAlloc` measures zero allocations for CRC32C and 2.0 allocs/op
  for both bare and framed append paths.
- `TestWALCorruptChecksummedCheckpoint` requires `ErrWALCorrupt` for a damaged
  `0x06` checkpoint. With the comparison disabled, the same bytes reach the
  legacy ClockHigh clamp.
- `TestWALFirstRecordSeqGuard` uses one record with a valid content CRC but a
  nonzero outer sequence and requires `ErrWALSeqGap`.

### Snapshot and recovery tests

`pkg/durability/snapshot_integrity_test.go` covers both formats and recovery:

- `TestSnapshotCorruptDetect` checks body, Merkle-root, and short-trailer damage
  in v3 images, requiring `ErrSnapshotCorrupt`.
- `TestRecoveryExactWALFallback` requires successful recovery from the WAL after
  snapshot corruption, with `ExactWALFallback=true`, `Bounded=false`, and a
  recovered Merkle root equal to the live root.
- `TestSnapshotBackwardCompat` checks unprotected v2 decoding, valid v3 decoding,
  and a byte-exact populated-image round trip.
- `TestValidCRCSwapStillCaughtByFingerprint` keeps the fingerprint check active
  after the CRC passes.
- `TestWALCorruptBootRefused` corrupts a `0x06` WAL record and requires
  `RecoverEngineWithSnapshot` to return `ErrWALCorrupt`. One recorded error was
  `record seq 0 crc mismatch (stored a2482001, computed 0f357350)`.

### Append-path cost

A temporary `internal/chaos` microbenchmark ran on a 4-core local machine with
`GOMAXPROCS=1`:

| Measurement | ns/op | B/op | allocs/op |
|---|---:|---:|---:|
| Bare `encodeMutationV2Record` | 61.39 | 176 | 1 |
| Framed `encodeMutationV2Checksummed` | 72.63 | 192 | 1 |
| CRC32C alone over an approximately 159-byte inner payload | 9.84 | 0 | 0 |

The CRC32C measurement corresponds to 16.2 GB/s using the hardware-accelerated
Castagnoli path on ARM64. The complete frame added 11.2 ns/op while retaining one
allocation; the 5-byte frame accounts for the size-class difference in B/op.
`TestWALCRCZeroAlloc` separately measured 2.0 allocs/op for both complete append
paths and zero additional allocations for the checksum.

At the production ingest rate measured when this decision was written,
1.0M–3.1M deltas/sec with fsync-bound appends on the order of milliseconds,
11 ns/record was approximately 0.001% of append time. The durability `-race`
suite took 1700.5s against an approximately 1619s pre-change baseline, within
run-to-run variation; this comparison did not isolate a CRC-attributable
throughput regression.

### Verification runs

The decision's `-race -count=1` verification ran on a 32-core c8g.8xlarge.
Passing suite times were admission 1.0s, durability 1700.5s, attribution 14.3s,
the filtered mesh convergence subset 89.4s, receive 625.7s, chaos 1212.8s, and
database 654.9s. Two `pkg/sync` runs passed in 1203.5s and 1069.8s. Build and vet
passed, as did `TestHotPathZeroAllocations` and the zero-byte-artifact scan. The
fieldalignment report had no findings other than the intentional 128-byte stride
padding and remained report-only.

The full `pkg/mesh` suite minus the 10K-convergence case timed out under
`-race`: its natural duration was approximately 2400s against a 1500s timeout.
The filtered convergence run passed in 89.4s. This was a pre-existing test-time
capacity limit, not a passing result for the full mesh suite; the durability
suite used a 2400s timeout for the same reason.

`TestScalingGate`, an in-process CRDT core microbenchmark rather than an ingest
measurement, ran twice without the race detector and with `-count=1` on the same
32-core machine. The fresh runs measured 65,102,733 and 63,302,411 ops/s, giving
the range 63,302,411–65,102,733 ops/s with approximately 3% variation and
clearing the 50,736,038 ops/s floor.

An earlier reading of 66,048,248 ops/s with a reported duration of 4.02s came
from the Go test cache because that invocation omitted `-count=1`. The package
under test did not import the changed WAL or snapshot packages, so those changes
did not invalidate its cached test result. The cached value was excluded in
favor of the two fresh measurements; subsequent benchmark invocations use
`-count=1` when a fresh result is required.

The following merge-law and wire-schema files were unchanged immediately before
and after this change:

- `pkg/sync/crdt.go`
- `pkg/sync/crdt_apply.go`
- `pkg/attribution/envelope.go`
- `api/capnp/api/capnp/schema.capnp`
- `api/capnp/api/capnp/schema.capnp.go`

### Runtime verification

Two runs of the real `sovereign-node` binary over mTLS both exited zero. Each run
booted a node, inserted 6 keys, created a checkpoint, inspected the on-disk
formats, sent SIGINT, restarted on the same WAL and snapshot, and queried the
recovered state.

All 12/12 complete WAL records were `0x06`: 6 mutations and 6 checkpoints. The
snapshot had magic `SNSP`, version 3, and a valid CRC32C recomputed from its
847-byte on-disk image. After restart, 6/6 inserted keys were recovered. The
`boot2.unknown_key_404s` check confirmed that an unknown-key query did not
fabricate a result.
