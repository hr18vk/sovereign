# ADR-0053: WAL + snapshot CRC32C integrity that fails loud

**Date:** 2026-09-11 · **Status:** Accepted

## 1. Root cause (one sentence)

The durability layer had **zero content integrity**: a WAL record was guarded only by
sequence-contiguity + a length bound, and a snapshot image by nothing at all — so a
bit-flip *inside* a complete, length-consistent record (WAL) or image body (snapshot)
was decoded and replayed as **valid state** — fail-SILENT corruption that boots, self-
certifies healthy, and serves rotten bytes.

The seq-contiguity + length bound catch a *missing* or *truncated* record (a structural
hole); they are blind to a record that is *present, well-formed, and wrong*. That is the
gap a content checksum exists to close.

## 2. The gap — pre-fix reproduction evidence (before any fix)

A throwaway probe (read-only; not shipped) demonstrated the silent accept on the
pre-fix tree:

- A single WAL mutation with one payload byte flipped on disk: `ReplayWAL` returned
  `err == nil` and the corrupted mutation was applied as valid. **Fail-silent.**
- A snapshot body byte flipped: `decodeSnapshotImage` accepted it and recovery used the
  rotten image. **Fail-silent.**
- Torn-tail baseline: a truncated FINAL record truncates cleanly (no error), leading
  records intact. This is the contract the fix must NOT regress (a crash boundary is
  not corruption).

## 3. The fix — design A over B (the only permitted format change: a NEW type byte)

**Design choice (A over B).** **A (chosen):** ONE new type byte `0x06`, a CRC-framed
**wrapper** that protects *every* record kind via inner-dispatch. **B (rejected):**
per-type new bytes (`0x06/0x07/0x08` for mutation/checkpoint/clock). A wins because one
wrapper (a) protects all record kinds uniformly, (b) reuses the EXISTING decode arms
verbatim (the inner dispatch re-enters the same `switch`), and (c) keeps the legacy set
exactly `0x01–0x05` — the minimal format surface for comprehensive coverage.

**Constraint honored:** a per-record checksum is a record-format change permitted ONLY
via a NEW TYPE BYTE. NOT a `walVersion` bump, NOT a `walEntryLen` bump, NOT payloadLen
arithmetic. The WAL replay law holds: the checksum is METADATA — it changes NOTHING
about WHAT is replayed, only DETECTS corruption.

### 3a. WAL — `internal/chaos/wal.go`

- `WALRecChecksummed WALRecordType = 0x06` (`wal.go:182`). Payload =
  `innerType(1) ‖ innerPayload ‖ crc32c(innerType‖innerPayload, 4, big-endian, trailing)`.
- The CRC covers `innerType ‖ innerPayload` — **NOT** the outer `seq`/`payloadLen`,
  which stay guarded by seq-contiguity + the existing length bound + the NEW
  first-record-must-be-seq-0 guard (`wal.go:1249`).
- `castagnoliTable = crc32.MakeTable(crc32.Castagnoli)` (`wal.go:201`) — package-level,
  no `crc32.New` per record. `walCRC32Skip atomic.Bool` (`wal.go:211`) — the TEST-ONLY
  bug-injection seam (zero-value = verify ON).
- `frameChecksummed(seq, innerType, innerLen, writeInner)` (`wal.go:924`) — the
  single-allocation framer; the shared `put*Payload` writers are the ONE source of byte
  layout for both the bare and framed forms (no drift).
- The 4 production appends (`AppendMutation`/`AppendMutations`/`AppendCheckpoint`/
  `AppendClockAdvance`) emit `0x06` by DEFAULT (protection ON, not opt-in).
  `AppendMutationV2ForTest` (`wal.go:826`) emits the bare `0x04` form for the
  mixed-format test — the ONLY remaining bare producer, test-only.
- DECODE (`ReplayWAL`, `wal.go:1185`): on `0x06`, `unwrapChecksummed` (`wal.go:1025`)
  splits the trailing 4-byte CRC, recomputes over `innerType‖innerPayload`, compares.
  Mismatch → `ErrWALCorrupt` (`wal.go:194`). Match → dispatch on the inner type to the
  SAME arms `0x01/0x04/0x03/0x02/0x05` use. The unwrap runs AFTER the complete-payload
  read, so a torn tail breaks BEFORE the CRC and is never misread as corruption.

### 3b. Snapshot — `pkg/durability/snapshot.go`

- `snapshotVersionV2 = 2` (legacy, disclosed-unprotected) / `snapshotVersionV3 = 3`
  (current) (`snapshot.go:98`/`:107`).
- `encodeSnapshotImage`: same 61-byte header + records, PLUS a trailing 4-byte
  whole-image CRC32C (`snapshot.go:225` sets `hdr[4]=v3`; `:250` appends the CRC).
- `decodeSnapshotImage` (`:258`): version dispatch — v3 requires ≥4 trailing bytes and a
  CRC match over all-but-last-4, else `ErrSnapshotCorrupt` (`:76`); v2 decodes with no
  CRC (disclosed-unprotected); any other version → loud "unsupported version".
- A snapshot is written WHOLE (one Upload of a complete buffer), so it has NO torn-tail
  concept: ANY CRC mismatch or short trailer = corruption = FAIL LOUD.
- `snapshotCastagnoliTable` (`:81`), `snapshotCRC32Skip` (`:88`) — the test seam.

### 3c. The re-export shim — `pkg/durability/wal.go`

`WALRecChecksummed = chaos.WALRecChecksummed` and `var ErrWALCorrupt = chaos.ErrWALCorrupt`
(so `errors.Is` works across the package boundary).

## 4. The fail-LOUD split — WAL and snapshot have DIFFERENT correct semantics

This is the crux of the design. The WAL is the AUTHORITATIVE truth (no fallback); the
snapshot is a DERIVED cache (the WAL rebuilds). The two corruptions must NOT be
conflated.

### 4a. WAL corruption → boot-REFUSAL (no fallback)

`ErrWALCorrupt` propagates out of `ReplayWAL` to BOTH callers, neither swallows it:

```
$ grep -rn 'ReplayWAL(' --include=*.go internal/ pkg/ cmd/ | grep -v _test
  pkg/durability/recovery.go:262:  rep, err := ReplayWAL(walPath)
  internal/chaos/supervisor.go:354: rep, rerr := ReplayWAL(s.walPath)
```

- `recovery.go:262` — a non-`os.ErrNotExist` error returns `fmt.Errorf("durability:
  replay %s: %w", ...)` at `:272` → the boot is REFUSED. (A missing WAL is a cold boot,
  handled separately at `:265`.)
- `supervisor.go:354` — the supervisor's replay error aborts the supervised boot.

Test: `TestWALCorruptBootRefused` — a corrupt `0x06` record (CRC flipped) →
`RecoverEngineWithSnapshot` returns `ErrWALCorrupt`:
`durability: replay …/b2.wal: chaos/wal: record content CRC32C mismatch (corrupt
record): record seq 0 crc mismatch (stored a2482001, computed 0f357350)`. No fallback,
no silent boot.

### 4b. Snapshot corruption → LOUD exact-WAL fallback (NOT a refusal)

`ErrSnapshotCorrupt` routes into the EXISTING loud fallback — the suspect image is
DISCARDED and state is rebuilt from the WAL:

```
$ grep -rn 'LoadSnapshotImage\|decodeSnapshotImage(' --include=*.go internal/ pkg/ cmd/
  pkg/durability/recovery.go:313:  img, ierr := store.LoadSnapshotImage(...)
  → :314-317  exactWALFallback = true; log "EXACT-WAL-FALLBACK: … (suspect image not used)"
```

Test: `TestRecoveryExactWALFallback` — a CRC-corrupt v3 image → boot
SUCCEEDS from the WAL, `witness.ExactWALFallback=true`, `witness.Bounded=false`, and the
recovered Merkle root re-equals the live root. This is deliberately NOT a boot-refusal
(a single rotten cache file must not brick a node whose WAL is fine) and NEVER a silent
use of rotten bytes. The CRC's job is to make the corruption DETECTED so the image is
discarded, not trusted.

## 5. The layering statement (rot vs swap — the CRC does NOT retire the fingerprint)

These are two DIFFERENT detectors for two DIFFERENT failure classes, and both stay live:

- **The CRC catches ROT at DECODE-time.** Bytes on disk were corrupted so the image no
  longer matches its own checksum → `ErrSnapshotCorrupt` → exact-WAL fallback. Cheap,
  at read.
- **The fingerprint oracle catches a VALID-BUT-WRONG SWAP at RECOVERY-time**
  (`recovery.go:508`): an image that is well-formed (passes the CRC) but whose
  decoded bytes do not match the checkpoint's recorded fingerprint →
  `ErrRecoveryFingerprintMismatch`. The CRC CANNOT catch a swap — a swapped image has a
  CRC that honestly matches its (wrong) bytes.

The CRC does NOT retire the fingerprint. Proven by **`TestValidCRCSwapStillCaughtByFingerprint`**:
corrupt a dot-invisible byte (ValidTimeEnd — the Merkle root folds only
(DotNodeID,DotCounter), so the root is unchanged), then RECOMPUTE the CRC so the image
is CRC-VALID but content-SWAPPED. Result: the CRC passes (it honestly vouches for the
swapped bytes) and the FINGERPRINT fires:
`recovery fingerprint mismatch …: pre-tail image fingerprint mismatch: rebuilt=6642884a…
checkpoint=59a72208… (CutSeq=6) — the image's dots match the anchor but its BYTES do not`.
The test asserts the error is the fingerprint, NOT `ErrSnapshotCorrupt`. Rot ≠ swap;
both detectors live.

## 6. The tests — all bug-injection-proven

Every test carries an in-code RED control: the CRC compare is compiled out via the
`walCRC32Skip` / `snapshotCRC32Skip` seams and the SAME corrupt bytes are shown to pass
SILENTLY — proving the compare is load-bearing, not a tautology. (This is the RED-first
proof for a change whose tests compile against the fix's new symbols: a literal
test-first-compiling commit is impossible here. See §10.)

**WAL — `internal/chaos/wal_crc_integrity_test.go`:**
- `TestWALCorruptDetect` — corrupt `0x06` → `ErrWALCorrupt`; CRC compiled out → the SAME
  bytes replay SILENTLY (the load-bearing proof).
- `TestWALFormatEvolution` — a 6-record mixed log (`0x01/0x04/0x05/0x06×3`) replays
  cleanly (format evolution).
- `TestWALTornTailPreserved` — torn-tail preserved (truncate clean) +
  complete-but-corrupt IS corruption (the contrast pair — a crash boundary is not
  corruption).
- `TestWALReplayDeterminism` — bare vs framed → byte-identical `Replayed` structs
  (on-disk bytes differ, 937 vs 967; the CRC is metadata, never a change to WHAT is
  replayed).
- `TestWALCRCZeroAlloc` — CRC32C = 0 allocs/op; framed append 2.0 allocs == bare
  2.0 allocs.
- `TestWALCorruptChecksummedCheckpoint` — a corrupt `0x06` checkpoint → `ErrWALCorrupt`;
  CRC compiled out → the same bytes hit the ClockHigh clamp (the layering between the
  CRC and the legacy defense).
- `TestWALFirstRecordSeqGuard` — a single record, no contiguity partner, the CRC does
  not cover the seq → refused with `ErrWALSeqGap`.

**Snapshot — `pkg/durability/snapshot_integrity_test.go`:**
- `TestSnapshotCorruptDetect` — corrupt v3 → `ErrSnapshotCorrupt` (body / MerkleRoot /
  short-CRC-trailer) + the recovery route (loud exact-WAL fallback, root re-equals live).
- `TestSnapshotBackwardCompat` — v2 legacy decodes (disclosed-unprotected) / v3 good CRC
  decodes / a populated image round-trips byte-exact.
- `TestValidCRCSwapStillCaughtByFingerprint` — the layering test (§5).
- `TestWALCorruptBootRefused` — WAL-corrupt → boot-refused with `ErrWALCorrupt` (the
  other fail-LOUD half).

## 7. The collision rework (the format change is NOT blast-radius-free)

Switching the default writer to `0x06` and the snapshot to v3 collided with existing
test apparatus that walks the raw WAL by type byte or corrupts an image expecting it to
still decode. Every reworked scanner stays a REAL oracle — NONE was weakened to pass
(no assertion deleted; each re-points at the format it actually guards):

- **The WAL scanners.** New `walRecordAtForTest`
  (`pkg/durability/collision_helpers_test.go`) recognizes `0x06`, VERIFIES the CRC
  (Fatalf on mismatch — it stays a real oracle), and unwraps to the inner record. The
  pre-existing scanners re-pointed at it: `checkpoint_concurrency_test.go`
  (`countCheckpoints`), `checkpoint_posttail_test.go` (`ckptWatermarks` + the post-tail
  switch, reading the watermark/CutSeq from the INNER payload).
- **The ClockHigh clamp tests.** The bridge now writes `0x06`-framed
  checkpoints; patching a framed checkpoint's ClockHigh trips the CRC (the CORRECT new
  syntactic defense) BEFORE the clamp. To keep exercising the CLAMP (the legacy/no-CRC
  defense), the tests append a RAW `0x05` mirror (`appendMirroredRawCheckpointForTest`)
  and patch THAT. `clock_high_clamp_test.go` — the clamp still clamps.
- **The fingerprint / duplicate-detection / header-rot tests.** These corrupt an image
  and expect the DOWNSTREAM oracle (fingerprint / duplicate detection) to fire. Under v3
  the CRC now catches the corruption first at decode. To keep exercising the downstream
  oracle, the tests downgrade the image to v2 (strip the CRC trailer, set version=2) so
  the corruption survives decode. `integrity_oracle_test.go`, `image_binding_test.go`,
  `duplicate_detection_test.go`.
- **`UnknownTypeHardErrors`.** This test fabricated a record with
  seq=1 AND an unknown type (`0x7F`) — a DOUBLE defect. The new first-record-seq-0 guard
  fires before the type dispatch, so the record now trips the header-corruption guard
  instead of the unknown-type refusal. De-confounded to seq=0 so the test isolates
  exactly the unknown-type defect it claims to test. `wal_v2_format_test.go`.
- **Broader than the anticipated set:** the same scanner root also caught the
  duplicate-detection tests and the async-checkpoint tests (`countCheckpoints` returning
  0 under `0x06` had deadlocked `TestAsyncCheckpointRequiresDrain` — its cleanup
  busy-spun after the scanner Fatalf'd). The scanner rework fixed the root; the
  async-checkpoint tests pass under `-race` (4.8s locally).

## 8. CRC append-path cost (measured, not asserted)

Microbench (`internal/chaos`, 4-core local box, GOMAXPROCS=1, throwaway — not committed):

| measurement | ns/op | B/op | allocs/op |
|---|---|---|---|
| bare encode (`encodeMutationV2Record`) | 61.39 | 176 | 1 |
| framed encode (`encodeMutationV2Checksummed`) | 72.63 | 192 | 1 |
| **CRC32C alone** (crc32.Checksum, ~159-B innerPayload) | **9.84** | **0** | **0** |

- The CRC32C is **9.84 ns/op, 0 allocs/op, 16.2 GB/s** — the hardware-accelerated
  Castagnoli path (ARM64 PMULL/CRC32). The frame adds **+11.2 ns/op** total, still a
  single allocation (1 == 1; the B/op delta is the 5-byte frame rounded to a size class).
- `TestWALCRCZeroAlloc` confirms the FULL append path: bare 2.0 allocs == framed
  2.0 allocs; the CRC adds 0.
- At the production ingest rate (1.0M–3.1M deltas/sec at the time of writing,
  fsync-bound at ~ms/append), +11 ns/record is ~0.001% of the append — negligible by
  design. The durability `-race` suite ran 1700.5s vs the ~1619s pre-change baseline —
  within run-to-run noise, no throughput regression attributable to the CRC.

## 9. Verification (all measured on this tree; the `-race` suite + the crucible on a 32-core c8g.8xlarge)

All `-race` suites (`-count=1`) PASS: admission 1.0s; durability 1700.5s; attribution
14.3s; the mesh convergence subset 89.4s; receive 625.7s; chaos 1212.8s; database
654.9s; **pkg/sync run 1 1203.5s + run 2 1069.8s** (the intermittent-arena double-run —
BOTH green; that intermittent fault stayed dormant on this tree). Build/vet clean.
`TestHotPathZeroAllocations` PASS. Zero-byte-artifact scan PASS. The fieldalignment
report is clean modulo the intentional 128-byte stride padding (report-only by policy).

One capacity note: the full `pkg/mesh` suite minus the 10K-convergence case TIMED OUT
under `-race` — its natural `-race` duration (~2400s) exceeds the 1500s timeout it ran
under; the mesh convergence tests PASSED in the filtered run (89.4s). Pre-existing (this
change does not touch `pkg/mesh`); the per-suite timeout needs a bump, mirroring the
durability-suite 2400s bump.

**Core scaling-gate crucible (`TestScalingGate`, the CORE microbench, NOT ingest):
63,302,411–65,102,733 ops/s @32c**
(FRESH, `-count=1`, two runs, non-race) — clears the 50,736,038 floor. **Measurement
correction:** the first reading reported **66,048,248** — but the harness invoked the
crucible WITHOUT `-count=1`, so that number was a **go-test CACHE HIT from a prior tree**
(the box's persistent `~/.cache/go-build`; `pkg/sync`'s test binary does not import
`internal/chaos`/`pkg/durability`, so this change did not invalidate the cache, and the
bit-identical 66,048,248 across runs is the tell — a `-v` cache hit replays the original
duration, so `--- PASS (4.02s)` did NOT prove a fresh run). Re-measured FRESH with
`-count=1`: run 1 = 65,102,733, run 2 = 63,302,411 (the ~3% spread is normal
thermal/scheduling variance). The fresh number is the honest one for this tree; it is
unchanged *in kind* from the immediately preceding tree (this change does not touch
`pkg/sync`), NOT in the cached digit. Standing lesson: any cached-prone benchmark step
must pass `-count=1`.

**The merge-law/wire-schema core files — unchanged before and after:**

| file | unchanged |
|---|---|
| `pkg/sync/crdt.go` | ✓ |
| `pkg/sync/crdt_apply.go` | ✓ |
| `pkg/attribution/envelope.go` | ✓ |
| `api/capnp/api/capnp/schema.capnp` | ✓ |
| `api/capnp/api/capnp/schema.capnp.go` | ✓ |

**Runtime verify (the real binary, not tests).** Driven against the real
`sovereign-node` over mTLS: boot → insert 6 keys → checkpoint → assert on-disk format →
SIGINT → **restart on the same WAL+snapshot** → query. ALL PASS, every assertion
load-bearing:
`wal.all_records_0x06` (12/12 complete records are 0x06 — 6 mutations + 6 checkpoints,
the default writer is live); `snapshot.is_v3` (magic SNSP, version 3);
`snapshot.crc_valid_on_disk` (the trailing CRC32C **recomputed over the on-disk bytes**
and equal — 847-byte image); `boot2.all_keys_recovered` (**6/6 keys recovered after a
real process restart** — the binary replayed the `0x06` WAL + loaded the v3 snapshot);
`boot2.unknown_key_404s` (the negative control — the query path is not fabricating).
Reproducible (two runs, exit 0).

## 10. Test validity (disclosed)

The fix and its tests were landed together: the tests compile against the fix's NEW
symbols (`0x06`/`v3`/the new error vars), so a strictly test-first commit is impossible
here. The tests are nonetheless genuine guards, not decoration — each is proven to fail
without the fix by the pre-fix reproduction evidence (§2) and by the bug-injection
control in every test (§6), rather than assumed to bite.

## 11. Backward-compat statement (the honest scope)

- **Existing on-disk WAL (legacy `0x01`–`0x05`):** still replays. `ReplayWAL` accepts the
  legacy types verbatim (no CRC). **DISCLOSED: legacy records are UNPROTECTED** —
  retroactive integrity is impossible for bytes already written. Only NEW records
  (written `0x06`) are protected. A mixed log is fine (see `TestWALFormatEvolution`).
- **Existing v2 snapshot:** still decodes (no CRC), **disclosed-UNPROTECTED**. New images
  are written v3 (protected). A v2 image is never REJECTED for lacking a CRC.
- **Format-evolution safety:** an OLD binary reading a NEW log/image hits `0x06`/`v3` and
  HARD-errors ("unknown record type" / "unsupported version") — LOUD, never a silent
  misread. Downgrade is refused, not corrupted.

## 12. Honest future work — defects and limits not fixed here

- **mesh-full `-race` timeout** (§9): pre-existing capacity gap (1500s timeout vs a
  ~2400s suite). Needs a per-suite timeout bump, mirroring the durability-suite 2400s
  bump — NOT a regression from this change; the mesh convergence tests passed.
- **Legacy records remain unprotected** (§11) — inherent, disclosed, not fixable.
- **The CRC covers `innerType‖innerPayload`, NOT the outer `seq`/`payloadLen`** — by
  design (those are guarded by seq-contiguity + the length bound + the first-record
  guard). A corruption that ONLY flips a `seq`/`payloadLen` byte is caught by THOSE
  guards, not the CRC. This is the documented coverage boundary, not a gap.
- **No swallowed-error second defect found.** I traced every `ReplayWAL` /
  `LoadSnapshotImage` caller (§4): the WAL path refuses, the snapshot path falls back
  loudly. No silent-partial-state continue exists on these paths.
