# ADR-0029: Filename-Bounded Download Skip

**Status:** Accepted

**Date:** 2026-08-09

## Context

`Resolver.AsOf` and `Resolver.Range` listed and downloaded every L0 and L1 Arrow
file under an entity prefix before applying the transaction-time filter. Files
whose entire contents were newer than the query still incurred a download and
Arrow decode, even though their object keys already contained enough information
to reject them.

L0 and L1 keys end in `{firstSys}.arrow`, where `firstSys` is the minimum system
time in the file. For a query at transaction time `T`, `firstSys > T` implies
that every row in the file fails the `SystemTime <= T` predicate.

## Decision

Parse the decimal `firstSys` component with `parseFirstSysFromKey` before each
Arrow download in the `AsOf` and `Range` scan loops. Skip the download only when
parsing succeeds and `firstSys > txTimeNs`. The comparison is strict: a file
whose first row has `SystemTime == txTimeNs` can contribute to the answer and
must still be read.

Malformed, negative, or otherwise unparseable suffixes return `ok=false` and
fall back to the normal download. A damaged filename is never treated as proof
that its contents can be discarded.

`ResolverConfig.EnableFirstSysSkip` controls the optimization.
`DefaultResolverConfig` enables it, while a literal zero-value configuration
leaves it disabled. `QueryDownloadSkippedFirstSys` records each avoided download
as `supremum.l0.query_download_skipped_first_sys`; the existing telemetry bridge
exposes the counter without a counter-specific collector.

No SkipList seek is wired into this path. `scanWindowRecordBatch` receives an
`arrow.Record`, and SkipList key order interleaves system and valid time rather
than providing an independent valid-time index. The filename bound addresses
the actual download cost directly.

## Consequences

Skipping an ineligible file preserves query results because it cannot contain a
row visible at the query's transaction time. The valid-time window in `Range`
does not change that reasoning.

In the four-file LocalFS fixture, a query between the second and third system
times performs 2 downloads instead of 4 and records 2 skips instead of 0. With
the optimization disabled, all 4 files are downloaded and the selected row is
unchanged.

The optimization applies only to the lower system-time bound already present in
the key. No upper-bound `maxSys` sidecar or additional skip policy is introduced.
ADR-0030 applies the same bound to compaction manifests.

## Evidence

Twelve tests across four packages cover the parser and its allocation count,
malformed-key fallback, the strict boundary, default configuration, differential
query results, real LocalFS downloads, telemetry registration, and Prometheus
export:

- `internal/database/file_download_skip_test.go`: 5 tests.
- `pkg/durability/download_skip_test.go`: 4 tests.
- `internal/telemetry/download_skip_counter_test.go`: 2 tests.
- `pkg/metrics/bridge_l0_download_skip_test.go`: 1 test.

The differential test compares enabled and disabled skips over 64 staggered L0
files and 2,000 transaction times from seed 24. It compares the selected event's
system time, valid-time interval, and payload, with zero divergences recorded.

Boundary tests verify that `firstSys == txTimeNs` is read while
`firstSys == txTimeNs + 1` is skipped. The LocalFS tests independently count
downloads and counter deltas, so an increment cannot be mistaken for an avoided
download.
