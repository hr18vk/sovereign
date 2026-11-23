# ADR-0030: Manifest-Channel Download Skip

**Status:** Accepted

**Date:** 2026-08-09

## Context

Before scanning L0 and L1 files, `Resolver.AsOf` and `Resolver.Range` loaded
every compaction manifest for the entity to construct the superseded-L0 set.
ADR-0029 eliminated unnecessary Arrow downloads, but a manifest whose entire
compaction was newer than the query still incurred a download and parse.

A manifest key and its L1 key are derived from the same `firstSysT`, the minimum
system time in the compacted rows. Each listed L0 has a minimum system time
greater than or equal to that value. Consequently, when the manifest's
`firstSys` exceeds the query transaction time, the L1 and every listed L0 are
already ineligible under ADR-0029's file-skip rule.

## Decision

Reuse `parseFirstSysFromKey` in `loadSupersededL0Keys`. Its grammar examines the
last path component and the decimal text before the final extension, so it
handles both `.arrow` and `.manifest` keys without a manifest-specific parser.

Before downloading a manifest, skip it when parsing succeeds and
`firstSys > txTimeNs`. The strict comparison preserves manifests at the
transaction-time boundary. Parse failures retain the normal download path.

Both skip channels use `ResolverConfig.EnableFirstSysSkip`; a second manifest
flag would allow inconsistent configurations without providing a distinct
query semantic. Avoided manifests increment `QueryManifestSkippedFirstSys`,
exported as `supremum.compaction.query_manifest_skipped_first_sys` and as the
corresponding Prometheus series through the existing bridge.

The L0 reaper does not use this skip. Its maintenance sweep has no query
transaction time and must continue to inspect manifests before deleting data.

## Consequences

Skipping such a manifest cannot change the visible superseded set: every file it
could remove from the scan is skipped independently by the Arrow filename rule.
At `base-500` in the four-L0 LocalFS fixture, enabled skipping avoids both the
manifest and L1 downloads, reducing each from 1 to 0. L0 downloads remain 0 in
both configurations because the no-skip path reads the manifest and supersedes
those files.

An erroneous `>=` manifest comparison needs a more precise regression oracle
than the dominant answer. With the default Preserve-All compaction, the L1 still
contains the merged rows, and boundary L0 files are not file-skipped when
`firstSys == txTimeNs`. The dominant answer can therefore remain correct even
though the manifest was skipped too early. The useful invariant is that L0 keys
removed from the superseded set must be a subset of keys removed by the Arrow
file skip. A violation of that subset identifies the boundary error; dominant
answer equality alone does not.

The opposite `<=` predicate violates the subset invariant, and a no-op skip is
visible in the disclosure-counter delta. These cases are covered by negative
controls rather than by claiming that the dominant answer must diverge for every
comparison error.

## Evidence

Fifteen tests cover this decision:

- `internal/database/manifest_download_skip_test.go`: 9 tests for parsing,
  allocation, malformed names, boundaries, equivalence, defaults, download
  counts, and negative controls.
- `pkg/durability/manifest_download_skip_test.go`: 3 LocalFS tests for answer
  preservation, per-tier download counts, and Range behavior.
- `internal/telemetry/manifest_skip_counter_test.go`: 2 registration and
  OpenTelemetry tests.
- `pkg/metrics/bridge_manifest_skip_test.go`: 1 Prometheus scrape test.

The differential fixture compacts 32 staggered L0 files into one Preserve-All L1
and compares enabled and disabled skips over 2,000 transaction times from seed
25. The recorded run reported 46/2000 manifest skips and zero result
divergences.

A second fixture uses 4 L0 files. At `base+1500`, both configurations select the
row at `base+1000`; at `base-500`, both return not found. A wide Range window
returns the same 2 rows at `base+1500` and no rows at `base-500`. The bridge test
adds 11 to the counter and checks that the scrape reports a cumulative value of
at least 11.
