# ADR-0031: Streaming ParseManifest Without Per-Line Copies

**Status:** Accepted

**Date:** 2026-08-09

## Context

ADR-0030 avoided parsing manifests that were invisible at the query transaction
time. Downloaded manifests still used `strings.Split(string(body), "\n")`,
which allocated an intermediate slice of N+1 strings in addition to the returned
L0-key slice. Their three callers also used `io.ReadAll`, whose buffer starts at
512 bytes and grows by doubling.

The relevant callers are `Resolver.loadSupersededL0Keys` on the query path,
`L0Reaper.Reap` on the maintenance path, and `L1Compactor.SupersededL0Keys`
when compaction re-reads its manifests.

## Decision

`ParseManifest` converts the body to one string and scans it with
`strings.IndexByte`. Returned L0 keys are substrings of that single string, so
there is no per-line string conversion and no intermediate `[]string`.
`strings.TrimSpace` also returns a substring, preserving whitespace handling
without another allocation.

A `first` flag preserves the old malformed-input behavior: the first non-empty
line becomes `l1Key` even if it has an `l0/` prefix, and it is not also appended
to `l0Keys`. Later lines accept the expected L1 and L0 prefixes and ignore
unrelated lines. Empty lines, CRLF input, and a missing final newline retain the
reference implementation's behavior.

The three callers use `readManifestBody`, which starts with a 4,096-byte buffer,
reads directly into it, and doubles it when necessary. The initial allocation
covers the 2,990-byte observed production maximum; larger manifests remain
supported. The public `ParseManifest` signature and the manifest writer do not
change.

A candidate using `bytes.IndexByte` plus `string(line)` for every L0 line was
rejected. It preserved output but replaced the single shared string with a copy
per line. Recorded parse-only allocation counts were:

| L0 count | `strings.Split` reference | Per-line string copies |
|---:|---:|---:|
| 1 | 3 | 3 |
| 16 | 5 | 20 |
| 64 | 7 | 70 |
| 256 | 9 | 264 |

The candidate required more allocations at every N greater than 1, reaching
29× the reference count at N=256. `TestStreamAlloc` keeps this alternative as an
executable comparison so it is not reintroduced as an optimization.

## Consequences

The parser removes one allocation per parse at every tested size. Combined read
and parse allocations recorded by `testing.AllocsPerRun` were:

| L0 count | `io.ReadAll` plus `strings.Split` | `readManifestBody` plus streaming parse | Change |
|---:|---:|---:|---:|
| 1 | 6 | 5 | −1 |
| 16 | 10 | 7 | −3 |
| 64 | 15 | 9 | −6 (−40%) |
| 256 | 21 | 13 | −8 |

At N=64 (the compaction trigger and the per-query caller's relevant fixture),
the reduction is 40%. At N=256 the 8,370-byte body requires one buffer grow.
These are allocation counts for manifest loading and parsing, not query-latency
or write-path measurements.

The body string, returned L0-key slice, and read buffer still allocate. The API
continues to return strings because callers use the keys in string-keyed maps;
returning byte slices would not remove those requirements. The reaper's 5-minute
sweep shares the implementation for consistency, but its allocation reduction
is not presented as a hot-path latency improvement.

This change adds no telemetry series. The registry contained 17 counters when
the parser landed and contains 25 in v0.2.0;
`TestStreamTelemetryCounterUnchanged` checks the current total and rejects
duplicate names.

## Evidence

`internal/database/manifest_stream_parse_test.go` contains five tests covering
output equivalence, allocations, malformed first lines, buffer growth and
fragmented reads, and unchanged telemetry.
`pkg/durability/manifest_stream_load_test.go` adds the LocalFS integration test.

The differential test compares 2,000 generated manifests from seed 26 against
the original `strings.Split` implementation. It includes empty and unrelated
lines, CRLF input, and missing trailing newlines, and records zero divergences
for both the shipped parser and the rejected per-line-copy candidate. A separate
negative control shows that removing first-line handling changes both `l1Key`
and `l0Keys` on malformed input.

Read tests cover empty input, the 4096B initial capacity, growth beyond that
capacity, and a reader returning 7 bytes per call. The integration fixture
compacts 4 L0 files, downloads the manifest once at `base+1500`, avoids all 4
superseded L0 downloads, reads the L1 once, and returns the row at `base+1000`.
