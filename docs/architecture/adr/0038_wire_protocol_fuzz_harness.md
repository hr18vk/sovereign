# ADR-0038: Wire-Protocol Fuzz Harness

**Status:** Accepted

**Date:** 2026-08-12

## Context

Digest, batch, hybrid, and relay frames share a dispatch surface, but the receive-path no-panic contract had not been exercised with machine-generated adversarial input. The harness needed to reach that surface from an external test package without changing production parsers or hiding panics behind a recovery boundary.

The dispatch target covers classification and routing only. Its no-op sink does not invoke a `Receiver`, Cap'n Proto decoding, signature verification, or CRDT application; those are not claims of this harness.

## Decision

Add `pkg/security/fuzz` with six default native Go fuzz targets: `FuzzDispatchFrame`, `FuzzUnmarshalRelayEnvelope`, `FuzzUnmarshalBatchEnvelope`, `FuzzUnmarshalHybridFrame`, `FuzzUnmarshalStrataEstimator`, and `FuzzUnmarshalIBLT`. Each asserts only that its call returns without panicking. Round-trip and semantic correctness remain the responsibility of their own tests.

`DispatchFrame` takes the unexported `mesh.frameSink` interface. The test's `nopSink` satisfies it structurally through the three handler methods, so compilation checks reachability without exporting the interface. `nopDigester` similarly satisfies the exported `DigestSink`.

Commit 42 corpus files across seven targets: 11 dispatch, six relay, four batch, four hybrid, five strata, six IBLT, and six fault-injection seeds. The six default targets account for 36 files. Builders in `seeds_test.go` generate valid frames, truncated headers, extreme lengths, and empty or one-byte inputs under the fixed corpus seed `0x4441593333000001`.

`TestSeedCorpusIsValid` replays committed inputs without mutation and fails on a panic. `TestSeedCorpusMatchesBuilders` compares file counts, contiguous numeric indices, and decoded bytes with the builders. The fault injection comparison uses the opt-in parser copy in `bug_inject_test.go`; the default comparison covers 36 seeds.

A tagged negative control removes the length checks from a copy of the IBLT parser. On an 18-byte header declaring three buckets, the real parser rejects the input because the complete encoding needs 78 bytes, while the modified copy panics. The deterministic fault injection proof checks that contrast. The exploratory fuzz target recovers panics, so it is not itself a pass/fail panic oracle.

No recovery handler or fuzz telemetry counter is added to production receive code.

## Consequences

A run without findings establishes only that the explored inputs did not panic. It does not prove semantic correctness or the absence of later crashes, and the short runs below are not a 72-hour soak.

`UnmarshalRelayEnvelope` retains a 32-bit limitation: converting a wire length of `0xFFFFFFFF` to `int` produces -1, which can defeat the length check and lead to a negative-length allocation panic. On the supported 64-bit targets, the declared length fails the bounds check and returns `ErrMalformed`.

The same residual no longer applies to `UnmarshalIBLT`. [ADR-0041](0041_100_node_silicon_convergence.md) adds a 699050-bucket ceiling derived from the 16 MiB ingress budget and the 24-byte in-memory bucket size. The parser rejects negative or excessive counts before allocation on either integer width.

## Evidence

The 2026-08-12 short-burst runs on a four-core loopback machine reported no panic across 1,943,415 executions:

| Target | Executions | Run time | New interesting inputs |
|:--|--:|--:|--:|
| Dispatch | 785,353 | 15 s | 0 |
| IBLT | 501,769 | 10 s | 5 |
| Relay | 302,838 | 6 s | 4 |
| Batch | 323,121 | 6 s | 3 |
| Hybrid | 11,132 | 6 s | 0 |
| Strata | 19,202 | 6 s | 5 |

A separate negative control changed the valid IBLT builder from 80 to 128 buckets without regenerating its corpus. `TestSeedCorpusMatchesBuilders` rejected the resulting 2,578-byte builder seed against the committed 1,618-byte file, demonstrating that corpus drift is checked.

The ordinary corpus tests can be rerun with:

```bash
go test ./pkg/security/fuzz/
```

The deterministic fault injection control and its opt-in build requirement are documented beside the test in `pkg/security/fuzz/bug_inject_test.go`.
