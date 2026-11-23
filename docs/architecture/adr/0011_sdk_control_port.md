# ADR-0011: SDK and mutually authenticated control port

- **Status:** Accepted
- **Date:** 2026-07-29
- **Predecessor:** [ADR-0010](0010_batched_delta_wire_v1.md)

---

## Context

The engine had no public API for a downstream application. The existing
`examples/embed/main.go` drove `pkg/sync` directly, which demonstrated the
internal data structure rather than a client connecting to a running node.

This decision adds a small SDK, a runnable example of under 50 lines of Go, and
a separate control listener using JSON over mutual TLS. The client API must also
make an existing storage boundary explicit: joined entries retain payload
digests, not payload strings.

### Payloads on the originator and its peers

`CRDTEntry` contains a `[32]byte` `PayloadDigest` but no payload string.
`ReconstructEntry` checks the received payload against that digest and then
discards the payload before the entry joins the replicated state. Storing the
payload as well would increase the on-disk footprint by approximately 10x
without changing CRDT merge behavior.

The originator separately records payloads in `payloadCache`, keyed by entity
and causal dot. A peer that receives the delta through gossip retains the digest
and entry metadata but ordinarily has no corresponding cache entry. `PointGet`
returns the candidate replicated entries; it does not reconstruct the discarded
value.

Consequently, a `Get` on the originator can return the cached payload, while the
same request on a peer returns an empty payload and a non-empty payload digest.
The API must never present the hexadecimal digest as though it were the value.
The SDK exposes that distinction through `GetResult`:

```go
type GetResult struct {
    EntityID      string
    Present       bool
    Payload       string
    PayloadDigest string
    DotNodeID     string
    DotCounter    uint64
    OriginNodeID  string
}
```

`Gossiper.LatestPayload` reads only the existing cache. `PointGet` and
`selectLatestDot` choose an entry, then the cache lookup returns its payload if
one is present. This adds no second retention path.

---

## Decision

The `sdk/sovereign` client connects to a JSON-over-mTLS control port on a
separate `--control-addr` listener. The listener is disabled when that flag is
empty. `examples/sdk/main.go` demonstrates dialing, inserting, reading a Merkle
root, and fetching a value in under 50 lines of Go; certificate loading lives in
`DialWithCerts`, and the demo workload lives in `RunDemo`.

The control port is intended for low-rate management traffic, approximately
1 op/sec to ~1K ops/sec. Its JSON decoding, TLS records, and local insertion are
a different path from the batched binary data plane. The recorded design
estimates were ~100ns–1us for JSON unmarshalling, ~36 ns for a local
`InsertLocal` apply, and ~30–50 ns for an AES-GCM TLS record; these estimates
are not an end-to-end latency measurement.

### Use JSON without changing the wire schema

Adding a Cap'n Proto RPC request type to the existing schema would also change
its generated code. JSON avoids coupling this management API to the established
binary wire schema and is sufficient for the intended request rate. A separate
RPC schema can be considered later without revising this control-port decision.

### Separate the three listeners

```
--bind          peer gossip and batched binary frames over TLS
--control-addr  client JSON API over mutually authenticated TLS
--metrics-addr  plain-HTTP /livecheck and /metrics for operations
```

The control and peer paths share the development mesh CA, but not an accept
loop. `transport.ServerConfig()` requires and verifies client certificates and
pins TLS 1.3 as both minimum and maximum. A client without a certificate fails
during the handshake, and malformed JSON cannot enter the binary frame parser.

`ControlServer.Handler` is shared by `cmd/sovereign-node` and the in-process SDK
tests. It serves `/v1/insert`, `/v1/batch-insert`, `/v1/get`, `/v1/query`,
`/v1/range`, `/v1/merkle`, and `/livecheck`. `/metrics` is available when a
metrics handler is supplied. `/v1/querybyh3` and `/v1/querybysystime` are
registered only when the secondary index is enabled; otherwise they return 404.

The control port's `/metrics` route is a TLS-gated mirror. The canonical
Prometheus scrape remains the separate plain-HTTP `--metrics-addr` listener,
which must not be exposed to untrusted networks.

---

### Insert through the payload-recording seam

`/v1/insert` calls `Gossiper.InsertLocalEvents`, not `engine.InsertLocal`
directly. The wrapper derives `PayloadDigest` from the same payload it records
in the cache. A direct engine insertion would omit that cache entry, so a later
gossip frame could lack the payload required by the peer's `ReconstructEntry`
integrity check.

When durability is enabled, `InsertLocalEvents` records the payload only after
the WAL append succeeds. A zero causal dot then reports a failed durable write
to the HTTP client rather than acknowledging it as successful. A successful
response confirms the local write; peers still converge asynchronously.

The current handler also supplies default temporal bounds and accepts an H3
index only when the secondary index is enabled. `/v1/batch-insert` uses the
corresponding `InsertLocalEventsBatch` path and reports durable failure across
the batch rather than acknowledging a subset.

---

### Select a deterministic entry and preserve metric labels

`selectLatestDot` chooses the greatest `DotCounter` and breaks equal-counter ties
with the smallest `DotNodeID` using `bytes.Compare`. This is a deterministic
selection rule, not a claim that counters from different origins establish a
causal order.

The SDK's `Metrics` method returns `MetricSamples`, with one `MetricSample` for
each `name{labels} value` series. `Samples(name)` returns every labeled series,
while `Value(name)` succeeds only when exactly one series matches. This replaces
the earlier name-only map, which collapsed the six verdict-labeled values of
`sovereign_ingest_verdicts_total` into one last-wins scalar. Malformed metric
lines are skipped without panicking.

---

## Consequences

- A peer read is digest-complete, not value-complete. An application that needs
  the original payload on every node must distribute or retain it separately;
  the SDK does not disguise the digest as that payload.
- `InsertLocal` does not provide cross-node read-your-writes or linearizability.
  It returns after the local operation, and an immediate read from another node
  can be stale until gossip converges.
- `payloadCache` retains historical dots until sweep bookkeeping removes stale
  entries. `LatestPayload` reads the latest selected dot but does not impose a
  general cache-size bound or an LRU policy.
- JSON is a copy-mode management interface. Clients above the intended ~1K
  ops/sec range belong on the binary data path rather than this API.
- The SDK uses the Go standard library for HTTP, JSON, TLS, and X.509 handling;
  this decision added no Go module dependency.
- `examples/embed/main.go` remains the internal embedding example. The SDK
  example is additive and keeps certificate and workload helpers in the client
  package rather than hiding them in terse example code.

---

## Evidence

The following in-process tests exercise the same handlers used by the node:

- `TestClientInsertGet` covers insertion, local application, retrieval, and
  Merkle-root stability.
- `TestClientRejectsUnsigned` checks that a client without a certificate cannot
  use the control port. `TestClientTLSThirteen0Only` checks that only TLS 1.3
  can be negotiated.
- `TestClientGetOnPeerReturnsDigestNotValue` requires `Payload == ""` and a
  non-empty `PayloadDigest` after a peer converges through gossip.
- `TestClientMetricsLabelPreserving` checks that all six verdict labels survive
  an SDK metrics scrape. `TestClientMetricsMalformedNoPanic` covers malformed
  label groups without a parser panic.
- `examples/sdk/main.go` remains under 50 lines including its licence and
  comments. It uses `DialWithCerts` and `RunDemo` rather than compressing those
  operations into unreadable example code.
