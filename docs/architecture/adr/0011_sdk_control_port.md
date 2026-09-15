# ADR-0011: SDK + client library + runnable example — the engine becomes usable

- **Status:** ACCEPTED (2026-07-29) — in-process gates pass on a 4-core arm64 dev box (GOMAXPROCS=4)
- **Predecessor:** ADR-0010 (the batched delta wire — the 1M/sec arithmetic unlock)
- **Outcome:** advances the engine from "the API surface is zero; a developer cannot use this" to "a developer connects to a running mesh over mTLS, performs a state operation in <50 lines of Go, and the read path reports the originator-vs-peer payload boundary honestly (the value survives on the originator, the digest on a peer)"
- **Enforced by:** `TestClientInsertGet` (the insert→local-apply→Get loop + MerkleRoot stability), `TestClientRejectsUnsigned` + `TestClientTLSThirteen0Only` (the mTLS + TLS 1.3 teeth), `TestClientGetOnPeerReturnsDigestNotValue` (the load-bearing read-path honesty tooth), an assertion that the core merge-law/wire-schema files are untouched, the receiver.go/ingress_epoll.go UNCHANGED assert, the `wc -l examples/sdk/main.go < 50` gate, and `gofmt -s` / `go vet` / `go build` symmetry

---

## 1. Context

Until this change the engine had ZERO API surface a downstream developer could call. The only existing example (`examples/embed/main.go`) imports `pkg/sync` and drives the lock-free HAMT arena directly — it is a STACK SMOKE, not an engine API example. The failure criterion for this work was explicit: "cannot be used by a developer without reading 10,000 lines of internal code" is a failure.

This change ships the FIRST API surface a downstream consumer actually uses: a developer who has never read the internals connects to a running mesh and performs a state operation in under 50 lines of Go. The engine becomes USABLE, not just a benchmark.

### 1.1 The honest read-path boundary (load-bearing — encode it, do NOT hide it)

The initial draft of the client API wrote `Get(key) (val, ok)` returning the VALUE string. The bytes say otherwise. PHYSICAL TRUTH (grep-verified):

```
CRDTEntry (pkg/sync/hamt.go:29):
  PayloadDigest  [32]byte   // the digest only — NO Payload string field
  OriginNodeID   [16]byte
  DotNodeID      [16]byte
  DotCounter     uint64
  SystemTime     int64
  ...

pkg/sync/crdt_apply.go:20  the payload is DISCARDED after the integrity
                           check — only PayloadDigest is stored on CRDTEntry

pkg/mesh/gossip.go:78  payloadCache.lookup(entityID, CausalDot) (string, bool)
     — the payload lives ONLY in the origin node's payloadCache, keyed by
       (entityID, dot). A remote Get-by-entityID does NOT know the dot a
       priori (the dot is the engine's NextDot() stamp, opaque to the client
       before insert).
```

LOAD-BEARING CONCLUSION: a converged node's `State().Get(entityID)` returns the CRDTEntry's `PayloadDigest`, NOT the payload string. The original value is GONE from the joined state (the digest-only storage rule — the arena stores only the digest for memory discipline; the payload would 10x the on-disk footprint for no CRDT-merge benefit). The payload survives ONLY on the originator's `payloadCache` (the origin that `InsertLocalEvents`-ed it) — a peer that received the delta via gossip does NOT have the payload (it has the digest; the wire carried the payload once for the cross-check, then it was discarded peer-side too after Join).

```
>>> A Get(key) on the ORIGINATOR node returns the payload (it is in the
>>> originator's payloadCache). A Get(key) on a PEER node returns the
>>> PayloadDigest + the entry metadata (NOT the payload string; the payload
>>> was discarded on the peer after the cross-check). A Get that reports
>>> the digest as if it were the value is a FABRICATION.
```

The SDK's `Get` returns a typed `GetResult` that makes the boundary VISIBLE:

```go
type GetResult struct {
    EntityID       string
    Present        bool
    Payload        string // NON-EMPTY only on the originator node
    PayloadDigest  string // hex; ALWAYS present when Present=true
    DotNodeID      string // hex
    DotCounter     uint64
    OriginNodeID   string // hex
}
```

This required a NEW ADDITIVE accessor on the Gossiper (the only place the payload survives):

```go
func (g *Gossiper) LatestPayload(entityID string) (payload string, ok bool)
```

which walks `g.cache` for the entry `engine.State().Get(entityID)`'s latest dot (the most-recent `DotCounter` for this entity) and returns the cached payload if present. On the originator node the cache has it; on a peer (that received via gossip) the cache does NOT. The accessor does NOT add a new retention path — it READS the existing cache.

---

## 2. Decision

This change ships a JSON-over-mTLS control port on a SEPARATE `--control-addr` listener, an SDK client library (`sdk/sovereign`), and a runnable example (`examples/sdk/main.go`). The control port is a LOW-RATE manageability surface (1 op/sec to ~1K ops/sec); JSON's ~100ns–1us unmarshal per request is INVISIBLE against the `engine.InsertLocal` apply (~36 ns) + the TLS record write (~30–50 ns AES-GCM). JSON is the honest choice; the benchmark-grade data plane is the batched binary wire of ADR-0010 (a separate concern, already shipped). The two do NOT compete.

### 2.1 Why JSON, not Cap'n Proto RPC

`api/capnp/api/capnp/schema.capnp` is frozen (the wire schema is load-bearing). Adding a new "ClientRequest" Cap'n Proto struct would modify the code-gen (`schema.capnp.go`) — a frozen-file change. The JSON-over-mTLS control port is chosen here because (a) the capnp schema is frozen and an RPC method forces a codegen change to it, and (b) JSON is enough for control-plane ops. A Cap'n Proto RPC upgrade is a defensible later change (an additive `schema.gen.go` in a non-frozen package), not a blocker for this change. This is NOT a compromise: the control port is a low-rate surface; JSON's unmarshal cost is invisible against the apply + TLS record.

### 2.2 The control-plane / data-plane separation (three surfaces, one trust root)

```
--bind          the peer/gossip TLS port (the batched binary data plane)
--control-addr  the client TLS port (the JSON-over-mTLS control port)
--metrics-addr  the ops plain-HTTP surface (/livecheck + /metrics; ADR-0006/0008)
```

THREE surfaces, ONE trust root (the dev-mesh CA, `pkg/crypto/certgen.go`). The control port uses the SAME mTLS config as the peer path (`transport.ServerConfig()` — `RequireAndVerifyClientCert`, `Min==Max==1.3`, ADR-0006), so a no-cert dial is a hard TLS error. `--control-addr` defaults OFF (empty string) — no control port unless it is explicitly enabled, so a misconfigured node is still a peer in the mesh (the data plane is unaffected).

The control port's handlers live in `pkg/mesh/control.go` (`ControlServer`, holding a `*Gossiper`), reused by both `cmd/sovereign-node` (the `--control-addr` wiring) and the SDK test's in-process node — so the test drives the SAME handlers the production binary serves (no duplicated route logic). The control port also serves `/livecheck` and (optionally) `/metrics` over TLS so a single SDK dial reaches every read the SDK offers; the plain-HTTP `--metrics-addr` surface stays for unauthenticated ops scrape (ADR-0006 — the control-port `/metrics` is an ADDITIVE TLS-gated mirror, not a replacement).

---

## 3. The control-plane / data-plane separation (the primary-risk mitigation)

PRIMARY RISK: the control port MIXES data plane and control plane if it uses the SAME `--bind` listener as peer gossip. Root cause (one sentence): a client's JSON request and a peer's length-prefixed `BatchEnvelope` share one accept loop → a malformed JSON from a malicious client could be fed to the frozen `HandleFrame` gate stack, corrupting the verdict counters / tripping a chaos tooth.

Mitigation (ENCODED): the `--control-addr` is a SEPARATE `*tls.Listener` with its OWN handlers (`http.Server` driving the `/v1/*` JSON routes); `--bind` stays the peer path; `--metrics-addr` stays the ops plain-HTTP surface. The control port does NOT touch the receive gate stack (`receiver.go` / `ingress_epoll.go` stay untouched; the control port has its own `http.Server`, NOT the receive gate stack). THREE surfaces, ONE trust root.

---

## 4. The /v1/insert → InsertLocalEvents seam (NEVER engine.InsertLocal)

The `/v1/insert` handler routes through `Gossiper.InsertLocalEvents` (`gossip.go:202`) — NEVER `engine.InsertLocal` (`crdt.go:912`). The defect the tooth prevents: a route that called `engine.InsertLocal` directly would bypass the payload cache → a future gossip sweep ships a delta with no payload → the peer's `ReconstructEntry` cross-check FAILS → the delta is a `DropVerify` on every peer. `InsertLocalEvents` stamps `PayloadDigest = SHA-256(payload)` from the SAME payload the cache stores (`gossip.go:212`), so digest and payload are consistent by construction — the receive-side cross-check tooth stays honest. The handler doc encodes this; the SDK's `InsertLocal` doc states the insert is LOCAL-ONLY at return (peer convergence is eventual — the next gossip sweep).

---

## 5. The read-path boundary (restated — the LatestPayload accessor + the GetResult type)

The `LatestPayload(entityID)` accessor (`gossip.go`, NEW) reads `g.cache` via the EXISTING `cache.lookup(entityID, dot)` (`gossip.go:78`) for the dot that `engine.State().Get(entityID)`'s latest entry reports (the most-recent `DotCounter`). Returns `(payload string, ok bool)`. On the originator: the cache has it. On a peer: the cache does NOT (the digest-only discard). ONE new method; mount NO new retention path (it READS the existing cache, not a new store).

The `GetResult` type (SDK + the `/v1/get` JSON response) makes the originator-vs-peer boundary VISIBLE: `Payload` is NON-EMPTY only on the originator (cache hit); on a peer it is `""` and `PayloadDigest` carries the digest. A Get that returns the digest hex as if it were the value is the fabrication the peer-Get tooth catches.

---

## 6. IS-NOT (what this change does NOT deliver — scope discipline)

- Does NOT touch the five core merge-law/wire-schema files (unchanged before and after).
- Does NOT touch `receiver.go` / `ingress_epoll.go` (the control port is a SEPARATE server, NOT the receive gate stack).
- Does NOT ship a Cap'n Proto RPC (the schema is frozen; JSON is the honest control-port choice; a capnp RPC is a later additive-codegen change).
- Does NOT claim linearizability (`InsertLocal` returns at local-apply; peer convergence is eventual — the next gossip sweep; the doc says so).
- Does NOT ship the 1M/sec benchmark (a separate follow-up).
- Does NOT ship AF_XDP or eBPF steering (later tracks).
- Does NOT widen `NewReceiver` / `NewGossiper` arity (the constructor-arity discipline; the `--control-addr` routes hold a `*Gossiper` via the existing `Cache()` accessor + the new additive `LatestPayload`).
- Does NOT fabricate a value-return on a peer Get (the peer-Get tooth catches it).
- Does NOT delete `examples/embed/main.go` (it documents the engine-level stack; this change ADDS `examples/sdk/main.go`, the user-level example).
- Does NOT add a Go dependency (only stdlib: `net/http`, `encoding/json`, `crypto/tls`, `crypto/x509`); go.mod/go.sum are 0-diff.

---

## 7. Honest weaknesses

1. **The read path is digest-complete, NOT value-complete on peers.** A `Get` on a peer returns the `PayloadDigest`, not the payload string (the digest-only storage rule — the value is discarded after the integrity cross-check). A downstream consumer that needs the VALUE on a peer must re-publish it or hold it out-of-band; the SDK reports the boundary honestly but does NOT paper over it. This is the single most likely fabrication in this change and the peer-Get tooth exists to catch it.

2. **The control port is NOT linearizable.** `InsertLocal` returns at local-apply; peer convergence is eventual (the next gossip sweep). A client that inserts then immediately reads from a DIFFERENT node may see stale state until the sweep ships the delta. The doc says so; the SDK does NOT offer a read-your-writes guarantee across nodes.

3. **The payload cache is unbounded.** `payloadCache` (`gossip.go:55`) is unbounded by intent at this stage (a control-port gate does not need eviction). A long-running originator accumulates payloads for every dot it ever published; a production-sized cache (bounded map + LRU) is a known limitation (named in ADR-0007). The `LatestPayload` accessor reads the latest dot only, but the cache retains all historical dots until a sweep's `sweepStampedDrops` lazily GCs them.

4. **JSON is copy-mode by nature; the control port is NOT zero-copy.** The control port's floor is the JSON unmarshal + the `engine.InsertLocal` CAS + the TLS record write — all copy-mode. The data plane's zero-copy path is the later AF_XDP work. The control port does NOT compete with the data plane on throughput; a client doing >1K ops/sec should ride the batched binary wire, not the JSON control port.

5. **`/metrics` on the control port is an ADDITIVE TLS-gated mirror, not the canonical scrape.** The canonical Prometheus scrape is the plain-HTTP `--metrics-addr` surface (ADR-0006/0008). The control port's `/metrics` exists so a single SDK dial reaches every read, but an ops scraper should still hit `--metrics-addr` (no client cert required). The two are consistent (same Registry) but the plain-HTTP surface is the ops contract.

6. **The `LatestPayload` "latest dot" scan is a max-`DotCounter` heuristic.** For a single entity the entries are dot-ordered in the leaf, but the accessor scans for the max `DotCounter` to be robust to multi-origin Add-Wins coexistence. In a multi-origin overwrite race the "latest" by `DotCounter` may not be the causal latest (dots from different origins are not totally ordered by counter alone); the accessor returns the highest-counter entry's payload, which is the honest best-effort and matches the `/v1/get` handler's scan exactly. A follow-up made the pick a TOTAL ORDER (max `DotCounter`, ties broken by smallest `DotNodeID` via `bytes.Compare`) so two nodes scanning the same equal-counter multi-origin entries can no longer return a different "latest" — the heuristic is still not a causal claim, but it is now a deterministic pure function of the entry slice.

7. **The SDK's `Metrics()` reader originally collapsed a CounterVec's label dimensions to a single last-wins scalar.** `parsePrometheusText` returned `map[string]float64` keyed by metric NAME only (it stripped the `{labels}` at the brace), so `sovereign_ingest_verdicts_total` — a CounterVec with one `verdict` label and six values — collapsed to ONE scalar on a scrape: the caller saw one value and LOST five. This was silent data loss in the SDK's own metrics reader; the initial version shipped it (the gate never scraped a real CounterVec). A follow-up replaced it with a label-preserving `MetricSample` surface (`Client.Metrics() -> MetricSamples`, one `MetricSample` per `name{labels} value` line, with `Value(name)`/`Samples(name)` accessors that make the old scalar behavior explicit instead of silent). The old silent-collapse is GONE; a dedicated tooth proves all six verdict labels survive a scrape with their driven counts. The parser also skips (never panics on) malformed brace groups — a panic in `Metrics()` on a bad scrape would have been a NEW bug.

---

## 8. Self-adversarial critique (3 ATTACK + 1 MEDIOCRITY)

### ATTACK 1 — the capnp temptation

A capable engineer sees "JSON control port" and reaches for Cap'n Proto RPC for "efficiency." The attack: add a `ClientRequest` struct to `schema.capnp`. The refutation: `schema.capnp` is frozen; the codegen (`schema.capnp.go`) changes on any schema edit — a frozen-schema change, which the wire-format stability rule forbids here. JSON's ~100ns–1us unmarshal is invisible against the ~36 ns apply + ~30–50 ns TLS record on a LOW-RATE control surface. The capnp RPC is a later additive-codegen change in a non-frozen package; touching the frozen schema here is the sin.

### ATTACK 2 — the linearizability temptation

The attack: make `InsertLocal` block until peers acknowledge, or have `Get` fan out a quorum read, and market it as "linearizable." The refutation: the engine is a δ-CRDT; `InsertLocal` returns at local-apply by construction, and peer convergence is eventual (the next gossip sweep). A blocking insert or a quorum read would (a) couple the control port's latency to the gossip round-trip (~60 us verify per delta, pre-batch), defeating the low-rate manageability purpose, and (b) be a FALSE claim — the mesh does NOT provide linearizability, it provides eventual convergence. The honest doc states the boundary; a fabricated linearizability claim is the sin (the peer-Get tooth is the read-side enforcement; the write-side equivalent is the doc).

### ATTACK 3 — the value-fabrication on a peer Get (the catastrophic-failure mode)

The attack: the initial `Get(key) (val, ok)` draft invites returning the `PayloadDigest` hex AS IF it were the value on a peer (where only the digest survives). A peer Get that returns a non-empty `Payload` where the value was discarded is a FORGERY — it reports data the node does not hold. The refutation: the `GetResult` type makes the boundary VISIBLE (`Payload` empty on a peer, `PayloadDigest` non-empty), and `TestClientGetOnPeerReturnsDigestNotValue` is the tooth that catches it — it asserts `Payload == ""` AND `PayloadDigest != ""` on a gossip-converged peer. A fabricated value-return on a peer is the single most likely fabrication in this change and the ONLY way to fail catastrophically; the tooth makes the boundary OBSERVABLE.

### MEDIOCRITY 1 — the <50-line knob is the SDK's job, not the example's

A mediocre engineer hits the <50-line gate by golfing the example: cryptic one-liners, elided error handling, magic numbers. The spirit of the gate is that a developer can READ the example cold and use the engine; a tricked-up 49-line example that is unreadable fails that spirit even though it passes the count. The honest fix is to MOVE the helper into `sdk/sovereign` (the SDK's job) — the SDK added `DialWithCerts` (the cert-loading one-liner) so the example's cert boilerplate lives in the SDK, not the caller. The example is the DEVELOPER'S reading material; it is CLEAR, not golfed. The <50-line count is the proof a developer can use this; the clarity is the proof it is usable.

---

## 9. Verdict + bottom line

This change does not re-prove any performance number and does not alter the engine's performance posture. It advances the engine's claim from "the API surface is zero; a developer cannot use this" to "a developer connects to a running mesh over mTLS, performs a state operation in <50 lines of Go, and the read path reports the originator-vs-peer payload boundary honestly (the value survives on the originator, the digest on a peer)." A fabricated value-return on a peer is the catastrophic-failure mode the peer-Get tooth catches.

**Bottom line:** the engine is USABLE, not linearizable. The bytes are the truth. The <50-line example is the proof a developer can use this. The peer-Get tooth is the proof the read path is honest. Nothing fabricated; the read path reports the digest/value boundary honestly.
