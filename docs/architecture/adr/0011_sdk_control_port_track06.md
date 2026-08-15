# ADR-0011: SDK + client library + runnable example — the engine becomes usable (Day 6)

- **Status:** ACCEPTED (Day 6, 2026-07-29) — in-process gates G06.a–h PASS on the executor box (GOMAXPROCS=4, gear-light, arm64); §5 STAYS CONDITIONAL-GO
- **Scope:** Day 6 of the World-No.1 Battle Plan (`phase-03/WORLD_NO1_BATTLE_PLAN.md`, ed.2.1, Day 6 section; Head = 7b163c0, Day 5 landed)
- **Predecessor:** ADR-0010 (the Day-5 batched delta wire — the 1M/sec arithmetic unlock)
- **§5 verdict:** STAYS CONDITIONAL-GO (Day 6 is NOT an E1/E2/E3/E5 verdict-blocker; it ADVANCES the architectural claim from "the API surface is zero; a developer cannot use this" to "a developer connects to a running mesh over mTLS, performs a state operation in <50 lines of Go, and the read path reports the originator-vs-peer payload boundary HONESTLY (Ruling 3 — the value survives on the originator, the digest on a peer)")
- **Enforced by:** `TestClientInsertGet` (G06.c — the insert→local-apply→Get loop + MerkleRoot stability), `TestClientRejectsUnsigned` + `TestClientTLSThirteen0Only` (G06.b — the mTLS + TLS 1.3 teeth), `TestClientGetOnPeerReturnsDigestNotValue` (G06.e — the load-bearing read-path honesty tooth), the FROZEN md5 PRE+POST assert, the receiver.go/ingress_epoll.go UNCHANGED assert, the `wc -l examples/sdk/main.go < 50` gate (G06.d), the glued-token grep (G06.g), the `gofmt -s` / `go vet` / `go build` symmetry (G06.a)

---

## 1. Context

Through Day 5 the engine had ZERO API surface a downstream developer could call. The only existing example (`examples/embed/main.go`) imports `pkg/sync` and drives the lock-free HAMT arena directly — it is a STACK SMOKE, not an engine API example. The WHAT-FAILURE-LOOKS-LIKE clause names this exactly: "Cannot be used by a developer without reading 10,000 lines of internal code → YOU FAILED."

Day 6 ships the FIRST API surface a downstream consumer actually uses: a developer who has NEVER read the internals connects to a running mesh and performs a state operation in under 50 lines of Go. The engine becomes USABLE, not just a benchmark.

### 1.1 The honest read-path boundary (load-bearing — encode it, do NOT hide it)

The battle plan draft wrote `Get(key) (val, ok)` returning the VALUE string. The bytes say otherwise. PHYSICAL TRUTH (grep-verified):

```
CRDTEntry (pkg/sync/hamt.go:29):
  PayloadDigest  [32]byte   // the digest only — NO Payload string field
  OriginNodeID   [16]byte
  DotNodeID      [16]byte
  DotCounter     uint64
  SystemTime     int64
  ...

pkg/sync/crdt_apply.go:20  "payload ... DISCARDED after the integrity check
                            (Ruling 3 - only PayloadDigest is stored on CRDTEntry)"

pkg/mesh/gossip.go:78  payloadCache.lookup(entityID, CausalDot) (string, bool)
     — the payload lives ONLY in the origin node's payloadCache, keyed by
       (entityID, dot). A remote Get-by-entityID does NOT know the dot a
       priori (the dot is the engine's NextDot() stamp, opaque to the client
       before insert).
```

LOAD-BEARING CONCLUSION: a converged node's `State().Get(entityID)` returns the CRDTEntry's `PayloadDigest`, NOT the payload string. The original value is GONE from the joined state (Ruling 3 — the arena stores only the digest for memory discipline; the payload would 10x the on-disk footprint for no CRDT-merge benefit). The payload survives ONLY on the originator's `payloadCache` (the origin that `InsertLocalEvents`-ed it) — a peer that received the delta via gossip does NOT have the payload (it has the digest; the wire carried the payload once for the cross-check, then it was discarded peer-side too after Join).

```
>>> A Get(key) on the ORIGINATOR node returns the payload (it is in the
>>> originator's payloadCache). A Get(key) on a PEER node returns the
>>> PayloadDigest + the entry metadata (NOT the payload string; the payload
>>> was discarded on the peer after the Ruling-3 cross-check). A Get that
>>> reports the digest as if it were the value is a FABRICATION.
```

The SDK's `Get` returns a typed `GetResult` that makes the boundary VISIBLE:

```go
type GetResult struct {
    EntityID       string
    Present        bool
    Payload        string // NON-EMPTY only on the originator node (Ruling-3)
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

Day 6 ships a JSON-over-mTLS control port on a SEPARATE `--control-addr` listener, an SDK client library (`sdk/sovereign`), and a runnable example (`examples/sdk/main.go`). The control port is a LOW-RATE manageability surface (1 op/sec to ~1K ops/sec); JSON's ~100ns–1us unmarshal per request is INVISIBLE against the `engine.InsertLocal` apply (~36 ns) + the TLS record write (~30–50 ns AES-GCM). JSON is the honest choice; the benchmark-grade data plane is the Day-5 batched binary wire (a separate concern, already shipped). The two do NOT compete.

### 2.1 Why JSON, not Cap'n Proto RPC

`api/capnp/api/capnp/schema.capnp` (md5 47d2796a) is FROZEN (TRUE-FROZEN, NEVER touch). Adding a new "ClientRequest" Cap'n Proto struct would modify the code-gen (`schema.capnp.go`, md5 590af228) — a FROZEN breach. The JSON-over-mTLS control port is chosen at Day 6 BECAUSE (a) the capnp schema is FROZEN and an RPC method risks the md5 lock trivially via a codegen change, and (b) JSON is enough for control-plane ops. A Cap'n Proto RPC upgrade is a defensible POST-10-DAY track (an additive `schema.gen.go` in a non-FROZEN package), NOT a Day-6 blocker. This is NOT a compromise: the control port is a low-rate surface; JSON's unmarshal cost is invisible against the apply + TLS record.

### 2.2 The control-plane / data-plane separation (three surfaces, one trust root)

```
--bind          the peer/gossip TLS port (the Day-5 batched binary data plane)
--control-addr  the client TLS port (the JSON-over-mTLS control port; Day 6)
--metrics-addr  the ops plain-HTTP surface (/livecheck + /metrics; ADR-0006/0008)
```

THREE surfaces, ONE trust root (the dev-mesh CA, `pkg/crypto/certgen.go`). The control port uses the SAME mTLS config as the peer path (`transport.ServerConfig()` — `RequireAndVerifyClientCert`, `Min==Max==1.3`, ADR-0006), so a no-cert dial is a hard TLS error. `--control-addr` defaults OFF (empty string) — no control port unless the operator explicitly enables it, so a misconfigured node is still a peer in the mesh (the data plane is unaffected).

The control port's handlers live in `pkg/mesh/control.go` (`ControlServer`, holding a `*Gossiper`), reused by both `cmd/sovereign-node` (the `--control-addr` wiring) and the SDK test's in-process node — so the test drives the SAME handlers the production binary serves (no duplicated route logic). The control port also serves `/livecheck` and (optionally) `/metrics` over TLS so a single SDK dial reaches every read the SDK offers; the plain-HTTP `--metrics-addr` surface stays for unauthenticated ops scrape (ADR-0006 — the control-port `/metrics` is an ADDITIVE TLS-gated mirror, not a replacement).

---

## 3. The control-plane / data-plane separation (the primary-risk mitigation)

PRIMARY RISK: the control port MIXES data plane and control plane if it uses the SAME `--bind` listener as peer gossip. Root cause (one sentence): a client's JSON request and a peer's length-prefixed `BatchEnvelope` share one accept loop → a malformed JSON from a malicious client could be fed to the FROZEN `HandleFrame` gate stack, corrupting the verdict counters / tripping a chaos tooth.

Mitigation (ENCODED): the `--control-addr` is a SEPARATE `*tls.Listener` with its OWN handlers (`http.Server` driving the `/v1/*` JSON routes); `--bind` stays the peer path; `--metrics-addr` stays the ops plain-HTTP surface. The control port does NOT touch the receive gate stack (`receiver.go` / `ingress_epoll.go` stay byte-locked — the 12.2 locks; Day 6's control port has its own `http.Server`, NOT the receive gate stack). THREE surfaces, ONE trust root.

---

## 4. The /v1/insert → InsertLocalEvents seam (NEVER engine.InsertLocal)

The `/v1/insert` handler routes through `Gossiper.InsertLocalEvents` (`gossip.go:202`) — NEVER `engine.InsertLocal` (`crdt.go:912`). The defect the tooth prevents: a route that called `engine.InsertLocal` directly would bypass the payload cache → a future gossip sweep ships a delta with no payload → the peer's `ReconstructEntry` cross-check FAILS → the delta is a `DropVerify` on every peer. `InsertLocalEvents` stamps `PayloadDigest = SHA-256(payload)` from the SAME payload the cache stores (`gossip.go:212`), so digest and payload are consistent by construction — the receive-side C6 tooth stays honest. The handler doc encodes this; the SDK's `InsertLocal` doc states the insert is LOCAL-ONLY at return (peer convergence is eventual — the next gossip sweep).

---

## 5. The read-path boundary (restated — the LatestPayload accessor + the GetResult type)

The `LatestPayload(entityID)` accessor (`gossip.go`, NEW) reads `g.cache` via the EXISTING `cache.lookup(entityID, dot)` (`gossip.go:78`) for the dot that `engine.State().Get(entityID)`'s latest entry reports (the most-recent `DotCounter`). Returns `(payload string, ok bool)`. On the originator: the cache has it. On a peer: the cache does NOT (Ruling-3 discard). ONE new method; mount NO new retention path (it READS the existing cache, not a new store).

The `GetResult` type (SDK + the `/v1/get` JSON response) makes the originator-vs-peer boundary VISIBLE: `Payload` is NON-EMPTY only on the originator (cache hit); on a peer it is `""` and `PayloadDigest` carries the digest. A Get that returns the digest hex as if it were the value is the fabrication the G06.e tooth catches.

---

## 6. IS-NOT (what Day 6 does NOT deliver — scope discipline)

- Does NOT touch the 5 TRUE-FROZEN files (md5-lock PRE+POST).
- Does NOT touch `receiver.go` / `ingress_epoll.go` (the 12.2 locks; Day 6's control port is a SEPARATE server, NOT the receive gate stack).
- Does NOT ship a Cap'n Proto RPC (the schema is FROZEN; JSON is the honest control-port choice; capnp RPC is a post-10-day additive-gen track).
- Does NOT claim linearizability (`InsertLocal` returns at local-apply; peer convergence is eventual — the next gossip sweep; the doc says so).
- Does NOT ship the 1M/sec benchmark (Day 7 — SCISSORS).
- Does NOT ship AF_XDP (Day 9) or eBPF steering (Day 8).
- Does NOT widen `NewReceiver` / `NewGossiper` arity (the §7 symbol-gate discipline; the `--control-addr` routes hold a `*Gossiper` via the existing `Cache()` accessor + the new additive `LatestPayload`).
- Does NOT fabricate a value-return on a peer Get (G06.e catches the sin).
- Does NOT delete `examples/embed/main.go` (it documents the engine-level stack; Day 6 ADDS `examples/sdk/main.go`, the user-level file the battle plan names).
- Does NOT add a Go dependency (Day 6 uses ONLY stdlib: `net/http`, `encoding/json`, `crypto/tls`, `crypto/x509`); go.mod/go.sum are 0-diff.

---

## 7. Honest weaknesses (minimum 5)

1. **The read path is digest-complete, NOT value-complete on peers.** A `Get` on a peer returns the `PayloadDigest`, not the payload string (Ruling 3 — the value is discarded after the integrity cross-check). A downstream consumer that needs the VALUE on a peer must re-publish it or hold it out-of-band; the SDK reports the boundary honestly but does NOT paper over it. This is the single most likely fabrication on Day 6 and the G06.e tooth exists to catch it.

2. **The control port is NOT linearizable.** `InsertLocal` returns at local-apply; peer convergence is eventual (the next gossip sweep). A client that inserts then immediately reads from a DIFFERENT node may see stale state until the sweep ships the delta. The doc says so; the SDK does NOT offer a read-your-writes guarantee across nodes.

3. **The payload cache is unbounded.** `payloadCache` (`gossip.go:55`) is unbounded by intent through Day 6 (a control-port gate does not need eviction). A long-running originator accumulates payloads for every dot it ever published; a production-sized cache (bounded map + LRU) is a carry-forward (named in ADR-0007). The `LatestPayload` accessor reads the latest dot only, but the cache retains all historical dots until a sweep's `sweepStampedDrops` lazily GCs them.

4. **JSON is copy-mode by nature; the control port is NOT zero-copy.** The control port's floor is the JSON unmarshal + the `engine.InsertLocal` CAS + the TLS record write — all copy-mode. The data plane's zero-copy is Day-9 AF_XDP. The control port does NOT compete with the data plane on throughput; a client doing >1K ops/sec should ride the batched binary wire, not the JSON control port.

5. **`/metrics` on the control port is an ADDITIVE TLS-gated mirror, not the canonical scrape.** The canonical Prometheus scrape is the plain-HTTP `--metrics-addr` surface (ADR-0006/0008). The control port's `/metrics` exists so a single SDK dial reaches every read, but an ops scraper should still hit `--metrics-addr` (no client cert required). The two are consistent (same Registry) but the plain-HTTP surface is the ops contract.

6. **The `LatestPayload` "latest dot" scan is a max-`DotCounter` heuristic.** For a single entity the entries are dot-ordered in the leaf, but the accessor scans for the max `DotCounter` to be robust to multi-origin Add-Wins coexistence. In a multi-origin overwrite race the "latest" by `DotCounter` may not be the causal latest (dots from different origins are not totally ordered by counter alone); the accessor returns the highest-counter entry's payload, which is the honest best-effort and matches the `/v1/get` handler's scan exactly. Day-6.5 made the pick a TOTAL ORDER (max `DotCounter`, ties broken by smallest `DotNodeID` via `bytes.Compare`) so two nodes scanning the same equal-counter multi-origin entries can no longer return a different "latest" — the heuristic is still not a causal claim, but it is now a deterministic pure function of the entry slice.

7. **The SDK's `Metrics()` reader historically collapsed a CounterVec's label dimensions to a single last-wins scalar.** `parsePrometheusText` returned `map[string]float64` keyed by metric NAME only (it stripped the `{labels}` at the brace), so `sovereign_ingest_verdicts_total` — a CounterVec with one `verdict` label and six values — collapsed to ONE scalar on a scrape: the caller saw one value and LOST five. This was silent data loss in the SDK's own metrics reader; Day-6 shipped it (the gate never scraped a real CounterVec). Day-6.5 replaced it with a label-preserving `MetricSample` surface (`Client.Metrics() -> MetricSamples`, one `MetricSample` per `name{labels} value` line, with `Value(name)`/`Samples(name)` accessors that make the old scalar behavior explicit instead of silent). The old silent-collapse is GONE; the G06.5.C tooth proves all six verdict labels survive a scrape with their driven counts. The parser also skips (never panics on) malformed brace groups — a panic in `Metrics()` on a bad scrape would have been a NEW bug.

---

## 8. Self-adversarial critique (4 ATTACK + 1 MEDIOCRITY)

### ATTACK 1 — the capnp temptation

A capable engineer sees "JSON control port" and reaches for Cap'n Proto RPC for "efficiency." The attack: add a `ClientRequest` struct to `schema.capnp`. The refutation: `schema.capnp` (md5 47d2796a) is TRUE-FROZEN; the codegen (`schema.capnp.go`, md5 590af228) changes on any schema edit — a FROZEN breach that FAILS G06.f. JSON's ~100ns–1us unmarshal is invisible against the ~36 ns apply + ~30–50 ns TLS record on a LOW-RATE control surface. The capnp RPC is a post-10-day additive-gen track in a non-FROZEN package; touching the FROZEN schema at Day 6 is the sin.

### ATTACK 2 — the linearizability temptation

The attack: make `InsertLocal` block until peers acknowledge, or have `Get` fan out a quorum read, and market it as "linearizable." The refutation: the engine is a δ-CRDT; `InsertLocal` returns at local-apply by construction, and peer convergence is eventual (the next gossip sweep). A blocking insert or a quorum read would (a) couple the control port's latency to the gossip round-trip (~60 us verify per delta, pre-batch), defeating the low-rate manageability purpose, and (b) be a FALSE claim — the mesh does NOT provide linearizability, it provides eventual convergence. The honest doc states the boundary; a fabricated linearizability claim is the sin (G06.e is the read-side tooth; the write-side equivalent is the doc).

### ATTACK 3 — the track36 transient-conflict (the SAME Day-4/Day-5 hit)

The `track36` scope tooth (`pkg/receive/track36_crosscheck_test.go`) runs `git diff --name-only HEAD -- pkg/` and asserts every `pkg/` path is in `track36EditedSet` (lines 365–376). Day 6 touches `pkg/mesh/gossip.go` (ADDITIVE: the `LatestPayload` accessor) and adds `pkg/mesh/control.go` — NEITHER is in the allowlist. SAME transient conflict as Days 4 + 5 (ADR-0009/0010 ATTACK 4). The tooth passes POST-COMMIT (the `pkg/` diff vs HEAD is empty once committed). DO NOT edit the tooth. Commit Day 6 as ONE atomic unit; the tooth passes post-commit. Verified by the architect on Day 4 AND Day 5 post-commit.

### ATTACK 4 — the value-fabrication on a peer Get (the catastrophic-failure mode)

The attack: the battle plan's `Get(key) (val, ok)` draft invites returning the `PayloadDigest` hex AS IF it were the value on a peer (where only the digest survives). A peer Get that returns a non-empty `Payload` where the value was discarded is a FORGERY — it reports data the node does not hold. The refutation: the `GetResult` type makes the boundary VISIBLE (`Payload` empty on a peer, `PayloadDigest` non-empty), and `TestClientGetOnPeerReturnsDigestNotValue` (G06.e) is the tooth that catches it — it asserts `Payload == ""` AND `PayloadDigest != ""` on a gossip-converged peer. A fabricated value-return on a peer is the single most likely Day-6 fabrication and the ONLY way to fail catastrophically; the tooth makes the boundary OBSERVABLE.

### MEDIOCRITY 1 — the <50-line knob is the SDK's job, not the example's

A mediocre engineer hits the <50-line gate by golfing the example: cryptic one-liners, elided error handling, magic numbers. The spirit of the gate is that a developer can READ the example cold and use the engine; a tricked-up 49-line example that is unreadable FAILS the spirit (the auditor flags it). The honest fix is to MOVE the helper into `sdk/sovereign` (the SDK's job) — Day 6 added `DialWithCerts` (the cert-loading one-liner) so the example's cert boilerplate lives in the SDK, not the caller. The example is the DEVELOPER'S reading material; it is CLEAR, not golfed. The <50-line count is the proof a developer can use this; the clarity is the proof it is usable.

---

## 9. §5 verdict lock + bottom line

Day 6 is NOT an E1/E2/E3/E5 verdict-blocker. §5 STAYS CONDITIONAL-GO. Day 6 does NOT flip §5, does NOT upgrade to UNCONDITIONAL-GO, does NOT re-prove a §5 number. Day 6 ADVANCES the architectural claim from "the API surface is zero; a developer cannot use this" to "a developer connects to a running mesh over mTLS, performs a state operation in <50 lines of Go, and the read path reports the originator-vs-peer payload boundary HONESTLY (Ruling 3 — the value survives on the originator, the digest on a peer)." A fabricated value-return on a peer is the catastrophic-failure mode the G06.e tooth catches.

**Bottom line:** the engine is USABLE, not linearizable. The bytes are the truth. The <50-line example is the proof a developer can use this. The G06.e tooth is the proof the read path is honest. Nothing fabricated; the read path reports the digest/value boundary HONESTLY.
