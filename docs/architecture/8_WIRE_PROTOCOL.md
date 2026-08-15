# 8. Wire Protocol

The Supremum Engine discards standard HTTP/gRPC stacks in favor of a zero-copy, EPOLLET-based Cap'n Proto interface. This document maps the exact physical byte-layout over the network and memory architectures as seen in `internal/transport/capnp_server.go` and `internal/network/capnp_arena.go`.

## TCP Packet Layout

The Supremum Engine requires clients to send Cap'n Proto single-segment stream frames over a persistent TCP socket.

### Framing Header (8 Bytes)

The engine strictly mandates a single segment message. Multi-segment messages are treated as protocol violations.

| Offset | Size (Bytes) | Field Name | Expected Value | Description |
|--------|--------------|------------|----------------|-------------|
| 0x00   | 4            | `segmentCount - 1` | `0x00000000` | Little-endian uint32. Must be 0 (indicating 1 segment). |
| 0x04   | 4            | `segmentWords` | `uint32` | Little-endian. The size of the payload in 8-byte words. |
| 0x08   | N            | `Segment Data` | - | The serialized Cap'n Proto payload. |

### Visual Hex-Byte Diagram

```hex
// Example: A 16-byte Cap'n Proto payload
00 00 00 00  02 00 00 00  // Framing: 1 segment, 2 words (16 bytes)
xx xx xx xx  xx xx xx xx  // Word 1
xx xx xx xx  xx xx xx xx  // Word 2
```

### Cap'n Proto Schema

The zero-copy overlay maps directly to the following structural schema, which
lives verbatim at `api/capnp/api/capnp/schema.capnp` and is the authoritative
source for the generated Go bindings (`schema.capnp.go`, produced by
`capnp compile -ogo -I <capnp-go>/std`). The Cap'n Proto type ID
(`TriTemporalEvent_TypeID = 0xbeb44ec2f6a3f8ae`) is derived from the file ID
below; a client sending a message whose root struct has any other Type ID is
rejected by `ReadRootTriTemporalEvent` in the transport hot path.

```capnp
@0xeb5b7e1f3a9c4d27;

using Go = import "/go.capnp";
$Go.package("capnp");
$Go.import("github.com/hr18vk/supremum/api/capnp/api/capnp");

# 8-byte-aligned data section: 3 fixed-width primitives (24 bytes) +
# 2 Text pointer slots. Zero internal padding.
struct TriTemporalEvent {
    latitude        @0 :Float64;
    longitude       @1 :Float64;
    assertionTime   @2 :UInt64;
    entityId        @3 :Text;
    payload         @4 :Text;
}
```

**Note on the logical vs. wire data model.** The wire schema above carries the
five fields the EPOLLET transport actually parses off the socket. The full
**logical** `TriTemporalEvent` the database layer materializes
(`internal/database/memtable.go`) additionally carries `SystemTime`,
`ValidTimeStart`, `ValidTimeEnd`, `H3Index`, and `PayloadDigest` — those are
derived/attested by the engine after ingest, not transmitted on the wire. See
`docs/architecture/1_ARCHITECTURE.md` §1.4 for the logical data-model tuple.

---

## The Two Distinct Wires

This document documents TWO physically-distinct Cap'n Proto wires, both
rooted in the same file (`api/capnp/api/capnp/schema.capnp`, file ID
`@0xeb5b7e1f3a9c4d27`). The schema's own header comment
(`schema.capnp:33-40`) states they are intentionally distinct protocols and
MUST NOT be folded into one another (folding re-entrenches the audited C5
defect class). They differ in sender, receiver, trust boundary, and field set:

| Wire | Struct | TypeID | Direction | Transport | Trust boundary |
|------|--------|--------|-----------|-----------|-----------------|
| **client→engine ingestion** | `TriTemporalEvent` | `0xbeb44ec2f6a3f8ae` | untrusted client → single engine | raw `EPOLLET` + `syscall.Read` (this doc, §TCP Packet Layout / §EPOLLET Raw Event Loop) | untrusted edge — spatial lat/long, no peer auth |
| **engine↔engine CRDT sync** | `CRDTDeltaEvent` (single) / `CRDTDeltaBatch` (batch wrapper) | `0xa90774c0daa3fdc7` / `0x8832c13e5bbfaa0c` | mutually-authenticated peer engines | TLS mesh `DispatchFrame` ingress (see §Engine↔Engine CRDT Wire below) | mutually-authenticated peers — CRDT delta contract, Ed25519+ML-DSA-65 signed |

Everything above this divider (§TCP Packet Layout through §EPOLLET Raw Event
Loop and the `mmap` mapping) is the **client→engine ingestion wire**
(`TriTemporalEvent`). Everything below is the **engine↔engine CRDT wire**
(`CRDTDeltaEvent` / `CRDTDeltaBatch`).

## Engine↔Engine CRDT Wire

### `CRDTDeltaEvent` — the engine↔engine CRDT sync wire unit

`CRDTDeltaEvent` is the single-delta wire unit one engine ships to a peer to
reconstruct-and-Join a CRDT delta. Schema lives verbatim at
`api/capnp/api/capnp/schema.capnp` (the `struct CRDTDeltaEvent` block); the
generated binding's TypeID constant is
`CRDTDeltaEvent_TypeID = 0xa90774c0daa3fdc7`
(`api/capnp/api/capnp/schema.capnp.go:139`).

```capnp
struct CRDTDeltaEvent {
    version         @0 :UInt16;
    payloadDigest   @1 :Data;
    originNodeID    @2 :Data;
    dotNodeID       @3 :Data;
    dotCounter      @4 :UInt64;
    h3Index         @5 :UInt64;
    systemTime      @6 :Int64;
    validTimeStart  @7 :Int64;
    validTimeEnd    @8 :Int64;
    assertionTime   @9 :Int64;
    decisionTime    @10 :Int64;
    entityId        @11 :Text;
    payload         @12 :Text;
}
```

Field set (13 fields; data section is a contiguous run of 8-byte slots with
zero internal padding — `Data` slots are 8-byte-aligned, the two `Text` slots
are pointers):

- `version @0 :UInt16` — the single forward-compat surface. The encoder stamps
  the schema version it serialized against; the decoder compares the on-wire
  tag against its compiled-in version and on mismatch fails explicitly (no
  silent fall-through to zero-received fields). The compiled-in version is
  `CRDTDeltaEventWireVersion uint16 = 1` (`pkg/sync/crdt_apply.go:67`), enforced
  as a hard refusal at `pkg/sync/crdt_apply.go:137` (`if ev.Version() != CRDTDeltaEventWireVersion { … "refusing silent fall-through to zero-received fields (C5 guard)" }`).
- `payloadDigest @1 :Data` — the `[32]` SHA-256 digest; the receiver
  cross-validates `PayloadDigest == SHA-256(payload)` in `ReconstructEntry`
  (`pkg/sync/crdt_reconstruct.go`). A mismatch is an honest `DropVerify` on the
  receive side, never a silent accept. Per the schema physics comment, the
  payload bytes (`@12`) MUST cross the wire alongside the digest — never the
  digest alone (the C6 pair).
- `originNodeID @2 :Data` — the `[16]` origin node ID.
- `dotNodeID @3 :Data` / `dotCounter @4 :UInt64` — the CRDT causal dot
  (`{nodeID, counter}`).
- `h3Index @5 :UInt64` — the H3 spatial index cell.
- The FIVE temporal fields — `systemTime @6 :Int64`, `validTimeStart @7 :Int64`,
  `validTimeEnd @8 :Int64`, `assertionTime @9 :Int64`, `decisionTime @10 :Int64`
  — the full tri-temporal-plus-decision envelope the database layer carries.
  (Only `assertionTime` is shared with `TriTemporalEvent`; the other four are
  disjoint on the two wires.)
- `entityId @11 :Text` / `payload @12 :Text` — the C6 entity/payload pair.

The decoder is `ReadRootCRDTDeltaEvent` (generated). A root struct with any
other TypeID is rejected at decode.

### `CRDTDeltaBatch` — the batched wrapper

`CRDTDeltaBatch` is the Phase-2e batch wrapper around `CRDTDeltaEvent`. It
carries a `List(CRDTDeltaEvent)` so one decode + one Join moves N deltas
through the reconstruct-then-join seam atomically. Schema at
`api/capnp/api/capnp/schema.capnp` (`struct CRDTDeltaBatch`); generated TypeID
`CRDTDeltaBatch_TypeID = 0x8832c13e5bbfaa0c`
(`api/capnp/api/capnp/schema.capnp.go:342`).

```capnp
struct CRDTDeltaBatch {
    events @0 :List(CRDTDeltaEvent);
}
```

It is a DISTINCT struct from `CRDTDeltaEvent`; the single-event wire surface
(13 fields, TypeID `0xa90774c0daa3fdc7`) is byte-identical — the batch is a new
wrapper, not a modification of the single-event schema.

### Build / apply seams

- `BuildCRDTDeltaEvent(entityID, payload string, entry CRDTEntry) ([]byte, error)`
  (`pkg/sync/crdt_capnp_wire.go:66`) — the production encoder. Stamps
  `CRDTDeltaEventWireVersion` and constructs the entry from `InsertLocal`'s
  returned `CRDTEntry`; payload and `PayloadDigest` are kept consistent by the
  caller (the receiver cross-validates).
- `ApplyCRDTDeltaEvent(wire []byte) error` (`pkg/sync/crdt_apply.go:113`) — the
  production single-event ingress entry point. Owns the
  `capnp.Unmarshal` → `ReadRootCRDTDeltaEvent` → version guard
  (`:137`) → `ReconstructEntryWithSkewBound` → `Join` boundary; enforces wire
  integrity on EVERY frame before it reaches `Join`. `Release`s the single
  `*Message` at function scope (one arena per frame).
- `ApplyCRDTDeltaBatch(wire []byte) error` (`pkg/sync/crdt_apply_batch.go:118`)
  — the batched ingress entry point; decodes the `CRDTDeltaBatch` and applies
  the per-element reconstruct-then-join, releasing the single arena at function
  scope (one arena per batch frame, not one per element).

### Envelope framing + versioning (the attribution layer)

The CRDT wire's batch bytes are not shipped bare — they are wrapped by the
attribution layer (`pkg/attribution/wire_v1.go`) in a crypto-minimal envelope
that carries the origin's signature:

- `BatchEnvelope` (`pkg/attribution/wire_v1.go:148`) — the v1 classical
  envelope: ONE Ed25519 signature over a batch of N self-originated deltas.
  Fixed header `BatchEnvelopeHeaderLen = 4 + 1 + 8 + 2 + OriginNodeIDSize + OriginSigSize`
  (`wire_v1.go:128`); forward-compat tag `WireV1Version uint8 = 1`
  (`wire_v1.go:122`), honored on parse — a version field `!= WireV1Version` is
  an `ErrMalformed` (no silent downgrade). `OriginNodeIDSize = 16`
  (`envelope.go:164`), `OriginSigSize = 64` (`envelope.go:161`, the origin
  Ed25519 signature). The 15-byte fixed prefix is
  `4 (magic) + 1 (WireV1Version) + 8 (originSeq) + 2 (batchCount)`, followed by
  the `[16]` originNodeID and `[64]` originSig, then the verbatim batchWire.
- `HybridEnvelope` (`pkg/attribution/wire_v1.go:490`) — the Day-32 (ADR-0037)
  hybrid-PQ envelope: BOTH an Ed25519 `edSig [64]` AND an ML-DSA-65
  `pqSig [3309]` over a shared 120-byte SHAKE256 pad. Fixed header
  `HybridEnvelopeHeaderLen = 4 + 1 + 8 + 2 + OriginNodeIDSize + OriginSigSize + PQSignatureSize`
  (`wire_v1.go:464`), where `PQSignatureSize = 3309` (`wire_v1.go:451`, the
  ML-DSA-65 signature wire slot — 3309 B = 51.7× the 64 B Ed25519 sig). A zero
  `edSig` or `pqSig` is rejected pre-verify — BOTH signatures is the
  both-required contract.

### Ingress router (the 4-way `DispatchFrame`)

Every engine readLoop, after TLS, hands the inbound frame to the 4-way ingress
router `DispatchFrame(frame []byte, peerID [16]byte, recv frameSink, digester DigestSink) receive.AcceptVerdict`
(`pkg/mesh/digest.go:176`). It peeks the first 4 bytes (the magic) and routes
to exactly one of four arms — the batch frame arm
(`attribution.IsBatchFrame` → `recv.HandleBatchFrame`), the digest-exchange arm
(`attribution.IsDigestFrame` → `digester.DeliverDigest`), the hybrid frame arm
(`→ recv.HandleHybridFrame`, the state-carrying CRDT-delta path that runs the
Receiver's gate stack: rate → verify → Join), and the relay arm. A digest frame
is not a CRDT delta; the receive gate stack never touches it. The fuzz harness
`FuzzDispatchFrame` (`pkg/security/fuzz/`, corpus in
`pkg/security/fuzz/dispatch_fuzz_test.go` + `seeds_test.go`) is the Day-33
(ADR-0038) no-panic anchor over `DispatchFrame` and the FIVE unmarshalers under
it (`UnmarshalRelayEnvelope`, `UnmarshalBatchEnvelope`, `UnmarshalHybridFrame`,
`UnmarshalStrataEstimator`, `UnmarshalIBLT`); the corpus is committed
(tracked on-disk, not git-ignored) and byte-identity-asserted against the
builders, and a bug-inject test proves the harness is non-tautological.

### Hybrid PQ signature pad (Ed25519 + ML-DSA-65)

When `--hybrid-sign` is set, the self-originated delta path ships each batch
under a hybrid signature: one Ed25519 signature `[64]` AND one ML-DSA-65
signature `[3309]`, both computed over the SAME 120-byte SHAKE256 pad of
`batchWire` (the 120-byte CRDT-frame delta is the ADR-10 `CRDTEntry` shape;
`hybridFrameSize = 120` at `pkg/identity/hybrid_verify.go:110`). A classical
break does NOT compromise a PQ frame; a PQ break does NOT compromise a
classical frame (defense-in-depth).

- `ShipBatchHybrid` (`pkg/mesh/batch.go:245`) — the hybrid-SIGN shipper; signs
  via `SignCRDTFrame_Hybrid` and wraps in a `HybridEnvelope`.
- `VerifyCRDTFrame_Hybrid(edPub ed25519.PublicKey, pqPub *mldsa.PublicKey, msg, edSig, pqSig []byte, ctx string) bool`
  (`pkg/identity/hybrid_verify.go:77`) — the both-required verify gate; returns
  `edOK && pqOK`.
- `--hybrid-sign` (cmd/sovereign-node/main.go:434) and `--hybrid-verify`
  (cmd/sovereign-node/main.go:420) are BOTH **OPT-IN, default false**. OFF keeps
  the self-originated path on the v1 `BatchEnvelope` (one Ed25519) and the
  receive path classical-only — byte-identical to Day-31. `--hybrid-sign=true`
  switches `shipBatchedDelta` to `ShipBatchHybrid`; `--hybrid-verify=true`
  switches the receive path to the both-required `VerifyCRDTFrame_Hybrid` seam
  (a v1 frame is REJECTED in strict mode). The relay/foreign path stays
  per-frame regardless.

### Batched-delta HTTP/control wire (v1)

The control port exposes a JSON batch-insert endpoint that stages N events for
the engine AND records their payloads for the gossiper, so a subsequent sweep
can put the payloads on the wire alongside the engine's `PayloadDigest`:

- `BatchItem` (`pkg/mesh/gossip.go:652`) — `{EntityID string; Payload string; Entry eng.CRDTEntry}`, mirrors `durability.LocalItem` field-for-field.
- `InsertLocalEventsBatch(items []BatchItem) (dots []eng.CausalDot, failedFrom int, err error)` (`pkg/mesh/gossip.go:685`) — the ADR-0044 (Day 39) batch insertion seam. Durable path (`g.bridge != nil`): N × `InsertLocal` + ONE `AppendMutations` + ONE fsync (the group-commit — 10K keys → 1 fsync, not 10K). In-memory path (`g.bridge == nil`, the `--wal-path=""` research mode): N × bare `engine.InsertLocal`. Per-batch 503 signal: a `failedFrom != -1` or non-nil `err` means the WHOLE batch is un-durable (the WAL atomic-batch model) and the caller ACKs all items 503; on success the caller ACKs all items 200 with `DotHex=dots[i]`.
- HTTP surface: `mux.HandleFunc("/v1/batch-insert", s.handleBatchInsert)` (`pkg/mesh/control.go:275`); handler `handleBatchInsert` at `pkg/mesh/control.go:395`. The single `/v1/insert` (`control.go:274` → `handleInsert`, routing through `Gossiper.InsertLocalEvents`) stays byte-identical and is NOT removed.

### WAL opcodes (the durability wire, not the network wire)

For completeness, the durability wire (`pkg/durability/wal.go`, re-exported
from `internal/chaos/wal.go`) carries three record types — these are on-disk
opcodes, NOT network frame types, but they are the third wire a node's data
crosses:

- `WALRecMutation = 0x01` (`internal/chaos/wal.go:58`, re-exported `pkg/durability/wal.go:47`) — a mutation record.
- `WALRecCheckpoint = 0x02` (`internal/chaos/wal.go:61`, re-exported `pkg/durability/wal.go:48`) — a checkpoint record (the Day-8 pair).
- `WALRecClockAdvance = 0x03` (`internal/chaos/wal.go:70`, re-exported `pkg/durability/wal.go:49`) — the Day-8.5 foreign-clock-advance record (the clock jump a peer-driven `Join` performs, fsync-on-commit).

## EPOLLET Raw Event Loop

The `internal/transport/capnp_server.go` implementation leverages raw `epoll(7)` in edge-triggered (`EPOLLET`) mode:
1. **Zero Goroutines Per Connection:** A single thread handles the event loop. Go's standard `net.Listener` is bypassed entirely to avoid `bufio.Reader` heap allocations.
2. **Jemalloc Overlays:** All reads from the socket directly populate a `jemalloc`-backed buffer (`ReadBufSize = 64 * 1024`, `internal/transport/capnp_server.go:44`).
3. **Backpressure via `EPOLLET` drain + hard admission cap (no `net.Conn`, no RWIN):** The read path uses raw `syscall.Read` directly on the fd (`internal/transport/capnp_server.go:324`, comment at `:323` — *"Use raw syscall.Read to bypass Go's net.Conn GC-tracked buffers"*); there is no `net.Conn.Read()` to block and no `gopark`. Under `EPOLLET`, the handler loops `syscall.Read` into the jemalloc grow-buffer until the fd returns `EAGAIN`/`EWOULDBLOCK`, at which point it simply `return`s (`internal/transport/capnp_server.go:334-335` — *"No more data available — edge drained"*). This drains the socket to empty on every edge notification and relies on the kernel's natural TCP flow control (the sender blocks on its own send window when the receiver stops reading); the engine performs no intentional receive-window manipulation and emits no Zero-Window mechanism. The ONLY admission control is a hard connection cap: `MaxConnections = 4096` (`internal/transport/capnp_server.go:47`), enforced at accept time by closing the freshly-accepted fd when `len(s.conns) >= MaxConnections` (`internal/transport/capnp_server.go:262-266`). Beyond that cap, backpressure is edge-triggered drain-until-`EAGAIN` only — no bounded semaphore, no `gopark`, no `internal/temporal_store/toki.go` (that package was deleted in the Day-28 ADR-0033 TOKI closure).

## `mmap` Zero-Copy Pointer Mapping

When a payload traverses the NIC, it is placed directly into the `jemalloc` buffer.
The `internal/network/capnp_arena.go` system applies the `capnp.SingleSegment(messageData)` wrapper to construct a Cap'n Proto `Arena`.

- **Strict Read-Only Guarantee:** Bypassing `bufferpool.Default`, the `SingleSegmentArena` disables the `.Allocate()` method.
- **Zero-GC Invariant:** The Cap'n Proto message structure reads memory directly from the bounded `jemalloc` slice. The byte slice is never registered with the Go runtime pool, and no serialization structs are allocated on the heap, allowing data to flow from the NIC straight to the Tri-Temporal MemTable with O(1) processing overhead.
- **`runtime.Pinner` Relocation Lock (Go 1.21+):** The slice surfaced to the
  Go runtime is GC-visible, so the runtime is *theoretically* free to relocate
  its backing array. A relocation mid-handler would dangle the parsed
  `TriTemporalEvent`'s Text pointers into stale memory — silent cross-request
  corruption. `internal/transport/pinner.go` wraps every handler dispatch in
  `pinIngestionMessage(msgData, …)`, which calls `pin.Pin(&msgData[0])` /
  `defer pin.Unpin()`. Pinning the backing-array object guarantees the GC
  cannot move it for the duration of the handler; `Unpin` releases on return
  (or on panic, via `defer`). This is the second half of the zero-copy
  contract: not only is the buffer not copied, it is *pinned* so it cannot be
  moved out from under the zero-copy struct. `Pin`/`Unpin` are allocation-free
  (the `runtime.Pinner` is a stack value); the witness is
  `TestParseMessages_RealClient_EndToEnd` in `internal/transport/`.
