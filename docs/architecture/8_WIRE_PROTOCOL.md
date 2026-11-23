# 8. Wire Protocol

Sovereign Engine has separate protocols for peer synchronization, client control,
and the experimental Cap'n Proto ingestion server. They have different trust
boundaries and framing. A shared schema file does not make them interchangeable.

The node binary uses a length-prefixed TLS data plane between peers and a
JSON-over-mTLS control listener for clients. The raw EPOLLET server under
`internal/transport` is implemented and tested on Linux, but
`cmd/sovereign-node` does not start it. It is therefore an available transport
implementation, not the listener used by the node binary.

## Wire surfaces

| Surface | Framing and encoding | Authentication | Status |
|---|---|---|---|
| Peer data plane | Big-endian length prefix around relay, batch, hybrid, digest, or challenge bodies; Cap'n Proto inside state-carrying envelopes | TLS peer identity, signed deltas, and a node-key challenge | Used by `cmd/sovereign-node` |
| Client control | JSON over HTTP | mTLS with client certificates | Enabled by `--control-addr`; disabled when that flag is empty |
| Operations | HTTP, including health and optional metrics | Separate listener configuration | Separate from the peer and client-control listeners |
| Raw event ingestion | Cap'n Proto stream framing around `TriTemporalEvent` | No peer authentication in `EpollServer` | Built and tested on Linux; not wired into the node binary |

## Cap'n Proto schemas

`api/capnp/api/capnp/schema.capnp` defines the three Cap'n Proto structs. The
file ID is `@0xeb5b7e1f3a9c4d27`. Generated bindings are produced with
`capnp compile -ogo -I <capnp-go>/std` and live beside the schema.

The generated `*_TypeID` constants identify the schema types. The generated
`ReadRoot*` functions resolve the message root as the requested Go type; they
do not compare a root Type ID against those constants. Envelope dispatch,
explicit version checks, and field validation provide the protocol checks.

### Client event: `TriTemporalEvent`

`TriTemporalEvent` is the input to the standalone EPOLLET ingestion server:

```capnp
struct TriTemporalEvent {
    latitude        @0 :Float64;
    longitude       @1 :Float64;
    assertionTime   @2 :UInt64;
    entityId        @3 :Text;
    payload         @4 :Text;
}
```

Its generated Type ID is `0xbeb44ec2f6a3f8ae`. The three scalar fields occupy
24 bytes and the two text fields are pointers. This client event is not the
full database record: system time, the valid-time interval, the H3 cell, and
the payload digest are handled separately by the database and CRDT paths. The
logical tuple is described in `docs/architecture/1_ARCHITECTURE.md` §1.4.

### Peer event: `CRDTDeltaEvent`

`CRDTDeltaEvent` carries one delta between engines. Its generated Type ID is
`0xa90774c0daa3fdc7`.

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

The 13 fields have these contracts:

- `version` must equal `CRDTDeltaEventWireVersion`, currently `1`. Both apply
  paths reject a mismatch instead of interpreting missing or incompatible
  fields as zero values.
- `payloadDigest` is the 32-byte SHA-256 digest of `payload`.
  `ReconstructEntry` recomputes the digest from the received payload and
  rejects a mismatch. The payload itself must be present; its digest alone
  cannot reconstruct the value.
- `originNodeID` and `dotNodeID` are 16-byte node identities. Reconstruction
  requires them to match, binding the causal counter to its origin.
- `dotCounter` is the origin's causal counter. `h3Index` is the H3 cell carried
  by the entry.
- `systemTime`, `validTimeStart`, `validTimeEnd`, `assertionTime`, and
  `decisionTime` carry the temporal coordinates. Only `assertionTime` also
  appears in `TriTemporalEvent`.
- `entityId` and `payload` are the entity/value pair. Reconstruction copies
  fields out of the Cap'n Proto arena. The engine retains the digest but not
  the payload bytes after validation.

### Batch wrapper: `CRDTDeltaBatch`

`CRDTDeltaBatch` adds a list without changing `CRDTDeltaEvent`. Its generated
Type ID is `0x8832c13e5bbfaa0c`.

```capnp
struct CRDTDeltaBatch {
    events @0 :List(CRDTDeltaEvent);
}
```

`BuildCRDTDeltaEvent` in `pkg/sync` builds one event. `BuildCRDTDeltaBatch` in
`pkg/mesh` builds the batch form directly from `BuiltEvent` values. Both use
`capnp.Message.Marshal`, so the returned `batchWire` or event wire includes
Cap'n Proto stream framing. Attribution and transport envelopes wrap those
bytes; they do not replace that inner framing.

The receive methods are:

- `(*DeltaCRDTEngine).ApplyCRDTDeltaEvent(wire []byte) error` decodes one
  event, checks its version, reconstructs it with the receiver's Lamport skew
  bound, and joins the validated entry.
- `(*DeltaCRDTEngine).ApplyCRDTDeltaBatch(wire []byte) (BatchApplyResult,
  error)` uses one Cap'n Proto message and one Lamport snapshot for the whole
  batch. Valid elements are accumulated before one `Join`. An excessive
  Lamport counter holds only that element; a version, field, attribution, or
  digest failure rejects the batch before `Join`.

`BatchApplyResult` reports joined and held counts, the held dot counters, and
the origin of the first joined element. The receiver reports a batch held in
full as `DropVerify`; an empty batch is an accepted no-op. Index feeds omit
held elements. A partially held batch is not retained for relay because its
origin signature covers the complete batch and cannot be split into a new
signed subset.

## Peer transport framing

Every peer body is prefixed by a four-byte big-endian length:

```text
[4] frameLen, uint32 big-endian
[frameLen] frame body
```

`receive.LengthPrefixFrame` adds the prefix and `receive.FrameReader.ReadFrame`
removes it. The reader rejects empty bodies and bodies larger than 16 MiB,
retains trailing bytes for the next call, and returns an owned copy of each
body. The limit bounds allocation from an untrusted length prefix; it is not a
Cap'n Proto segment-size field.

TLS protects the resulting byte stream. After reassembly, the body is a
`RelayEnvelope`, `BatchEnvelope`, `HybridEnvelope`, digest frame, or challenge
frame. The first bytes select the parser.

### `RelayEnvelope`: one event with relay provenance

`RelayEnvelope.Marshal` writes version 3. The parser also accepts version 2.
Fields in this envelope are little-endian, unlike the outer length prefix and
the batch-envelope header.

```text
v3 fixed header:
  [2]  envelopeVersion = 3
  [2]  hopCount
  [4]  innerLen
  [64] originSig, over innerWire
  [8]  dotCounter mirror
  [16] originNodeID mirror

then:
  [innerLen] innerWire, the marshaled CRDTDeltaEvent
  hopCount records:
    [32] relayPub
    [64] relay signature
    [8]  wallUSec

The accepted v2 header is 72 bytes and omits both mirror fields.
```

`RelayEnvelope.Open` checks the hop bound before verifying relay signatures.
Each hop signs `innerWire || precedingHopsSigMaterial || hopIndex || wallUSec`.
After `Open` returns, `Receiver.HandleFrame` resolves the origin key and checks
`originSig` against the unchanged inner event.

Version 3 lets the rate and clock gates read the counter and origin before a
Cap'n Proto decode. Those mirrors are cross-checked against the authenticated
inner event before it is applied. Version 2 instead decodes its admission
fields from the inner event.

### `BatchEnvelope`: one Ed25519 signature per batch

`BatchEnvelope` carries self-originated events in one signed Cap'n Proto batch.
Its header fields are big-endian.

```text
fixed header:
  [4]  magic = "SBAT"
  [1]  version = 1
  [8]  originSeq
  [2]  batchCount, informational
  [16] originNodeID
  [64] originSig, Ed25519 over batchWire

then:
  [...] batchWire, the marshaled CRDTDeltaBatch
```

`UnmarshalBatchEnvelope` rejects a short header, wrong magic, or unsupported
version with `ErrBatchMalformed`; a zero origin signature returns
`ErrBatchUnsigned`. Parsing leaves `batchWire` opaque until verification
succeeds. `CRDTDeltaBatch.Events().Len()`, not the informational header count,
is authoritative for apply.

`ShipBatch` signs the marshaled batch directly and increments `originSeq` for
each distinct batch. `Receiver.HandleBatchFrame` resolves `originNodeID`,
charges the sequence advance to the origin's rate budget, verifies the exact
bytes later passed to `ApplyCRDTDeltaBatch`, and then applies them.

A relayer cannot sign for another origin. After a fully joined batch,
`RetainForeignBatch` retains its original envelope. `shipBatchedDelta`
republishes those signed bytes unchanged and deduplicates the batch for each
peer and sweep. If no retained batch exists, it falls back to a retained
per-frame `RelayEnvelope` when one is available.

### `HybridEnvelope`: Ed25519 and ML-DSA-65

The opt-in hybrid format extends the batch header with a post-quantum
signature:

```text
fixed header:
  [4]    magic = "SHYB"
  [1]    version = 1
  [8]    originSeq
  [2]    batchCount, informational
  [16]   originNodeID
  [64]   edSig
  [3309] pqSig, ML-DSA-65

then:
  [...] batchWire
```

`ShipBatchHybrid` obtains both signatures from `SignCRDTFrame_Hybrid`. They
cover the same 120-byte SHAKE256 pad derived from `batchWire`; the receiver
applies the original `batchWire`, not the pad. `VerifyBatchHybrid` requires
both signatures to verify. A zero value for either returns
`ErrHybridUnsigned`, and an invalid header returns `ErrHybridMalformed`.

`--hybrid-sign` and `--hybrid-verify` both default to false. Signing selects
`ShipBatchHybrid` for self-originated batches and requires the owner's ML-DSA
key. Verification enables `HandleHybridFrame` and rejects classical-only relay
and batch frames; with verification disabled, hybrid frames are rejected.
Foreign hybrid envelopes are retained and republished with both signatures
intact.

### Digest frames

Digest frames carry reconciliation hints rather than CRDT state. `SDST`
distinguishes them from signed state envelopes.

```text
fixed header:
  [4]  magic = "SDST"
  [16] senderNodeID
  [1]  role
  [8]  seed
  [8]  buildStamp
  [4]  seLen

then, for an ordinary request or response:
  [seLen] marshaled StrataEstimator
  [...]   marshaled IBLT
```

The roles are `0x01` for a v1 request, `0x02` for a v1 response, `0x11` and
`0x12` for their v2 counterparts, and `0x03` for a one-way Merkle-root
announcement. A root announcement has `seLen == 0` followed by the root, not
an estimator and IBLT. Multi-byte digest-header fields are big-endian; the
IBLT body has its own encoding.

With `--iblt-v2` enabled alongside stratified anti-entropy, a request body can
contain only the eight-byte `IBL2` header: its little-endian magic and the
requested bucket count. The responder builds the populated table at that size,
so the request need not carry a table the receiver would discard. The option
defaults to false and has no effect when stratified anti-entropy is disabled.

Digests are unsigned advisory input. `Gossiper.DeliverDigest` requires a
challenge-verified connection and an exact match between that connection's
identity and `senderNodeID`. A malformed response or failed peel leads to the
configured defer or oversend path. Any resulting state still arrives in signed
delta envelopes.

### Connection challenge

`SGWC` frames bind the TLS connection's claimed node identity to possession of
the Ed25519 key registered in the identity directory. They run during
connection setup, outside `RelayEnvelope`:

```text
challenge:
  [4] "SGWC" + [1] role 0x01 + [16] challengerID + [32] nonce

response:
  [4] "SGWC" + [1] role 0x02 + [16] responderID +
  [16] challengerID + [32] nonce + [64] Ed25519 signature
```

The response signs a domain-separated message containing the nonce and both
identities. The challenger checks the returned nonce and the directory key.
The accept-side `serveConnWithDigest` handles these frames before ordinary
batch, digest, hybrid, or relay dispatch.

## Dispatch and parser tests

`DispatchFrame` classifies an already reassembled body without copying it:

```text
IsBatchFrame  -> Receiver.HandleBatchFrame
IsDigestFrame -> DigestSink.DeliverDigest
IsHybridFrame -> Receiver.HandleHybridFrame
otherwise     -> Receiver.HandleFrame
```

The frame discriminators are pairwise distinct; relay bodies instead begin
with their little-endian version. Challenges are intercepted before
this router on the accept side. A nil digest sink consumes and drops a digest
without sending it through the state-receive gates.

`FuzzDispatchFrame` checks classification and routing with no-op sinks. It
does not decode Cap'n Proto, verify signatures, or apply CRDT entries. Separate
fuzz targets drive `UnmarshalRelayEnvelope`, `UnmarshalBatchEnvelope`,
`UnmarshalHybridFrame`, `UnmarshalStrataEstimator`, and `UnmarshalIBLT`
directly. The seed builders supply both the in-process inputs and committed
corpora.

## HTTP control wire

`ControlServer.Handler` serves JSON on the `--control-addr` mTLS listener.
Client certificates are required and the listener uses TLS 1.3. These routes
are not carried on the peer data plane.

| Method and route | Purpose |
|---|---|
| `POST /v1/insert` | Insert one key/value and return its causal dot |
| `POST /v1/batch-insert` | Insert a JSON `items` array through the WAL group-commit path when durable mode is configured |
| `GET /v1/get` | Read current live state and, on a local cache hit, its payload |
| `GET /v1/query` | Resolve one persisted version at valid and transaction times |
| `GET /v1/range` | Return persisted rows intersecting a valid-time window |
| `GET /v1/merkle` | Return the current Merkle root and commit statistics |
| `GET /livecheck` | Return node, peer, and TLS status |
| `GET /metrics` | Serve metrics when a metrics handler is configured |

The persisted query routes return HTTP 503 when no resolver is configured.
`/v1/querybyh3` and `/v1/querybysystime` are registered only with
`--secondary-index`; they use the same resolver and also return HTTP 503 when
it is unavailable. The H3 value is opaque to the engine apart from syntactic
cell-mode validation.

Insert handlers call the gossiper so the payload cache and engine state stay
suitable for a later signed delta. `BatchItem` contains `EntityID`, `Payload`,
and `Entry` and is converted to `durability.LocalItem` for durable insertion.
With a bridge configured, `InsertLocalEventsBatch` performs the engine inserts
and one `AppendMutations` group commit. Without a bridge, it performs the same
in-memory insertion sequence as repeated single inserts.

A durable batch error sets every otherwise valid item's JSON status to `503`;
success sets it to `200` and returns its dot. This is all-or-none
acknowledgment, not a rollback: earlier inserts may already have changed
engine state or reached the page cache when a later write or fsync fails. The
caller retries the batch.

The plain-HTTP operations listener is configured separately from this mTLS
control API. Enabling one does not move its routes onto the other listener.

## WAL records

The write-ahead log is an on-disk format, not a peer frame. Its implementation
is in `internal/chaos/wal.go`; `pkg/durability/wal.go` aliases the same types so
recovery and callers share one codec.

A WAL file starts with an eight-byte header containing `WAL\0`, format version
`1`, and two reserved bytes. Each record then has a big-endian sequence,
type, and payload length:

```text
file record:
  [8] sequence
  [1] record type
  [4] payload length
  [payload length] payload
```

The type byte has six defined values:

```text
0x01  WALRecMutation       legacy mutation subset
0x02  WALRecCheckpoint     legacy root and Lamport watermark
0x03  WALRecClockAdvance   peer-driven Lamport advance
0x04  WALRecMutationV2     complete CRDTEntry with its recorded dot
0x05  WALRecCheckpointV2   CutSeq, ClockHigh, and optional state fingerprint
0x06  WALRecChecksummed    CRC32C wrapper around another record
```

New appends use `0x06`. Its payload is:

```text
[1] innerType + [innerPayload] + [4] CRC32C, big-endian
```

The Castagnoli checksum covers `innerType` and `innerPayload`. Sequence
contiguity and the payload-length bound check the outer fields separately.
New local mutations carry the V2 payload inside this wrapper, preserving the
recorded dot so replay restores rather than re-mints it. Checkpoints and clock
advances use the same wrapper. Replay also accepts unframed `0x01` through
`0x05` records for existing logs.

A partial trailing record is treated as the crash boundary. A complete record
with a bad checksum returns `ErrWALCorrupt`, and recovery refuses to rebuild
from it. Group commit appends each mutation record under one write-side lock
and then releases that lock before the batch fsync. A nil return means the
batch's fsync completed.

## Standalone EPOLLET ingestion server

`internal/transport.EpollServer` accepts `TriTemporalEvent` messages on a
persistent TCP or Unix domain socket. It is Linux-specific and independent of
the peer `FrameReader`. `TestParseMessages_RealClient_EndToEnd` exercises it
over a Unix domain socket; that test is not evidence of node-binary TCP wiring.

### Single-segment stream framing

The server accepts Cap'n Proto single-segment stream messages and closes the
connection on a multi-segment message.

| Offset | Size | Field | Meaning |
|---|---:|---|---|
| `0x00` | 4 bytes | `segmentCount - 1` | Little-endian uint32; zero selects one segment |
| `0x04` | 4 bytes | `segmentWords` | Little-endian uint32; payload size in eight-byte words |
| `0x08` | variable | segment data | Serialized Cap'n Proto payload |

For example, a 16-byte segment uses two words:

```text
00 00 00 00  02 00 00 00  // one segment, two words
xx xx xx xx  xx xx xx xx  // word 1
xx xx xx xx  xx xx xx xx  // word 2
```

`parseMessages` waits for the complete header and segment, and limits a
segment to 64 MiB. A larger declared segment closes the connection. Once the
segment is complete, `ReadRootTriTemporalEvent` decodes it and the handler runs
synchronously before the reassembly buffer is advanced.

### Event loop and buffer lifetime

One event-loop goroutine serves all connections to an `EpollServer`. The read
path uses `syscall.Read` into a jemalloc-backed reassembly buffer, initially
64 KiB, and drains each edge-triggered socket until `EAGAIN` or `EWOULDBLOCK`.
TCP flow control applies when the receiver stops reading; the server does not
manipulate the receive window. A separate admission limit closes newly
accepted connections above `MaxConnections = 4096`.

`network.NewIngestionArena` wraps the exact segment slice with
`capnp.SingleSegment`. The arena is read-only: `Allocate` returns an error,
`Release` does not return the segment to Cap'n Proto's buffer pool, and
Cap'n Proto reads the segment in place. This avoids copying the segment into a
Go-owned buffer; it is not a claim that event handling or the complete write
path performs no allocations.

The event and its text views remain valid only during the synchronous handler
call. The handler must copy anything it retains. `pinIngestionMessage` uses a
zero-value `runtime.Pinner` around dispatch: for a Go-backed slice, pinning
keeps its allocation at a fixed address until `Unpin`, and the first Go-heap
use may allocate pinner state. For the server's off-heap jemalloc storage,
`Pin` is a no-op because the garbage collector does not move or free that
storage.

After the handler returns and the message is released, `advanceBuffer` moves
any trailing partial message over the consumed bytes. Closing a connection
frees its jemalloc buffer. These lifetime rules, rather than pinning alone,
keep decoded views from referring to reused storage.

