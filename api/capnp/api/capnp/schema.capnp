# Cap'n Proto schema for the Sovereign Engine ingestion wire format.
#
# the physical invariant:
#   - Absolute 8-byte alignment is the physical invariant. Every field here
#     is either a fixed 8-byte primitive (Float64 / UInt64) or a pointer
#     (Text) so that the struct's data section is a contiguous run of 8-byte
#     slots with zero internal padding. The go-capnp v3 decoder overlays
#     the struct directly onto the raw socket buffer (SingleSegment arena,
#     no copy), and runtime.Pinner locks the backing mmap so the GC never
#     moves reclaimed arena memory from under the parsed TriTemporalEvent.
#
# Field name casing: Go bindings use CamelCase accessors. The names below are
# already CamelCase so capnpc-go generates SetLatitude/Latitude etc. exactly
# as the consumers in internal/transport expect.

@0xeb5b7e1f3a9c4d27;

using Go = import "/go.capnp";
$Go.package("capnp");
$Go.import("github.com/hr18vk/sovereign/api/capnp/api/capnp");

# TriTemporalEvent is the unit ingested by the EPOLLET transport and written
# into the off-heap MemTable. It encodes a spatial event with a tri-temporal
# timestamp envelope.
struct TriTemporalEvent {
    latitude        @0 :Float64;
    longitude       @1 :Float64;
    assertionTime   @2 :UInt64;
    entityId        @3 :Text;
    payload         @4 :Text;
}

# CRDTDeltaEvent is the engine<->engine CRDT sync wire format. It is a DISTINCT
# protocol from TriTemporalEvent: TriTemporalEvent is client->engine ingestion
# (untrusted edge, spatial lat/long); CRDTDeltaEvent is engine<->engine sync
# (mutually-authenticated peers, CRDT delta contract). Their senders, receivers,
# trust boundaries, and lifecycles differ; their field sets are disjoint except
# for the assertionTime dimension. Folding one into the other would re-entrench
# the bypassed-schema defect class: a schema that does not fit the data is
# circumvented rather than extended.
#
# the physical constraint: the data section is a contiguous run of 8-byte slots with zero
# internal padding. The two [16]byte node IDs and the [32]byte digest are
# carried as fixed-size Data (capnp pads Data to 8-byte granularity
# automatically) so the receiver decodes them sliceless. The two Text pointer
# fields (entityId, payload) carry the entityId and payload pair -- the payload
# bytes must cross the wire, never only PayloadDigest; the CRDT reconstruction
# integrity checks (ADR-0045) never allow that regression.
#
# version is the single forward-compat surface (@0 :UInt16). Semantics: the
# encoder stamps the version of the schema it serialized against; the decoder
# compares the on-wire tag against its own compiled-in schema version and, on
# mismatch, fails explicitly (never silent fall-through to zero-received
# fields -- that is how the bypassed-schema defect hid). Minimum
# forward-compat machinery: no
# unknown-field bags, no bitmasks.
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

# CRDTDeltaBatch is the batched wrapper for the causal dot attribution checks
# (ADR-0045) around CRDTDeltaEvent. It carries a List(CRDTDeltaEvent) so that
# one decode + one Join can move N CRDT-entries through the ReconstructEntry
# seam atomically (reconstruct-all-then-join-once). It is a distinct struct
# from CRDTDeltaEvent; CRDTDeltaEvent's CRDT reconstruction integrity checks
# (ADR-0045) wire surface (13 fields, TypeID 0xa90774c0daa3fdc7) stays
# byte-identical — the batch is a new wrapper, not a modification of the
# single-event schema.
#
# the physical constraint: the struct's single field is a pointer to a List(CRDTDeltaEvent)
# (composite list, 8-byte-aligned element stride). The decoder overlays the
# list onto the raw buffer and yields per-element views that share the parent
# arena; the production entry point (pkg/sync ApplyCRDTDeltaBatch) Releases the
# single *Message at function scope, exactly as the delta batch integrity checks
# (ADR-0045) single-event path does — there is exactly one arena per batch
# frame, not one per element.
#
# Scope (the causal dot attribution checks (ADR-0045), and only that):
# length-prefix framing, gzip/Snappy, and a real network transport are
# carry-forwards gated on the Ed25519 origin auth and transport work
# (ADR-0036, ADR-0037) real traffic. This schema is the batch shape only; the
# transport concerns are out of scope.
struct CRDTDeltaBatch {
    events @0 :List(CRDTDeltaEvent);
}
