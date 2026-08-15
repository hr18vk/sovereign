// Package attribution — wire_v1.go is the crypto-minimal BATCH envelope for
// self-originated delta transport (the Day-5 arithmetic unlock).
//
// THE PHYSICS THIS ENVELOPE BREAKS (deconstruct to atoms first):
//
//	Ed25519 VerifyCRDTFrame = 60.19 us/frame (32c PROVEN, circl v1.6.4)
//	=> single-verify ceiling = 1 / 60.19e-6 ~= 533,000 verifies/sec
//	=> 1M/sec is ARITHMETIC-FALSE on the per-frame path while one verify buys
//	   one delta. The ONLY honest path: collapse N verifies into ONE verify.
//
// BatchEnvelope carries ONE Ed25519 signature over a BATCH of N self-originated
// deltas, so the verify cost amortizes from 60.19 us/delta to 60.19/N us/delta.
// At N=100 that is ~0.60 us/delta; the floor then moves to (batch-wire decode +
// N applies + net), each sub-microsecond per delta on the PROVEN 32c apply
// number (~36 ns/entry). This is the arithmetic unlock for the Day-7 >=1M/sec
// headline bench.
//
// THE CRYPTO-MINIMAL DESIGN (strictly STRONGER than a SHA-256 batch-root):
//
//	Ed25519 signs the MARSHALED CRDTDeltaBatch WIRE DIRECTLY:
//	    batchSig = identity.SignCRDTFrame(originSeed, batchWire)
//	    verify   = identity.VerifyCRDTFrame(originPub, batchWire, batchSig)
//
//	Ed25519 (circl, RFC-8032 strict) internally SHA-512-hashes the message
//	byte string in Verify. Signing the wire directly gives:
//	  - ONE hash inside verify (the SHA-512 over batchWire) vs (N+1) SHA-256
//	    hashes in a batch-root scheme — LESS crypto compute, same security
//	    (Ed25519 is already a hash-then-sign scheme; an outer hash is
//	    redundant).
//	  - ZERO new hash scheme (reuse VerifyCRDTFrame VERBATIM — the 60.19us
//	    PROVEN symbol, no new crypto to audit).
//	  - NO hash-then-reconstruct gap: the bytes Verify checks ARE the bytes
//	    ApplyCRDTDeltaBatch (pkg/sync/crdt_apply_batch.go:118) decodes — the
//	    signature covers the EXACT wire batch the engine Join()s. STRONGER
//	    binding than a hash-then-apply scheme (a wire-tamper opportunity
//	    between a verified hash and a decoded wire is closed by construction).
//	  - the FROZEN ApplyCRDTDeltaBatch ALREADY accepts a marshaled
//	    CRDTDeltaBatch wire ([]byte) — so the wire you sign is the wire you
//	    apply, end to end.
//
// THE SELF-ORIGIN BOUNDARY (load-bearing — encode it, do NOT hide it):
//
// A relayer forwarding a FOREIGN delta holds ONLY its own relay seed — it NEVER
// holds the foreign ORIGIN's seed. It can ADD a relay hop-signature
// (attribution.SignHop) over (innerWire || preceding) — the FROZEN RelayEnvelope
// hop chain (envelope.go) — but it CANNOT re-origin-sign a foreign delta.
// BatchEnvelope therefore covers the SELF-ORIGINATED delta path (a node
// batching its OWN N writes into one signed batch). Relay-chained foreign
// deltas STAY per-frame (the FROZEN RelayEnvelope v3 hop chain — UNTOUCHED).
// A batch that relayer-signs foreign origins is a FORGERY (the relay has no
// origin seed) and is a fabrication, not a feature. This is honest and is also
// the DOMINANT production workload (a node's own writes are the high-rate path;
// relay-chained foreign deltas are lower-rate forwarding).
//
// WIRE LAYOUT (the header is the ONLY thing the cheap gate stack parses;
// batchWire is opaque until verify passes):
//
//	[4]  magic         (uint32 big-endian, WireV1Magic — the dispatch
//	                      discriminator; DISTINCT from the RelayEnvelope's
//	                      uint16 little-endian version prefix so a post-length-
//	                      prefix peek routes a batch to HandleBatchFrame and a
//	                      relay frame to HandleFrame with zero ambiguity)
//	[1]  version       (uint8, WireV1Version — honored, no silent downgrade)
//	[8]  originSeq     (uint64 big-endian — the origin's MONOTONIC per-batch
//	                      sequence number, advancing by 1 per batch the origin
//	                      ships. This is the rate-gate counter the receiver
//	                      hands to PeerBucket.Accept: the bucket drains on the
//	                      DELTA between successive originSeq values from the
//	                      same origin, so a burst of batches drains the origin's
//	                      budget (the Sybil-burst isolation the rate gate exists
//	                      to enforce), amortized to one check per batch. It is
//	                      NOT the BatchCount (a static count of deltas would
//	                      produce a zero delta between same-size batches and the
//	                      budget would never drain — a dead rate gate for the
//	                      dominant steady-state workload). It mirrors the
//	                      per-frame path's dotCounter (the monotonic per-origin
//	                      sequence the per-frame rate gate keys on).)
//	[2]  batchCount    (uint16 big-endian — the number of deltas in the batch;
//	                      informational; the authoritative count is the capnp
//	                      CRDTDeltaBatch.Events().Len() the FROZEN apply path
//	                      decodes. Carried in the header so a cheap gate can
//	                      bound a batch without a capnp decode.)
//	[16] originNodeID  ([16]byte — for the GAP-3 Directory.Lookup)
//	[64] originSig     (Ed25519 signature over batchWire by the origin;
//	                      verified by the caller via VerifyCRDTFrame AFTER the
//	                      header parse. A zero originSig is an automatic DROP
//	                      — no unsigned batch is accepted, the same tooth as
//	                      envelope.go's zero-originSig rule.)
//	[...] batchWire    (the marshaled CRDTDeltaBatch capnp frame, verbatim —
//	                      the FROZEN schema is untouched; this is the EXACT
//	                      []byte handed to ApplyCRDTDeltaBatch and the EXACT
//	                      []byte the origin signature covers.)
//
// NO SHA-256 batch root (per the crypto-minimal design — sign the wire
// directly). NO reuse of the FROZEN RelayEnvelope for the batch itself (the
// per-frame RelayEnvelope path in envelope.go stays the SOLE carrier of RELAY
// deltas; the batch is a distinct wire shape). envelope.go (b1beba1e) is NOT
// touched.
package attribution

import (
	"encoding/binary"
	"errors"
)

// WireV1Magic is the 4-byte big-endian dispatch discriminator a receiver peeks
// AFTER the length prefix is stripped to route a frame to the batch path. It is
// DISTINCT from the RelayEnvelope's first on-wire bytes: a RelayEnvelope begins
// with a uint16 little-endian version (2 or 3), so its first 4 bytes are
// 0x02_00_???? or 0x03_00_???? (little-endian). WireV1Magic is chosen so its
// big-endian encoding shares NO leading-uint16-LE prefix with any RelayEnvelope
// version — the dispatch is unambiguous and a batch frame is never handed to
// the FROZEN RelayEnvelope parser (which would DropMalformed it — a silent
// throughput collapse). The value is a fixed, opaque constant (NOT a budget or
// hop-count magic number, so it is outside the forbidden-budget tooth).
const WireV1Magic uint32 = 0x53424154 // "SBAT" — Sovereign BATch (big-endian on the wire)

// WireV1Version is the forward-compat tag for the BatchEnvelope framing. It is
// honored on parse: a version field != WireV1Version is an ErrMalformed (no
// silent downgrade). It is a framing constant, not a budget/hop-count magic
// number, so it is outside the forbidden-budget tooth.
const WireV1Version uint8 = 1

// BatchEnvelopeHeaderLen is the fixed size of the BatchEnvelope header
// (everything BEFORE the variable-length batchWire). It is the offset at which
// batchWire begins and the minimum length a frame must reach to parse a header.
// Kept in sync with the layout above: 4 + 1 + 8 + 2 + 16 + 64 = 95.
const BatchEnvelopeHeaderLen = 4 + 1 + 8 + 2 + OriginNodeIDSize + OriginSigSize

// ErrBatchMalformed is returned by UnmarshalBatchEnvelope when the wire is too
// short for a header, the magic does not match WireV1Magic, or the version does
// not match WireV1Version. It is the cheap pre-verify reject (the parser touches
// ONLY the header; a malformed batchWire is deferred to the post-verify apply).
var ErrBatchMalformed = errors.New("attribution: malformed batch envelope header")

// ErrBatchUnsigned is returned when the parsed header carries a zero originSig
// — no unsigned batch is accepted (the same tooth as envelope.go's
// zero-originSig rule: a zero originSig is a DropVerify, never an Accept).
var ErrBatchUnsigned = errors.New("attribution: batch envelope carries a zero origin signature")

// BatchEnvelope is the crypto-minimal batch envelope for self-originated
// delta transport. It holds the parsed header fields plus a reference to the
// verbatim batchWire slice (the bytes the origin signature covers and the
// FROZEN ApplyCRDTDeltaBatch decodes). UnmarshalBatchEnvelope performs an O(1)
// header parse and NEVER decodes batchWire — the parser touches ONLY the
// header, so a malformed batchWire is deferred to the post-verify apply (the
// reject-before-Verify discipline).
type BatchEnvelope struct {
	originNodeID [OriginNodeIDSize]byte
	originSig    [OriginSigSize]byte
	originSeq    uint64
	batchCount   uint16
	wire         []byte // the FULL envelope wire (header + batchWire); owned by the caller
}

// MarshalBatchEnvelope assembles the BatchEnvelope wire from the origin's
// identity fields and the marshaled CRDTDeltaBatch wire. It is the SEND-side
// builder: the caller (pkg/mesh ShipBatch) has already built batchWire via the
// generated capnp API (NewRootCRDTDeltaBatch + NewEvents) and signed it once
// via identity.SignCRDTFrame(originSeed, batchWire); this function stamps the
// header around the signed wire. The returned slice is a fresh allocation owned
// by the caller (the header is small and built once per batch, off the per-delta
// hot path — the amortization is the point).
//
// batchCount is the number of deltas in the batch (informational; the
// authoritative count is the capnp CRDTDeltaBatch.Events().Len() the FROZEN
// apply path decodes). originSeq is the origin's MONOTONIC per-batch sequence
// number (advancing by 1 per batch the origin ships) — the rate-gate counter
// the receiver hands to PeerBucket.Accept (the bucket drains on the delta
// between successive originSeq values, NOT on the static batchCount). originSig
// is the 64-byte Ed25519 signature over batchWire; a zero originSig is still
// marshaled (the receiver rejects it pre-verify), so a caller that fails to
// sign produces a wire the receiver drops — never a silent accept.
func MarshalBatchEnvelope(originNodeID [OriginNodeIDSize]byte, originSig [OriginSigSize]byte, originSeq uint64, batchCount uint16, batchWire []byte) []byte {
	out := make([]byte, BatchEnvelopeHeaderLen+len(batchWire))
	binary.BigEndian.PutUint32(out[0:4], WireV1Magic)
	out[4] = WireV1Version
	binary.BigEndian.PutUint64(out[5:13], originSeq)
	binary.BigEndian.PutUint16(out[13:15], batchCount)
	copy(out[15:15+OriginNodeIDSize], originNodeID[:])
	copy(out[15+OriginNodeIDSize:BatchEnvelopeHeaderLen], originSig[:])
	copy(out[BatchEnvelopeHeaderLen:], batchWire)
	return out
}

// UnmarshalBatchEnvelope parses the BatchEnvelope header from wire (the FULL
// envelope bytes — the length-prefix reassembler has already stripped the 4-byte
// prefix). It is an O(1) header parse: it reads the magic, version, originSeq,
// batchCount, originNodeID, and originSig, and stores a reference to the
// verbatim batchWire slice (out[BatchEnvelopeHeaderLen:]). It NEVER decodes
// batchWire — the parser touches ONLY the header, so a malformed batchWire is
// deferred to the post-verify apply (the reject-before-Verify discipline). A
// too-short wire, a magic mismatch, or a version mismatch is an
// ErrBatchMalformed. A zero originSig is an ErrBatchUnsigned (the unsigned-batch
// tooth).
//
// The returned *BatchEnvelope aliases the caller's wire slice (batchWire is a
// sub-slice); the caller MUST NOT mutate wire for the lifetime of the envelope.
func UnmarshalBatchEnvelope(wire []byte) (*BatchEnvelope, error) {
	if len(wire) < BatchEnvelopeHeaderLen {
		return nil, ErrBatchMalformed
	}
	if binary.BigEndian.Uint32(wire[0:4]) != WireV1Magic {
		return nil, ErrBatchMalformed
	}
	if wire[4] != WireV1Version {
		return nil, ErrBatchMalformed
	}
	env := &BatchEnvelope{
		originSeq:  binary.BigEndian.Uint64(wire[5:13]),
		batchCount: binary.BigEndian.Uint16(wire[13:15]),
		wire:       wire,
	}
	copy(env.originNodeID[:], wire[15:15+OriginNodeIDSize])
	copy(env.originSig[:], wire[15+OriginNodeIDSize:BatchEnvelopeHeaderLen])
	if env.originSig == ([OriginSigSize]byte{}) {
		return nil, ErrBatchUnsigned
	}
	return env, nil
}

// BatchWire returns the verbatim marshaled CRDTDeltaBatch wire the origin
// signature covers and the FROZEN ApplyCRDTDeltaBatch decodes. It is the EXACT
// []byte handed to ApplyCRDTDeltaBatch — the bytes Verify checks ARE the bytes
// the engine Join()s (the no-hash-then-reconstruct-gap property of the
// crypto-minimal design). The returned slice aliases the envelope's wire; the
// caller MUST NOT mutate it.
func (e *BatchEnvelope) BatchWire() []byte {
	return e.wire[BatchEnvelopeHeaderLen:]
}

// OriginNodeID returns the [16]byte origin identity the receiver resolves to an
// Ed25519 public key via the GAP-3 Directory.Lookup. It is the key the verify
// (one Ed25519 over the batch) keys on, and (zero-extended to 32 bytes) the key
// the rate gate buckets the origin under.
func (e *BatchEnvelope) OriginNodeID() [OriginNodeIDSize]byte { return e.originNodeID }

// OriginSeq returns the origin's MONOTONIC per-batch sequence number — the
// rate-gate counter the receiver hands to PeerBucket.Accept. The bucket drains
// on the DELTA between successive OriginSeq values from the same origin, so a
// burst of batches drains the origin's budget (the Sybil-burst isolation the
// rate gate exists to enforce), amortized to one check per batch. It mirrors
// the per-frame path's dotCounter (the monotonic per-origin sequence the
// per-frame rate gate keys on). It is NOT the BatchCount: a static count would
// produce a zero delta between same-size batches and the budget would never
// drain — a dead rate gate for the dominant steady-state workload (a node
// shipping its own N writes/sec in fixed-size batches).
func (e *BatchEnvelope) OriginSeq() uint64 { return e.originSeq }

// OriginSig returns the 64-byte Ed25519 signature over batchWire by the origin,
// handed to identity.VerifyCRDTFrame(originPub, batchWire, originSig). It is
// the ONE verify that now covers N deltas (the 60.19us amortized to 60.19/N
// us/delta). A zero originSig is rejected pre-verify by UnmarshalBatchEnvelope
// (the unsigned-batch tooth), so a verified envelope always carries a non-zero
// sig.
func (e *BatchEnvelope) OriginSig() [OriginSigSize]byte { return e.originSig }

// BatchCount returns the header-declared number of deltas in the batch. It is
// informational (the authoritative count is the capnp CRDTDeltaBatch.Events()
// .Len() the FROZEN apply path decodes); it lets a cheap gate bound a batch
// without a capnp decode.
func (e *BatchEnvelope) BatchCount() uint16 { return e.batchCount }

// IsBatchFrame is the dispatch discriminator a receiver peeks AFTER the length
// prefix is stripped: it reads the first 4 bytes of the post-prefix frame body
// and returns true iff they match WireV1Magic (big-endian). It is a NO-COPY
// peek (it reads the slice header, never allocates). A false return routes the
// frame to the existing RelayEnvelope path (HandleFrame); a true return routes
// it to HandleBatchFrame. The RelayEnvelope's first 2 bytes are its uint16
// little-endian version (2 or 3), so its first 4 bytes never equal WireV1Magic
// (big-endian) — the dispatch is unambiguous.
//
// The peek reads the post-length-prefix BODY (ReadFrame already stripped the
// 4-byte length prefix), NOT the length prefix itself (the length prefix is
// common to both wire shapes and carries no type information).
func IsBatchFrame(frame []byte) bool {
	return len(frame) >= 4 && binary.BigEndian.Uint32(frame[0:4]) == WireV1Magic
}

// WireDigestMagic is the 4-byte big-endian dispatch discriminator a receiver
// peeks AFTER the length prefix is stripped to route a frame to the Day-29
// STRATIFIED ANTI-ENTROPY digest-exchange path (ADR-0034). It is DISTINCT from
// BOTH WireV1Magic (the batch path) AND the RelayEnvelope's uint16 little-
// endian version prefix (2 or 3 -> first bytes 0x02/0x03), so the THREE-way
// dispatch (batch / digest / relay) is unambiguous: a digest frame is never
// handed to the FROZEN RelayEnvelope parser (which would DropMalformed it) nor
// to the batch path (which would ErrBatchMalformed it). The value spells "SDST"
// big-endian — Sovereign DiGeST — chosen so its first byte (0x53) shares no
// leading byte with the RelayEnvelope's 0x02/0x03 and its full 4 bytes differ
// from WireV1Magic ("SBAT" 0x53424154).
//
// THREAT MODEL (honest, load-bearing): a StrataEstimator + remote-IBLT digest
// is NOT signed. It is a COARSE-DIFF SUMMARY, not state — a tampered digest
// cannot corrupt engine state: the worst outcome of a wrong remote IBLT is a
// wrong |A−B| estimate, which makes GenerateDelta either (a) ship a delta that
// is a strict superset of the genuine diff (oversend — CRDT-idempotent Join
// absorbs it, convergence holds) or (b) fall back to full oversend via the
// peel-failure branch (crdt.go:1603 — the M5 honest fallback). A malicious
// digest CANNOT drop a dot the recipient lacks (the peel EXCLUDES only keys the
// remote estimator hashes say the remote HAS, and the fallback yields EVERY
// entry when the peel fails — never an empty delta). The integrity of the
// actual STATE transfers is unchanged: every delta the sweep ships is still a
// signed RelayEnvelope routed through the FROZEN HandleFrame gate stack. The
// digest exchange only selects WHICH signed deltas to send; it never carries
// state itself. This is the same trust boundary the /v1/merkle control route
// (control.go handleMerkle) already draws: a digest is advisory, the signed
// frame is authoritative.
const WireDigestMagic uint32 = 0x53445354 // "SDST" — Sovereign DiGeST (big-endian on the wire)

// IsDigestFrame is the dispatch discriminator a receiver peeks AFTER the length
// prefix is stripped: it returns true iff the first 4 bytes of the post-prefix
// frame body match WireDigestMagic (big-endian). It is a NO-COPY peek (sibling
// to IsBatchFrame). A true return routes the frame to the mesh-internal digest
// sink (the Day-29 digest-exchange phase), NOT to the FROZEN receive gate
// stack — a StrataEstimator is not a CRDTDeltaEvent, so HandleFrame would
// DropMalformed it (the gossip.go:356 comment names this). The three-way
// dispatch order is: IsBatchFrame -> batch path; else IsDigestFrame -> digest
// sink; else -> relay/HandleFrame. The magics are pairwise distinct AND
// distinct from the RelayEnvelope's uint16-LE version prefix, so the order is
// unambiguous and a digest frame never reaches the relay parser.
func IsDigestFrame(frame []byte) bool {
	return len(frame) >= 4 && binary.BigEndian.Uint32(frame[0:4]) == WireDigestMagic
}

// PutDigestFrame stamps WireDigestMagic (big-endian) into the first 4 bytes of
// dst. It is the SEND-side counterpart to IsDigestFrame's receive-side peek:
// the mesh's buildDigestFrame (mesh/digest.go) uses it to tag a marshaled
// StrataEstimator so the peer's readLoop routes the frame to the digestSink.
// dst MUST be at least 4 bytes (the caller sizes the full frame buffer). It is
// a NO-COPY 4-byte write (sibling to the MarshalBatchEnvelope header stamp).
func PutDigestFrame(dst []byte) {
	binary.BigEndian.PutUint32(dst[0:4], WireDigestMagic)
}

// ──────────────────────────────────────────────────────────────────────────
// Day 32 (ADR-0037): the hybrid-PQ CRDT-delta SIGN-WIRE — a NEW frame shape
// carrying BOTH the Ed25519 originSig [64] AND the ML-DSA-65 pqSig [3309] over
// the SAME batchWire, dispatched by a NEW magic (WireHybridPQMagic) WITHOUT a
// FROZEN-envelope.go touch. Day 31 (ADR-0036) wired the VERIFY half of the PQ
// moat (VerifyCRDTFrame_Hybrid — the BOTH-required gate) but disclosed an
// honest NOT-YET: under --hybrid-verify EVERY v1 frame is REJECTED today (the
// v1 wire carries ONE 64-byte Ed25519 originSig; the Directory carries ONE
// ed25519.PublicKey — a both-verify with one input is a strict-reject gate for
// a wire shape that does not exist). Day 32 closes the SIGN half: this NEW
// frame shape (a sibling to the BatchEnvelope + the digest frame) carries BOTH
// sigs; the receiver's HandleHybridFrame looks up BOTH pubkeys via the grown
// Directory.LookupBoth + calls VerifyBatchHybrid (the BOTH gate, fed the SAME
// 120-byte SHAKE256 pad both sigs signed).
//
// THE MOLD (the Day-29 digest-frame precedent, applied to a state-carrying
// frame). Day 29 added WireDigestMagic to THIS file (wire_v1.go, NOT FROZEN) as
// a NEW dispatch discriminator for the digest-exchange frame WITHOUT touching
// envelope.go (b1beba1e) — the "new magic in a non-FROZEN file dispatches a
// new frame shape" precedent. Day 32 uses the SAME pattern: WireHybridPQMagic
// (sibling to WireV1Magic + WireDigestMagic) dispatches a hybrid frame the
// EXISTING DispatchFrame router routes to its 4th arm (HandleHybridFrame). The
// FROZEN envelope.go body is byte-UNCHANGED — MarshalBatchEnvelope is UNCHANGED;
// a v1 peer that does NOT speak hybrid forwards the v1 BatchEnvelope
// byte-identical (backward-compat, the Day-29 mold). The hybrid frame is a
// STATE-CARRYING CRDT-delta frame (NOT a mesh-internal advisory like the
// digest), so it routes to the Receiver's gate stack (rate -> clock-gate-free
// for a 0-hop self-originated batch -> verify -> Join), NOT to a mesh sink.
//
// WIRE LAYOUT (sibling to the BatchEnvelope header, grown by the [3309] pqSig
// slot; batchWire is opaque until verify passes — the SAME crypto-minimal
// discipline):
//
//	[4]   magic        (uint32 big-endian, WireHybridPQMagic — "SHYB")
//	[1]   version      (uint8, WireHybridPQVersion — honored, no silent downgrade)
//	[8]   originSeq    (uint64 big-endian — the origin's MONOTONIC per-batch
//	                     sequence, the SAME rate-gate counter BatchEnvelope
//	                     carries; the receiver's PeerBucket.Accept drains on
//	                     the delta between successive originSeq values)
//	[2]   batchCount   (uint16 big-endian — informational; the authoritative
//	                     count is the capnp CRDTDeltaBatch.Events().Len() the
//	                     FROZEN apply path decodes; carried so a cheap gate can
//	                     bound a batch without a capnp decode)
//	[16]  originNodeID ([16]byte — for the grown Directory.LookupBoth, which
//	                     resolves originNodeID -> BOTH the Ed25519 + ML-DSA-65
//	                     pubkeys; the OOB provisioning model the classical
//	                     verify uses, carried forward to BOTH keys)
//	[64]  edSig        (the hedged Ed25519 signature over the 120-byte SHAKE256
//	                     pad of batchWire — identity.SignCRDTFrame_Hybrid's
//	                     edSig half; verified by VerifyCRDTFrame inside the
//	                     hybrid gate. A zero edSig is an automatic DROP — no
//	                     unsigned hybrid frame is accepted, the SAME tooth as
//	                     BatchEnvelope's zero-originSig rule.)
//	[3309] pqSig       (the ML-DSA-65 signature over the SAME 120-byte pad —
//	                     identity.SignCRDTFrame_Hybrid's pqSig half; verified by
//	                     VerifyCRDTFrame_PostQuantum inside the hybrid gate. A
//	                     zero pqSig is an automatic DROP — BOTH sigs is the
//	                     contract; a frame with one sig is a classical-only
//	                     frame the hybrid verifier rejects, NOT a hybrid frame.)
//	[...] batchWire    (the marshaled CRDTDeltaBatch capnp frame, verbatim —
//	                     the FROZEN schema is untouched; this is the EXACT
//	                     []byte handed to ApplyCRDTDeltaBatch. The pad is for
//	                     SIGNING only; the receiver applies the ORIGINAL wire,
//	                     NOT the pad, so Join sees the real bytes — the no-
//	                     hash-then-reconstruct-gap property of the crypto-
//	                     minimal design, preserved for the hybrid frame.)
//
// NO SHA-256 batch root (per the crypto-minimal design — the pad is a SIGN
// binding, NOT an apply binding; the apply path consumes the verbatim
// batchWire). NO reuse of the FROZEN RelayEnvelope (the per-frame
// RelayEnvelope path in envelope.go stays the SOLE carrier of RELAY deltas;
// the hybrid frame is a self-originated-BATCH shape, a sibling to the
// BatchEnvelope, NOT a relay envelope). envelope.go (b1beba1e) is NOT touched.
// ──────────────────────────────────────────────────────────────────────────

// WireHybridPQMagic is the 4-byte big-endian dispatch discriminator a receiver
// peeks AFTER the length prefix is stripped to route a frame to the Day-32
// HYBRID-PQ CRDT-delta path (ADR-0037). It is DISTINCT from BOTH WireV1Magic
// (the batch path, "SBAT" 0x53424154) AND WireDigestMagic (the Day-29 digest
// path, "SDST" 0x53445354) AND the RelayEnvelope's uint16 little-endian version
// prefix (2 or 3 -> first bytes 0x02/0x03), so the FOUR-way dispatch (batch /
// digest / hybrid / relay) is unambiguous: a hybrid frame is never handed to
// the FROZEN RelayEnvelope parser (which would DropMalformed it), nor to the
// batch path (which would ErrBatchMalformed it), nor to the digest sink (which
// would deliver a CRDT delta to a mesh-internal advisory channel — a
// state-loss bug). The value spells "SHYB" big-endian — Sovereign HYBrid —
// chosen so its first byte (0x53) shares no leading byte with the
// RelayEnvelope's 0x02/0x03 (the SAME first-byte discipline SBAT/SDST use) and
// its full 4 bytes (0x53485942) differ from WireV1Magic (0x53424154) +
// WireDigestMagic (0x53445354) at every byte position past the shared 'S'
// (byte 1: 0x48 vs 0x42/0x44; byte 2: 0x59 vs 0x41/0x53; byte 3: 0x42 vs
// 0x54/0x54). The pairwise bit-distinctness is asserted by the
// T-PQ-HYBRID-FRAME-WIRE-SHAPE tooth (the Day-29 digest-magic-collision tooth
// carried forward to the 4th magic).
const WireHybridPQMagic uint32 = 0x53485942 // "SHYB" — Sovereign HYBrid (big-endian on the wire)

// WireHybridPQVersion is the forward-compat tag for the hybrid-frame framing.
// It is honored on parse: a version field != WireHybridPQVersion is an
// ErrHybridMalformed (no silent downgrade — the SAME tooth WireV1Version
// enforces for the BatchEnvelope). It is a framing constant, not a budget/
// hop-count magic number, so it is outside the forbidden-budget tooth.
const WireHybridPQVersion uint8 = 1

// PQSignatureSize is the wire slot size for the ML-DSA-65 signature (3309
// bytes — mldsa.MLDSA65SignatureSize, FIPS 204). It is a WIRE CONSTANT cited
// from the filippo.io/mldsa pin (pq_mldsa.go:26) — attribution is a LEAF
// package (encoding/binary + errors only; the Day-5 crypto-minimal discipline)
// and does NOT import filippo.io/mldsa, so the size is a const here, the single
// source of truth for the hybrid frame's [3309] pqSig slot. The mesh's
// MarshalHybridFrame caller copies the mldsa sig into a
// [attribution.PQSignatureSize]byte array; the identity layer's
// SignCRDTFrame_Hybrid returns a [mldsa.MLDSA65SignatureSize]byte (the SAME
// 3309 — the two consts are the same value, asserted by the
// T-PQ-HYBRID-SIGN-THEN-VERIFY tooth which round-trips a sig through both).
// The 3309B sig is 51.7x the 64B Ed25519 sig (the Day-31 pqecobench SIZE gate,
// RECORDED) — the honest wire-cost inflation the hybrid frame carries.
const PQSignatureSize = 3309

// HybridEnvelopeHeaderLen is the fixed size of the hybrid-frame header
// (everything BEFORE the variable-length batchWire). It is the offset at which
// batchWire begins and the minimum length a frame must reach to parse a header.
// Kept in sync with the layout above: 4 + 1 + 8 + 2 + 16 + 64 + 3309 = 3404.
// The [3309] pqSig slot is the dominant term (the ML-DSA-65 wire cost) — the
// hybrid frame's per-frame overhead is 3404B vs the BatchEnvelope's 95B (the
// 3309B sig + the 16B nodeID + the 64B edSig + the 15B fixed header), the
// honest wire-cost disclosed in ADR-0037 §2.M4 (the /verify audit caught a
// prior draft citing a nonexistent "T-PQ-HYBRID-SIGN-COST" tooth as the
// record site; no such tooth exists in the day32 test set — the wire-cost is
// a doc disclosure, not a tooth-recorded number).
const HybridEnvelopeHeaderLen = 4 + 1 + 8 + 2 + OriginNodeIDSize + OriginSigSize + PQSignatureSize

// ErrHybridMalformed is returned by UnmarshalHybridFrame when the wire is too
// short for a header, the magic does not match WireHybridPQMagic, or the
// version does not match WireHybridPQVersion. It is the cheap pre-verify reject
// (the parser touches ONLY the header; a malformed batchWire is deferred to the
// post-verify apply — the SAME reject-before-Verify discipline
// UnmarshalBatchEnvelope uses).
var ErrHybridMalformed = errors.New("attribution: malformed hybrid-PQ envelope header")

// ErrHybridUnsigned is returned when the parsed header carries a zero edSig OR
// a zero pqSig — no unsigned hybrid frame is accepted (BOTH sigs is the
// contract; a frame with one sig is a classical-only frame the hybrid verifier
// rejects, NOT a hybrid frame). It is the SAME tooth as ErrBatchUnsigned (a
// zero originSig is a DropVerify, never an Accept) extended to BOTH sigs.
var ErrHybridUnsigned = errors.New("attribution: hybrid-PQ envelope carries a zero Ed25519 or ML-DSA-65 signature")

// HybridEnvelope is the crypto-minimal hybrid-PQ batch envelope for
// self-originated delta transport under --hybrid-sign. It holds the parsed
// header fields plus a reference to the verbatim batchWire slice (the bytes
// BOTH sigs cover via the 120-byte SHAKE256 pad + the FROZEN
// ApplyCRDTDeltaBatch decodes). UnmarshalHybridFrame performs an O(1) header
// parse and NEVER decodes batchWire — the parser touches ONLY the header, so a
// malformed batchWire is deferred to the post-verify apply (the reject-before-
// Verify discipline). It is the sibling of BatchEnvelope (the Day-5 batch
// path) carrying the SECOND signature (the PQ half of the hybrid contract).
type HybridEnvelope struct {
	originNodeID [OriginNodeIDSize]byte
	edSig        [OriginSigSize]byte
	pqSig        [PQSignatureSize]byte
	originSeq    uint64
	batchCount   uint16
	wire         []byte // the FULL envelope wire (header + batchWire); owned by the caller
}

// MarshalHybridFrame assembles the HybridEnvelope wire from the origin's
// identity fields, the dual signatures, and the marshaled CRDTDeltaBatch wire.
// It is the SEND-side builder: the caller (pkg/mesh ShipBatchHybrid) has already
// built batchWire via the generated capnp API + signed it ONCE under BOTH
// Ed25519 + ML-DSA-65 via identity.SignCRDTFrame_Hybrid (which returns the
// [64] edSig + the [3309] pqSig over the 120-byte SHAKE256 pad of batchWire);
// this function stamps the header around the signed wire. The returned slice is
// a fresh allocation owned by the caller (the header is built once per batch,
// off the per-delta hot path — the amortization is the point, the SAME as
// MarshalBatchEnvelope).
//
// batchCount is the number of deltas in the batch (informational; the
// authoritative count is the capnp CRDTDeltaBatch.Events().Len() the FROZEN
// apply path decodes). originSeq is the origin's MONOTONIC per-batch sequence
// number (advancing by 1 per batch the origin ships) — the rate-gate counter
// the receiver hands to PeerBucket.Accept (the SAME field BatchEnvelope
// carries). edSig is the 64-byte Ed25519 signature over the batchWire's pad;
// pqSig is the 3309-byte ML-DSA-65 signature over the SAME pad. A zero edSig
// or pqSig is still marshaled (the receiver rejects it pre-verify), so a caller
// that fails to sign produces a wire the receiver drops — never a silent accept.
//
// This is a NEW function, NOT an edit to MarshalBatchEnvelope (the FROZEN-
// adjacent v1 path stays byte-identical — the hybrid is an ADD, sibling to the
// digest frame's PutDigestFrame, the Day-29 add-not-replace discipline).
func MarshalHybridFrame(originNodeID [OriginNodeIDSize]byte, edSig [OriginSigSize]byte, pqSig [PQSignatureSize]byte, originSeq uint64, batchCount uint16, batchWire []byte) []byte {
	out := make([]byte, HybridEnvelopeHeaderLen+len(batchWire))
	binary.BigEndian.PutUint32(out[0:4], WireHybridPQMagic)
	out[4] = WireHybridPQVersion
	binary.BigEndian.PutUint64(out[5:13], originSeq)
	binary.BigEndian.PutUint16(out[13:15], batchCount)
	copy(out[15:15+OriginNodeIDSize], originNodeID[:])
	copy(out[15+OriginNodeIDSize:15+OriginNodeIDSize+OriginSigSize], edSig[:])
	copy(out[15+OriginNodeIDSize+OriginSigSize:HybridEnvelopeHeaderLen], pqSig[:])
	copy(out[HybridEnvelopeHeaderLen:], batchWire)
	return out
}

// UnmarshalHybridFrame parses the HybridEnvelope header from wire (the FULL
// envelope bytes — the length-prefix reassembler has already stripped the
// 4-byte prefix). It is an O(1) header parse: it reads the magic, version,
// originSeq, batchCount, originNodeID, edSig, and pqSig, and stores a reference
// to the verbatim batchWire slice (out[HybridEnvelopeHeaderLen:]). It NEVER
// decodes batchWire — the parser touches ONLY the header, so a malformed
// batchWire is deferred to the post-verify apply (the reject-before-Verify
// discipline). A too-short wire, a magic mismatch, or a version mismatch is an
// ErrHybridMalformed. A zero edSig OR a zero pqSig is an ErrHybridUnsigned (the
// unsigned-hybrid tooth — BOTH sigs is the contract).
//
// The returned *HybridEnvelope aliases the caller's wire slice (batchWire is a
// sub-slice); the caller MUST NOT mutate wire for the lifetime of the envelope.
func UnmarshalHybridFrame(wire []byte) (*HybridEnvelope, error) {
	if len(wire) < HybridEnvelopeHeaderLen {
		return nil, ErrHybridMalformed
	}
	if binary.BigEndian.Uint32(wire[0:4]) != WireHybridPQMagic {
		return nil, ErrHybridMalformed
	}
	if wire[4] != WireHybridPQVersion {
		return nil, ErrHybridMalformed
	}
	edOff := 15 + OriginNodeIDSize
	pqOff := edOff + OriginSigSize
	env := &HybridEnvelope{
		originSeq:  binary.BigEndian.Uint64(wire[5:13]),
		batchCount: binary.BigEndian.Uint16(wire[13:15]),
		wire:       wire,
	}
	copy(env.originNodeID[:], wire[15:15+OriginNodeIDSize])
	copy(env.edSig[:], wire[edOff:edOff+OriginSigSize])
	copy(env.pqSig[:], wire[pqOff:HybridEnvelopeHeaderLen])
	if env.edSig == ([OriginSigSize]byte{}) || env.pqSig == ([PQSignatureSize]byte{}) {
		return nil, ErrHybridUnsigned
	}
	return env, nil
}

// BatchWire returns the verbatim marshaled CRDTDeltaBatch wire BOTH sigs cover
// (via the 120-byte SHAKE256 pad) and the FROZEN ApplyCRDTDeltaBatch decodes.
// It is the EXACT []byte handed to ApplyCRDTDeltaBatch — the bytes Verify
// checks (via the pad) ARE the bytes the engine Join()s (the no-hash-then-
// reconstruct-gap property of the crypto-minimal design, preserved for the
// hybrid frame). The returned slice aliases the envelope's wire; the caller
// MUST NOT mutate it.
func (e *HybridEnvelope) BatchWire() []byte {
	return e.wire[HybridEnvelopeHeaderLen:]
}

// OriginNodeID returns the [16]byte origin identity the receiver resolves to
// BOTH the Ed25519 + ML-DSA-65 public keys via the grown Directory.LookupBoth
// (Day 32, ADR-0037). It is the key the hybrid verify keys on (BOTH sigs over
// the batchWire's pad) AND (zero-extended to 32 bytes) the key the rate gate
// buckets the origin under — the SAME dual role BatchEnvelope's OriginNodeID
// plays, carried forward to the hybrid frame.
func (e *HybridEnvelope) OriginNodeID() [OriginNodeIDSize]byte { return e.originNodeID }

// OriginSeq returns the origin's MONOTONIC per-batch sequence number — the
// rate-gate counter the receiver hands to PeerBucket.Accept (the SAME field
// BatchEnvelope carries; the bucket drains on the delta between successive
// originSeq values from the same origin). It is NOT the BatchCount (a static
// count would produce a zero delta between same-size batches and the budget
// would never drain — a dead rate gate for the dominant steady-state
// workload). See BatchEnvelope.OriginSeq for the full rationale.
func (e *HybridEnvelope) OriginSeq() uint64 { return e.originSeq }

// EdSig returns the 64-byte hedged Ed25519 signature over the 120-byte SHAKE256
// pad of batchWire — the classical half of the hybrid contract, verified by
// VerifyCRDTFrame inside the hybrid gate (the cheap first gate; a classical
// reject skips the PQ verify — short-circuit AND). A zero edSig is rejected
// pre-verify by UnmarshalHybridFrame (the unsigned-hybrid tooth), so a
// verified envelope always carries a non-zero edSig.
func (e *HybridEnvelope) EdSig() [OriginSigSize]byte { return e.edSig }

// PQSig returns the 3309-byte ML-DSA-65 signature over the SAME 120-byte
// SHAKE256 pad of batchWire — the PQ half of the hybrid contract, verified by
// VerifyCRDTFrame_PostQuantum inside the hybrid gate (the expensive ~74us 4c
// gate that runs only after the classical verify passes). A zero pqSig is
// rejected pre-verify by UnmarshalHybridFrame (the unsigned-hybrid tooth —
// BOTH sigs is the contract; a frame with one sig is a classical-only frame
// the hybrid verifier rejects, NOT a hybrid frame).
func (e *HybridEnvelope) PQSig() [PQSignatureSize]byte { return e.pqSig }

// BatchCount returns the header-declared number of deltas in the batch. It is
// informational (the authoritative count is the capnp CRDTDeltaBatch.Events()
// .Len() the FROZEN apply path decodes); it lets a cheap gate bound a batch
// without a capnp decode — the SAME role BatchEnvelope.BatchCount plays.
func (e *HybridEnvelope) BatchCount() uint16 { return e.batchCount }

// IsHybridFrame is the dispatch discriminator a receiver peeks AFTER the length
// prefix is stripped: it reads the first 4 bytes of the post-prefix frame body
// and returns true iff they match WireHybridPQMagic (big-endian). It is a
// NO-COPY peek (it reads the slice header, never allocates — sibling to
// IsBatchFrame + IsDigestFrame). A true return routes the frame to the hybrid
// path (Receiver.HandleHybridFrame, the 4th DispatchFrame arm); a false return
// leaves it for the batch/digest/relay arms. The four magics (WireV1Magic /
// WireDigestMagic / WireHybridPQMagic / the RelayEnvelope's uint16-LE version
// prefix 2|3) are pairwise bit-distinct (the first byte 0x53/0x53/0x53/0x02|0x03
// — the hybrid's 0x48 second byte separates it from SBAT's 0x42 + SDST's 0x44),
// so the dispatch order is unambiguous and a hybrid frame never reaches the
// relay parser (which would DropMalformed it) or the batch path (which would
// ErrBatchMalformed it).
//
// The peek reads the post-length-prefix BODY (ReadFrame already stripped the
// 4-byte length prefix), NOT the length prefix itself (the length prefix is
// common to all wire shapes and carries no type information).
func IsHybridFrame(frame []byte) bool {
	return len(frame) >= 4 && binary.BigEndian.Uint32(frame[0:4]) == WireHybridPQMagic
}
