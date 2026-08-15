// Package mesh — digest.go is the Day-29 STRATIFIED ANTI-ENTROPY digest-
// exchange seam (ADR-0034, the Phase-5 Track-5.1 FIRST stake).
//
// WHY THIS FILE EXISTS. The mesh's AntiEntropySweep (gossip.go) shipped the
// FULL delta to every peer every round (O(N×M) oversend) because it never
// exchanged the coarse-diff digest that lets a node produce a MINIMAL delta.
// Day 29 Wires the digest exchange — the Day-23 SkipList.Seek mold (a dormant
// primitive, the production consumer never wired it).
//
// THE M2 FIX (the Architect's Amendment — the load-bearing correction this
// fork ships). The premise-audit M2 ("the diff is a strict subset → byte-
// identity + bandwidth cut") was REFUTED by direct read of the primitive's
// pre-deletion body (documented in the crdt.go:1920 tombstone): the dormant
// `GenerateDeltaStratified(remoteEstimator)` created `remoteIBLT` then NEVER
// populated it — the shard-root loop filled only the LOCAL IBLT. The `Subtract`
// subtracted an EMPTY IBLT → diff == local → peel yielded ALL local keys → the
// stratified delta was byte-identical to oversend for ANY non-empty remote
// overlap. The dormant unit test (TestCRDTEngine_GenerateDeltaStratified) only
// covered the EMPTY-remote case (where oversend==stratified by coincidence),
// so the defect never fired.
//
// THE FUNDAMENTAL OBSTACLE: the StrataEstimator is a LOSSY digest (XOR-based
// KeySum, not invertible to the key set); `GenerateDeltaStratified` CANNOT
// populate `remoteIBLT` from the estimator alone — the remote's full IBLT
// MUST come from the wire. The amendment's resolution: the digest exchange
// sends the remote's FULL IBLT digest (NOT just the strata estimator), and
// the wiring calls `GenerateDelta(remoteIBLT)` — the FROZEN, CORRECT set-
// reconciliation primitive (crdt.go:1603) — which subtracts the POPULATED
// remote IBLT + peels the real diff. `GenerateDeltaStratified` is KILLED
// (the broken sibling removed); the strata estimator survives ONLY as the
// dEst sizing hint (the IBLT is sized dynamically by the estimate).
//
// THE DIGEST EXCHANGE (the M3 two-phase sweep, load-bearing):
//
//	Phase i  — each node SENDS its StrataEstimator + its FULL IBLT digest to
//	           its peers (a digest frame: MarshalStrataEstimator + the
//	           dEst-sized MarshalIBLT — the SE for sizing, the IBLT for the
//	           real subtract).
//	Phase ii — each node RECEIVES its peers' (SE, IBLT), then calls
//	           GenerateDelta(remoteIBLT) per peer — a MINIMAL delta
//	           proportional to |A−B| (the honest diff), NOT the full set.
//
// THE WIRE COST (T-STRUCE-WIRE-COST — the honest disclosure). The stratified
// path adds a digest round-trip per peer per round: the SE (~50KB, 32 strata
// IBLTs) + the remote IBLT (sized by dEst, ~1.5×|A−B|×20 bytes). The bandwidth
// cut (the delta is the DIFF, not the full set) pays this overhead back when
// |A−B| << |A|; for a near-empty diff the IBLT digest may EXCEED the oversend
// delta — disclosed honestly in the ADR + the wire-cost tooth (the cut is the
// DELTA cut; the wire cost is the digest overhead; the net is the honest
// number the operator reads off sovereign_mesh_* at silicon scale, the NEXT-
// NEXT fork).
//
// The naive "call GenerateDelta(LOCAL IBLT)" is a NO-OP (you diff against
// yourself → empty diff → never converges, the M3 no-op premise). The remote
// IBLT MUST come from the peer. THIS FILE is how the remote digest arrives: a
// peer-TLS data-plane digest frame.
//
// THE TRANSPORT DECISION (M4 — the honest path, NOT the prior session's draft):
//
// The digest exchange rides the EXISTING peer-TLS data-plane (the same
// length-prefixed framing every CRDT delta uses), NOT a new control-port route.
// A new magic discriminator (attribution.WireDigestMagic, sibling to
// WireV1Magic/IsBatchFrame) tags a digest frame; the readLoop peeks it (the
// same 4-byte post-length-prefix peek IsBatchFrame uses) and routes a digest
// frame to the digestSink, NOT to the FROZEN receive gate stack. This touches
// ZERO FROZEN files:
//
//   - envelope.go (b1beba1e) — UNTOUCHED (the digest is a distinct wire shape,
//     NOT a RelayEnvelope; a digest is not a CRDT delta).
//   - receiver.go / HandleFrame — UNTOUCHED (a StrataEstimator is not a
//     CRDTDeltaEvent; HandleFrame would DropMalformed it, the gossip.go:356
//     comment names this). The digest delivery is a MESH-INTERNAL concern.
//
// The REJECTED alternative — a /v1/strata-digest control-port route (option b/c
// the prior session's recon agent recommended) — was REFUTED by direct read of
// the 2-node test infra (gossip_test.go + partition_test.go): both build ONLY
// PeerSet + Gossiper per node, NO ControlServer, NO HTTP listener. The mesh is
// pure peer-TLS data-plane. A control-port route is unreachable from the sweep
// in the test infra (and is the OPERATOR-facing surface, not the peer-mesh
// surface). The peer-TLS data-plane digest frame is the ONLY path that works
// in both the test infra AND the production binary. This is the decisive
// fork-shaping fact (recorded in the Day-29 pre-audit memory).
//
// THE THREE-WAY DISPATCH (centralized here so the three readLoop sites —
// peer.go readLoop, cmd serveConn, gossip_test.go serveTestConn — call ONE
// helper and the batch/digest/relay routing stays in lock-step):
//
//	DispatchFrame(frame, peerID, recv, digester):
//	  IsBatchFrame(frame)  -> recv.HandleBatchFrame  (the Day-5 batch path)
//	  IsDigestFrame(frame) -> digester.DeliverDigest (the Day-29 digest path)
//	  IsHybridFrame(frame) -> recv.HandleHybridFrame (the Day-32 hybrid path)
//	  else                 -> recv.HandleFrame       (the FROZEN relay path)
//
// Day 32 (ADR-0037) adds the FOURTH arm: a frame tagged WireHybridPQMagic
// (attribution.IsHybridFrame) routes to recv.HandleHybridFrame — the receiver's
// BOTH-sig verify gate (a STATE-CARRYING CRDT-delta frame, NOT a mesh-internal
// advisory like the digest, so it routes to the Receiver's gate stack — NOT to
// a mesh sink). The hybrid frame is the sibling of the BatchEnvelope; the
// dispatch order is load-bearing: IsBatchFrame first (the highest-rate opt-in
// path), then IsDigestFrame (the digest exchange), then IsHybridFrame (the
// hybrid-PQ batch), then the default routes to the FROZEN relay/HandleFrame.
// The four magics (WireV1Magic / WireDigestMagic / WireHybridPQMagic / the
// RelayEnvelope's uint16-LE version prefix 2|3) are pairwise bit-distinct
// (verified at ADR-0037 §3), so the order is unambiguous and a hybrid frame is
// never handed to the relay parser (which would DropMalformed it), the batch
// path (which would ErrBatchMalformed it), OR the digest sink (which would
// deliver a CRDT delta to a mesh-internal advisory channel — a state-loss bug
// the Day-29 mold's "state-carrying frames route to the Receiver" discipline
// forbids).
//
// The digester is nil-safe: a Gossiper with stratified OFF (the opt-IN default)
// never registers a digestSink, so DispatchFrame's digest branch is a no-op
// drop (a digest frame arrives only when a peer opted IN; a node that has NOT
// opted in ignores it — the honest cold-start, M3). The fallback counter
// (StratifiedAntiEntropyFallback, the 19th SSoT counter) increments when the
// sweep's digest-exchange phase falls back to oversend (timeout, malformed
// digest, or peel failure) — the M5 honest disclosure.
package mesh

import (
	"log"

	eng "github.com/hr18vk/supremum/pkg/sync"

	"github.com/hr18vk/supremum/pkg/attribution"
	"github.com/hr18vk/supremum/pkg/receive"
)

// DigestSink is the mesh-internal contract a Gossiper satisfies to RECEIVE a
// peer's StrataEstimator digest frame. It is SEPARATE from the frameSink
// interface (which is the FROZEN receive gate stack) because a StrataEstimator
// is NOT a CRDT delta — it never reaches HandleFrame. The Gossiper implements
// DigestSink so the readLoop can hand a received estimator to the sweep's
// digest-exchange phase (which is blocking on it, per M3's synchronous
// request-response). A nil digester (stratified OFF — the opt-IN default) makes
// the digest branch a no-op drop, preserving the byte-identical oversend path
// (T-STRUCE-OFF-IS-BYTE-IDENTICAL).
//
// peerID is the SENDING peer's nodeID (the dial-side readLoop knows it from
// pc.peerID; the accept-side serveConn passes a zero and DeliverDigest reads
// the authoritative senderID from the digest-frame header), so the sweep's
// per-peer blocking receive can route the estimator to the RIGHT peer's channel
// (a digest from peer X reaches the sweep's wait-for-X, not a different peer's).
type DigestSink interface {
	DeliverDigest(peerID [16]byte, wire []byte)
}

// DispatchFrame is the FOUR-way frame router every readLoop calls after the
// length-prefix reassembler strips the 4-byte prefix. It centralizes the
// batch/digest/hybrid/relay dispatch so peer.go readLoop, cmd serveConn, and
// gossip_test.go serveTestConn route identically (the Day-5 batch path + the
// Day-29 digest path + the Day-32 hybrid-PQ batch path + the FROZEN relay
// path). It is a NO-COPY peek: it reads the first 4 bytes of the slice header,
// never allocates.
//
// The dispatch order is load-bearing: IsBatchFrame is checked first (batch
// magic is the highest-rate opt-in path), then IsDigestFrame (the Day-29 digest
// path), then IsHybridFrame (the Day-32 hybrid-PQ batch path), then the default
// routes to the FROZEN relay/HandleFrame. The four magics (WireV1Magic /
// WireDigestMagic / WireHybridPQMagic / the RelayEnvelope's uint16-LE version
// prefix 2|3) are pairwise bit-distinct (verified at ADR-0034 §3 + ADR-0037
// §3), so the order is unambiguous and a digest frame is never handed to the
// relay parser (which would DropMalformed it — a silent throughput collapse),
// and a hybrid frame is never handed to the batch path (which would
// ErrBatchMalformed it) or the digest sink (which would state-loss it).
//
// digester is nil-safe: when the Gossiper has NOT opted into stratified
// anti-entropy (the default), the digest branch drops the frame (a digest
// arrives only from a peer that opted IN; a node that has NOT opted in ignores
// it — the honest cold-start). recv is the Receiver sink for the batch +
// hybrid + relay paths; it is never touched by the digest branch. The hybrid
// branch ALWAYS routes to recv.HandleHybridFrame (a STATE-CARRYING CRDT-delta
// frame MUST run the Receiver's gate stack — rate -> verify -> Join; the
// --hybrid-verify gate inside HandleHybridFrame is the opt-IN, NOT the
// dispatch — a hybrid frame is never silently dropped at dispatch).
func DispatchFrame(frame []byte, peerID [16]byte, recv frameSink, digester DigestSink) receive.AcceptVerdict {
	if attribution.IsBatchFrame(frame) {
		return recv.HandleBatchFrame(frame) // the Day-5 batch gate stack
	}
	if attribution.IsDigestFrame(frame) {
		if digester != nil {
			digester.DeliverDigest(peerID, frame) // the Day-29 digest-exchange phase
		}
		// A digest frame is not a CRDT delta; the receive gate stack never
		// touches it. Return Accept (the frame was consumed by the digest
		// sink, or dropped when stratified is OFF — either way it is NOT a
		// gate-stack reject that should surface as a drop verdict).
		return receive.AcceptVerdict{Verdict: receive.Accept}
	}
	if attribution.IsHybridFrame(frame) {
		return recv.HandleHybridFrame(frame) // the Day-32 hybrid-PQ batch gate stack
	}
	return recv.HandleFrame(frame) // the FROZEN relay gate stack
}

// peerDigest is the (StrataEstimator, IBLT) pair the digest exchange delivers
// to the sweep's per-peer blocking-receive channel. The SE is the dEst sizing
// hint (the coarse |A−B| estimate); the IBLT is the remote's FULL digest (the
// POPULATED IBLT `GenerateDelta` subtracts to produce the minimal diff — the M2
// fix: the remote IBLT MUST come from the wire, NOT reconstructed from the
// lossy strata estimator). Either may be nil (a malformed digest delivers a
// nil IBLT → the sweep's M5 fallback to oversend; a nil SE → dEst=0 → the
// IBLT is sized to the minimum). The channel carries *peerDigest (NOT the bare
// *StrataEstimator the pre-M2 draft carried — that draft had no IBLT on the
// wire, so the broken GenerateDeltaStratified subtracted an empty IBLT every
// round = byte-identical to oversend).
type peerDigest struct {
	se   *eng.StrataEstimator // the dEst sizing hint (may be nil on a malformed SE)
	iblt *eng.IBLT            // the remote's FULL digest (the M2 load-bearing field; nil → M5 fallback)
}

// digestFrameHeaderLen is the fixed size of the digest-frame header BEFORE the
// variable body: WireDigestMagic(4) + senderNodeID(16) = 20. The body that
// follows is [seLen(4, big-endian) + MarshalStrataEstimator(se) + MarshalIBLT(iblt)]
// — the 4-byte SE length lets the receiver split the body into the SE (for
// dEst) + the IBLT (for the real subtract). The senderNodeID is the SENDING
// peer's [16]byte CRDT-delta signing nodeID (the same field BatchEnvelope
// carries as originNodeID), so the ACCEPT-side serveConn — which does NOT know
// which peer dialed in from the conn alone — can route the digest to the RIGHT
// per-peer blocking-receive channel via DeliverDigest(senderID, frame). The
// dial-side readLoop already knows pc.peerID and could pass it directly, but
// the accept-side cannot, so the sender stamps it in the header and BOTH sides
// read it from the frame (the single source of truth — a conn that lies about
// its senderID delivers a digest the sweep is not waiting for, which drops
// cleanly; the threat model in wire_v1.go's WireDigestMagic comment covers
// this: a digest is advisory, the signed delta is authoritative, and a
// spoofed senderID cannot corrupt state).
const digestFrameHeaderLen = 4 + 16

// digestFrameSELenOff is the offset of the 4-byte big-endian SE-length field
// in the digest frame body (immediately after the 20-byte header). The body
// layout is:
//
//	[4] seLen (big-endian) + [seLen] MarshalStrataEstimator(se) +
//	[..] MarshalIBLT(iblt)  (the trailing IBLT spans body[digestFrameSEBodyOff+seLen:])
const digestFrameSELenOff = digestFrameHeaderLen // 20

// digestFrameSplit splits a digest frame into the marshaled StrataEstimator
// body + the marshaled IBLT body. It is the receive-side counterpart to
// buildDigestFrame. The frame layout is:
//
//	[4] WireDigestMagic (big-endian) + [16] senderNodeID +
//	[4] seLen (big-endian) + [seLen] MarshalStrataEstimator(se) +
//	[..] MarshalIBLT(iblt)
//
// It is a NO-COPY pair of sub-slices (both alias the frame's backing array;
// the caller MUST Unmarshal BOTH before the frame buffer is recycled — the
// StrataEstimator + IBLT copy the bucket state into their own heap structs).
// A frame too short for the header + seLen field returns (nil, nil) (the
// caller's DeliverDigest treats a nil IBLT as the M5 fallback to oversend).
// A seLen that overruns the body returns the IBLT slice as nil (a truncated
// SE → the M5 fallback; the IBLT alone is not usable without the SE's seed).
func digestFrameSplit(frame []byte) (seBody, ibltBody []byte) {
	if len(frame) < digestFrameSELenOff+4 {
		return nil, nil // too short for the header + the seLen field
	}
	seLen := int(binaryBigEndianUint32(frame[digestFrameSELenOff:]))
	seStart := digestFrameSELenOff + 4
	if seStart > len(frame) || seStart+seLen > len(frame) {
		return nil, nil // seLen overruns → malformed (M5 fallback)
	}
	seBody = frame[seStart : seStart+seLen]
	ibltBody = frame[seStart+seLen:]
	return seBody, ibltBody
}

// digestFrameSender extracts the [16]byte senderNodeID from a digest frame
// header. It is the routing key the accept-side serveConn hands to
// DeliverDigest so the digest reaches the RIGHT per-peer blocking-receive
// channel (the sweep registered a wait for THIS peer, not a different one).
// A frame too short for the header returns a zero [16]byte (the caller treats
// a zero senderID as "no live wait" — DeliverDigest's digestRecvFor returns
// nil for a zero key the sweep never registered, so the digest drops cleanly).
func digestFrameSender(frame []byte) [16]byte {
	var id [16]byte
	if len(frame) < digestFrameHeaderLen {
		return id
	}
	copy(id[:], frame[4:digestFrameHeaderLen])
	return id
}

// buildDigestFrame is the SEND-side digest-frame builder: it stamps the
// 4-byte WireDigestMagic prefix + the 16-byte senderNodeID + a 4-byte
// big-endian SE-length + the marshaled StrataEstimator + the marshaled IBLT,
// so the peer's readLoop's IsDigestFrame peek routes it to the digestSink (NOT
// to the FROZEN relay parser) AND the accept-side serveConn can route it to the
// RIGHT per-peer channel. The returned []byte is a fresh allocation (the caller
// length-prefixes the result via receive.LengthPrefixFrame the same way every
// other mesh frame is framed). It is the Day-29 sibling of the batch-frame
// send path (batch.go BuildCRDTDeltaBatch + MarshalBatchEnvelope). senderID is
// the SENDING node's CRDT-delta signing nodeID (g.owner.NodeID — the same
// identity the signed deltas carry as OriginNodeID, so the receiver's per-peer
// channel keys match).
//
// The M2 fix (Architect's Amendment): the frame carries BOTH the SE (the dEst
// sizing hint) AND the full IBLT (the remote's POPULATED digest the receiver's
// `GenerateDelta` subtracts). The pre-M2 draft carried ONLY the SE — the
// broken `GenerateDeltaStratified` subtracted an empty IBLT every round =
// byte-identical to oversend. marshaledStrata + marshaledIBLT are the bytes
// MarshalStrataEstimator / MarshalIBLT produced (the caller builds both).
func buildDigestFrame(senderID [16]byte, marshaledStrata, marshaledIBLT []byte) []byte {
	out := make([]byte, digestFrameHeaderLen+4+len(marshaledStrata)+len(marshaledIBLT))
	attribution.PutDigestFrame(out[0:4])
	copy(out[4:digestFrameHeaderLen], senderID[:])
	binaryBigEndianPutUint32(out[digestFrameSELenOff:], uint32(len(marshaledStrata)))
	copy(out[digestFrameSELenOff+4:], marshaledStrata)
	copy(out[digestFrameSELenOff+4+len(marshaledStrata):], marshaledIBLT)
	return out
}

// binaryBigEndianUint32 / binaryBigEndianPutUint32 are the encoding/binary
// big-endian uint32 helpers (inlined to a single word load/store; the frame
// length fields are big-endian to match WireV1Magic's big-endian discriminator
// convention). Kept local to digest.go so the file has no new import.
func binaryBigEndianUint32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}
func binaryBigEndianPutUint32(b []byte, v uint32) {
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
}

// DeliverDigest is the Gossiper's digestSink implementation. It extracts the
// sender's nodeID from the digest-frame header (so the accept-side serveConn —
// which does NOT know which peer dialed in from the conn alone — can route the
// digest to the RIGHT per-peer channel), unmarshals the peer's StrataEstimator
// (the dEst hint) AND the peer's full IBLT (the M2 load-bearing remote digest),
// and delivers them as a *peerDigest to the per-peer blocking channel the
// sweep's digest-exchange phase is waiting on. It is called from the readLoop
// (peer.go) and the accept-side serveConn (main.go) — both route digest frames
// through DispatchFrame, which calls this. A malformed digest (bad SE, bad
// IBLT, or a truncated frame) is logged + the channel receives a peerDigest
// with a nil IBLT (the sweep's wait treats a nil IBLT as "fallback to oversend"
// — the M5 honest path, never a silent drop of convergence).
//
// The peerID argument from DispatchFrame is the DIAL-side readLoop's pc.peerID
// (authoritative on the dial path); on the accept path serveConn passes a zero
// peerID (it does not know the peer), so DeliverDigest reads the senderID from
// the frame header as the authoritative routing key on BOTH paths (the single
// source of truth — the sender stamped its own nodeID; a conn that lies delivers
// a digest the sweep is not waiting for, which drops cleanly per the
// WireDigestMagic threat model).
//
// The channel send is NON-BLOCKING (a buffered channel of capacity 1): the
// sweep sends its OWN digest then blocks on the receive; the peer's digest
// arrives within one round-trip. If the sweep is NOT currently waiting (e.g. a
// late digest from a previous round), the non-blocking send drops it (the next
// round re-exchanges) — a digest is advisory, the signed delta is authoritative
// (the threat model in wire_v1.go's WireDigestMagic comment).
func (g *Gossiper) DeliverDigest(_ [16]byte, frame []byte) {
	peerID := digestFrameSender(frame) // the authoritative routing key (the sender stamped it)
	ch := g.digestRecvFor(peerID)
	if ch == nil {
		return // no live wait for this peer; drop (the next round re-exchanges)
	}
	seBody, ibltBody := digestFrameSplit(frame)
	pd := &peerDigest{}
	if seBody != nil {
		se, err := eng.UnmarshalStrataEstimator(seBody)
		if err != nil {
			// Malformed SE: log + deliver a nil-IBLT peerDigest so the sweep
			// falls back to oversend (M5) rather than blocking forever.
			log.Printf("mesh: malformed strata estimator from %x: %v — sweep will oversend (M5 fallback)", peerID, err)
			select {
			case ch <- pd: // pd.iblt == nil → M5 fallback
			default:
			}
			return
		}
		pd.se = se
	}
	if ibltBody != nil {
		iblt, err := eng.UnmarshalIBLT(ibltBody)
		if err != nil {
			// Malformed IBLT: log + deliver the SE-only peerDigest (nil IBLT
			// → M5 fallback; the SE is kept for the dEst log/diagnostic).
			log.Printf("mesh: malformed IBLT digest from %x: %v — sweep will oversend (M5 fallback)", peerID, err)
			select {
			case ch <- pd: // pd.iblt == nil → M5 fallback
			default:
			}
			return
		}
		pd.iblt = iblt
	}
	select {
	case ch <- pd:
	default: // sweep not waiting on this peer this round; drop (next round)
	}
}
