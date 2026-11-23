// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Package mesh implements stratified anti-entropy digest exchange in this file
// (ADR-0034, ADR-0054).
//
// AntiEntropySweep needs the peer's populated IBLT to produce a minimal delta.
// A StrataEstimator cannot supply it: the estimator's XOR-based KeySum is lossy
// and cannot be inverted into a key set. Each peer therefore sends its full
// IBLT, and the receiver calls GenerateDelta(remoteIBLT) to subtract and peel
// the actual difference. The estimator remains only as the dEst sizing hint.
// Sending a local IBLT instead would subtract the receiver's own set and could
// not converge.
//
// Each exchange sends MarshalStrataEstimator and a dEst-sized MarshalIBLT,
// then uses the received pair to build a delta proportional to |A−B|. The
// digest round trip adds about 50 KB for the estimator's 32 strata plus the
// remote IBLT, approximately 1.5×|A−B|×20 bytes. This saves bandwidth when
// |A−B| << |A|, although a near-empty diff can make the digest larger than the
// delta it avoids (ADR-0054).
//
// Digest frames use the existing peer-TLS data plane and its length-prefixed
// framing. attribution.WireDigestMagic distinguishes them after the length
// prefix, and readLoop routes them to digestSink. They are mesh-internal
// advisory frames, not RelayEnvelope or CRDTDeltaEvent values, so HandleFrame
// does not parse them.
//
// A control-port route would not serve the peer mesh: the two-node harness in
// gossip_test.go and partition_test.go constructs only PeerSet and Gossiper,
// without a ControlServer or HTTP listener. Peer TLS works in both that harness
// and the production binary.
//
// DispatchFrame centralizes routing for peer.go readLoop, cmd serveConn, and
// gossip_test.go serveTestConn:
//
//	IsBatchFrame(frame)  -> recv.HandleBatchFrame
//	IsDigestFrame(frame) -> digester.DeliverDigest
//	IsHybridFrame(frame) -> recv.HandleHybridFrame
//	else                 -> recv.HandleFrame
//
// Hybrid frames carry CRDT state and require the receiver's dual-signature
// verification (ADR-0037); unlike digests, they cannot go to a mesh sink. The
// batch, digest, hybrid, and relay discriminators are pairwise bit-distinct
// (ADR-0037 §3), preventing a frame from entering the wrong parser.
//
// A nil digester drops digest frames when stratified anti-entropy is disabled.
// StratifiedAntiEntropyFallback increments when timeout, malformed input, or
// peel failure makes the sweep fall back to oversend.
package mesh

import (
	"hash/maphash"
	"log"

	eng "github.com/hr18vk/sovereign/pkg/sync"

	"github.com/hr18vk/sovereign/pkg/attribution"
	"github.com/hr18vk/sovereign/pkg/receive"
	"sync/atomic"
	"time"
)

// DigestSink receives mesh-internal digest frames for a Gossiper. Digest data
// is not a CRDT delta and never enters HandleFrame. readLoop delivers each
// estimator and IBLT to the synchronous digest-exchange phase in ADR-0054.
// A nil sink drops digests when stratified anti-entropy is disabled.
//
// peerID is the sending peer's node ID. The dial side knows it from pc.peerID;
// the accept side supplies the connection identity and DeliverDigest checks it
// against the frame's sender ID before routing to that peer's wait channel.
type DigestSink interface {
	DeliverDigest(peerID [16]byte, wire []byte)
}

// DispatchFrame routes a reassembled frame to batch, digest, hybrid, or relay
// handling without copying or allocating. peer.go readLoop, cmd serveConn, and
// gossip_test.go serveTestConn all use this router.
//
// The batch, digest, and hybrid magics and the RelayEnvelope version prefix are
// pairwise bit-distinct (ADR-0034 §3, ADR-0037 §3). The checks therefore cannot
// send a digest to the relay parser or a hybrid frame to the batch parser or
// digest sink.
//
// A nil digester drops digest frames while stratified anti-entropy is disabled.
// recv handles every state-carrying frame. In particular, hybrid frames always
// run HandleHybridFrame's rate, verification, and Join path; --hybrid-verify
// controls acceptance inside that handler rather than dispatch.
func DispatchFrame(frame []byte, peerID [16]byte, recv frameSink, digester DigestSink) receive.AcceptVerdict {
	if attribution.IsBatchFrame(frame) {
		return recv.HandleBatchFrame(frame) // the batch gate stack
	}
	if attribution.IsDigestFrame(frame) {
		if digester != nil {
			digester.DeliverDigest(peerID, frame) // the digest-exchange phase
		}
		// A digest frame is not a CRDT delta; the receive gate stack never
		// touches it. Return Accept (the frame was consumed by the digest
		// sink, or dropped when stratified is off — either way it is not a
		// gate-stack reject that should surface as a drop verdict).
		return receive.AcceptVerdict{Verdict: receive.Accept}
	}
	if attribution.IsHybridFrame(frame) {
		return recv.HandleHybridFrame(frame) // the hybrid-PQ batch gate stack
	}
	return recv.HandleFrame(frame) // the relay validation path
}

// peerDigest carries the estimator and IBLT to a sweep's per-peer wait channel.
// The estimator supplies dEst; GenerateDelta subtracts the populated remote
// IBLT to obtain the actual diff. A malformed digest has a nil IBLT and triggers
// fallback. A nil estimator leaves dEst=0 and selects the minimum IBLT size.
type peerDigest struct {
	se         *eng.StrataEstimator // the dEst sizing hint (may be nil on a malformed SE)
	iblt       *eng.IBLT            // the remote's full digest (nil → fallback to oversend)
	buildStamp int64                // Unix nanos; zero marks an unstamped frame and is counted at the drain
}

// digestFrameHeaderLen is the 37-byte fixed header: WireDigestMagic(4),
// senderNodeID(16), role(1), seed(8), and buildStamp(8). The body contains a
// four-byte big-endian SE length, MarshalStrataEstimator, and MarshalIBLT.
// The length lets the receiver separate the sizing hint from the IBLT.
//
// senderNodeID is the CRDT signing identity also carried as BatchEnvelope's
// originNodeID. DeliverDigest checks it against the verified connection identity
// before routing, so an accept-side connection cannot select another peer's
// wait channel by changing the header.
//
// role and seed implement the one-RTT exchange in ADR-0054. A receiver answers
// digestRoleRequest with digestRoleResponse and never answers a response, so
// the exchange cannot recurse. Without this response, a requester would wait
// for the peer's next sweep rather than one network round trip.
//
// The responder reads the big-endian SeedToUint64 value and builds its IBLT
// with the requester's seed. GenerateDelta rebuilds its local table under that
// seed so subtraction aligns. The IBLT body also carries the seed; the header
// copy avoids a full unmarshal on readLoop. These mesh-internal fields are
// outside the Cap'n Proto schema.
const digestFrameHeaderLen = 4 + 16 + 1 + 8 + 8 // magic + senderNodeID + role + seed + buildStamp = 37

// digestFrameRoleOff / digestFrameSeedOff are the offsets of the role byte
// and the 8-byte big-endian seed word (after the 20-byte magic+senderNodeID).
// digestFrameSELenOff is the offset of the 4-byte big-endian SE-length field
// that starts the variable body.
const digestFrameRoleOff = 4 + 16     // 20
const digestFrameSeedOff = 4 + 16 + 1 // 21

// digestFrameStampOff is the offset of the 8-byte big-endian build-stamp field
// in the fixed header. buildDigestFrame records the frame's build time in Unix
// nanoseconds. For a response, the requester computes drained-class latency as
// drain time minus buildStamp. This includes responses that arrive after their
// wait expires; slowest_ms alone covers only completed exchanges. Requests use
// the same layout, allowing a stale request drained from a wait channel to
// contribute an arrival-latency observation. A root announcement leaves the
// field zero and is consumed by recordPeerRoot rather than a wait channel.
// The drain site counts and logs zero as the broken-stamp class instead of
// computing a duration from it.
const digestFrameStampOff = digestFrameSeedOff + 8 // 29

// digestFrameSELenOff is the offset of the 4-byte big-endian SE-length field
// in the digest frame body (immediately after the 37-byte header). The body
// layout is:
//
//	[4] seLen (big-endian) + [seLen] MarshalStrataEstimator(se) +
//	[..] MarshalIBLT(iblt)  (the trailing IBLT spans body[digestFrameSELenOff+4+seLen:])
const digestFrameSELenOff = digestFrameHeaderLen // 37

// digestRoleRequest asks the receiver to answer with its own digest;
// digestRoleResponse is that answer. A receiver answers requests but never
// responses, preventing an endless exchange of answers.
const (
	digestRoleRequest  byte = 0x01
	digestRoleResponse byte = 0x02
	// The v2 scheme uses request/response tags 0x11/0x12 in the same positions
	// as the v1 tags (ADR-0064). A v1 peer does not recognize a v2 request and
	// does not answer it. The v2 requester rejects a v1 response by its IBLT
	// magic before subtraction, so the schemes cannot be peeled against each
	// other. A mixed pair times out and oversends until both sides use the same
	// scheme, while Join still merges their states. The root-announce role is
	// shared because announcements carry no IBLT and work across schemes.
	digestRoleRequestV2  byte = 0x11
	digestRoleResponseV2 byte = 0x12
	// digestRoleRootAnnounce is the one-way Merkle-root announcement role
	// (ADR-0055). Its body is the sender's 32-byte MerkleRootFromShards with
	// seLen==0 and no SE or IBLT. The receiver records the root through
	// recordPeerRoot, never responds, and never routes it to a digest wait
	// channel. Sending this root every sweep lets the change gate skip full
	// digest exchanges while roots match. Making the announcement itself a
	// round trip would add a WAN RTT before any necessary digest exchange.
	digestRoleRootAnnounce byte = 0x03
)

// digestFrameRootLen is the root-announce body length (the 32-byte Merkle
// root that follows the seLen==0 word in a digestRoleRootAnnounce frame).
const digestFrameRootLen = 32

// digestFrameSplit returns no-copy sub-slices for the marshaled estimator and
// IBLT. The caller must unmarshal them before recycling the frame buffer.
// The layout is:
//
//	[4] WireDigestMagic + [16] senderNodeID + [1] role +
//	[8] seed + [8] buildStamp + [4] seLen +
//	[seLen] MarshalStrataEstimator + [..] MarshalIBLT
//
// Multi-byte integer fields are big-endian. A short header or an seLen that
// overruns the frame returns nil bodies, which DeliverDigest handles as a
// malformed digest and fallback.
func digestFrameSplit(frame []byte) (seBody, ibltBody []byte) {
	if len(frame) < digestFrameSELenOff+4 {
		return nil, nil // too short for the header + the seLen field
	}
	seLen := int(binaryBigEndianUint32(frame[digestFrameSELenOff:]))
	seStart := digestFrameSELenOff + 4
	if seStart > len(frame) || seStart+seLen > len(frame) {
		return nil, nil // seLen overruns → malformed (fallback)
	}
	seBody = frame[seStart : seStart+seLen]
	ibltBody = frame[seStart+seLen:]
	return seBody, ibltBody
}

// digestFrameSender extracts the [16]byte senderNodeID from a digest frame
// header. It is the routing key the accept-side serveConn hands to
// DeliverDigest so the digest reaches the correct per-peer blocking-receive
// channel (the sweep registered a wait for this peer, not a different one).
// A frame too short for the header returns a zero [16]byte (the caller treats
// a zero senderID as "no live wait" — DeliverDigest's digestRecvFor returns
// nil for a zero key the sweep never registered, so the digest drops cleanly).
func digestFrameSender(frame []byte) [16]byte {
	var id [16]byte
	if len(frame) < digestFrameRoleOff { // need the full [4:20] senderNodeID
		return id
	}
	copy(id[:], frame[4:digestFrameRoleOff]) // the senderNodeID is bytes [4:20]
	return id
}

// digestFrameRole reads the role byte (digestRoleRequest /
// digestRoleResponse). A frame too short for the role byte returns 0 (neither
// request nor response — the receiver does not answer it, and the route-to-wait
// still works off the sender ID).
func digestFrameRole(frame []byte) byte {
	if len(frame) <= digestFrameRoleOff {
		return 0
	}
	return frame[digestFrameRoleOff]
}

// digestFrameStamp extracts the 8-byte build stamp (Unix nanos) from a
// digest frame header. A frame too short for the stamp field returns 0 — the
// unstamped/broken class (the drain site counts it, never a garbage span).
func digestFrameStamp(frame []byte) int64 {
	if len(frame) < digestFrameSELenOff {
		return 0
	}
	return int64(binaryBigEndianUint64(frame[digestFrameStampOff:]))
}

// digestFrameSeed reads the 8-byte big-endian seed word (the sender's IBLT
// seed, stamped by buildDigestFrame) and reconstructs the maphash.Seed the
// responder uses to build its answering digest under the same seed (so the
// requester's GenerateDelta(response) rebuilds its local IBLT under that seed
// and the subtract aligns). A frame too short for the seed returns the zero
// Seed; that is only reachable on a truncated frame, which digestFrameRole
// already reported as 0 (not a request), so the seed is never consumed then.
func digestFrameSeed(frame []byte) maphash.Seed {
	if len(frame) < digestFrameSeedOff+8 {
		return maphash.Seed{}
	}
	return eng.Uint64ToSeed(binaryBigEndianUint64(frame[digestFrameSeedOff:]))
}

// buildDigestFrame allocates and populates one digest frame from marshaled
// estimator and IBLT bodies. The caller adds transport framing with
// receive.LengthPrefixFrame. senderID is g.owner.NodeID, matching the identity
// used in signed deltas and per-peer wait channels.
//
// The header carries role, the requester's IBLT seed, and a build timestamp.
// A responder uses the header seed without unmarshaling the request IBLT;
// GenerateDelta reads the same seed from the response body (ADR-0054).
//
// The package-level broken-stamp fault injection exists because this is a free
// function. When enabled, it zeroes buildStamp so latency tests exercise the
// counted broken-stamp path rather than computing an invalid duration.
var digestStampBugInject atomic.Bool

func buildDigestFrame(role byte, senderID [16]byte, seed maphash.Seed, marshaledStrata, marshaledIBLT []byte) []byte {
	out := make([]byte, digestFrameHeaderLen+4+len(marshaledStrata)+len(marshaledIBLT))
	attribution.PutDigestFrame(out[0:4])
	copy(out[4:digestFrameRoleOff], senderID[:]) // the senderNodeID is bytes [4:20]
	out[digestFrameRoleOff] = role
	binaryBigEndianPutUint64(out[digestFrameSeedOff:], eng.SeedToUint64(seed))
	// Record Unix nanoseconds at build time. The requester uses a response's
	// stamp to compute drained-class latency. The broken-stamp fault injection
	// zeroes it to exercise the counted invalid-timestamp path.
	stamp := time.Now().UnixNano()
	if digestStampBugInject.Load() {
		stamp = 0
	}
	binaryBigEndianPutUint64(out[digestFrameStampOff:], uint64(stamp))
	binaryBigEndianPutUint32(out[digestFrameSELenOff:], uint32(len(marshaledStrata)))
	copy(out[digestFrameSELenOff+4:], marshaledStrata)
	copy(out[digestFrameSELenOff+4+len(marshaledStrata):], marshaledIBLT)
	return out
}

// buildRootAnnounceFrame builds a 73-byte, one-way root announcement: the
// digest-frame header with role=digestRoleRootAnnounce, seLen=0, and the local
// 32-byte Merkle root. The receiver records the root through recordPeerRoot and
// never responds or routes it to a wait channel. The seed and buildStamp fields
// remain zero because an announcement carries no IBLT and has no drain latency.
func buildRootAnnounceFrame(senderID [16]byte, root [32]byte) []byte {
	out := make([]byte, digestFrameHeaderLen+4+digestFrameRootLen)
	attribution.PutDigestFrame(out[0:4])
	copy(out[4:digestFrameRoleOff], senderID[:])
	out[digestFrameRoleOff] = digestRoleRootAnnounce
	// Seed bytes [21:29], buildStamp bytes [29:37], and seLen remain zero.
	binaryBigEndianPutUint32(out[digestFrameSELenOff:], 0)
	copy(out[digestFrameSELenOff+4:], root[:])
	return out
}

// digestFrameRoot extracts the 32-byte Merkle root from a root-announce frame
// (the body after the seLen==0 word). ok=false on a short frame — a truncated
// announce is dropped, never recorded (a partial root would poison the gate).
func digestFrameRoot(frame []byte) (root [32]byte, ok bool) {
	if len(frame) < digestFrameSELenOff+4+digestFrameRootLen {
		return root, false
	}
	copy(root[:], frame[digestFrameSELenOff+4:digestFrameSELenOff+4+digestFrameRootLen])
	return root, true
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

// binaryBigEndianUint64 / binaryBigEndianPutUint64 are the 8-byte big-endian
// siblings (the seed word). Same single-word inline discipline as the u32 pair
// (the seed matches the frame's other big-endian fields, not the IBLT body's
// little-endian — the frame header is mesh-owned, the IBLT body is sync-owned).
func binaryBigEndianUint64(b []byte) uint64 {
	return uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
}
func binaryBigEndianPutUint64(b []byte, v uint64) {
	b[0] = byte(v >> 56)
	b[1] = byte(v >> 48)
	b[2] = byte(v >> 40)
	b[3] = byte(v >> 32)
	b[4] = byte(v >> 24)
	b[5] = byte(v >> 16)
	b[6] = byte(v >> 8)
	b[7] = byte(v)
}

// DeliverDigest routes a verified peer digest to a waiting sweep and answers
// requests with the local digest under the requester's seed (ADR-0054).
// Responses complete in about one RTT and are never answered themselves.
// enqueueDigestResponse keeps that work asynchronous and bounded off readLoop.
//
// peer.go readLoop and the accept-side serveConn in main.go both call this via
// DispatchFrame. Malformed input is logged and delivered with a nil IBLT so the
// waiting sweep falls back rather than blocking indefinitely.
//
// connID is the installed connection identity, not the self-stamped sender in
// the frame. ADR-0068 requires it to be challenge-verified and equal to the
// header sender. The accept path may supply zero after a decode failure; zero
// is never verified and is dropped.
//
// The per-peer channel has capacity 1 and the send is non-blocking. A late or
// unsolicited digest is dropped when no sweep is waiting; the next round starts
// a new exchange, and signed deltas remain authoritative.
func (g *Gossiper) DeliverDigest(connID [16]byte, frame []byte) {
	peerID := digestFrameSender(frame) // the claimed sender (the self-stamped header)
	role := digestFrameRole(frame)
	// Record arrival before verification and delivery so drops and late deposits
	// are included. The entry-stamp fault injection moves the test stamp to deposit
	// time to exercise the loss in observability. Root announcements deliberately
	// have buildStamp zero and must not increment ArriveBrokenTotal.
	if g.l0iExchDebug && !l0iArrivalAtEntryBugInject.Load() && (role != digestRoleRootAnnounce || g.disableRootAnnounceArrivalGateBugInject.Load()) {
		g.l0iNoteArrival(peerID, digestFrameStamp(frame))
	}
	// A zero-value Gossiper has no PeerSet and cannot verify any identity
	// (ADR-0069). Drop and count the frame rather than dereferencing nil in
	// egressVerified. The nil-guard fault injection restores the nil dereference
	// in tests to prove this guard is required.
	if g.peers == nil && !g.disableNilPeersGuardBugInject.Load() {
		// Count every drop; log the first eight and each thousandth thereafter.
		g.deliverDigestNilGuardDrops.Add(1)
		if n := g.nilGuardLogSeq.Add(1); n <= 8 || n%1000 == 0 {
			log.Printf("mesh: digest frame from %x dropped: nil-peers 0-value Gossiper — nothing is verified (the guard: drop loud, never panic; drops %d)", peerID, g.deliverDigestNilGuardDrops.Load())
		}
		return
	}
	// ADR-0068 requires both a challenge-verified connection and an exact match
	// between connID and the frame's claimed sender. Verification alone would
	// permit a connection to impersonate another peer; a header match alone would
	// trust self-asserted identity. Apply the gate to announces, wait routing,
	// and request answers without removing the connection itself.
	//
	// The channel-gate fault injection trusts the header in negative controls;
	// the read-seam fault injection exercises the corresponding read path.
	if !g.disableDigestChannelGateBugInject.Load() && (connID == ([16]byte{}) || !g.peers.egressVerified(connID) || peerID != connID) {
		if peerID != connID {
			g.digestIdentityDrops.Add(1)
			log.Printf("mesh: digest frame from %x dropped: self-stamped sender does not match the conn identity %x (gate)", peerID, connID)
		} else {
			g.digestUnverifiedDrops.Add(1)
			log.Printf("mesh: digest frame from %x dropped: conn not challenge-verified (gate; membership is not verification)", peerID)
		}
		return
	}
	// Below the gate, peerID == connID and the connection is challenge-verified,
	// so each role-specific branch can use peerID as the proven identity.
	// A root announcement supplies the change gate's root without entering a
	// digest wait channel or triggering a response. recordPeerRoot is nil-safe,
	// leaving disabled stratified anti-entropy unchanged.
	if role == digestRoleRootAnnounce {
		if root, ok := digestFrameRoot(frame); ok {
			g.recordPeerRoot(peerID, root)
		}
		return
	}
	// Only response frames may be deposited into g.digestRecvFor(peerID).
	// An unsolicited request left in the persistent capacity-1 channel could
	// remain until the next registerDigestRecv, then be counted as a drained
	// exchange and distort the adaptive digestWait EWMA.
	if role == digestRoleResponse || role == digestRoleResponseV2 || g.disableDigestRecvRoleGateBugInject.Load() {
		if ch := g.digestRecvFor(peerID); ch != nil {
			seBody, ibltBody := digestFrameSplit(frame)
			// Preserve the wire build stamp for drained-class latency accounting.
			g.deliverPeerDigest(peerID, ch, seBody, ibltBody, digestFrameStamp(frame))
		}
	}
	// Answer requests asynchronously through the bounded, nil-guarded
	// enqueueDigestResponse path; never answer a response.
	//
	// Responses are scheme-aware (ADR-0064). A v2 node answers only a
	// magic-verified v2 request and adopts its numBuckets from the [0:8] body
	// prefix inspected by digestRequestBuckets. It does not build an O(S) v2
	// response for a v1 requester, which would reject the body and time out.
	// A v1 node answers v1 requests with the legacy default size. Its request
	// role comparison does not match v2 requests, so it does not answer them.
	// A truncated or otherwise invalid v2 IBLT body receives no response.
	if role == digestRoleRequest {
		if !g.ibltV2.Load() {
			g.enqueueDigestResponse(peerID, digestFrameSeed(frame), eng.IBLTDigestDefaultBuckets)
		}
	} else if role == digestRoleRequestV2 && g.ibltV2.Load() {
		if n, ok := digestRequestBuckets(frame); ok {
			g.enqueueDigestResponse(peerID, digestFrameSeed(frame), int(n))
		}
	}
}

// deliverPeerDigest unmarshals the estimator and IBLT and delivers them to the
// sweep's per-peer wait channel. Malformed input produces a peerDigest with a
// nil IBLT, allowing the sweep to defer or oversend according to its
// configuration rather than leaving the wait blocked. Request responses use
// this same parsing and delivery path.
func (g *Gossiper) deliverPeerDigest(peerID [16]byte, ch chan *peerDigest, seBody, ibltBody []byte, stamp int64) {
	pd := &peerDigest{buildStamp: stamp}
	// The nil-digest fault injection delivers a well-formed frame with a
	// nil IBLT, exercising the malformed-digest defer path without wire noise.
	// It defaults to false and adds one atomic load to digest receipt.
	if g.nilDigestBugInject.Load() {
		select {
		case ch <- pd:
		default:
		}
		return
	}
	// An IBLT-only frame has a zero-length, non-nil seBody. Test length rather
	// than nil so the absent estimator is not unmarshaled as an empty, malformed
	// 13-byte-header value (ADR-0055). A present estimator is still parsed.
	// GenerateDelta consumes only pd.iblt, so an absent estimator does not
	// change the diff.
	if len(seBody) > 0 {
		se, err := eng.UnmarshalStrataEstimator(seBody)
		if err != nil {
			// Deliver the nil-IBLT result after logging the malformed estimator.
			if g.deferHandler {
				log.Printf("mesh: malformed strata estimator from %x: %v — sweep defers and escalates bounded slices", peerID, err)
			} else {
				log.Printf("mesh: malformed strata estimator from %x: %v — sweep falls back to oversend", peerID, err)
			}
			select {
			case ch <- pd: // nil IBLT selects defer or oversend in the sweep
			default:
			}
			return
		}
		pd.se = se
	}
	if ibltBody != nil {
		iblt, err := eng.UnmarshalIBLT(ibltBody)
		if err != nil {
			// Keep the estimator for dEst diagnostics and deliver a nil IBLT.
			if g.deferHandler {
				log.Printf("mesh: malformed IBLT digest from %x: %v — sweep defers and escalates bounded slices", peerID, err)
			} else {
				log.Printf("mesh: malformed IBLT digest from %x: %v — sweep falls back to oversend", peerID, err)
			}
			select {
			case ch <- pd: // nil IBLT selects defer or oversend in the sweep
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

// The verified-key challenge frame family (ADR-0068).
//
// The TLS leaf CommonName supplies a routing identity but does not prove
// possession of the node signing key registered in the identity Directory.
// The challenge binds those identities during connection setup. Each side
// sends a fresh random 32-byte nonce; the responder signs
// domain || nonce || responderID || challengerID with its node Ed25519 key,
// and the challenger verifies the signature against the Directory entry.
// Checking the returned nonce against the connection's stored nonce rejects a
// replayed response before signature verification.
//
// The mesh-internal wire shapes are fixed-width and bounds-checked, with no
// varints and no RelayEnvelope wrapper:
//
//	CHALLENGE  [4] magic "SGWC" BE + [1] role 0x01 + [16] challengerID +
//	           [32] nonce                                        = 53 B
//	RESPONSE   [4] magic         + [1] role 0x02 + [16] responderID +
//	           [16] challengerID + [32] nonce + [64] Ed25519 sig = 133 B
//
// The magic 0x53475743 ("SGWC") differs from WireV1Magic "SBAT",
// WireDigestMagic "SDST", and WireHybridPQMagic "SHYB" in byte 1, and from the
// RelayEnvelope's little-endian uint16 version prefix in byte 0. Dispatch can
// therefore distinguish challenge, batch, digest, hybrid, and relay frames.

// challengeMagic is the 4-byte big-endian dispatch discriminator of the
// verified-key challenge family. See the block comment above for
// the distinctness argument.
const challengeMagic uint32 = 0x53475743 // "SGWC" — Sovereign Gateway Challenge (big-endian)

// The challenge frame roles. A challenge asks the remote to prove
// possession of the Directory-registered key for the identity its TLS leaf
// claims; a response is that proof. No-ping-pong: a response is never
// answered (this is a one-round handshake, both directions in parallel).
const (
	challengeRoleChallenge byte = 0x01
	challengeRoleResponse  byte = 0x02
)

// Fixed offsets/lengths of the challenge wire shapes (post-length-prefix).
const (
	challengeRoleOff       = 4   // the role byte after the 4-byte magic
	challengeChallengerOff = 5   // challenge: challengerID [16]
	challengeNonceOff      = 21  // challenge: nonce [32]
	challengeFrameLen      = 53  // magic 4 + role 1 + challengerID 16 + nonce 32
	respResponderOff       = 5   // response: responderID [16]
	respChallengerOff      = 21  // response: challengerID [16]
	respNonceOff           = 37  // response: nonce [32]
	respSigOff             = 69  // response: Ed25519 sig [64]
	respFrameLen           = 133 // magic 4 + role 1 + ids 32 + nonce 32 + sig 64
)

// challengeSigLen is the Ed25519 signature size (ed25519.SignatureSize).
const challengeSigLen = 64

// challengeDomain is the domain-separation constant inside every signed
// challenge message. It binds the signature to this protocol: the same
// node key signs CRDT deltas (SignCRDTFrame) and challenge responses, and
// without the domain string a captured delta signature could be replayed
// as a challenge response (or vice versa). The message is the fixed
// 97-byte concatenation domain || nonce || responderID || challengerID,
// assembled by buildChallengeMsg.
const challengeDomain = "sovereign-mesh-keyed-challenge-v1" // 33 bytes

// buildChallengeMsg assembles the fixed 97-byte Ed25519 challenge message:
// domain || nonce || responderID || challengerID. Returning buf[:] moves its
// backing array to the heap. This allocation occurs once per connection
// handshake, not on the per-frame data path.
func buildChallengeMsg(nonce [32]byte, responderID, challengerID [16]byte) []byte {
	var buf [len(challengeDomain) + 32 + 16 + 16]byte
	n := copy(buf[:], challengeDomain)
	n += copy(buf[n:], nonce[:])
	n += copy(buf[n:], responderID[:])
	copy(buf[n:], challengerID[:])
	return buf[:]
}

// IsChallengeFrame reports whether a post-length-prefix body starts with
// challengeMagic, without copying it. cmd's serveConnWithDigest performs this
// check directly instead of calling DispatchFrame so challenge frames reach
// PeerSet's handshake handler before any other dispatch.
func IsChallengeFrame(frame []byte) bool {
	return len(frame) >= 5 && binaryBigEndianUint32(frame[0:4]) == challengeMagic
}

// frameIsDigest lets the mesh read loops recognize digest frames without
// importing pkg/attribution into their files.
func frameIsDigest(frame []byte) bool { return attribution.IsDigestFrame(frame) }

// challengeFrameRole returns the role byte, or 0 for a short frame.
func challengeFrameRole(frame []byte) byte {
	if len(frame) <= challengeRoleOff {
		return 0
	}
	return frame[challengeRoleOff]
}

// buildChallengeFrame encodes the challenger's node ID and fresh per-connection
// nonce.
func buildChallengeFrame(challengerID [16]byte, nonce [32]byte) []byte {
	out := make([]byte, challengeFrameLen)
	binaryBigEndianPutUint32(out[0:4], challengeMagic)
	out[challengeRoleOff] = challengeRoleChallenge
	copy(out[challengeChallengerOff:], challengerID[:])
	copy(out[challengeNonceOff:], nonce[:])
	return out
}

// parseChallengeFrame extracts the challenger ID and nonce. A short frame
// returns ok=false and is not treated as a verification attempt.
func parseChallengeFrame(frame []byte) (challengerID [16]byte, nonce [32]byte, ok bool) {
	if len(frame) < challengeFrameLen {
		return challengerID, nonce, false
	}
	copy(challengerID[:], frame[challengeChallengerOff:challengeChallengerOff+16])
	copy(nonce[:], frame[challengeNonceOff:challengeNonceOff+32])
	return challengerID, nonce, true
}

// buildChallengeResponseFrame encodes the responder's own node ID, the
// challenger ID and nonce from the request, and the Ed25519 signature over the
// 97-byte challenge message. A responder cannot sign for an identity whose
// private key it does not possess.
func buildChallengeResponseFrame(responderID, challengerID [16]byte, nonce [32]byte, sig []byte) []byte {
	out := make([]byte, respFrameLen)
	binaryBigEndianPutUint32(out[0:4], challengeMagic)
	out[challengeRoleOff] = challengeRoleResponse
	copy(out[respResponderOff:], responderID[:])
	copy(out[respChallengerOff:], challengerID[:])
	copy(out[respNonceOff:], nonce[:])
	copy(out[respSigOff:], sig[:challengeSigLen])
	return out
}

// parseChallengeResponseFrame extracts the response fields. sig aliases the
// frame buffer and must not be retained after that buffer is reused. A short
// frame returns ok=false and is not treated as a verification attempt.
func parseChallengeResponseFrame(frame []byte) (responderID, challengerID [16]byte, nonce [32]byte, sig []byte, ok bool) {
	if len(frame) < respFrameLen {
		return responderID, challengerID, nonce, nil, false
	}
	copy(responderID[:], frame[respResponderOff:respResponderOff+16])
	copy(challengerID[:], frame[respChallengerOff:respChallengerOff+16])
	copy(nonce[:], frame[respNonceOff:respNonceOff+32])
	sig = frame[respSigOff : respSigOff+challengeSigLen]
	return responderID, challengerID, nonce, sig, true
}
