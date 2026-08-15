package receive

import (
	"encoding/binary"
	"fmt"

	"github.com/cloudflare/circl/sign/ed25519"
	"github.com/hr18vk/supremum/pkg/attribution"
	"github.com/hr18vk/supremum/pkg/transport"
	"golang.org/x/sys/unix"
)

// ForwardEnvelope relays a verified envelope one more hop: it appends a new
// relay Hop (signed by this node's relay key, chaining custody over the
// existing hop prefix), Marshals the envelope, length-prefixes the Marshal
// output (the GAP-2 wire shape [uint32 frameLen BE][envelope bytes]), and
// hands the OUTERMOST frame bytes to pkg/transport.TransmitHeapBufferSend,
// which copies the frame into a pinned Go-heap slice and sendmsg's it with
// MSG_ZEROCOPY. This is the 2.0 egress tie: the copy-before-Pin is the 2.0
// lock (TransmitHeapBufferSend does make -> copy -> Pin -> send -> Unpin
// internally), so this path NEVER Pins the in-memory envelope region — it
// hands TransmitHeapBufferSend a fresh []byte and lets the 2.0 boundary own
// the Pin on the heap copy.
//
// relayPriv is this node's Ed25519 relay private key; relayPub is its
// canonical [32]byte public key; innerWire is the verified inner wire (the
// same bytes the receiver's 1.1 verify accepted); originSig is the origin's
// signature (carried verbatim, unchanged — relays attest custody, they do
// not re-sign the origin); existingHops is the relay chain so far; hopIndex
// is the new hop's index (len(existingHops)); wallUSec is this relay's
// physical timestamp; fd is the egress socket; to is the destination
// Sockaddr.
//
// Kernel zero-copy is conditionally-verified, NOT asserted (the 2.0 AF_UNIX
// build logs SO_ZEROCOPY EOPNOTSUPP; ERRQUEUE completion is 2.1/12.0): the
// send proceeds whether or not the kernel zero-copies. Do NOT assert true
// zero-copy occurred on this box.
// ForwardEnvelope relays a verified envelope one more hop: it appends a new
// relay Hop (signed by this node's relay key, chaining custody over the
// existing hop prefix), Marshals the envelope, length-prefixes the Marshal
// output (the GAP-2 wire shape [uint32 frameLen BE][envelope bytes]), and
// hands the OUTERMOST frame bytes to pkg/transport.TransmitHeapBufferSend,
// which copies the frame into a pinned Go-heap slice and sendmsg's it with
// MSG_ZEROCOPY. This is the 2.0 egress tie: the copy-before-Pin is the 2.0
// lock (TransmitHeapBufferSend does make -> copy -> Pin -> send -> Unpin
// internally), so this path NEVER Pins the in-memory envelope region — it
// hands TransmitHeapBufferSend a fresh []byte and lets the 2.0 boundary own
// the Pin on the heap copy.
//
// relayPriv is this node's Ed25519 relay private key; relayPub is its
// canonical [32]byte public key; innerWire is the verified inner wire (the
// same bytes the receiver's 1.1 verify accepted); originSig is the origin's
// signature (carried verbatim, unchanged — relays attest custody, they do
// not re-sign the origin); dotCounter + originNodeID are the v3 header mirror
// fields the relay copies VERBATIM off the verified incoming envelope (Track
// 3.6: relays attest custody, they do not alter the origin's gate fields —
// the receiver cross-checks these against the inner capnp on the accept
// path, so a relay that altered them would be DropVerify'd). They are sourced
// from the incoming env's DotCounter()/OriginNodeID() accessors at the
// forward seam, NOT re-derived from literals (the desync tooth). existingHops
// is the relay chain so far; hopIndex is the new hop's index (len(existingHops));
// wallUSec is this relay's physical timestamp; fd is the egress socket; to is
// the destination Sockaddr.
//
// Kernel zero-copy is conditionally-verified, NOT asserted (the 2.0 AF_UNIX
// build logs SO_ZEROCOPY EOPNOTSUPP; ERRQUEUE completion is 2.1/12.0): the
// send proceeds whether or not the kernel zero-copies. Do NOT assert true
// zero-copy occurred on this box.
func ForwardEnvelope(relayPriv ed25519.PrivateKey, relayPub [32]byte, innerWire []byte, originSig [64]byte, dotCounter uint64, originNodeID [16]byte, existingHops []attribution.Hop, hopIndex uint16, wallUSec int64, fd int, to unix.Sockaddr) (sent int, err error) {
	// 1. Append the new relay Hop, chaining custody over the existing
	//    prefix. SignHop signs (innerWire || preceding || hopIndex ||
	//    wallUSec); preceding is the signed material of all prior hops,
	//    rebuilt here exactly as Open threads it.
	preceding := rebuildPreceding(innerWire, existingHops)
	newHop := attribution.SignHop(relayPriv, relayPub, innerWire, preceding, hopIndex, wallUSec)
	allHops := make([]attribution.Hop, 0, len(existingHops)+1)
	allHops = append(allHops, existingHops...)
	allHops = append(allHops, newHop)

	// 2. Marshal the envelope (originSig + the v3 mirror fields ride the
	//    header; the inner wire is carried verbatim). The mirrors are copied
	//    off the verified incoming envelope unchanged — relays attest
	//    custody, they do not alter the origin's gate fields.
	env := attribution.NewSignedRelayEnvelopeV3(innerWire, originSig, dotCounter, originNodeID, allHops)
	envelopeBytes := env.Marshal()

	// 3. Length-prefix the Marshal output (the GAP-2 wire shape). The prefix
	//    is a pkg/receive framing concern; envelope.Marshal stays a pure
	//    envelope (no outer-length prefix).
	prefixed := LengthPrefixFrame(envelopeBytes)

	// 4. Hand the prefixed frame to the 2.0 egress boundary. The copy-before-
	//    Pin is the 2.0 lock; this path NEVER Pins the in-memory envelope
	//    region (TransmitHeapBufferSend copies into a fresh heap slice and
	//    Pins that copy).
	return transport.TransmitHeapBufferSend(fd, prefixed, to)
}

// LengthPrefixFrame prepends the 4-byte big-endian length prefix to a Marshal'd
// envelope, producing the GAP-2 wire shape [uint32 frameLen BE][envelope
// bytes] the receiver's FrameReader expects. It is the inverse of
// FrameReader.ReadFrame. The prefix is a pkg/receive framing concern, NOT an
// envelope concern (envelope.Marshal stays a pure envelope).
func LengthPrefixFrame(envelopeBytes []byte) []byte {
	out := make([]byte, frameLenPrefixSize+len(envelopeBytes))
	binary.BigEndian.PutUint32(out[:frameLenPrefixSize], uint32(len(envelopeBytes)))
	copy(out[frameLenPrefixSize:], envelopeBytes)
	return out
}

// rebuildPreceding reconstructs the signed-material accumulator Open threads
// through the verify loop, for the existing hops. It is the build-side
// inverse of Open's per-hop verify: each hop's signed material is
// (innerWire || preceding || hopIndex || wallUSec), and the accumulator for
// the NEXT hop is THIS hop's material. It is exported so a relay forwarding
// a frame it received can rebuild the prefix without re-verifying (the
// receiver already verified the outer hops in Open; the relay re-signs only
// its own new hop over the rebuilt prefix).
//
// The material layout is sourced from the single source of truth
// (attribution.SignedMaterial), NOT re-derived here. Re-deriving duplicated
// the framing layout in two files; drift between the two silently produced
// per-hop matériel the next hop's Open would reject (or accept the wrong
// bytes). The desync tooth (the G3.5.l-DSYN block of TestReceiver_SourceGuard)
// fails the build if this re-derivation is reintroduced.
func rebuildPreceding(innerWire []byte, hops []attribution.Hop) []byte {
	var preceding []byte
	for i, hop := range hops {
		preceding = attribution.SignedMaterial(innerWire, preceding, uint16(i), hop.WallUSec)
	}
	return preceding
}

// ErrForwardEmptyInner is returned by ForwardEnvelope when the inner wire is
// empty (there is nothing to relay).
var ErrForwardEmptyInner = fmt.Errorf("receive: forward inner wire is empty")
