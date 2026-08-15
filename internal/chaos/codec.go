// ---------------------------------------------------------------------------
// Stage 6 §2 — exported IPC codec wrappers + payload encode/decode.
// ---------------------------------------------------------------------------
//
// protocol.go defines the wire frame and the unexported writeFrame/readFrame,
// deliberately keeping the framing logic private to this package. The
// chaos-worker child process (cmd/chaos-worker) and the supervisor
// (supervisor.go) both reach the protocol ONLY through these exported
// helpers, so the wire layout lives in exactly one place.
//
// PAYLOAD LAYOUTS (all big-endian, fixed-size where noted):
//
//	OpHello      payload = nodeID(16) + lamport(8) + merkleRoot(32) = 56 bytes
//	OpSubmitOK   payload = nodeID(16) + counter(8) + merkleRoot(32) = 56 bytes
//	OpSubmit     payload = entityIDLen(4) + entityID + CRDTEntry(120)
//	OpQuery      payload = entityIDLen(4) + entityID            (resp = OpSubmitOK shape)
//	OpBye/OpPoke/OpCrashProbe payload = empty
package chaos

import (
	"encoding/binary"
	"io"

	"github.com/hr18vk/supremum/pkg/sync"
)

// crdtEntryWireLen is the on-wire size of a sync.CRDTEntry carried inside an
// OpSubmit frame. It MUST equal sizeof(sync.CRDTEntry) (120 bytes per the
// struct comment in pkg/sync/hamt.go). A compile-time check lives in
// consumeCRDTEntry that guards against silent layout drift.
const crdtEntryWireLen = 120

// ReadFrameFromReader is the exported read seam. It returns io.EOF on a clean
// or truncated end-of-stream, which the supervisor interprets as a worker
// crash (graceful exit if the last frame was OpBye).
func ReadFrameFromReader(r io.Reader) (Frame, error) {
	return readFrame(r)
}

// WriteFrameToWriter is the exported write seam. It encodes one frame to w.
func WriteFrameToWriter(w io.Writer, op FrameOp, seq uint32, payload []byte) error {
	return writeFrame(w, op, seq, payload)
}

// EncodeHello serializes a worker hello: (nodeID, lamport, merkleRoot).
func EncodeHello(nodeID [16]byte, lamport uint64, root [32]byte) []byte {
	p := make([]byte, 56)
	copy(p[0:16], nodeID[:])
	binary.BigEndian.PutUint64(p[16:24], lamport)
	copy(p[24:56], root[:])
	return p
}

// DecodeHello deserializes a worker hello. ok=false on a malformed payload; the
// supervisor never trusts a truncated hello from a possibly-crashing child.
func DecodeHello(p []byte) (nodeID [16]byte, lamport uint64, root [32]byte, ok bool) {
	if len(p) != 56 {
		return nodeID, 0, root, false
	}
	copy(nodeID[:], p[0:16])
	lamport = binary.BigEndian.Uint64(p[16:24])
	copy(root[:], p[24:56])
	return nodeID, lamport, root, true
}

// EncodeAckOK serializes an OpSubmitOK response: (nodeID, counter, root).
// Shape is identical to EncodeHello so an OpQuery response needs no extra codec.
func EncodeAckOK(nodeID [16]byte, counter uint64, root [32]byte) []byte {
	p := make([]byte, 56)
	copy(p[0:16], nodeID[:])
	binary.BigEndian.PutUint64(p[16:24], counter)
	copy(p[24:56], root[:])
	return p
}

// DecodeAckOK deserializes an OpSubmitOK payload.
func DecodeAckOK(p []byte) (nodeID [16]byte, counter uint64, root [32]byte, ok bool) {
	if len(p) != 56 {
		return nodeID, 0, root, false
	}
	copy(nodeID[:], p[0:16])
	counter = binary.BigEndian.Uint64(p[16:24])
	copy(root[:], p[24:56])
	return nodeID, counter, root, true
}

// EncodeSubmit serializes an OpSubmit payload: length-prefixed entityID plus a
// full 120-byte CRDTEntry. The supervisor relays a client mutation to the
// worker with this; the worker decodes it with DecodeSubmit.
func EncodeSubmit(entityID string, entry sync.CRDTEntry) []byte {
	p := make([]byte, 4+len(entityID)+crdtEntryWireLen)
	binary.BigEndian.PutUint32(p[0:4], uint32(len(entityID)))
	copy(p[4:4+len(entityID)], entityID)
	encodeCRDTEntry(p[4+len(entityID):], entry)
	return p
}

// DecodeSubmit deserializes an OpSubmit payload into the entry + entityID. The
// DotNodeID/DotCounter fields in the decoded entry are HONORED by the worker
// for the merkle-root equality contract on replay; on a fresh submit they are
// overwritten by InsertLocal's NextDot(), which is the intended live path.
func DecodeSubmit(p []byte) (entry sync.CRDTEntry, entityID string, ok bool) {
	if len(p) < 4 {
		return entry, "", false
	}
	entLen := binary.BigEndian.Uint32(p[0:4])
	need := 4 + int(entLen) + crdtEntryWireLen
	if len(p) < need {
		return entry, "", false
	}
	entityID = string(p[4 : 4+int(entLen)])
	entry = decodeCRDTEntry(p[4+int(entLen) : need])
	return entry, entityID, true
}

// encodeCRDTEntry writes a sync.CRDTEntry into a 120-byte destination. Field
// order matches the struct declaration in pkg/sync/hamt.go so the wire
// format is a simple, uuid-stable serialization with no padding reliance.
func encodeCRDTEntry(dst []byte, e sync.CRDTEntry) {
	off := 0
	copy(dst[off:off+32], e.PayloadDigest[:])
	off += 32
	copy(dst[off:off+16], e.OriginNodeID[:])
	off += 16
	copy(dst[off:off+16], e.DotNodeID[:])
	off += 16
	binary.BigEndian.PutUint64(dst[off:off+8], e.DotCounter)
	off += 8
	binary.BigEndian.PutUint64(dst[off:off+8], uint64(e.SystemTime))
	off += 8
	binary.BigEndian.PutUint64(dst[off:off+8], uint64(e.ValidTimeStart))
	off += 8
	binary.BigEndian.PutUint64(dst[off:off+8], uint64(e.ValidTimeEnd))
	off += 8
	binary.BigEndian.PutUint64(dst[off:off+8], uint64(e.AssertionTime))
	off += 8
	binary.BigEndian.PutUint64(dst[off:off+8], uint64(e.DecisionTime))
	off += 8
	binary.BigEndian.PutUint64(dst[off:off+8], e.H3Index)
	off += 8
}

func decodeCRDTEntry(src []byte) sync.CRDTEntry {
	var e sync.CRDTEntry
	off := 0
	copy(e.PayloadDigest[:], src[off:off+32])
	off += 32
	copy(e.OriginNodeID[:], src[off:off+16])
	off += 16
	copy(e.DotNodeID[:], src[off:off+16])
	off += 16
	e.DotCounter = binary.BigEndian.Uint64(src[off : off+8])
	off += 8
	e.SystemTime = int64(binary.BigEndian.Uint64(src[off : off+8]))
	off += 8
	e.ValidTimeStart = int64(binary.BigEndian.Uint64(src[off : off+8]))
	off += 8
	e.ValidTimeEnd = int64(binary.BigEndian.Uint64(src[off : off+8]))
	off += 8
	e.AssertionTime = int64(binary.BigEndian.Uint64(src[off : off+8]))
	off += 8
	e.DecisionTime = int64(binary.BigEndian.Uint64(src[off : off+8]))
	off += 8
	e.H3Index = binary.BigEndian.Uint64(src[off : off+8])
	off += 8
	return e
}
