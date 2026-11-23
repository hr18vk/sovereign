// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package identity

import (
	"errors"
	"sync"

	"filippo.io/mldsa"
	"github.com/cloudflare/circl/sign/ed25519"
)

// ErrDirectoryBadPubKey is returned by Register when the supplied public key
// is not a valid 32-byte Ed25519 key. It mirrors the zero-alloc length check
// in PeerBucket.Accept (which rejects len(pub) != 32 before any map lookup):
// a short or long key cannot be a valid Ed25519 key (ed25519.PublicKeySize == 32)
// and must not silently truncate into the registry.
var ErrDirectoryBadPubKey = errors.New("identity: directory public key is not 32 bytes")

// ErrDirectoryBadPQPubKey is returned by RegisterPQ (ADR-0037) when the
// supplied ML-DSA-65 public key is nil. A nil PQ pubkey cannot be a valid
// ML-DSA-65 verification key (mldsa.Verify rejects a nil public key)
// and must not silently register as a usable binding. The Directory stores the
// *mldsa.PublicKey by pointer (the filippo.io/mldsa type is a heap struct,
// not a value type — unlike the 32-byte ed25519.PublicKey slice); the pointer
// is copied into the registry so the Directory owns an independent reference
// (the caller may drop its pointer after RegisterPQ returns; the
// mldsa.PublicKey itself is immutable post-derivation).
var ErrDirectoryBadPQPubKey = errors.New("identity: directory ML-DSA-65 public key is nil")

// Directory is the concurrency-safe originNodeID -> originPub registry the
// receiving socket queries between envelope.Open and the inner origin
// VerifyCRDTFrame. The capnp CRDTDeltaEvent carries originNodeID [16]byte but
// no pubkey field, so the receiver cannot verify the inner origin signature
// without resolving originNodeID to the origin's Ed25519 public key
// out-of-band. The Directory is that out-of-band resolution: peers are
// pre-provisioned at deploy, and the receiver's hot path is a read-only
// Lookup.
//
// ADR-0037: the Directory carries the origin's ML-DSA-65 public key alongside
// the classical Ed25519 key. Under --hybrid-verify a hybrid frame's receiver
// resolves originNodeID to both pubkeys via LookupBoth and feeds both to
// VerifyBatchHybrid. The classical Register and Lookup stay byte-identical;
// a non-PQ-provisioned peer falls back to the classical-only verify path.
// The PQ pubkey is a separate map (mPQ) keyed by the same [16]byte
// originNodeID; the two maps are independent so a peer that registers only
// the classical key (the default before ADR-0037) leaves mPQ unpopulated for
// that nodeID. LookupBoth returns (edPub, nil, true) and the hybrid verify
// rejects the nil pqPub (the strict mode from ADR-0036). RegisterPQ and
// LookupBoth are the new siblings for PQ provisioning. The PQ provisioning is
// out-of-band (the Directory does not carry the ML-DSA-65 pubkey on the wire;
// only the originNodeID [16] rides the wire; the receiver resolves nodeID to
// both pubkeys via the Directory — the same OOB model the classical verify
// uses).
//
// Concurrency: a sync.RWMutex guards a plain map. The directory is
// pre-provisioned (writes are rare, deploy-time), while the receiver's hot
// path is read-dominated (one Lookup per accepted frame), so an RWMutex gives
// cheap concurrent reads with deterministic semantics. sync.Map is optimized
// for the write-rare/read-mostly case too, but its opaque internals make
// deterministic test iteration harder and it offers no advantage here: the
// registry is bounded (one entry per peer) and never unbounded-grown, so the
// map-never-shrinks concern that motivates sync.Map does not apply. RWMutex
// is the simpler, deterministic primitive.
//
// This is a new mutable surface. It is not the AWS-LC hedged stub
// (aws_lc_hedged_stub.go, build-tag-gated panic) and it does not touch
// VerifyCRDTFrame or RejectSmallOrderKey. It imports circl ed25519 (for the
// ed25519.PublicKey type) and filippo.io/mldsa (for the *mldsa.PublicKey type)
// and the standard library only.
type Directory struct {
	mu sync.RWMutex
	m  map[[16]byte]ed25519.PublicKey
	// mPQ is the ADR-0037 parallel map carrying the origin's ML-DSA-65 public
	// key, keyed by the same [16]byte originNodeID as m. It is independent from
	// m so a peer that registered only the classical key (the default before
	// ADR-0037) leaves mPQ unpopulated for that nodeID; LookupBoth returns a
	// nil pqPub (the hybrid verify rejects — the strict mode). The two maps
	// share one RWMutex (writes are rare deploy-time; the read path takes the
	// read lock once for both). A nil *mldsa.PublicKey indicates the origin is not
	// PQ-provisioned; ADR-0037 uses static provisioning rather than directory gossip.
	mPQ map[[16]byte]*mldsa.PublicKey
}

// NewDirectory returns a ready, empty Directory.
func NewDirectory() *Directory {
	return &Directory{
		m:   make(map[[16]byte]ed25519.PublicKey),
		mPQ: make(map[[16]byte]*mldsa.PublicKey),
	}
}

// Register binds an originNodeID to its Ed25519 public key. It rejects a key
// whose length is not 32 (the zero-alloc length check mirroring
// PeerBucket.Accept): a short or long key cannot be a valid Ed25519 key and
// must not silently truncate. The key is copied into a fixed 32-byte buffer
// so the Directory owns an independent canonical copy (the caller may mutate
// or discard its slice after Register returns).
//
// Register is safe for concurrent use. Re-registering an existing nodeID
// overwrites the prior binding (a key-rotation deploy concern); the receiver
// hot path never writes, so a concurrent Lookup observes a consistent
// pre- or post-rotation key, never a torn one.
func (d *Directory) Register(nodeID [16]byte, pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return ErrDirectoryBadPubKey
	}
	canonical := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(canonical, pub)
	d.mu.Lock()
	d.m[nodeID] = canonical
	d.mu.Unlock()
	return nil
}

// Lookup resolves an originNodeID to its Ed25519 public key. It returns
// (pub, true) on a hit and (nil, false) on a miss. A miss is a verdict on the
// receiver's hot path (DropVerify: the receiver cannot verify an inner origin
// signature for an unknown origin), never a panic. Lookup is safe for
// concurrent use; it takes the read lock so concurrent Lookups do not block
// each other.
func (d *Directory) Lookup(nodeID [16]byte) (ed25519.PublicKey, bool) {
	d.mu.RLock()
	pub, ok := d.m[nodeID]
	d.mu.RUnlock()
	return pub, ok
}

// RegisterPQ binds an originNodeID to its ML-DSA-65 public key — the ADR-0037
// sibling of Register, provisioning the hybrid-SIGN verify (under
// --hybrid-verify a hybrid frame's receiver resolves originNodeID to both
// pubkeys via LookupBoth). It rejects a nil pqPub (a nil key cannot be a
// valid ML-DSA-65 verification key — mldsa.Verify rejects a nil pk; the same
// zero-alloc guard Register applies to a non-32-byte classical key). The
// *mldsa.PublicKey pointer is stored verbatim (the mldsa.PublicKey is an
// immutable heap struct post-derivation — the caller's pointer is safe to
// share; the Directory does not clone the pointed-to struct, unlike Register's
// 32-byte canonical copy, because mldsa.PublicKey is not a value slice the
// caller can mutate).
//
// RegisterPQ is independent from Register: a peer that registered only the
// classical key (Register, the default before ADR-0037) leaves mPQ unpopulated
// for that nodeID; LookupBoth returns (edPub, nil, true) and the hybrid verify
// rejects (the nil-pqPub strict mode from ADR-0036). A peer that registers
// both (Register then RegisterPQ) is hybrid-verify-ready. Re-registering an
// existing nodeID overwrites the prior PQ binding (a key-rotation deploy
// concern; the receiver hot path never writes, so a concurrent LookupBoth
// observes a consistent pre- or post-rotation key).
//
// RegisterPQ is safe for concurrent use. It does not touch the classical m
// map (the two maps are independent; a classical-only peer's Register calls
// and a hybrid peer's RegisterPQ calls never contend on the same key space).
func (d *Directory) RegisterPQ(nodeID [16]byte, pqPub *mldsa.PublicKey) error {
	if pqPub == nil {
		return ErrDirectoryBadPQPubKey
	}
	d.mu.Lock()
	d.mPQ[nodeID] = pqPub
	d.mu.Unlock()
	return nil
}

// LookupBoth resolves an originNodeID to both its Ed25519 and ML-DSA-65 public
// keys — the ADR-0037 sibling of Lookup, the provisioning seam the receiver's
// hybrid verify calls. It returns (edPub, pqPub, ok): ok is true iff the
// classical key is registered (the PQ key may be nil — a peer that registered
// only the classical key is "classical-provisioned but not PQ-provisioned";
// the hybrid verify rejects a nil pqPub via the ADR-0036 strict mode). A
// classical miss (edPub nil, ok false) is a DropVerify on the receiver's hot
// path (the same verdict a classical Lookup miss produces — the receiver
// cannot verify an unknown origin's signature under any seam).
//
// The two lookups share one RLock (the read path takes the read lock once for
// both maps; the maps are guarded by the same RWMutex). A peer that registered
// both keys returns (edPub, pqPub, true) — hybrid-verify-ready. A peer that
// registered only the classical key returns (edPub, nil, true) — the hybrid
// verify then rejects via the nil-pqPub strict mode. A peer that registered
// only the PQ key (RegisterPQ without Register) returns (nil, pqPub, false)
// because ok is sourced exclusively from the classical map d.m, so a PQ-only
// peer is treated as an identity miss at HandleHybridFrame. Classical-first
// registration is therefore required.
//
// LookupBoth is safe for concurrent use; it takes the read lock so concurrent
// LookupBoth calls do not block each other (the same RWMutex discipline Lookup
// uses). It does not replace Lookup — the classical-only verify path (the
// production default, --hybrid-verify=false) still calls Lookup (byte-identical
// to the classical path); LookupBoth is the new seam the hybrid verify path
// calls.
func (d *Directory) LookupBoth(nodeID [16]byte) (edPub ed25519.PublicKey, pqPub *mldsa.PublicKey, ok bool) {
	d.mu.RLock()
	edPub, ok = d.m[nodeID]
	pqPub = d.mPQ[nodeID]
	d.mu.RUnlock()
	return edPub, pqPub, ok
}

// Len returns the number of registered origins. It is a test/diagnostic
// accessor; it takes the read lock for a consistent count.
func (d *Directory) Len() int {
	d.mu.RLock()
	n := len(d.m)
	d.mu.RUnlock()
	return n
}
