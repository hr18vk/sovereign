package identity

import (
	"errors"
	"sync"

	"filippo.io/mldsa"
	"github.com/cloudflare/circl/sign/ed25519"
)

// ErrDirectoryBadPubKey is returned by Register when the supplied public key
// is not a valid 32-byte Ed25519 key. It mirrors 3.1's zero-alloc length
// check (PeerBucket.Accept rejects len(pub) != 32 before any map lookup): a
// short/long key cannot be a valid Ed25519 key (ed25519.PublicKeySize == 32)
// and MUST NOT silently truncate into the registry.
var ErrDirectoryBadPubKey = errors.New("identity: directory public key is not 32 bytes")

// ErrDirectoryBadPQPubKey is returned by RegisterPQ (Day 32, ADR-0037) when the
// supplied ML-DSA-65 public key is nil. A nil PQ pubkey cannot be a valid
// ML-DSA-65 verification key (mldsa.Verify rejects a nil pk at pq_mldsa.go:133)
// and MUST NOT silently register as a usable binding. The Directory stores the
// *mldsa.PublicKey by pointer (the filippo.io/mldsa type is a heap struct, NOT
// a value type — unlike the 32-byte ed25519.PublicKey slice); the pointer is
// copied into the registry so the Directory owns an independent reference (the
// caller may drop its pointer after RegisterPQ returns; the mldsa.PublicKey
// itself is immutable post-derivation).
var ErrDirectoryBadPQPubKey = errors.New("identity: directory ML-DSA-65 public key is nil")

// Directory is the concurrency-safe originNodeID -> originPub registry the
// receiving socket queries between envelope.Open and the inner origin
// VerifyCRDTFrame. It is the GAP-3 surface this track introduces: the FROZEN
// capnp CRDTDeltaEvent carries originNodeID [16]byte but NO pubkey field, so
// the receiver cannot verify the inner origin signature without resolving
// originNodeID to the origin's Ed25519 public key out-of-band. The Directory
// is that out-of-band resolution: peers are pre-provisioned at deploy (a
// config concern, not a 3.5 concern), and the receiver's hot path is a
// read-only Lookup.
//
// Day 32 (ADR-0037): the Directory GROWS to carry the origin's ML-DSA-65
// public key ALONGSIDE the classical Ed25519 key (the hybrid-SIGN moat's
// provisioning layer — under --hybrid-verify a hybrid frame's receiver
// resolves originNodeID -> BOTH pubkeys via LookupBoth + feeds both to
// VerifyBatchHybrid). The classical Register/Lookup stay byte-identical (a
// non-PQ-provisioned peer falls back to the classical-only verify path —
// backward-compat; the SAME opt-in model Day-31's hybrid verify uses). The PQ
// pubkey is a SEPARATE map (mPQ) keyed by the SAME [16]byte originNodeID; the
// two maps are independent so a peer that registers the classical key only
// (the pre-Day-32 default) LookupBoth returns (edPub, nil, true) — the hybrid
// verify then rejects (the nil-pqPub STRICT mode, the Day-31 contract carried
// forward). RegisterPQ is the NEW sibling; LookupBoth is the NEW sibling that
// returns both. The PQ provisioning is OUT-OF-BAND (the Directory does NOT
// carry the ML-DSA-65 pubkey ON the wire — only the originNodeID [16] rides
// the wire; the receiver resolves nodeID -> BOTH pubkeys via the Directory;
// the SAME OOB model the classical verify uses — directory.go:20 comment).
//
// Concurrency: a sync.RWMutex guards a plain map. The directory is
// pre-provisioned (writes are rare, deploy-time), while the receiver's hot
// path is read-dominated (one Lookup per accepted frame), so an RWMutex gives
// cheap concurrent reads with deterministic semantics. sync.Map is optimized
// for the write-rare/read-mostly case too, but its opaque internals make
// deterministic test iteration harder and it offers no advantage here: the
// registry is bounded (one entry per peer) and never unbounded-grown, so the
// map-never-shrinks concern that motivates sync.Map does not apply. RWMutex
// is the simpler, deterministic primitive (the ruthless-pragmatism call).
//
// This is a NEW mutable surface. It is NOT the AWS-LC hedged stub
// (aws_lc_hedged_stub.go, build-tag-gated panic) and it does NOT touch
// VerifyCRDTFrame or RejectSmallOrderKey. It imports circl ed25519 (for the
// ed25519.PublicKey type) + filippo.io/mldsa (for the *mldsa.PublicKey type,
// Day-32) and the standard library only.
type Directory struct {
	mu sync.RWMutex
	m  map[[16]byte]ed25519.PublicKey
	// mPQ is the Day-32 (ADR-0037) parallel map carrying the origin's ML-DSA-65
	// public key, keyed by the SAME [16]byte originNodeID as m. It is INDEPENDENT
	// from m so a peer that registered ONLY the classical key (the pre-Day-32
	// default) leaves mPQ unpopulated for that nodeID -> LookupBoth returns a nil
	// pqPub (the hybrid verify rejects — the STRICT mode). The two maps share the
	// ONE RWMutex (writes are rare deploy-time; the read path takes the read lock
	// once for both). A nil *mldsa.PublicKey is the "not provisioned" sentinel
	// (the honest NOT-YET — the OOB provisioning is a future directory-gossip
	// fork; Day 32 assumes a statically-provisioned directory).
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
// whose length is not 32 (the zero-alloc length check mirroring 3.1's
// PeerBucket.Accept): a short/long key cannot be a valid Ed25519 key and
// MUST NOT silently truncate. The key is copied into a fixed 32-byte buffer
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

// RegisterPQ binds an originNodeID to its ML-DSA-65 public key — the Day-32
// (ADR-0037) sibling of Register, provisioning the hybrid-SIGN verify
// (under --hybrid-verify a hybrid frame's receiver resolves originNodeID ->
// BOTH pubkeys via LookupBoth). It rejects a nil pqPub (a nil key cannot be a
// valid ML-DSA-65 verification key — mldsa.Verify rejects a nil pk; the SAME
// zero-alloc guard Register applies to a non-32-byte classical key). The
// *mldsa.PublicKey pointer is stored verbatim (the mldsa.PublicKey is an
// immutable heap struct post-derivation — the caller's pointer is safe to
// share; the Directory does NOT clone the pointed-to struct, unlike Register's
// 32-byte canonical copy, because mldsa.PublicKey is not a value slice the
// caller can mutate).
//
// RegisterPQ is INDEPENDENT from Register: a peer that registered ONLY the
// classical key (Register, the pre-Day-32 default) leaves mPQ unpopulated for
// that nodeID -> LookupBoth returns (edPub, nil, true) -> the hybrid verify
// rejects (the nil-pqPub STRICT mode, the Day-31 contract carried forward). A
// peer that registers BOTH (Register THEN RegisterPQ) is hybrid-verify-ready.
// Re-registering an existing nodeID overwrites the prior PQ binding (a
// key-rotation deploy concern; the receiver hot path never writes, so a
// concurrent LookupBoth observes a consistent pre- or post-rotation key).
//
// RegisterPQ is safe for concurrent use. It does NOT touch the classical m
// map (the two maps are independent; a classical-ONLY peer's Register calls +
// a hybrid peer's RegisterPQ calls never contend on the same key space).
func (d *Directory) RegisterPQ(nodeID [16]byte, pqPub *mldsa.PublicKey) error {
	if pqPub == nil {
		return ErrDirectoryBadPQPubKey
	}
	d.mu.Lock()
	d.mPQ[nodeID] = pqPub
	d.mu.Unlock()
	return nil
}

// LookupBoth resolves an originNodeID to BOTH its Ed25519 + ML-DSA-65 public
// keys — the Day-32 (ADR-0037) sibling of Lookup, the provisioning seam the
// receiver's hybrid verify calls. It returns (edPub, pqPub, ok): ok is true iff
// the classical key is registered (the PQ key MAY be nil — a peer that
// registered ONLY the classical key is "classical-provisioned but not
// PQ-provisioned"; the hybrid verify rejects a nil pqPub via the Day-31
// STRICT mode). A classical miss (edPub nil, ok false) is a DropVerify on the
// receiver's hot path (the SAME verdict a classical Lookup miss produces — the
// receiver cannot verify an unknown origin's signature under ANY seam).
//
// The two lookups share ONE RLock (the read path takes the read lock once for
// both maps; the maps are guarded by the SAME RWMutex). A peer that registered
// BOTH keys returns (edPub, pqPub, true) — hybrid-verify-ready. A peer that
// registered ONLY the classical key returns (edPub, nil, true) — the hybrid
// verify then rejects (the nil-pqPub STRICT mode). A peer that registered ONLY
// the PQ key (RegisterPQ without Register — an UNSUPPORTED posture the deploy
// discipline forbids; the classical-register-first ordering is documented
// below) returns (nil, pqPub, FALSE) — the `ok` is sourced EXCLUSIVELY from the
// classical map (d.m), so a RegisterPQ-only peer reports ok=false (a Directory
// miss), NOT ok=true as a prior draft of this doc claimed (the /verify audit
// caught the doc/code mismatch: the code returns ok from d.m, so a PQ-only
// peer is an identity miss, not a both-verify reject). The classical verify
// rejects a PQ-only peer (no edPub, ok=false → DropVerify as a Directory
// miss); the hybrid verify also rejects it (ok=false → DropVerify as a
// Directory miss at HandleHybridFrame step 3, NOT a both-verify reject). The
// classical-register-first ordering is the documented deploy discipline.
//
// LookupBoth is safe for concurrent use; it takes the read lock so concurrent
// LookupBoth calls do not block each other (the SAME RWMutex discipline Lookup
// uses). It does NOT replace Lookup — the classical-only verify path (the
// production default, --hybrid-verify=false) still calls Lookup (byte-identical
// Day-30/31); LookupBoth is the NEW seam the hybrid verify path calls.
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
