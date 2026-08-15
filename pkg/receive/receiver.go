// Package receive implements the INGRESS wire listener that binds the Phase-3
// admission gate stack over a real receiving socket. It is the composition
// track (Track 3.5): the LAST gate-stack module (engine.Join via
// engine.ApplyCRDTDeltaEvent) gains its first production caller here.
//
// Track 12.1 (ADR-0005) closes the §2.X1(a) wiring gap (ADR-0003 §8 Gap 4): the
// edge-triggered epoll ingress loop that drives the 12.0 KernelFanout's
// SO_REUSEPORT socket group into HandleFrame lives in ingress_epoll.go, GATED
// by the `ebpf_kernel` build tag. The DEFAULT build EXCLUDES it — HandleFrame's
// gate stack (below) is byte-identical to HEAD; the wiring is ABOVE HandleFrame
// (delivery), NOT inside it. Under -tags ebpf_kernel, EpollIngress.Serve drives
// the eBPF-pinned fds, reassembles each datagram to frame boundaries, and calls
// HandleFrame per frame — the seam in the ENGINE, not in a test file.
//
// The receiver wires unfoldsocket-reassembled frames through the proven
// ordering (re-derived on this box from the gate packages, not copied from
// probe prose):
//
//	[socket read -> length-prefixed frame reassembler (GAP-2)]
//	  -> UnmarshalRelayEnvelope(frameBytes)                # parse header, no crypto
//	  -> PeerBucket.Accept(lastHopRelayPub, dotCounter)    # 3.1, ~36 ns; cheap
//	  -> if Keep: IngressHLCScalarCap.Admit(lastHopWallUSec, dotCounter)  # 3.0
//	  -> if accept: RelayEnvelope.Open(MaxHopsForBudget(budget))          # 3.2
//	  -> if open ok: Directory.Lookup(originNodeID) -> originPub           # GAP-3
//	  -> identity.VerifyCRDTFrame(originPub, innerWire, originSig)        # 1.1
//	  -> if verify ok: engine.ApplyCRDTDeltaEvent(innerWire) -> Join       # first prod caller
//
// The cheap gates (3.1 rate, 3.0 clock, 3.2 depth) run BEFORE the expensive
// ~60 us Ed25519 Verify (1.1): a forged deep / rate / clock frame is dropped
// in nanoseconds, zero Verifies — the §1.D3.E DoS defense. This ordering is
// EXECUTED-instrumented (G3.5.e), not prose-asserted (F2): a counting Verify
// hook proves zero Verify calls fire on each cheap-reject path.
package receive

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"time"

	capnp "capnproto.org/go/capnp/v3"
	capnp_schema "github.com/hr18vk/supremum/api/capnp/api/capnp"
	"github.com/hr18vk/supremum/pkg/admission"
	"github.com/hr18vk/supremum/pkg/attribution"
	"github.com/hr18vk/supremum/pkg/clock"
	"github.com/hr18vk/supremum/pkg/identity"
	eng "github.com/hr18vk/supremum/pkg/sync"
)

// frameLenPrefixSize is the size of the length prefix the wire listener
// frames every envelope with (GAP-2). The on-the-wire shape the receiver
// reads is [uint32 frameLen][envelope bytes...]: a 4-byte big-endian frame
// length, then exactly frameLen envelope bytes. The prefix is a pkg/receive
// framing concern, NOT an envelope concern — envelope.Marshal stays a pure
// envelope (no outer-length prefix); the prefix belongs to the wire listener
// and is emitted by the relay-forward path before SendPinnedHeap.
//
// Big-endian is chosen for the prefix so a human can read it in a packet
// capture (network-byte-order convention) and so a future TCP/Unix socket
// listener is byte-order-stable across mixed-endian peers. The envelope's
// OWN header fields stay little-endian (envelope.go framing); only the
// outer pkg/receive prefix is big-endian.
const frameLenPrefixSize = 4

// maxFrameSize is the upper bound on a single framed envelope the receiver
// will reassemble. It is a defensive cap against a forged length prefix
// claiming a multi-GB frame (the reassembly buffer would grow unbounded). It
// is a buffer-bound, sized generously over the largest honest envelope (a
// 15-hop relay chain carrying a 120-byte inner wire is ~1.6 KB; 16 MiB
// admits envelopes with megabyte-scale inner capnp frames, far beyond any
// honest CRDT delta).
const maxFrameSize = 16 << 20 // 16 MiB

// Verdict is the typed drop/accept decision HandleFrame returns. A forged
// frame is a Verdict, never a crash: the receiver NEVER panics on adversarial
// input (the chaos supervisor's SIGSEGV-isolation path is a different safety
// net; 3.5's job is to not produce the SIGSEGV). Each non-Accept verdict
// names the gate that dropped the frame so the caller can attribute the drop.
type Verdict int

const (
	// Accept means the frame crossed every gate and the engine joined the
	// CRDT delta (ApplyCRDTDeltaEvent returned nil).
	Accept Verdict = iota
	// DropMalformed means the frame did not parse as a relay envelope or the
	// inner wire did not decode as a CRDTDeltaEvent (the cheap pre-Open
	// capnp decode failed). Dropped before any crypto.
	DropMalformed
	// DropRate means the 3.1 PeerBucket rate cap dropped the frame (the
	// last relay's per-peer budget was exhausted). Dropped before any
	// crypto; zero Open Verifies.
	DropRate
	// DropClock means the 3.0 IngressHLCScalarCap clock cap dropped the
	// frame (the last hop's physical timestamp was too far in the future).
	// Dropped before any crypto; zero Open Verifies.
	DropClock
	// DropDepth means the 3.2 envelope.Open depth check dropped the frame
	// (the hop count exceeded the budget bound). Dropped before any crypto;
	// zero Open Verifies.
	DropDepth
	// DropVerify means a cryptographic check failed: an outer relay hop
	// (Open), the inner origin (VerifyCRDTFrame), an unknown origin
	// (Directory miss), or ApplyCRDTDeltaEvent rejected the wire integrity.
	DropVerify
)

// String returns the verdict name for logs/metrics. It is the human-readable
// form of the typed drop decision.
func (v Verdict) String() string {
	switch v {
	case Accept:
		return "Accept"
	case DropMalformed:
		return "DropMalformed"
	case DropRate:
		return "DropRate"
	case DropClock:
		return "DropClock"
	case DropDepth:
		return "DropDepth"
	case DropVerify:
		return "DropVerify"
	default:
		return fmt.Sprintf("Verdict(%d)", int(v))
	}
}

// AcceptVerdict is the result of HandleFrame: the typed verdict plus the
// reason (the gate error or a human-readable drop cause) for attribution.
// Reason is empty on Accept.
type AcceptVerdict struct {
	Verdict Verdict
	Reason  error
}

// Receiver is the wire listener that runs the gate-stack composition over a
// reassembled envelope frame. It holds the bound gate objects (the 3.1
// PeerBucket, the 3.0 IngressHLCScalarCap, the 3.2 envelope bound, the GAP-3
// identity Directory) and the FROZEN CRDT engine (called via
// ApplyCRDTDeltaEvent — the first production caller). It is safe for
// concurrent use: every gate it composes is concurrency-safe (PeerBucket is
// sharded-mutex, IngressHLCScalarCap is read-only-on-clock, Open is
// immutable-envelope, Directory is RWMutex, ApplyCRDTDeltaEvent is the
// FROZEN engine's own race-proven path).
//
// wallClock is the receiver's own WallClock reference (the same clock the
// IngressHLCScalarCap binds). It is read for the 0-hop origin-frame path,
// whose physical timestamp is not on the wire (the envelope carries no
// origin wall time — only the relay hops carry WallUSec). The relay path
// (hops > 0) is the load-bearing one this track composes; the 0-hop path
// uses the local clock now as the physical timestamp (a carry-forward: the
// origin's physical time on the wire is a future track).
type Receiver struct {
	bucket    *admission.PeerBucket
	cap       *clock.IngressHLCScalarCap
	wallClock clock.WallClock
	dir       *identity.Directory
	engine    *eng.DeltaCRDTEngine
	budget    int64 // nanoseconds, injected (deploy config); the 3.2 hop-bound dividend
	maxHops   int   // MaxHopsForBudget(budget), computed once at construction

	// onClockAdvance is the Day-8.5 receive-seam hook for the foreign-advance
	// seed fix. A peer-driven Join (ApplyCRDTDeltaEvent/ApplyCRDTDeltaBatch)
	// calls AdvanceLamportTo inside the FROZEN engine (crdt.go:1028), jumping
	// the Lamport clock with NO WAL record — the seed-break. On a successful
	// Accept the hook fires ONLY when the frame actually advanced the clock
	// (post > pre, captured at function entry) and records the post-Accept
	// high-water so the WAL is the complete clock history and the recovery
	// seed is exact. A WAL-append/fsync error is LOGGED loudly (NOT swallowed,
	// NOT a 503 — a foreign Join is irreversible; see ADR-0013 §7(h) for the
	// origin/receive asymmetry). Nil by default (the in-memory research path
	// never sets it → FROZEN-safe no-op); the durability Bridge sets it via
	// SetClockAdvanceRecorder to wal.AppendClockAdvance. See ADR-0013 §7 for
	// the slight over-record caveat (post-Accept high-water vs the exact
	// foreign-but-pre-mint counter).
	onClockAdvance func(uint64) error

	// hybridVerify is the Day-31 (ADR-0036) opt-IN seam that switches the two
	// signature-verify call sites (HandleFrame :350 + HandleBatchFrame :586)
	// from the classical-only identity.VerifyCRDTFrame to the hybrid
	// identity.VerifyCRDTFrame_Hybrid (Ed25519 + ML-DSA-65, BOTH-required,
	// defense-in-depth). false (the DEFAULT) keeps the receive path on the
	// classical seam — byte-identical Day-30 (the production default stays
	// classical-only; the hybrid is an ADD, NOT a replace). Set via
	// SetHybridVerify once at construction; nil-safe (the
	// SetClockAdvanceRecorder precedent — a default false is the byte-identical
	// prior-day posture). Day 32 (ADR-0037) EXTENDS this seam to the
	// HandleHybridFrame path: under --hybrid-verify a hybrid frame's BOTH sigs
	// are verified by VerifyBatchHybrid (the SAME both-required gate, fed the
	// 120-byte SHAKE256 pad); under the DEFAULT (false) a hybrid frame is
	// REJECTED (the symmetric STRICT mode — a non-hybrid-verify receiver cannot
	// fall back to the classical single-sig verify on a BOTH-sig frame). The
	// byte-identical-Day-31 default is preserved because --hybrid-sign=false
	// (the send-side DEFAULT) produces NO hybrid frame on the production path.
	// A nil pqPub (the Directory does not yet carry a peer's ML-DSA-65 pubkey)
	// is a DropVerify under --hybrid-verify (the STRICT mode — the Day-31
	// contract carried forward to the grown Directory.LookupBoth).
	hybridVerify bool

	// onHybridAccept is the Day-32 (ADR-0037) opt-IN disclosure seam: a
	// non-nil callback fires on every hybrid frame ACCEPTED by the BOTH-verify
	// gate (HandleHybridFrame step 6) — the operator-VISIBLE proof the moat is
	// in USE, not just wired (the HybridFrameAccepted counter, the 23rd SSoT
	// IF shipped). nil by default (the SetClockAdvanceRecorder precedent — a
	// default nil is the byte-identical prior-day posture; the receiver's
	// gate-stack behavior is UNCHANGED by the counter). Set via
	// SetHybridAcceptReporter once at construction; the production node wires
	// it to telemetry.HybridFrameAccepted.Inc (the SetStratifiedFallbackReporter
	// + SetPQHandshakeReporter precedent — the counter is the DISCLOSURE, not
	// the mechanism). The callback is read on the readLoop goroutine;
	// SetHybridAcceptReporter is called once at construction before the
	// readLoop starts (the single-writer-before-reader discipline).
	onHybridAccept func()
}

// NewReceiver binds the gate objects and the FROZEN engine into a Receiver.
// budget is the deploy-time admission budget (nanoseconds) the 3.2
// MaxHopsForBudget transform converts to a max hop-count; it is INJECTED,
// never baked into source (the forbidden-budget tooth). wallClock is the
// WallClock the IngressHLCScalarCap binds (the receiver holds its own
// reference for the 0-hop physical-timestamp path). The receiver computes
// maxHops once at construction and reuses it on every HandleFrame (the O(1)
// depth check reads it without re-deriving).
func NewReceiver(bucket *admission.PeerBucket, cap *clock.IngressHLCScalarCap, wallClock clock.WallClock, dir *identity.Directory, engine *eng.DeltaCRDTEngine, budget int64) *Receiver {
	return &Receiver{
		bucket:    bucket,
		cap:       cap,
		wallClock: wallClock,
		dir:       dir,
		engine:    engine,
		budget:    budget,
		maxHops:   attribution.MaxHopsForBudget(time.Duration(budget)),
	}
}

// SetClockAdvanceRecorder installs the Day-8.5 receive-seam hook (the
// foreign-advance seed fix). After a successful Accept, the Receiver fires the
// recorder with the engine's post-Join LamportCounter() so the WAL records the
// peer-driven clock advance. A nil recorder (the default) leaves the Receiver
// FROZEN-behavior-identical: the in-memory research path never records, so the
// hot path is untouched. The durability Bridge wires this to
// wal.AppendClockAdvance; the production node sets it only when --wal-path is
// set (durability ON). Set once at construction before the accept loop starts
// (the production boot path is sequential; the recorder is not mutated
// concurrently with HandleFrame).
func (r *Receiver) SetClockAdvanceRecorder(fn func(uint64) error) {
	r.onClockAdvance = fn
}

// SetHybridVerify installs the Day-31 (ADR-0036) opt-IN seam that switches the
// two signature-verify call sites (HandleFrame + HandleBatchFrame) from the
// classical-only identity.VerifyCRDTFrame to the hybrid
// identity.VerifyCRDTFrame_Hybrid (Ed25519 + ML-DSA-65, BOTH-required,
// defense-in-depth). enable=false (the DEFAULT) keeps the receive path on the
// classical seam — byte-identical Day-30 (the hybrid is an ADD, NOT a replace).
// Set once at construction before the accept loop starts (the production boot
// path is sequential; the flag is not mutated concurrently with HandleFrame).
// The hybrid SIGN (a frame carries BOTH sigs) is a FUTURE fork — the verify
// seam alone is the load-bearing wiring this flag arms; a classical-only frame
// under --hybrid-verify is REJECTED (the STRICT mode). See ADR-0036.
func (r *Receiver) SetHybridVerify(enable bool) {
	r.hybridVerify = enable
}

// SetHybridAcceptReporter installs the Day-32 (ADR-0037) disclosure seam: a
// non-nil callback fires on every hybrid frame ACCEPTED by the BOTH-verify
// gate (HandleHybridFrame step 6). The production node wires it to
// telemetry.HybridFrameAccepted.Inc (the 23rd SSoT counter — the operator-
// VISIBLE proof the moat is in USE). A nil reporter (the default) leaves the
// Receiver FROZEN-behavior-identical: the counter does not fire, the gate
// stack is UNCHANGED (the counter is the DISCLOSURE, not the mechanism — the
// SetStratifiedFallbackReporter precedent). Set once at construction before
// the accept loop starts (the production boot path is sequential; the reporter
// is not mutated concurrently with HandleHybridFrame). See ADR-0037 §5.
func (r *Receiver) SetHybridAcceptReporter(fn func()) {
	r.onHybridAccept = fn
}

// readGateFields is the cheap pre-Open read of the two gate fields the 3.1
// rate gate and 3.0 clock gate need (dotCounter, originNodeID). On a v3
// envelope (Track 3.6) it is an O(1) HEADER read — two fixed-offset slice
// reads off the parsed envelope's mirror fields, NO capnp decode — so the
// reject-path floor is tens of ns, not the ~1 us capnp.Unmarshal+
// ReadRootCRDTDeltaEvent the v2 path paid (the 3.5b-measured ~300x ratio's
// floor). On a v2 envelope (forward-compat, G3.6.e) the mirrors are absent
// from the header, so it falls back to a capnp decode of the inner wire (the
// v2 frame carries the gate fields only inside the inner capnp) — the v2
// path keeps the v2 cost; the v3 path is the lift.
//
// It returns (dotCounter, originNodeID, error). A v2 capnp-decode failure is
// a DropMalformed verdict (the inner wire is not a CRDTDeltaEvent at all). A
// v3 header read never fails (the mirrors are fixed-offset slices already
// validated for length by UnmarshalRelayEnvelope).
func readGateFields(env *attribution.RelayEnvelope) (dotCounter uint64, originNodeID [16]byte, err error) {
	if env.Version() == attribution.RelayEnvelopeVersion() {
		// v3: O(1) header read. The mirrors were read off the wire by
		// UnmarshalRelayEnvelope (fixed offsets [72:80] and [80:96]); no
		// capnp decode, no allocation. This is the reject-path floor.
		return env.DotCounter(), env.OriginNodeID(), nil
	}
	// v2 forward-compat: the header carries no mirrors, so decode the inner
	// capnp for the gate fields (the v2 cost the v3 lift eliminates). A
	// decode failure is a DropMalformed (the inner wire is not a
	// CRDTDeltaEvent). This branch is the honest v2 fallback, NOT a silent
	// fall-through to zero fields (the C5 failure mode): the version is an
	// explicit dispatch and the gate fields come from the capnp decode.
	return readGateFieldsFromCapnp(env.InnerWire())
}

// readGateFieldsFromCapnp is the v2-fallback capnp decode of the gate fields
// (dotCounter, originNodeID) from the inner wire. It is the path the v3 lift
// REPLACES on the reject path: a v3 frame never reaches it (the header
// mirrors are O(1)); only a v2 frame (forward-compat) pays it. It is retained
// (not deleted) so a v2 peer's frames still cross the cheap gates. It is also
// the decode the accept-path cross-check reuses (crossCheckGateFields) so the
// v2 fallback and the cross-check share one decode path, not two.
func readGateFieldsFromCapnp(innerWire []byte) (dotCounter uint64, originNodeID [16]byte, err error) {
	msg, derr := capnp.Unmarshal(innerWire)
	if derr != nil {
		return 0, originNodeID, fmt.Errorf("receive: decode CRDTDeltaEvent for gate fields: unmarshal: %w", derr)
	}
	defer msg.Release()
	ev, rerr := capnp_schema.ReadRootCRDTDeltaEvent(msg)
	if rerr != nil {
		return 0, originNodeID, fmt.Errorf("receive: decode CRDTDeltaEvent for gate fields: read root: %w", rerr)
	}
	originBytes, oerr := ev.OriginNodeID()
	if oerr != nil {
		return 0, originNodeID, fmt.Errorf("receive: read originNodeID: %w", oerr)
	}
	if len(originBytes) != 16 {
		return 0, originNodeID, fmt.Errorf("receive: originNodeID len %d != 16", len(originBytes))
	}
	copy(originNodeID[:], originBytes)
	return ev.DotCounter(), originNodeID, nil
}

// HandleFrame runs the gate-stack composition over a single reassembled
// envelope frame (frameBytes is a FULL envelope — the length-prefix
// reassembler has already stripped the 4-byte prefix and accumulated the full
// frame). It returns a typed AcceptVerdict; it NEVER panics on adversarial
// input (a forged frame is a Verdict, never a crash).
//
// The ordering is the §3 composition: cheap gates (3.1 rate, 3.0 clock, 3.2
// depth) run BEFORE the expensive ~60 us Ed25519 Verify (1.1), so a forged
// deep / rate / clock frame is dropped in nanoseconds with zero Verifies.
func (r *Receiver) HandleFrame(frameBytes []byte) AcceptVerdict {
	// preAdvance captures the Lamport high-water at function entry — BEFORE the
	// 3.0 clock gate (which itself calls engine.AdvanceLamportTo) and before
	// the Apply/Join. The Day-8.5 receive-seam recorder must fire ONLY when the
	// frame actually advanced the clock past where it started (a stale or
	// duplicate delta whose DotCounter <= the current clock leaves the clock
	// unchanged → no advance → no WAL record). Capturing at entry (not just
	// before Apply) brackets BOTH the clock gate's advance AND Join's advance,
	// so post-pre is the cumulative foreign advance the frame produced.
	preAdvance := r.engine.LamportCounter()

	// 1. Parse the envelope header. No crypto. A malformed frame is a
	//    DropMalformed verdict, never a panic.
	env, err := attribution.UnmarshalRelayEnvelope(frameBytes)
	if err != nil {
		return AcceptVerdict{Verdict: DropMalformed, Reason: err}
	}

	// 2. Read the last hop's relayPub + wallUSec from the parsed envelope
	//    (cheap, before Open). The last hop is the direct sender the
	//    receiver rate-bounds (3.1) and clock-bounds (3.0). A 0-hop
	//    envelope (origin frame, no relays) has no last hop; the rate gate
	//    is skipped (no relay pub to bound) and the clock gate uses the
	//    local clock now (the origin's physical time is not on the wire).
	hops := env.HopCount()
	var lastHopPub [32]byte
	var lastHopWall int64
	if hops > 0 {
		lastHopPub, lastHopWall, err = readLastHop(frameBytes, hops)
		if err != nil {
			return AcceptVerdict{Verdict: DropMalformed, Reason: err}
		}
	}

	// 3. Cheap read of the gate fields (dotCounter, originNodeID). On a v3
	//    frame this is an O(1) HEADER read (two fixed-offset slice reads off
	//    the parsed envelope's mirrors, NO capnp decode) — the Track 3.6 lift
	//    that drops the reject-path floor from ~1 us (capnp decode) to tens of
	//    ns. On a v2 frame (forward-compat) it falls back to a capnp decode of
	//    the inner wire (the v2 cost). Runs BEFORE Open's expensive verify. A
	//    v2 decode failure is a DropMalformed (the inner wire is not a
	//    CRDTDeltaEvent); a v3 header read never fails.
	dotCounter, originNodeID, err := readGateFields(env)
	if err != nil {
		return AcceptVerdict{Verdict: DropMalformed, Reason: err}
	}

	// 4. 3.1 rate gate: PeerBucket.Accept(lastHopRelayPub, dotCounter).
	//    ~36 ns; cheap. The source of pub is the last hop's relayPub; the
	//    source of counter is the capnp DotCounter. A 0-hop frame skips the
	//    rate gate (no relay pub to bound).
	if hops > 0 {
		if r.bucket.Accept(lastHopPub[:], dotCounter) == admission.Drop {
			return AcceptVerdict{Verdict: DropRate, Reason: errors.New("receive: 3.1 rate cap dropped frame (peer budget exhausted)")}
		}
	}

	// 5. 3.0 clock gate: IngressHLCScalarCap.Admit(lastHopWallUSec,
	//    dotCounter). The physical timestamp is the last hop's WallUSec; the
	//    logical is the capnp DotCounter. On accept, 3.0 calls
	//    engine.AdvanceLamportTo itself. A 0-hop frame uses the local clock
	//    now (the origin's physical time is not on the wire).
	var physUSec int64
	if hops > 0 {
		physUSec = lastHopWall
	} else {
		physUSec = r.wallClock.PhysicalNowUSec()
	}
	if !r.cap.Admit(physUSec, dotCounter) {
		return AcceptVerdict{Verdict: DropClock, Reason: errors.New("receive: 3.0 clock cap dropped frame (Byzantine-future physical timestamp)")}
	}

	// 6. 3.2 depth + outer-verify gate: RelayEnvelope.Open(maxHops). O(1)
	//    depth check THEN N outer Verifies — the expensive gate; runs only
	//    after the cheap 3.1/3.0 rejects pass. ErrHopBoundExceeded is a
	//    DropDepth (zero Verifies); ErrVerify is a DropVerify.
	verifiedInner, _, err := env.Open(r.maxHops)
	if err != nil {
		if errors.Is(err, attribution.ErrHopBoundExceeded) {
			return AcceptVerdict{Verdict: DropDepth, Reason: err}
		}
		return AcceptVerdict{Verdict: DropVerify, Reason: fmt.Errorf("receive: 3.2 Open failed: %w", err)}
	}

	// 7. GAP-3: resolve originPub via the identity Directory. A miss is a
	//    DropVerify (the receiver cannot verify an unknown origin).
	originPub, ok := r.dir.Lookup(originNodeID)
	if !ok {
		return AcceptVerdict{Verdict: DropVerify, Reason: fmt.Errorf("receive: identity Directory miss for originNodeID %x", originNodeID)}
	}

	// 8. 1.1 inner origin verify: VerifyCRDTFrame(originPub, innerWire,
	//    originSig). ~60 us; the expensive gate. originSig is ON the
	//    envelope (GAP-1 closed) — not test-computed. A zero originSig
	//    (version-1 envelope) fails here (DropVerify).
	//
	// Day 31 (ADR-0036): --hybrid-verify switches this to the hybrid
	// VerifyCRDTFrame_Hybrid (Ed25519 + ML-DSA-65, BOTH-required). The v1
	// envelope carries ONLY the Ed25519 originSig (NO PQ sig) — so under
	// --hybrid-verify a v1 frame is REJECTED here (the STRICT mode: a hybrid
	// verifier NEVER accepts a classical-only frame; BOTH sigs is the
	// contract). The hybrid SIGN (a frame carries BOTH sigs) is a FUTURE fork
	// — the CRDT-delta wire shape change — disclosed ADR-0036 §6; the verify
	// seam is the load-bearing wiring this fork arms, the sign is the NEXT PQ
	// fork. The Directory does NOT yet carry a peer's ML-DSA-65 pubkey (the
	// honest NOT-YET — the peer-pubkey provisioning is the FUTURE fork), so the
	// hybrid arm passes a nil pqPub → VerifyCRDTFrame_Hybrid returns false (the
	// nil-pqPub reject). This is the byte-identical-Day-30 gate: --hybrid-verify
	// OFF (the DEFAULT) keeps the classical VerifyCRDTFrame seam UNCHANGED.
	originSig := env.OriginSig()
	if r.hybridVerify {
		// Day-31 hybrid verify — BOTH sigs required. The v1 envelope carries NO
		// PQ sig, so this REJECTS (the STRICT mode) until the hybrid-SIGN fork
		// ships a frame carrying BOTH sigs + the Directory carries the peer's
		// ML-DSA-65 pubkey. The nil pqPub is the honest NOT-YET (ADR-0036 §6).
		if !identity.VerifyCRDTFrame_Hybrid(originPub, nil, verifiedInner, originSig[:], nil, "") {
			return AcceptVerdict{Verdict: DropVerify, Reason: errors.New("receive: 1.1 hybrid origin signature verification failed (BOTH Ed25519 + ML-DSA-65 required; a v1 classical-only frame is rejected under --hybrid-verify — the STRICT mode; the hybrid SIGN is a future fork)")}
		}
	} else if !identity.VerifyCRDTFrame(originPub, verifiedInner, originSig[:]) {
		return AcceptVerdict{Verdict: DropVerify, Reason: errors.New("receive: 1.1 inner origin signature verification failed")}
	}

	// 8b. §4 SECURITY TOOTH — header/inner gate-field cross-check (Track 3.6).
	//     A malicious relay can put a DIFFERENT dotCounter / originNodeID in
	//     the v3 header than the inner capnp carries: the cheap gates read the
	//     adversarial HEADER value, pass, and step 9 Join consumes the INNER
	//     capnp value — a gate-bypass (the rate gate bounds the wrong counter,
	//     the clock gate sees the wrong counter, Directory.Lookup keys on the
	//     wrong originNodeID). The v3 header lift is INSECURE without this
	//     cross-check. It runs AFTER the cheap gates AND the expensive
	//     Open+Verify (it only fires for frames that cleared them), so it adds
	//     ZERO cost to the reject path (the whole point of the lift) and a
	//     bounded cost (one capnp decode + one uint64 compare + one 16-byte
	//     compare) to the accept path. A mismatch is a DropVerify ("gate-field
	//     header/inner desync — adversarial or corrupt") BEFORE
	//     ApplyCRDTDeltaEvent, so Join is NOT called on a desync frame.
	//
	//     BRANCH A (chosen, see §6): the cross-check does its OWN capnp
	//     decode of the Open-verified inner wire (the compare-decode), and
	//     ApplyCRDTDeltaEvent then does its internal decode — accept-path
	//     decode is 3x (readGateFields header read = 0x on v3, this compare-
	//     decode = 1x, ApplyCRDTDeltaEvent = 1x... see commit for the honest
	//     count). Branch B (reuse the apply-path decode via the pre-decoded
	//     ReconstructEntryWithSkewBound + an inline CRDTDelta/Join) was
	//     REJECTED: it clones crdt_apply.go's apply logic into pkg/receive,
	//     re-opening the C5/C6 drift seams the frozen file's own comments warn
	//     against ("a bypass here re-opens C6 on the live path AND A1 on the
	//     live path"). Branch A touches NO frozen file and keeps the apply
	//     path single-sourced in crdt_apply.go; the accept path is crypto-
	//     dominated (~300 us/frame), so the extra compare-decode (~1 us) is
	//     ~0.3% — a measured, honest cost reported in the commit, not hidden.
	//     On a v2 frame the cross-check is a no-op (the v2 header carries no
	//     mirrors; the gate fields already came from the inner capnp decode in
	//     step 3, so header == inner by construction — there is nothing to
	//     desync).
	if env.Version() == attribution.RelayEnvelopeVersion() {
		if err := crossCheckGateFields(env, verifiedInner); err != nil {
			return AcceptVerdict{Verdict: DropVerify, Reason: err}
		}
	}

	// 9. Join: ApplyCRDTDeltaEvent(verifiedInner) — the FIRST production
	//    caller of crdt_apply.go:113. A WireIntegrityError (digest
	//    mismatch) is a DropVerify; the engine's Join is not called.
	if err := r.engine.ApplyCRDTDeltaEvent(verifiedInner); err != nil {
		return AcceptVerdict{Verdict: DropVerify, Reason: fmt.Errorf("receive: ApplyCRDTDeltaEvent rejected frame: %w", err)}
	}
	// Day-8.5 receive-seam hook: gate on an ACTUAL foreign clock advance, not
	// on every Accept. The frame advanced the Lamport clock only if post > pre;
	// a stale/duplicate delta whose DotCounter <= the entry clock leaves the
	// clock unchanged (AdvanceLamportTo's guard no-ops at crdt.go:1642), so it
	// is NOT an advance and must NOT append a WAL record (the DEFECT-1 fsync
	// bomb: a spurious no-op record + fsync per Accept). A nil recorder (the
	// in-memory research path) is a no-op. The clock advance's effect is the
	// post-entry high-water; recording post (not the raw foreign DotCounter)
	// is the slight over-record the seed tolerates (ADR-0013 §7(h)).
	//
	// ERROR SURFACING (DEFECT-3 honest correction): a WAL-append/fsync failure
	// on the clock-advance record is LOGGED loudly — NOT swallowed. A foreign
	// Join is IRREVERSIBLE (the FROZEN crdt.go already merged the entry into
	// e.shards by the time Apply returned), so this path CANNOT return a
	// DropVerify style refusal without lying (the state IS merged). Unlike the
	// ORIGIN /v1/insert path — which can withhold a 503 because the client
	// write is local and retryable — the receive path cannot un-join. The
	// operator reads the log; the next checkpoint re-anchors the WAL at the
	// true high-water; if recovery fires before that checkpoint, the missing
	// advance is the same residual the FROZEN-crdt.go foreign-STATE limit
	// already documents (foreign state regossips on rejoin). This is honest:
	// the error is visible (logged), not silently dropped; the asymmetry with
	// the origin 503 is a FROZEN-lock consequence, recorded verbatim. See
	// ADR-0013 §7(h) for the surfaced-not-503 contract.
	if r.onClockAdvance != nil {
		if post := r.engine.LamportCounter(); post > preAdvance {
			if err := r.onClockAdvance(post); err != nil {
				log.Printf("receive: durability WAL clock-advance record failed (post=%d): %v — frame Accepted, state merged, advance NOT durable until next checkpoint", post, err)
			}
		}
	}
	return AcceptVerdict{Verdict: Accept}
}

// HandleBatchFrame runs the gate-stack composition over a single reassembled
// BATCH envelope frame (batchFrameBytes is a FULL BatchEnvelope — the length-
// prefix reassembler has already stripped the 4-byte prefix and the dispatch
// peek has already routed it here via attribution.IsBatchFrame). It is the
// batched sibling of HandleFrame: where HandleFrame verifies ONE Ed25519 over
// ONE inner wire and ApplyCRDTDeltaEvent-Joins one delta, HandleBatchFrame
// verifies ONE Ed25519 over the marshaled CRDTDeltaBatch wire and
// ApplyCRDTDeltaBatch-Joins ALL N deltas in one decode + one Join — the
// arithmetic unlock (60.19us amortized to 60.19/N us/delta). It returns a
// typed AcceptVerdict; it NEVER panics on adversarial input.
//
// The ordering (the §3 composition, lifted to the batch):
//
//  1. Parse the BatchEnvelope header (UnmarshalBatchEnvelope) — O(1), no capnp
//     decode of batchWire. Malformed => DropMalformed; zero originSig =>
//     DropVerify (the unsigned-batch tooth, caught inside Unmarshal).
//  2. Cheap gate: RATE — r.bucket.Accept on the batch's originNodeID, ONCE per
//     batch (the per-origin budget is decremented once per batch, NOT once per
//     delta — the honest amortization of the rate gate). Over-budget => DropRate.
//  3. GAP-3: r.dir.Lookup(originNodeID) => originPub. Miss => DropVerify.
//  4. THE ONE VERIFY: identity.VerifyCRDTFrame(originPub, batchWire, originSig)
//     => false => DropVerify. (This is the 60.19us that now covers N deltas.)
//  5. THE BATCH APPLY: r.engine.ApplyCRDTDeltaBatch(batchWire)
//     (crdt_apply_batch.go:118) => on *WireIntegrityError => DropVerify (S1a
//     atomic-reject: zero joined).
//  6. Verdict: Accept (N deltas joined in one decode + one Join).
//
// The per-event clock/depth gates are NOT re-run here: a 0-hop self-originated
// batch has NO relay hop walls, so the receiver's batch-level cheap gate is
// RATE only. The per-event clock/Lamport-skegate gate is enforced by
// ApplyCRDTDeltaBatch's ReconstructEntryWithSkewBound-per-element (the FROZEN
// engine path, crdt_apply_batch.go:206), NOT re-implemented in the receiver.
// A batch whose element exceeds the Lamport skew bound is rejected by
// ApplyCRDTDeltaBatch with a *WireIntegrityError (S1a atomic-reject: zero
// joined).
func (r *Receiver) HandleBatchFrame(batchFrameBytes []byte) AcceptVerdict {
	// preAdvance brackets the whole batch (clock gate + batch Join) — see the
	// HandleFrame comment. The recorder fires once per batch only if post>pre.
	preAdvance := r.engine.LamportCounter()

	// 1. Parse the BatchEnvelope header. O(1); never decodes batchWire. A
	//    malformed header (too short, bad magic, bad version) is a DropMalformed;
	//    a zero originSig is a DropVerify (the unsigned-batch tooth, caught
	//    inside UnmarshalBatchEnvelope as ErrBatchUnsigned).
	env, err := attribution.UnmarshalBatchEnvelope(batchFrameBytes)
	if err != nil {
		if errors.Is(err, attribution.ErrBatchUnsigned) {
			return AcceptVerdict{Verdict: DropVerify, Reason: err}
		}
		return AcceptVerdict{Verdict: DropMalformed, Reason: err}
	}

	// 2. Cheap gate: RATE — r.bucket.Accept on the batch's originNodeID, ONCE
	//    per batch. PeerBucket.Accept keys on a 32-byte pubkey; the batch's
	//    originNodeID is 16 bytes, so it is zero-extended to 32 bytes as the
	//    rate-gate key. This is a DISTINCT key space from the 32-byte relay
	//    pubkeys the per-frame path rate-gates on (a real Ed25519 pubkey is
	//    never 16-zero-bytes-padded), so there is no collision in practice; the
	//    choice is documented in ADR-0010 §2. The counter is the batch's
	//    OriginSeq — the origin's MONOTONIC per-batch sequence (advancing by 1
	//    per batch the origin ships). The bucket drains on the DELTA between
	//    successive OriginSeq values from the same origin, so a burst of
	//    batches drains the origin's budget (the Sybil-burst isolation the rate
	//    gate exists to enforce), amortized to one check per batch. It is NOT
	//    the BatchCount: a static count of deltas would produce a zero delta
	//    between same-size batches and the budget would never drain — a dead
	//    rate gate for the dominant steady-state workload (a node shipping its
	//    own N writes/sec in fixed-size batches). It mirrors the per-frame
	//    path's dotCounter (the monotonic per-origin sequence the per-frame
	//    rate gate keys on). The per-origin budget is decremented ONCE per
	//    batch, NOT once per delta — the honest amortization.
	originNodeID := env.OriginNodeID()
	var rateKey [32]byte
	copy(rateKey[:16], originNodeID[:])
	if r.bucket.Accept(rateKey[:], env.OriginSeq()) == admission.Drop {
		return AcceptVerdict{Verdict: DropRate, Reason: errors.New("receive: batch rate cap dropped batch (origin budget exhausted — decremented once per batch on the origin's monotonic sequence)")}
	}

	// 3. GAP-3: resolve originPub via the identity Directory. A miss is a
	//    DropVerify (the receiver cannot verify an unknown origin's signature).
	originPub, ok := r.dir.Lookup(originNodeID)
	if !ok {
		return AcceptVerdict{Verdict: DropVerify, Reason: fmt.Errorf("receive: identity Directory miss for batch originNodeID %x", originNodeID)}
	}

	// 4. THE ONE VERIFY — the amortization. identity.VerifyCRDTFrame over the
	//    marshaled CRDTDeltaBatch wire (the crypto-minimal design: the bytes
	//    Verify checks ARE the bytes ApplyCRDTDeltaBatch decodes — no SHA-256
	//    batch root, no hash-then-reconstruct gap). This is the 60.19us that
	//    now covers N deltas. A tampered batchWire fails here (DropVerify),
	//    never reaching ApplyCRDTDeltaBatch.
	batchWire := env.BatchWire()
	originSig := env.OriginSig()
	// Day 31 (ADR-0036): --hybrid-verify switches this to the hybrid
	// VerifyCRDTFrame_Hybrid (Ed25519 + ML-DSA-65, BOTH-required). The v1 batch
	// envelope carries ONLY the Ed25519 originSig (NO PQ sig) — so under
	// --hybrid-verify a v1 batch is REJECTED here (the STRICT mode: a hybrid
	// verifier NEVER accepts a classical-only batch; BOTH sigs is the contract).
	// The hybrid batch SIGN is a FUTURE fork; see the HandleFrame :415 comment.
	// --hybrid-verify OFF (the DEFAULT) keeps the classical VerifyCRDTFrame seam.
	if r.hybridVerify {
		if !identity.VerifyCRDTFrame_Hybrid(originPub, nil, batchWire, originSig[:], nil, "") {
			return AcceptVerdict{Verdict: DropVerify, Reason: errors.New("receive: batch hybrid origin signature verification failed (BOTH Ed25519 + ML-DSA-65 required; a v1 classical-only batch is rejected under --hybrid-verify — the STRICT mode; the hybrid SIGN is a future fork)")}
		}
	} else if !identity.VerifyCRDTFrame(originPub, batchWire, originSig[:]) {
		return AcceptVerdict{Verdict: DropVerify, Reason: errors.New("receive: batch origin signature verification failed (one Ed25519 over the batch wire)")}
	}

	// 5. THE BATCH APPLY — the FROZEN engine path (crdt_apply_batch.go:118).
	//    One decode, N reconstructs (each through ReconstructEntryWithSkewBound,
	//    which enforces the per-event clock/Lamport-skegate gate the receiver
	//    does NOT re-run), ONE Join. On the FIRST *WireIntegrityError (a
	//    tampered digest, a dot/origin mismatch, or a Lamport skew poisoning on
	//    ANY element) it returns an error and ZERO deltas are joined (S1a
	//    atomic-reject: reconstruct-all-then-join-once). A partial batch is a
	//    batch-level failure, never a partial apply.
	if err := r.engine.ApplyCRDTDeltaBatch(batchWire); err != nil {
		return AcceptVerdict{Verdict: DropVerify, Reason: fmt.Errorf("receive: ApplyCRDTDeltaBatch rejected batch: %w", err)}
	}

	// 6. Verdict: Accept — N deltas joined in one decode + one Join. The
	//    per-delta verdict counter is incremented by N (not +1) at the CALLER
	//    (the dispatch wrapper in serveConn/readLoop) via BatchAcceptCount +
	//    the existing Recorder seam — the verdict counter is PER-DELTA, so a
	//    batch of N adds N to the Accept label.
	//
	// Day-8.5 receive-seam hook (the batch sibling of HandleFrame's): gate on
	// an ACTUAL advance (post > preAdvance), not on every Accept. A stale or
	// duplicate batch whose elements do not advance the clock beyond the
	// entry high-water produces zero WAL records (no per-Accept fsync bomb).
	// Recorded once per batch (NOT once per delta — the advance is the
	// high-water the replay must reach, recorded once per batch Accept).
	// Error surfacing mirrors HandleFrame's (logged loudly, not swallowed;
	// irreversible batch Join cannot be un-done with a 503 — see ADR-0013
	// §7(h) for the surfaced-not-503 contract).
	if r.onClockAdvance != nil {
		if post := r.engine.LamportCounter(); post > preAdvance {
			if err := r.onClockAdvance(post); err != nil {
				log.Printf("receive: durability WAL clock-advance record failed (batch post=%d): %v — batch Accepted, state merged, advance NOT durable until next checkpoint", post, err)
			}
		}
	}
	return AcceptVerdict{Verdict: Accept}
}

// crossCheckGateFields is the §4 security tooth: it decodes the Open-verified
// inner capnp CRDTDeltaEvent and asserts the v3 header mirrors equal the inner
// values — headerDotCounter == ev.DotCounter() AND headerOriginNodeID ==
// [16]byte(ev.OriginNodeID()). A mismatch is a gate-bypass (a malicious relay
// put different gate fields in the header than the inner carries) and is
// rejected as a DropVerify BEFORE ApplyCRDTDeltaEvent (so Join is not called).
// It reuses readGateFieldsFromCapnp for the inner decode so the v2 fallback
// and the cross-check share one decode path. It runs only on the ACCEPT path
// (after Open+Verify), so it adds zero cost to the reject path.
func crossCheckGateFields(env *attribution.RelayEnvelope, verifiedInner []byte) error {
	innerDotCounter, innerOriginNodeID, err := readGateFieldsFromCapnp(verifiedInner)
	if err != nil {
		return fmt.Errorf("receive: gate-field header/inner cross-check: decode verified inner: %w", err)
	}
	if env.DotCounter() != innerDotCounter {
		return fmt.Errorf("receive: gate-field header/inner desync — adversarial or corrupt: header dotCounter %d != inner %d (the cheap gates bounded the wrong counter)", env.DotCounter(), innerDotCounter)
	}
	if env.OriginNodeID() != innerOriginNodeID {
		return fmt.Errorf("receive: gate-field header/inner desync — adversarial or corrupt: header originNodeID %x != inner %x (Directory.Lookup keyed on the wrong origin)", env.OriginNodeID(), innerOriginNodeID)
	}
	return nil
}

// readLastHop reads the LAST hop's relayPub and wallUSec directly from the
// raw frame bytes (a cheap O(1) read, no per-hop loop, no crypto). The
// envelope framing is [2]ver [2]hopCount [4]innerLen [64]originSig (v3 adds
// [8]dotCounter [16]originNodeID) [innerLen]innerWire then hops of HopSize
// bytes each; the last hop starts at hdrLen + innerLen + (hops-1)*HopSize,
// where hdrLen is version-dependent (v3=96, v2=72). The framing offsets are
// sourced from attribution.HeaderLenForVersion / HopSize / PubSize / SigSize
// (the single source of truth), NOT re-derived as literals here: the desync
// tooth (the G3.5.l-DSYN block of TestReceiver_SourceGuard) fails the build
// if these references are ever replaced by hardcoded byte-offset literals, so
// a future envelope layout change propagates by const-reference and the
// receiver can never disagree with the encoder. Returns an error if the frame
// is too short for the declared hops (a malformed frame UnmarshalRelayEnvelope
// should have caught, re-checked here for defense-in-depth).
func readLastHop(frameBytes []byte, hops int) (pub [32]byte, wallUSec int64, err error) {
	if hops <= 0 {
		return pub, 0, errors.New("receive: readLastHop called with hops <= 0")
	}
	if len(frameBytes) < 8 {
		return pub, 0, errors.New("receive: frame too short for header")
	}
	ver := binary.LittleEndian.Uint16(frameBytes[0:2])
	innerLen := int(binary.LittleEndian.Uint32(frameBytes[4:8]))
	// Frame layout constants sourced from the single source of truth
	// (pkg/attribution), NOT re-derived here. Re-deriving the byte offsets
	// duplicated the framing layout in two files; drift between the two
	// silently misattributes a good frame as a DropClock / DropVerify (the
	// wall-timestamp read drifts into the next hop's relayPub bytes -> a
	// far-future physical timestamp -> a false 3.0 clock-cap reject). The
	// desync tooth (the G3.5.l-DSYN block of TestReceiver_SourceGuard) fails the
	// build if these attribution.* references are ever replaced by literals.
	// The header length is version-dependent (v3=96, v2=72); sourcing it from
	// attribution.HeaderLenForVersion keeps the v2/v3 offset in lockstep with
	// the encoder without a re-derived literal.
	hdrLen, ok := attribution.HeaderLenForVersion(ver)
	if !ok {
		return pub, 0, fmt.Errorf("receive: readLastHop: unsupported envelope version %d", ver)
	}
	hopSz := attribution.HopSize
	lastBase := hdrLen + innerLen + (hops-1)*hopSz
	if lastBase+hopSz > len(frameBytes) {
		return pub, 0, errors.New("receive: frame too short for declared hops")
	}
	copy(pub[:], frameBytes[lastBase:lastBase+attribution.PubSize])
	wallUSec = int64(binary.LittleEndian.Uint64(frameBytes[lastBase+attribution.PubSize+attribution.SigSize : lastBase+hopSz]))
	return pub, wallUSec, nil
}

// HandleHybridFrame runs the gate-stack composition over a single reassembled
// HYBRID-PQ batch envelope frame (hybridFrameBytes is a FULL HybridEnvelope —
// the length-prefix reassembler has already stripped the 4-byte prefix + the
// dispatch peek has routed it here via attribution.IsHybridFrame). It is the
// Day-32 (ADR-0037) sibling of HandleBatchFrame: where HandleBatchFrame
// verifies ONE Ed25519 over the batchWire, HandleHybridFrame verifies BOTH the
// hedged Ed25519 sig AND the ML-DSA-65 sig over the SAME 120-byte SHAKE256 pad
// of batchWire (the hybrid both-required gate, VerifyBatchHybrid), then
// ApplyCRDTDeltaBatch-Joins ALL N deltas in one decode + one Join — the SAME
// arithmetic unlock, with the PQ half added. It returns a typed AcceptVerdict;
// it NEVER panics on adversarial input.
//
// The ordering (the §3 composition, lifted to the hybrid batch — the SAME
// cheap-gates-first discipline HandleBatchFrame uses):
//
//  1. Parse the HybridEnvelope header (UnmarshalHybridFrame) — O(1), no capnp
//     decode of batchWire. Malformed => DropMalformed; a zero edSig OR zero
//     pqSig => DropVerify (the unsigned-hybrid tooth, caught inside Unmarshal).
//  2. Cheap gate: RATE — r.bucket.Accept on the batch's originNodeID, ONCE per
//     batch (the per-origin budget decremented once per batch — the SAME
//     amortization HandleBatchFrame uses). Over-budget => DropRate.
//  3. GAP-3 grown: r.dir.LookupBoth(originNodeID) => (edPub, pqPub, ok). A
//     classical miss (ok=false) => DropVerify (the receiver cannot verify an
//     unknown origin under ANY seam). A hybrid miss (ok=true but pqPub=nil —
//     the peer registered ONLY the classical key) => DropVerify under
//     --hybrid-verify (the STRICT mode: a hybrid verifier NEVER accepts a
//     frame from a non-PQ-provisioned origin; the Day-31 contract carried
//     forward).
//  4. THE BOTH VERIFY: identity.VerifyBatchHybrid(edPub, pqPub, batchWire,
//     edSig[:], pqSig[:], ctx) => false => DropVerify. VerifyBatchHybrid
//     recomputes the 120-byte SHAKE256 pad + feeds it to the UNCHANGED
//     VerifyCRDTFrame_Hybrid (the both-required gate — the SAME gate the 6
//     Day-31 teeth exercise). This is the ~74us PQ verify that runs only after
//     the ~60us classical verify passes (short-circuit AND) — the SUM is the
//     honest hybrid verify cost, recorded per-op (NOT amortized).
//  5. THE BATCH APPLY: r.engine.ApplyCRDTDeltaBatch(batchWire) — the SAME
//     FROZEN engine path HandleBatchFrame calls (crdt_apply_batch.go:118). The
//     receiver applies the ORIGINAL batchWire (NOT the pad) so Join sees the
//     real bytes — the no-hash-then-reconstruct-gap property preserved for the
//     hybrid frame. On the FIRST *WireIntegrityError it returns an error +
//     ZERO deltas are joined (S1a atomic-reject).
//  6. Verdict: Accept (N deltas joined in one decode + one Join, BOTH sigs
//     verified). The HybridFrameAccepted counter (the 23rd SSoT, IF shipped)
//     increments here — the operator-VISIBLE proof the moat is in USE.
//
// The hybrid frame is OPT-IN on BOTH the send side (--hybrid-sign) AND the
// receive side (--hybrid-verify). A node with --hybrid-verify=false (the
// DEFAULT) routes a hybrid frame here via the 4th DispatchFrame arm — but the
// gate at step 4 calls VerifyBatchHybrid ONLY when r.hybridVerify is true; when
// false the frame is REJECTED as a hybrid frame a non-hybrid-verify receiver
// cannot accept (a hybrid frame is NOT a v1 BatchEnvelope — the receiver cannot
// fall back to the classical single-sig verify on a BOTH-sig frame; the honest
// posture, disclosed ADR-0037 §5). This keeps the byte-identical-Day-31
// default: --hybrid-verify=false + --hybrid-sign=false => NO hybrid frame is
// ever produced or accepted (the v1 mesh + the Day-1/30 TLS teeth run
// UNCHANGED — T-PQ-HYBRID-OFF-IS-BYTE-IDENTICAL).
func (r *Receiver) HandleHybridFrame(hybridFrameBytes []byte) AcceptVerdict {
	// 0. CONFIG GATE — reject a hybrid frame on an UNARMED receiver BEFORE ANY
	//    other work (the /verify-audit DoS-amplifier fix). The original ordering
	//    ran the engine.LamportCounter read (preAdvance) + the rate gate
	//    (r.bucket.Accept — which MUTATES the per-origin budget) + the LookupBoth
	//    RLock + two map reads BEFORE the !r.hybridVerify reject, so a
	//    --hybrid-sign peer dialing a --hybrid-verify=OFF (the DEFAULT) peer
	//    drained the origin's rate budget on a GUARANTEED-reject frame — a
	//    mixed-fleet rolling deploy where a hybrid-sign node burns every
	//    not-yet-hybrid-verify peer's budget, converging nothing. Worse, a
	//    SPOOFED hybrid frame with a forged victim originNodeID drained the
	//    VICTIM's budget on a default-config node with ZERO crypto work (the rate
	//    gate keys on the header's originNodeID, not a verified one); + the
	//    preAdvance engine read would nil-deref a receiver constructed without an
	//    engine (the test/posture a receiver that will reject anyway never
	//    needs). Moving the config gate to step 0 (the VERY TOP, before the
	//    unmarshal, the engine read, the rate gate, + the lookup) closes the
	//    amplifier: an unarmed receiver rejects a hybrid frame with zero
	//    side-effects. The honest posture is unchanged (a non-hybrid-verify
	//    receiver NEVER accepts a hybrid frame — the symmetric STRICT mode);
	//    only the ORDERING changes (the reject now precedes ALL the work, not
	//    follows it). The unmarshal is also deferred (an unarmed receiver does
	//    NOT need to parse a frame it will reject — the magic peek the dispatch
	//    already did is enough to route here; the full header parse is the
	//    armed receiver's job).
	if !r.hybridVerify {
		return AcceptVerdict{Verdict: DropVerify, Reason: errors.New("receive: hybrid-PQ batch received but --hybrid-verify is OFF — a BOTH-sig frame cannot be verified by a classical-only receiver (the symmetric STRICT mode; rejected at the TOP of HandleHybridFrame before the unmarshal, the engine read, the rate gate, + the Directory lookup so an unarmed receiver does NOT drain the origin's rate budget on a guaranteed-reject frame — the /verify-audit DoS-amplifier fix; --hybrid-sign=false is the byte-identical default so a hybrid frame is never produced on the production path)")}
	}

	// preAdvance brackets the whole hybrid batch (batch Join) — see the
	// HandleFrame comment. The recorder fires once per batch only if post>pre.
	// (Read AFTER the config gate — an unarmed receiver returns at step 0 + never
	// reaches this read, so a receiver constructed without an engine does NOT
	// nil-deref on a guaranteed-reject hybrid frame.)
	preAdvance := r.engine.LamportCounter()

	// 1. Parse the HybridEnvelope header. O(1); never decodes batchWire. A
	//    malformed header (too short, bad magic, bad version) is a
	//    DropMalformed; a zero edSig OR a zero pqSig is a DropVerify (the
	//    unsigned-hybrid tooth, caught inside UnmarshalHybridFrame as
	//    ErrHybridUnsigned).
	env, err := attribution.UnmarshalHybridFrame(hybridFrameBytes)
	if err != nil {
		if errors.Is(err, attribution.ErrHybridUnsigned) {
			return AcceptVerdict{Verdict: DropVerify, Reason: err}
		}
		return AcceptVerdict{Verdict: DropMalformed, Reason: err}
	}

	// 2. Cheap gate: RATE — r.bucket.Accept on the batch's originNodeID, ONCE
	//    per batch (the SAME amortization HandleBatchFrame uses). The batch's
	//    originNodeID is 16 bytes, zero-extended to 32 bytes as the rate-gate
	//    key (the DISTINCT key space from the 32-byte relay pubkeys — see the
	//    HandleBatchFrame comment for the collision rationale). The counter is
	//    the batch's OriginSeq — the origin's MONOTONIC per-batch sequence.
	originNodeID := env.OriginNodeID()
	var rateKey [32]byte
	copy(rateKey[:16], originNodeID[:])
	if r.bucket.Accept(rateKey[:], env.OriginSeq()) == admission.Drop {
		return AcceptVerdict{Verdict: DropRate, Reason: errors.New("receive: hybrid batch rate cap dropped batch (origin budget exhausted — decremented once per batch on the origin's monotonic sequence)")}
	}

	// 3. GAP-3 grown: resolve BOTH pubkeys via Directory.LookupBoth. A classical
	//    miss (ok=false) is a DropVerify (the receiver cannot verify an unknown
	//    origin under ANY seam). A hybrid miss (ok=true but pqPub=nil — the peer
	//    registered ONLY the classical key, the pre-Day-32 default) is a
	//    DropVerify under --hybrid-verify (the STRICT mode — a hybrid verifier
	//    NEVER accepts a frame from a non-PQ-provisioned origin; the Day-31
	//    nil-pqPub reject carried forward). LookupBoth is the grown seam; the
	//    classical Lookup stays byte-identical (the classical-only verify path
	//    still calls it — backward-compat).
	originPub, pqPub, ok := r.dir.LookupBoth(originNodeID)
	if !ok {
		return AcceptVerdict{Verdict: DropVerify, Reason: fmt.Errorf("receive: identity Directory miss for hybrid originNodeID %x", originNodeID)}
	}

	// 4. THE BOTH VERIFY — the hybrid gate. VerifyBatchHybrid recomputes the
	//    120-byte SHAKE256 pad of batchWire + feeds it to the UNCHANGED
	//    VerifyCRDTFrame_Hybrid (the both-required gate). This is the ~60us
	//    classical verify + the ~74us PQ verify (short-circuit AND — a classical
	//    reject skips the PQ verify). BOTH sigs over the SAME pad; EITHER reject
	//    => DropVerify. (The --hybrid-verify=OFF reject was hoisted to step 1.5
	//    above — BEFORE the rate gate + the lookup — so this step only runs on an
	//    ARMED receiver; the comment stays to name the gate the armed path runs.)
	batchWire := env.BatchWire()
	edSig := env.EdSig()
	pqSig := env.PQSig()
	if !identity.VerifyBatchHybrid(originPub, pqPub, batchWire, edSig[:], pqSig[:], "") {
		return AcceptVerdict{Verdict: DropVerify, Reason: errors.New("receive: hybrid-PQ batch signature verification failed (BOTH Ed25519 + ML-DSA-65 required over the SAME 120-byte SHAKE256 pad; either sig corrupt, or the origin's ML-DSA-65 pubkey is not provisioned — the STRICT mode)")}
	}

	// 5. THE BATCH APPLY — the SAME FROZEN engine path HandleBatchFrame calls
	//    (crdt_apply_batch.go:118). The receiver applies the ORIGINAL batchWire
	//    (NOT the pad) so Join sees the real bytes — the no-hash-then-reconstruct-
	//    gap property preserved for the hybrid frame. On the FIRST
	//    *WireIntegrityError it returns an error + ZERO deltas are joined (S1a
	//    atomic-reject).
	if err := r.engine.ApplyCRDTDeltaBatch(batchWire); err != nil {
		return AcceptVerdict{Verdict: DropVerify, Reason: fmt.Errorf("receive: ApplyCRDTDeltaBatch rejected hybrid batch: %w", err)}
	}

	// 6. Verdict: Accept — N deltas joined, BOTH sigs verified. The
	//    HybridFrameAccepted counter (the 23rd SSoT, IF shipped) increments
	//    here — the operator-VISIBLE proof the moat is in USE (not just wired).
	//    The counter is the M6 disclosure; the load-bearing deliverable is the
	//    BOTH-verify ACCEPT itself (the moat is now USEFUL under --hybrid-verify).
	if r.onHybridAccept != nil {
		r.onHybridAccept()
	}
	// Day-8.5 receive-seam hook (the hybrid-batch sibling of HandleBatchFrame's):
	// gate on an ACTUAL advance (post > preAdvance), not on every Accept. A
	// stale or duplicate hybrid batch whose elements do not advance the clock
	// beyond the entry high-water produces zero WAL records (no per-Accept fsync
	// bomb). Recorded once per batch. Error surfacing mirrors HandleBatchFrame's
	// (logged loudly, not swallowed; irreversible batch Join cannot be un-done
	// with a 503 — see ADR-0013 §7(h) for the surfaced-not-503 contract).
	if r.onClockAdvance != nil {
		if post := r.engine.LamportCounter(); post > preAdvance {
			if err := r.onClockAdvance(post); err != nil {
				log.Printf("receive: durability WAL clock-advance record failed (hybrid batch post=%d): %v — hybrid batch Accepted, state merged, advance NOT durable until next checkpoint", post, err)
			}
		}
	}
	return AcceptVerdict{Verdict: Accept}
}

// an io.Reader (a net.Conn or an *os.File over an AF_UNIX socket) and
// accumulates bytes into a reassembly buffer until a full frame is available,
// then returns the frame's envelope bytes (the 4-byte prefix stripped). The
// on-the-wire shape is [uint32 frameLen BE][envelope bytes...].
//
// It mirrors the proven reassembly idiom in internal/transport's read loop
// (capnp_server.go:370-404: accumulate into a buffer, check if enough bytes
// for the framing header, parse the length, wait for the full frame) but does
// NOT import internal/transport (that is the client->engine TriTemporalEvent
// ingest path, a separate track). pkg/receive is a leaf over the gate
// packages; it imports only stdlib + the gate packages + the capnp schema.
type FrameReader struct {
	r   io.Reader
	buf []byte // reassembly buffer
}

// NewFrameReader binds an io.Reader to a FrameReader.
func NewFrameReader(r io.Reader) *FrameReader {
	return &FrameReader{r: r}
}

// ReadFrame reads one length-prefixed frame from the underlying reader and
// returns the envelope bytes (prefix stripped). It blocks until a full frame
// is available or the reader returns EOF/error. A frame whose declared
// length exceeds maxFrameSize is rejected with ErrFrameTooLarge (a forged
// length prefix cannot grow the reassembly buffer unbounded). The returned
// slice is a fresh copy owned by the caller (the reassembly buffer is reused
// for the next frame).
//
// It returns io.EOF when the reader returns EOF before a full prefix is
// available (a clean end-of-stream).
func (f *FrameReader) ReadFrame() ([]byte, error) {
	// 1. Accumulate until we have the 4-byte length prefix.
	for len(f.buf) < frameLenPrefixSize {
		if err := f.fill(frameLenPrefixSize); err != nil {
			return nil, err
		}
	}
	frameLen := int(binary.BigEndian.Uint32(f.buf[:frameLenPrefixSize]))
	if frameLen <= 0 || frameLen > maxFrameSize {
		return nil, ErrFrameTooLarge
	}
	// 2. Accumulate until we have the full frame (prefix + frameLen).
	need := frameLenPrefixSize + frameLen
	for len(f.buf) < need {
		if err := f.fill(need); err != nil {
			return nil, err
		}
	}
	// 3. Copy out the envelope bytes (prefix stripped) and compact the
	//    reassembly buffer (keep any trailing bytes for the next frame).
	out := make([]byte, frameLen)
	copy(out, f.buf[frameLenPrefixSize:need])
	remaining := len(f.buf) - need
	copy(f.buf, f.buf[need:])
	f.buf = f.buf[:remaining]
	return out, nil
}

// fill reads from the underlying reader into the reassembly buffer until at
// least target bytes are buffered (or the reader errors). It grows the buffer
// as needed.
func (f *FrameReader) fill(target int) error {
	if cap(f.buf) < target {
		newCap := 1024
		for newCap < target {
			newCap *= 2
		}
		if newCap > maxFrameSize+frameLenPrefixSize {
			newCap = maxFrameSize + frameLenPrefixSize
		}
		grown := make([]byte, len(f.buf), newCap)
		copy(grown, f.buf)
		f.buf = grown
	}
	for len(f.buf) < target {
		n, err := f.r.Read(f.buf[len(f.buf):cap(f.buf)])
		if n > 0 {
			f.buf = f.buf[:len(f.buf)+n]
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// ErrFrameTooLarge is returned by ReadFrame when the declared frame length
// exceeds maxFrameSize (a forged length prefix cannot grow the reassembly
// buffer unbounded).
var ErrFrameTooLarge = errors.New("receive: frame length prefix exceeds maxFrameSize")

// MaxUint64DotCounter is the MaxUint64 DotCounter value the G3.5.e2 rate-
// reject test uses (a Sybil ratcheting DotCounter to MaxUint64). It is a test
// constant exported so the receiver test can build a MaxUint64-counter frame
// without re-typing the literal.
const MaxUint64DotCounter = math.MaxUint64
