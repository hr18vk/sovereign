// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Package receive reassembles length-prefixed envelopes and applies their
// admission, attribution, and integrity checks before merging deltas into the
// CRDT engine. HandleFrame accepts one relay envelope; HandleBatchFrame and
// HandleHybridFrame accept their respective batch formats.
//
// For relayed frames, the rate, physical-clock, and hop-depth checks precede
// signature verification. Successful verification is followed by an apply,
// optional secondary-index and WAL notifications, and relay retention. A v3
// header's mirrored dot counter and origin are cross-checked against the signed
// inner event before it is applied.
//
// The ebpf_kernel build tag adds EpollIngress, an optional UDP delivery adapter
// for transport.KernelFanout. The default build uses other delivery paths.
package receive

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"sync"
	"sync/atomic"
	"time"

	capnp "capnproto.org/go/capnp/v3"
	capnp_schema "github.com/hr18vk/sovereign/api/capnp/api/capnp"
	"github.com/hr18vk/sovereign/pkg/admission"
	"github.com/hr18vk/sovereign/pkg/attribution"
	"github.com/hr18vk/sovereign/pkg/clock"
	"github.com/hr18vk/sovereign/pkg/identity"
	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// frameLenPrefixSize is the size of the big-endian uint32 that precedes each
// marshaled envelope on stream and datagram delivery paths. Envelope fields
// retain their own little-endian encoding; only this outer prefix is big-endian.
const frameLenPrefixSize = 4

// maxFrameSize bounds reassembly so a forged length prefix cannot request an
// unbounded allocation. It also accommodates Cap'n Proto payloads much larger
// than an ordinary CRDT delta.
const maxFrameSize = 16 << 20 // 16 MiB

// Verdict identifies the gate that accepted or rejected a frame. Malformed
// input produces a verdict rather than a panic.
type Verdict int

const (
	// Accept means the apply joined at least one delta, or an empty batch was
	// accepted as a no-op. Accepted reports the number joined.
	Accept Verdict = iota
	// DropMalformed means the envelope or a required inner field could not be
	// decoded before signature verification.
	DropMalformed
	// DropRate means the applicable PeerBucket rejected the frame's sequence
	// advance before signature verification.
	DropRate
	// DropClock means the last hop's physical timestamp exceeded the permitted
	// future drift. A frame without hops uses the local physical clock.
	DropClock
	// DropDepth means RelayEnvelope.Open rejected the hop count before doing
	// signature verification.
	DropDepth
	// DropVerify means authentication, origin resolution, header consistency,
	// or engine integrity validation failed. It also reports a batch held in
	// full by the Lamport skew bound.
	DropVerify
)

// String returns the verdict name for logs and metrics.
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

// AcceptVerdict reports the gate result and its reason. Accepted is 1 for an
// accepted single frame, the joined-element count for an accepted batch, and 0
// for every drop. Reason is empty on Accept.
type AcceptVerdict struct {
	Verdict  Verdict
	Reason   error
	Accepted int
}

// Receiver applies admission and verification to reassembled frames before
// passing them to the CRDT engine. Its gates and engine support concurrent
// handlers. Configuration callbacks must be installed before handlers start.
//
// wallClock supplies the physical timestamp for origin frames without relay
// hops; those envelopes carry no origin wall time. Relayed frames use the last
// hop's WallUSec instead.
type Receiver struct {
	bucket    *admission.PeerBucket
	cap       *clock.IngressHLCScalarCap
	wallClock clock.WallClock
	dir       *identity.Directory
	engine    *eng.DeltaCRDTEngine
	budget    int64 // nanoseconds; converted to maxHops at construction

	// rateDropMu guards per-origin DropRate counters. Detailed messages are
	// capped independently for each origin, and the mutex is only taken while
	// formatting a drop.
	rateDropMu   sync.Mutex
	rateDropSeen map[[16]byte]uint64
	maxHops      int

	// onClockAdvance records the post-apply Lamport high-water only when a
	// handler advanced it. This lets the WAL reconstruct the recovery seed after
	// peer-driven advances. The durability bridge installs the callback; a nil
	// callback disables recording. See ADR-0013 for the recovery semantics.
	onClockAdvance func(uint64) error

	// hybridVerify selects strict hybrid verification. HandleFrame and
	// HandleBatchFrame then require both Ed25519 and ML-DSA-65, rejecting
	// classical-only frames. HandleHybridFrame is rejected immediately when this
	// is false. The default is classical-only verification; see ADR-0036 and
	// ADR-0037.
	hybridVerify bool

	// onHybridAccept runs after a hybrid batch passes both signature checks and
	// joins at least one element. The production node uses it to increment
	// telemetry.HybridFrameAccepted. Nil disables the notification.
	onHybridAccept func()

	// onAcceptRelay receives every accepted frame and its origin and dot. The
	// Gossiper's RetainForeign hook keeps only foreign frames, keyed by that
	// identity, so shipDelta can forward the original signed envelope. Without a
	// hook, HandleFrame discards the wire bytes after applying the delta.
	onAcceptRelay func(originNodeID [16]byte, dotCounter uint64, frameBytes []byte)

	// onAcceptRelayBatch receives an accepted batch's original envelope,
	// OriginSeq, and joined dot counters. The mesh retains foreign batches by
	// (origin, OriginSeq) and indexes them by dot for later forwarding. The full
	// envelope is required because one signature covers the entire batch wire.
	// Batches with held elements are not retained.
	onAcceptRelayBatch func(originNodeID [16]byte, originSeq uint64, dotCounters []uint64, frameBytes []byte)

	// onIndexFeed receives entityID, h3Index, and systemTime after a successful
	// apply. Each handler decodes only those fields and invokes it synchronously;
	// a nil callback disables secondary-index feeding. The command layer closes
	// over the index implementation, keeping that dependency out of this package.
	onIndexFeed func(entityID string, h3Index uint64, systemTime int64)

	// batchSkewHeldTail counts elements held by the Lamport skew bound. It is
	// diagnostic state, not an admission input.
	batchSkewHeldTail atomic.Uint64
	// heldTailLogSeq limits held-tail messages to the first 8 and every 1000th
	// per Receiver without affecting the exact counter above.
	heldTailLogSeq atomic.Uint64

	// These flags restore removed behaviors for negative-control tests. Normal
	// operation leaves them false. advanceDeferFault restores the pre-apply
	// Lamport advance, and disableRefundFault suppresses pre-verify refunds.
	advanceDeferFault  atomic.Bool
	disableRefundFault atomic.Bool
	// disableRetainOnHoldFault restores retention of partially held batches.
	disableRetainOnHoldFault atomic.Bool
}

// noteHeldTail records held elements and emits a capped diagnostic message
// shared by the classical and hybrid batch handlers.
func (r *Receiver) noteHeldTail(kind string, res eng.BatchApplyResult) {
	r.batchSkewHeldTail.Add(uint64(res.Held))
	if n := r.heldTailLogSeq.Add(1); n <= 8 || n%1000 == 0 {
		log.Printf("receive: %s skew-held tail: %d of %d elements over the Lamport skew bound — the in-window subset Joined, the tail is loud (batchSkewHeldTail=%d; log line %d — rate-capped, the counter is exact)", kind, res.Held, res.Joined+res.Held, r.batchSkewHeldTail.Load(), n)
	}
}

// NewReceiver binds the admission gates, identity directory, and engine.
// budget is the verification budget in nanoseconds. MaxHopsForBudget converts
// it once to the hop bound reused by HandleFrame. wallClock supplies physical
// time for frames without relay hops.
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

// SetClockAdvanceRecorder installs a callback that records a peer-driven
// Lamport advance in the WAL. It runs only when the post-apply high-water
// exceeds the value at handler entry. The durability bridge connects it to
// wal.AppendClockAdvance when --wal-path is configured; nil disables recording.
// Install it before starting concurrent handlers.
func (r *Receiver) SetClockAdvanceRecorder(fn func(uint64) error) {
	r.onClockAdvance = fn
}

// SetRelayRetainer installs the callback used by the Gossiper to cache foreign
// relay envelopes for forwarding. HandleFrame invokes it after every accepted
// apply; RetainForeign discards self-originated frames. Nil leaves foreign
// frames without a relay copy. Install it before starting concurrent handlers.
func (r *Receiver) SetRelayRetainer(fn func(originNodeID [16]byte, dotCounter uint64, frameBytes []byte)) {
	r.onAcceptRelay = fn
}

// SetRelayRetainerBatch installs the callback used by the Gossiper to cache
// foreign batch envelopes. After an apply with no held elements, the handler
// supplies the original frame, OriginSeq, and joined dots. The callback runs
// for self-originated batches too; RetainForeignBatch filters those out. Nil
// disables relay retention. Install it before starting concurrent handlers.
func (r *Receiver) SetRelayRetainerBatch(fn func(originNodeID [16]byte, originSeq uint64, dotCounters []uint64, frameBytes []byte)) {
	r.onAcceptRelayBatch = fn
}

// SetHybridVerify selects strict Ed25519 plus ML-DSA-65 verification for
// HandleFrame and HandleBatchFrame, and enables HandleHybridFrame. With hybrid
// verification enabled, classical-only frames are rejected. The false default
// retains classical Ed25519 verification and rejects hybrid frames. Set it
// before starting concurrent handlers. See ADR-0036 and ADR-0037.
func (r *Receiver) SetHybridVerify(enable bool) {
	r.hybridVerify = enable
}

// SetHybridAcceptReporter installs a notification for each accepted hybrid
// batch. The production node connects it to HybridFrameAccepted; nil disables
// the notification without changing verification. Install it before starting
// concurrent handlers. See ADR-0037.
func (r *Receiver) SetHybridAcceptReporter(fn func()) {
	r.onHybridAccept = fn
}

// SetIndexFeeder installs a synchronous secondary-index callback. Each handler
// invokes it once per joined delta before returning, and omits held elements.
// Nil disables the feed. Install it before starting concurrent handlers.
func (r *Receiver) SetIndexFeeder(fn func(entityID string, h3Index uint64, systemTime int64)) {
	r.onIndexFeed = fn
}

// decodeIndexFields reads only the three fields consumed by the secondary
// index from an already verified and applied event. It does not repeat payload
// or digest validation.
func decodeIndexFields(wire []byte) (entityID string, h3Index uint64, systemTime int64, err error) {
	msg, err := capnp.Unmarshal(wire)
	if err != nil {
		return "", 0, 0, fmt.Errorf("receive: index feed decode: unmarshal: %w", err)
	}
	defer msg.Release()
	ev, err := capnp_schema.ReadRootCRDTDeltaEvent(msg)
	if err != nil {
		return "", 0, 0, fmt.Errorf("receive: index feed decode: read root: %w", err)
	}
	id, err := ev.EntityId()
	if err != nil {
		return "", 0, 0, fmt.Errorf("receive: index feed decode: entityId: %w", err)
	}
	return id, ev.H3Index(), ev.SystemTime(), nil
}

// batchHeldSet returns the held dots from an apply result, or nil when no
// element was held. Index and retention paths use it to exclude elements that
// did not enter state.
//
// decodeIndexFieldsBatch reads index fields directly from the shared Cap'n
// Proto message, skipping held dots and avoiding an intermediate event slice.
// The caller releases the message after the feed returns. Decode failures stop
// the feed; the index is derived state and does not change the apply verdict.
func batchHeldSet(res eng.BatchApplyResult) map[uint64]struct{} {
	if res.Held == 0 {
		return nil
	}
	set := make(map[uint64]struct{}, len(res.HeldDots))
	for _, d := range res.HeldDots {
		set[d] = struct{}{}
	}
	return set
}

// decodeIndexFieldsBatch feeds secondary-index fields for each joined event.
// A nil held set avoids filtering and allocation when the entire batch joined.
func decodeIndexFieldsBatch(wire []byte, held map[uint64]struct{}, feed func(entityID string, h3Index uint64, systemTime int64)) error {
	msg, err := capnp.Unmarshal(wire)
	if err != nil {
		return fmt.Errorf("receive: index feed batch decode: unmarshal: %w", err)
	}
	defer msg.Release()
	batch, err := capnp_schema.ReadRootCRDTDeltaBatch(msg)
	if err != nil {
		return fmt.Errorf("receive: index feed batch decode: read root: %w", err)
	}
	events, err := batch.Events()
	if err != nil {
		return fmt.Errorf("receive: index feed batch decode: events: %w", err)
	}
	n := events.Len()
	for i := 0; i < n; i++ {
		ev := events.At(i) // alias into the parent arena — no per-element Release
		if held != nil {
			if _, isHeld := held[ev.DotCounter()]; isHeld {
				continue
			}
		}
		id, err := ev.EntityId()
		if err != nil {
			return fmt.Errorf("receive: index feed batch decode: element %d: entityId: %w", i, err)
		}
		feed(id, ev.H3Index(), ev.SystemTime())
	}
	return nil
}

// readGateFields obtains the dot counter and origin used by the cheap gates.
// A v3 envelope supplies both from fixed-offset header mirrors without a
// Cap'n Proto decode. A v2 envelope has no mirrors and falls back to decoding
// its inner event. That fallback reports malformed input; a validated v3
// header read cannot fail.
func readGateFields(env *attribution.RelayEnvelope) (dotCounter uint64, originNodeID [16]byte, err error) {
	if env.Version() == attribution.RelayEnvelopeVersion() {
		return env.DotCounter(), env.OriginNodeID(), nil
	}
	// Decode v2 fields explicitly rather than allowing zero values to pass the
	// gates when the header has no mirrors.
	return readGateFieldsFromCapnp(env.InnerWire())
}

// readGateFieldsFromCapnp decodes a dot counter and 16-byte origin from an
// inner CRDTDeltaEvent. V2 admission and the v3 header cross-check share this
// decoder so both interpret the signed event identically.
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

// HandleFrame verifies and applies one complete relay envelope. The length
// prefix must already be removed. Rate, clock, and hop-depth checks precede
// signature verification; a successful apply is followed by configured index,
// clock-advance, and relay callbacks. Invalid input returns a verdict rather
// than panicking.
func (r *Receiver) HandleFrame(frameBytes []byte) AcceptVerdict {
	// Capture the high-water before any gate or apply work. The clock gate only
	// checks physical drift; ApplyCRDTDeltaEvent advances Lamport time for joined
	// entries. Comparing against this value suppresses WAL records for duplicates
	// and includes every advance made by the apply.
	preAdvance := r.engine.LamportCounter()

	// Parse the envelope before doing cryptographic work.
	env, err := attribution.UnmarshalRelayEnvelope(frameBytes)
	if err != nil {
		return AcceptVerdict{Verdict: DropMalformed, Reason: err}
	}

	// The last hop identifies the direct sender for rate and clock checks. An
	// origin frame has no relay key or physical timestamp, so it skips the rate
	// gate and uses the local clock.
	hops := env.HopCount()
	var lastHopPub [32]byte
	var lastHopWall int64
	if hops > 0 {
		lastHopPub, lastHopWall, err = readLastHop(frameBytes, hops)
		if err != nil {
			return AcceptVerdict{Verdict: DropMalformed, Reason: err}
		}
	}

	// Read gate fields before Open. V3 uses header mirrors; v2 decodes the inner
	// event and can therefore reject malformed input here.
	dotCounter, originNodeID, err := readGateFields(env)
	if err != nil {
		return AcceptVerdict{Verdict: DropMalformed, Reason: err}
	}

	// Charge the last relay for its DotCounter advance. If a pre-verification
	// gate rejects the frame, the corresponding charge is refunded below. An
	// uncharged duplicate or dropped frame leaves charged at zero.
	var charged uint64
	if hops > 0 {
		decision, ch := r.bucket.Accept(lastHopPub[:], dotCounter)
		charged = ch
		if decision == admission.Drop {
			return AcceptVerdict{Verdict: DropRate, Reason: errors.New("receive: rate cap dropped frame (peer budget exhausted)")}
		}
	}

	// Admit checks only physical drift. Lamport advancement belongs to the
	// engine's apply path, after verification and skew validation.
	var physUSec int64
	if hops > 0 {
		physUSec = lastHopWall
	} else {
		physUSec = r.wallClock.PhysicalNowUSec()
	}
	if !r.cap.Admit(physUSec) {
		// Open has not authenticated the relay, so this pre-verify drop refunds
		// the charge unless a test explicitly disables refunds.
		if charged > 0 && !r.disableRefundFault.Load() {
			r.bucket.Refund(lastHopPub[:], charged)
		}
		return AcceptVerdict{Verdict: DropClock, Reason: errors.New("receive: clock cap dropped frame (physical timestamp too far in the future)")}
	}

	// Open checks the hop bound before verifying relay signatures. Both failure
	// classes occur before the relay is authenticated, so both refund its charge.
	// Once Open succeeds, later failures keep the charge and commit the watermark.
	verifiedInner, _, err := env.Open(r.maxHops)
	if err != nil {
		if charged > 0 && !r.disableRefundFault.Load() {
			r.bucket.Refund(lastHopPub[:], charged)
		}
		if errors.Is(err, attribution.ErrHopBoundExceeded) {
			return AcceptVerdict{Verdict: DropDepth, Reason: err}
		}
		return AcceptVerdict{Verdict: DropVerify, Reason: fmt.Errorf("receive: relay envelope open failed: %w", err)}
	}

	// Open authenticated the charged relay, so its pending high-water mark can
	// now commit. Later origin or integrity failures retain both the charge and
	// the committed watermark. Uncharged frames and duplicates skip this step.
	if charged > 0 {
		r.bucket.CommitHWM(lastHopPub[:], dotCounter)
	}

	// Resolve the origin key before verifying the signed inner event.
	originPub, ok := r.dir.Lookup(originNodeID)
	if !ok {
		return AcceptVerdict{Verdict: DropVerify, Reason: fmt.Errorf("receive: identity Directory miss for originNodeID %x", originNodeID)}
	}

	// Classical mode verifies the envelope's Ed25519 origin signature. Strict
	// hybrid mode requires an ML-DSA-65 signature and public key as well; a
	// classical-only envelope supplies neither and is therefore rejected.
	originSig := env.OriginSig()
	if r.hybridVerify {
		if !identity.VerifyCRDTFrame_Hybrid(originPub, nil, verifiedInner, originSig[:], nil, "") {
			return AcceptVerdict{Verdict: DropVerify, Reason: errors.New("receive: hybrid origin signature verification failed (both Ed25519 and ML-DSA-65 required; classical-only frames are rejected under --hybrid-verify)")}
		}
	} else if !identity.VerifyCRDTFrame(originPub, verifiedInner, originSig[:]) {
		return AcceptVerdict{Verdict: DropVerify, Reason: errors.New("receive: inner origin signature verification failed")}
	}

	// A relay can alter the unsigned v3 header mirrors without changing the
	// signed inner event. Cross-check both after authentication so admission and
	// origin lookup cannot use values different from those applied by the engine.
	// A mismatch returns DropVerify before ApplyCRDTDeltaEvent.
	//
	// The comparison decodes the verified inner event, and the apply decodes it
	// again. With the optional index feed there is a third field decode; without
	// it there are two. Keeping ApplyCRDTDeltaEvent intact avoids duplicating its
	// reconstruction and join logic here. V2 needs no comparison because its gate
	// fields already came from the inner event.
	if env.Version() == attribution.RelayEnvelopeVersion() {
		if err := crossCheckGateFields(env, verifiedInner); err != nil {
			return AcceptVerdict{Verdict: DropVerify, Reason: err}
		}
	}

	// The engine advances Lamport time only while applying an accepted entry.
	// Advancing here would move the clock before the apply's skew check, allowing
	// a verified but excessive dot to poison subsequent local dots and be recorded
	// in the WAL. Leaving advancement to the apply keeps the bound anchored to the
	// pre-frame clock and leaves an over-bound frame with no clock side effects.
	//
	// advanceDeferFault restores the old pre-apply advance solely for a negative
	// control. It is false in normal operation.
	if r.advanceDeferFault.Load() {
		r.cap.Advance(dotCounter)
	}

	// Integrity or skew errors reject the frame without a successful apply.
	if err := r.engine.ApplyCRDTDeltaEvent(verifiedInner); err != nil {
		return AcceptVerdict{Verdict: DropVerify, Reason: fmt.Errorf("receive: ApplyCRDTDeltaEvent rejected frame: %w", err)}
	}
	// Feed the derived index after the join. Decode failures are logged but do
	// not reverse or downgrade an apply that already succeeded.
	if r.onIndexFeed != nil {
		if id, h3, sys, derr := decodeIndexFields(verifiedInner); derr != nil {
			log.Printf("receive: secondary-index feed decode failed (frame Joined; index best-effort): %v", derr)
		} else {
			r.onIndexFeed(id, h3, sys)
		}
	}
	// Record only an actual advance. Duplicates leave the high-water unchanged
	// and must not cause a WAL append and fsync. The recorded post-apply value
	// can be slightly higher than the foreign dot, as ADR-0013 permits.
	//
	// A recording failure is logged rather than returned as a drop: the entry is
	// already merged and cannot be unjoined. Unlike a local insert, which can
	// report HTTP 503 for a retry, this handler can only surface the durability
	// error and rely on the next checkpoint to re-anchor the WAL high-water.
	if r.onClockAdvance != nil {
		if post := r.engine.LamportCounter(); post > preAdvance {
			if err := r.onClockAdvance(post); err != nil {
				log.Printf("receive: durability WAL clock-advance record failed (post=%d): %v — frame Accepted, state merged, advance not durable until next checkpoint", post, err)
			}
		}
	}
	// Offer the original envelope to the relay cache after the apply. The mesh
	// keeps only foreign frames, keyed by origin and dot, and can forward them
	// without re-signing. Self-originated payloads already have an origin-side
	// copy. Retention is best-effort and cannot change the completed apply.
	if r.onAcceptRelay != nil {
		r.onAcceptRelay(originNodeID, dotCounter, frameBytes)
	}
	return AcceptVerdict{Verdict: Accept, Accepted: 1}
}

// rateDropReason reports the origin prefix, sequence, remaining budget, and
// per-origin drop count. The first 8 drops and every 1000th thereafter include
// all fields; other drops return only the count to bound log volume. rateDropMu
// protects the counts, which are updated only on this drop path.
func (r *Receiver) rateDropReason(kind string, originNodeID [16]byte, offendingSeq uint64, rateKey []byte) error {
	remaining := r.bucket.Budget(rateKey)
	r.rateDropMu.Lock()
	if r.rateDropSeen == nil {
		r.rateDropSeen = make(map[[16]byte]uint64)
	}
	r.rateDropSeen[originNodeID]++
	n := r.rateDropSeen[originNodeID]
	r.rateDropMu.Unlock()
	if n <= rateDropLogCap || n%rateDropLogEvery == 0 {
		return fmt.Errorf("receive: %s rate cap dropped batch: origin=%x seq=%d remaining_budget=%d drop#%d — the gap from this origin's high-water mark exceeds its remaining budget (the HWM never rewinds and only an accepted frame advances it, so this drop means a genuine unfunded advance, not a re-charged duplicate)",
			kind, originNodeID[:4], offendingSeq, remaining, n)
	}
	return fmt.Errorf("receive: %s rate cap dropped batch: origin=%x drop#%d (fields suppressed; first %d + every %dth carry full detail)",
		kind, originNodeID[:4], n, rateDropLogCap, rateDropLogEvery)
}

// rateDropLogCap and rateDropLogEvery limit detailed DropRate messages.
const (
	rateDropLogCap   uint64 = 8
	rateDropLogEvery uint64 = 1000
)

// HandleBatchFrame verifies and applies one complete BatchEnvelope. It charges
// the origin's zero-extended node ID against OriginSeq, verifies one signature
// over the batch wire, and calls ApplyCRDTDeltaBatch. Strict hybrid mode
// requires both signature algorithms even for this classical envelope.
//
// The engine enforces the per-element Lamport skew bound. In-window elements
// join while over-bound elements are held; any other integrity error rejects
// the whole batch. A batch held in full returns DropVerify, while an empty
// batch is an accepted no-op. Accepted reports the joined count, not BatchCount.
// Index and relay callbacks omit held elements, and batches with held elements
// are not retained for relay.
func (r *Receiver) HandleBatchFrame(batchFrameBytes []byte) AcceptVerdict {
	// One high-water comparison covers the whole batch apply.
	preAdvance := r.engine.LamportCounter()

	env, err := attribution.UnmarshalBatchEnvelope(batchFrameBytes)
	if err != nil {
		if errors.Is(err, attribution.ErrBatchUnsigned) {
			return AcceptVerdict{Verdict: DropVerify, Reason: err}
		}
		return AcceptVerdict{Verdict: DropMalformed, Reason: err}
	}

	// Zero-extend the 16-byte origin ID into PeerBucket's 32-byte key space;
	// trailing zeroes distinguish it from relay public keys (ADR-0010 §2).
	// OriginSeq advances monotonically per batch, so its delta charges the
	// origin once per batch. BatchCount would remain constant for fixed-size
	// batches and would not drain the budget.
	originNodeID := env.OriginNodeID()
	var rateKey [32]byte
	copy(rateKey[:16], originNodeID[:])
	// Directory and signature failures refund this pre-verification charge.
	// Once verified, an apply rejection keeps the charge against the origin.
	batchDecision, batchCharged := r.bucket.Accept(rateKey[:], env.OriginSeq())
	if batchDecision == admission.Drop {
		return AcceptVerdict{Verdict: DropRate, Reason: r.rateDropReason("batch", originNodeID, env.OriginSeq(), rateKey[:])}
	}

	originPub, ok := r.dir.Lookup(originNodeID)
	if !ok {
		if batchCharged > 0 && !r.disableRefundFault.Load() {
			r.bucket.Refund(rateKey[:], batchCharged)
		}
		return AcceptVerdict{Verdict: DropVerify, Reason: fmt.Errorf("receive: identity Directory miss for batch originNodeID %x", originNodeID)}
	}

	// Verify exactly the batch bytes that ApplyCRDTDeltaBatch will decode. There
	// is no intermediate digest whose reconstruction could diverge from the wire.
	// Strict hybrid mode rejects this classical-only batch because it has no
	// ML-DSA-65 signature or padding.
	batchWire := env.BatchWire()
	originSig := env.OriginSig()
	if r.hybridVerify {
		if !identity.VerifyCRDTFrame_Hybrid(originPub, nil, batchWire, originSig[:], nil, "") {
			if batchCharged > 0 && !r.disableRefundFault.Load() {
				r.bucket.Refund(rateKey[:], batchCharged)
			}
			return AcceptVerdict{Verdict: DropVerify, Reason: errors.New("receive: batch hybrid origin signature verification failed (both Ed25519 and ML-DSA-65 required; classical-only batches are rejected under --hybrid-verify)")}
		}
	} else if !identity.VerifyCRDTFrame(originPub, batchWire, originSig[:]) {
		if batchCharged > 0 && !r.disableRefundFault.Load() {
			r.bucket.Refund(rateKey[:], batchCharged)
		}
		return AcceptVerdict{Verdict: DropVerify, Reason: errors.New("receive: batch origin signature verification failed (one Ed25519 over the batch wire)")}
	}

	// Verification authenticates the origin and commits the charged watermark.
	// An apply failure keeps both the charge and this committed high-water mark.
	if batchCharged > 0 {
		r.bucket.CommitHWM(rateKey[:], env.OriginSeq())
	}

	// ReconstructEntryWithSkewBound enforces the per-element skew gate. A skew
	// violation holds only that element; other integrity errors reject the whole
	// batch without joining any elements.
	batchRes, err := r.engine.ApplyCRDTDeltaBatch(batchWire)
	if err != nil {
		return AcceptVerdict{Verdict: DropVerify, Reason: fmt.Errorf("receive: ApplyCRDTDeltaBatch rejected batch: %w", err)}
	}
	if batchRes.Held > 0 {
		r.noteHeldTail("batch", batchRes)
	}
	if batchRes.Joined == 0 && batchRes.Held > 0 {
		// Nothing entered state. The sender can re-ship after other joins advance
		// the window. Empty batches skip this branch and remain accepted no-ops.
		return AcceptVerdict{Verdict: DropVerify, Reason: fmt.Errorf("receive: batch held IN FULL: all %d elements over the Lamport skew bound — zero joined, zero side effects, the held tail is loud (batchSkewHeldTail=%d)", batchRes.Held, r.batchSkewHeldTail.Load())}
	}
	// Feed only joined elements. Index decode errors do not change the verdict.
	if r.onIndexFeed != nil {
		if ferr := decodeIndexFieldsBatch(batchWire, batchHeldSet(batchRes), r.onIndexFeed); ferr != nil {
			log.Printf("receive: secondary-index batch feed decode failed (batch Joined; index best-effort): %v", ferr)
		}
	}

	// Retention follows the apply so rejected or held elements cannot pin a relay
	// frame whose dots never entered state. InspectBatchDots reads the signed wire
	// without another join and supplies the identity needed by the relay cache.
	// This second decode is best-effort and never changes the apply verdict.
	//
	// A partially held batch is not retained: one signature covers the full batch,
	// so a relayer cannot split off and re-sign only the joined elements. Replaying
	// the full frame cannot heal the held tail; the sender must re-ship it later.
	// disableRetainOnHoldFault restores the old retention behavior for a control.
	if r.onAcceptRelayBatch != nil && !r.disableRetainOnHoldFault.Load() && batchRes.Held > 0 {
		if n := r.heldTailLogSeq.Add(1); n <= 8 || n%1000 == 0 {
			log.Printf("receive: Held>0 partial batch: relay retention skipped (Held=%d, Joined=%d) — the full origin-signed frame cannot heal the held tail; the sender must re-ship it (batchSkewHeldTail=%d; log line %d)", batchRes.Held, batchRes.Joined, r.batchSkewHeldTail.Load(), n)
		}
	} else if r.onAcceptRelayBatch != nil {
		batchOrigin, dotCounters, inspectErr := eng.InspectBatchDots(batchWire)
		if inspectErr != nil {
			log.Printf("receive: InspectBatchDots failed for batch origin=%x seq=%d: %v — relay retain skipped (the batch is joined; retention is best-effort)", originNodeID, env.OriginSeq(), inspectErr)
		} else {
			// The fault-control path can reach this filter with held elements.
			joinedDots := dotCounters
			if hs := batchHeldSet(batchRes); hs != nil {
				joinedDots = make([]uint64, 0, len(dotCounters))
				for _, d := range dotCounters {
					if _, isHeld := hs[d]; !isHeld {
						joinedDots = append(joinedDots, d)
					}
				}
			}
			r.onAcceptRelayBatch(batchOrigin, env.OriginSeq(), joinedDots, batchFrameBytes)
		}
	}

	// The dispatcher records Accepted, so held elements do not inflate the
	// per-delta accept count. The clock recorder runs once per batch and only
	// when its post-apply high-water exceeds the entry value. Recording errors
	// follow HandleFrame's log-only contract because the joins are irreversible.
	if r.onClockAdvance != nil {
		if post := r.engine.LamportCounter(); post > preAdvance {
			if err := r.onClockAdvance(post); err != nil {
				log.Printf("receive: durability WAL clock-advance record failed (batch post=%d): %v — batch Accepted, state merged, advance not durable until next checkpoint", post, err)
			}
		}
	}
	return AcceptVerdict{Verdict: Accept, Accepted: batchRes.Joined}
}

// crossCheckGateFields compares the v3 header's dot counter and origin with
// the authenticated inner event. A mismatch means the cheap gates and directory
// used different values from the apply, so the caller returns DropVerify before
// joining. readGateFieldsFromCapnp shares the v2 decoder and its validation.
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

// readLastHop locates the final relay public key and WallUSec directly in the
// frame. Header length depends on the envelope version; attribution supplies
// that length and all hop field offsets so the decoder cannot drift from the
// encoder. The declared hop extent is checked again before slicing.
func readLastHop(frameBytes []byte, hops int) (pub [32]byte, wallUSec int64, err error) {
	if hops <= 0 {
		return pub, 0, errors.New("receive: readLastHop called with hops <= 0")
	}
	if len(frameBytes) < 8 {
		return pub, 0, errors.New("receive: frame too short for header")
	}
	ver := binary.LittleEndian.Uint16(frameBytes[0:2])
	innerLen := int(binary.LittleEndian.Uint32(frameBytes[4:8]))
	// Use attribution constants rather than duplicating offset arithmetic. A
	// stale hop size can shift the timestamp read into key material and cause a
	// false clock rejection. TestReceiver_SourceGuard checks this invariant.
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

// HandleHybridFrame verifies and applies one complete HybridEnvelope. It is
// enabled only by SetHybridVerify(true); otherwise it returns DropVerify before
// decoding, reading engine state, charging a budget, or consulting the directory.
// There is no classical fallback for a frame that carries two signatures.
//
// VerifyBatchHybrid checks Ed25519 and ML-DSA-65 over the same 120-byte SHAKE256
// pad. The engine then applies the original batch wire, not the pad, using the
// same skew and integrity rules as HandleBatchFrame. Accepted reports joined
// elements. Index and relay callbacks omit held elements; hybrid acceptance and
// clock-advance notifications follow a successful apply. See ADR-0037.
func (r *Receiver) HandleHybridFrame(hybridFrameBytes []byte) AcceptVerdict {
	// Reject before decoding or touching any state. In particular, a forged
	// origin cannot drain its rate budget on a receiver that cannot accept the
	// frame, and a nil engine is not dereferenced on this path.
	if !r.hybridVerify {
		return AcceptVerdict{Verdict: DropVerify, Reason: errors.New("receive: hybrid-PQ batch rejected because --hybrid-verify is disabled")}
	}

	// This read follows the configuration gate, so disabled receivers do not
	// require an engine. One high-water comparison covers the hybrid batch apply.
	preAdvance := r.engine.LamportCounter()

	env, err := attribution.UnmarshalHybridFrame(hybridFrameBytes)
	if err != nil {
		if errors.Is(err, attribution.ErrHybridUnsigned) {
			return AcceptVerdict{Verdict: DropVerify, Reason: err}
		}
		return AcceptVerdict{Verdict: DropMalformed, Reason: err}
	}

	// Use the same zero-extended origin key and monotonic OriginSeq charging as
	// the classical batch path. Pre-verification failures refund this charge.
	originNodeID := env.OriginNodeID()
	var rateKey [32]byte
	copy(rateKey[:16], originNodeID[:])
	hybDecision, hybCharged := r.bucket.Accept(rateKey[:], env.OriginSeq())
	if hybDecision == admission.Drop {
		return AcceptVerdict{Verdict: DropRate, Reason: r.rateDropReason("hybrid batch", originNodeID, env.OriginSeq(), rateKey[:])}
	}

	// LookupBoth requires the classical identity and returns its ML-DSA-65 key
	// when provisioned. A missing classical identity fails before verification;
	// VerifyBatchHybrid rejects a missing post-quantum key.
	originPub, pqPub, ok := r.dir.LookupBoth(originNodeID)
	if !ok {
		if hybCharged > 0 && !r.disableRefundFault.Load() {
			r.bucket.Refund(rateKey[:], hybCharged)
		}
		return AcceptVerdict{Verdict: DropVerify, Reason: fmt.Errorf("receive: identity Directory miss for hybrid originNodeID %x", originNodeID)}
	}

	// VerifyBatchHybrid checks both signatures over one SHAKE256 pad. Classical
	// verification runs first and can reject without doing ML-DSA-65 work.
	batchWire := env.BatchWire()
	edSig := env.EdSig()
	pqSig := env.PQSig()
	if !identity.VerifyBatchHybrid(originPub, pqPub, batchWire, edSig[:], pqSig[:], "") {
		if hybCharged > 0 && !r.disableRefundFault.Load() {
			r.bucket.Refund(rateKey[:], hybCharged)
		}
		return AcceptVerdict{Verdict: DropVerify, Reason: errors.New("receive: hybrid-PQ batch signature verification failed (both Ed25519 and ML-DSA-65 required over the same 120-byte SHAKE256 pad)")}
	}

	// Both signatures have authenticated the origin, so commit the watermark
	// charged before verification. Later apply failures retain it.
	if hybCharged > 0 {
		r.bucket.CommitHWM(rateKey[:], env.OriginSeq())
	}

	// Apply the original wire rather than the signature pad. Skew violations hold
	// individual elements; other integrity errors reject the entire batch.
	hybRes, err := r.engine.ApplyCRDTDeltaBatch(batchWire)
	if err != nil {
		return AcceptVerdict{Verdict: DropVerify, Reason: fmt.Errorf("receive: ApplyCRDTDeltaBatch rejected hybrid batch: %w", err)}
	}
	if hybRes.Held > 0 {
		r.noteHeldTail("hybrid batch", hybRes)
	}
	if hybRes.Joined == 0 && hybRes.Held > 0 {
		return AcceptVerdict{Verdict: DropVerify, Reason: fmt.Errorf("receive: hybrid batch held IN FULL: all %d elements over the Lamport skew bound — zero joined, zero side effects (batchSkewHeldTail=%d)", hybRes.Held, r.batchSkewHeldTail.Load())}
	}
	// Hybrid deltas use the same joined-only index feed as classical batches.
	if r.onIndexFeed != nil {
		if ferr := decodeIndexFieldsBatch(batchWire, batchHeldSet(hybRes), r.onIndexFeed); ferr != nil {
			log.Printf("receive: secondary-index hybrid batch feed decode failed (batch Joined; index best-effort): %v", ferr)
		}
	}

	// Retain the complete hybrid envelope after a successful apply. DispatchFrame
	// recognizes its magic on the next hop, preserving both signatures end to end.
	// Partial batches are not retained because a relayer cannot re-sign a joined
	// subset and replaying the full frame cannot heal the held tail.
	if r.onAcceptRelayBatch != nil && !r.disableRetainOnHoldFault.Load() && hybRes.Held > 0 {
		if n := r.heldTailLogSeq.Add(1); n <= 8 || n%1000 == 0 {
			log.Printf("receive: Held>0 hybrid partial batch: relay retention skipped (Held=%d, Joined=%d) — the full hybrid frame cannot heal the held tail; the sender must re-ship it (batchSkewHeldTail=%d; log line %d)", hybRes.Held, hybRes.Joined, r.batchSkewHeldTail.Load(), n)
		}
	} else if r.onAcceptRelayBatch != nil {
		batchOrigin, dotCounters, inspectErr := eng.InspectBatchDots(batchWire)
		if inspectErr != nil {
			log.Printf("receive: InspectBatchDots failed for hybrid batch origin=%x seq=%d: %v — relay retain skipped (the batch is joined; retention is best-effort)", originNodeID, env.OriginSeq(), inspectErr)
		} else {
			// The fault-control path can reach this filter with held elements.
			joinedDots := dotCounters
			if hs := batchHeldSet(hybRes); hs != nil {
				joinedDots = make([]uint64, 0, len(dotCounters))
				for _, d := range dotCounters {
					if _, isHeld := hs[d]; !isHeld {
						joinedDots = append(joinedDots, d)
					}
				}
			}
			r.onAcceptRelayBatch(batchOrigin, env.OriginSeq(), joinedDots, hybridFrameBytes)
		}
	}

	// Report hybrid acceptance only after both verification and the apply succeed.
	if r.onHybridAccept != nil {
		r.onHybridAccept()
	}
	// Record one post-apply high-water when the batch advanced Lamport time.
	// Duplicates produce no record; failures are logged because joins cannot be
	// reversed (ADR-0013).
	if r.onClockAdvance != nil {
		if post := r.engine.LamportCounter(); post > preAdvance {
			if err := r.onClockAdvance(post); err != nil {
				log.Printf("receive: durability WAL clock-advance record failed (hybrid batch post=%d): %v — hybrid batch Accepted, state merged, advance not durable until next checkpoint", post, err)
			}
		}
	}
	return AcceptVerdict{Verdict: Accept, Accepted: hybRes.Joined}
}

// FrameReader reads from an io.Reader and returns complete envelope payloads
// without their 4-byte big-endian length prefixes. It retains trailing bytes
// for the next call and bounds buffered frames with maxFrameSize.
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

// MaxUint64DotCounter is the largest possible DotCounter. Receiver tests use
// it to exercise rejection of an excessive sequence advance.
const MaxUint64DotCounter = math.MaxUint64
