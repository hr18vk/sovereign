// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

// ReconstructEntry: the production-side wire-integrity enforcement seam.
//
// Background: the delta writer once wrote only hashes/digests, so the receiver
// could not reconstruct the entry; PayloadDigest == SHA-256(payload) was
// assumed and never enforced. The CRDT delta now has a dedicated wire schema
// carrying both payload and payloadDigest as independent fields — but decode
// reads both without cross-validating them. The cross-validation technique was
// first proven in a test-local helper before being promoted to production.
//
// ReconstructEntry sits between the capnp decode and Join: it takes an
// already-decoded capnp_schema.CRDTDeltaEvent, reads every contract field off
// the wire with NO zero-fill (re-opening the silent-fall-through failure mode
// is a regression this seam forbids), recomputes SHA-256(payload) and
// cross-validates it against the on-wire PayloadDigest, and returns either a
// fully-validated CRDTEntry plus the (entityID, payload) pair, or a typed
// *WireIntegrityError carrying the diagnostic context that makes decode-time
// rejection (which loses the entity ID before Join ever sees it) the wrong
// choice.
//
// The seam is deliberately NOT coupled to Join: it produces a validated entry,
// it does not apply it. Join consumes the seam's output via a Seq; the
// wire-integrity concern and the merge concern stay separate.
package sync

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math"

	capnp_schema "github.com/hr18vk/sovereign/api/capnp/api/capnp"
)

// ReconstructedEntry is the seam's validated output: the (entityID, payload,
// entry) triple reconstructed from a decoded CRDTDeltaEvent. The payload is
// carried alongside the entry because the integrity check needs the raw bytes,
// but the far-side CRDTEntry stores ONLY PayloadDigest. The payload-lifecycle
// question (retain-after-check for replay/audit vs discard) is deliberately
// out of scope here.
type ReconstructedEntry struct {
	EntityID string
	Payload  string
	Entry    CRDTEntry
}

// WireIntegrityError is the production-side typed integrity error the seam
// returns on a payload/PayloadDigest mismatch or a wire-read failure. It is a
// sealed-by-type error (errors.As-able) carrying the diagnostic context that
// makes decode-time rejection the wrong choice: the entityID and originNodeID
// of the offending frame, the digest the wire carried, and the digest the seam
// recomputed from the actual payload bytes.
//
// Diagnostic context is the entire reason decode-time rejection was ruled out:
// a bare "integrity failed" with no entity/dot context is the failure mode this
// design rules out (the silent-fall-through failure mode).
type WireIntegrityError struct {
	// EntityID of the frame that failed reconstruction. The receiver could not
	// have known this under decode-time rejection (which drops the frame before
	// Join sees the entity ID); carrying it here is the seam's payoff.
	EntityID string
	// OriginNodeID of the frame, read off the wire before the integrity check.
	// Paired with EntityID for diagnostic correlation (which peer + which entity).
	OriginNodeID [16]byte
	// OnWireDigest is the PayloadDigest the wire carried.
	OnWireDigest [32]byte
	// RecomputedDigest is SHA-256(payload) the seam recomputed from the actual
	// payload bytes read off the wire.
	RecomputedDigest [32]byte
	// DotNodeID is the causal-dot node id the wire carried (attribution
	// axis). Carried ONLY on the WireIntegrityDotOriginMismatch kind so the
	// error names BOTH the claimed origin and the claimed dot — the mismatched
	// pair that makes a foreign-dotted frame attributable. Empty for the other
	// kinds (it equals OriginNodeID by construction on a clean read failure and
	// is irrelevant to a digest mismatch).
	DotNodeID [16]byte
	// Field names the contract field that could not be read off the wire, for
	// the FieldUnread kind. Empty for DigestMismatch (all fields read OK).
	Field string
	// ReadErrText is the capnp read error text (best-effort) for FieldUnread,
	// preserved so a malformed frame keeps the underlying parse failure visible.
	ReadErrText string
	// ── Lamport-skew axis (additive fields, no repurpose of the earlier ──
	// fields). Populated ONLY on the WireIntegrityLamportSkewPoisoning
	// kind so the error carries full attribution the way the digest axis
	// carries on-wire/recomputed digests and the attribution axis carries
	// DotNodeID/OriginNodeID. Zero-valued for the other kinds (the bound is
	// irrelevant when the frame already failed digest or attribution; skew
	// only computes — and only reports — on a frame clean on those two).
	//
	// InboundDotCounter is the DotCounter the wire carried on the rejected
	// frame — the value that exceeded the receiver's bound.
	InboundDotCounter uint64
	// ReceiverLamport is snapshot.Lamport — the receiver's e.lamport at the
	// moment the caller built the atomic snapshot. Carried so a reader can
	// reconstruct the bound from the diagnostic without re-reading engine
	// state (and so the concurrency guard can prove the snapshot was coherent).
	ReceiverLamport uint64
	// ComputedBound is the bound the wrapper computed for this snapshot:
	// ReceiverLamport + ceil(ObservedInboundRate * HorizonSeconds) + AbsoluteSlack.
	ComputedBound uint64
	// ObservedInboundRate is the EWMA of inbound DotCounter advancement the
	// engine maintained (snapshot.ObservedInboundRate) — the rate-envelope
	// term the bound grows with honest traffic and an incremental-ratcheting
	// attacker can influence (a known limitation).
	ObservedInboundRate float64
	// HorizonSeconds is the policy knob that sized the rate-envelope window
	// (snapshot.HorizonSeconds; default 60.0). Carried so a reader can see
	// which policy was in force at reject time.
	HorizonSeconds float64
	// AbsoluteSlack is the policy knob floor absorbing reordering/restart skew
	// below the rate envelope (snapshot.AbsoluteSlack; default 1000).
	AbsoluteSlack uint64
	// Kind distinguishes a digest mismatch from a wire-read failure (a missing
	// or truncated Text/Data field). Both are integrity failures: the seam
	// refuses to zero-fill — re-opening the silent fall-through is a
	// regression this seam forbids.
	Kind WireIntegrityErrorKind
}

// WireIntegrityErrorKind classifies the integrity failure.
type WireIntegrityErrorKind int

const (
	// WireIntegrityDigestMismatch is the digest-integrity failure: PayloadDigest
	// on the wire does not equal SHA-256(payload) on the wire. A
	// buggy/tampering peer could stamp a digest of some other bytes; the seam
	// catches it.
	WireIntegrityDigestMismatch WireIntegrityErrorKind = iota
	// WireIntegrityFieldUnread is the field-unread failure: a contract field
	// the schema carries could not be read off the wire (typically a missing
	// or truncated Text/Data pointer on an inbound frame). The seam refuses to
	// zero-fill the field; it returns a typed error instead, because
	// zero-filling is exactly how a missing field once hid the schema-vs-CRDT
	// gap.
	WireIntegrityFieldUnread
	// WireIntegrityDotOriginMismatch is the attribution-axis failure:
	// the causal-dot node id the wire carried (DotNodeID) does not equal the
	// frame OriginNodeID. A buggy or hostile peer could stamp a dot from a
	// counter-space the origin does not own; the seam catches it (a strict
	// attribution contract, byte-equal [16]byte). The digest-integrity checks
	// already closed this class for PayloadDigest; this kind closes it for the
	// causal dot. The Lamport-skew and cross-host-relay axes are handled
	// separately.
	WireIntegrityDotOriginMismatch
	// WireIntegrityLamportSkewPoisoning is the Lamport-skew-axis failure: the
	// inbound DotCounter the wire carried exceeds the receiver's
	// maxAcceptableDotCounter(snapshot) =
	// snapshot.Lamport + ceil(snapshot.ObservedInboundRate * snapshot.HorizonSeconds) + snapshot.AbsoluteSlack.
	// A Byzantine peer stamps a far-future DotCounter to brick the
	// receiver's Lamport clock via Join→AdvanceLamportTo (the far-future-stamp
	// attack) — the receiver can then no longer mint a higher dot via NextDot.
	// The wrapper seam closes that attack at the wire BEFORE Join, and closes
	// persistent disk-state poisoning by construction (the poisoned value never
	// reaches AdvanceLamportTo). Incremental ratcheting and Sybil-burst
	// attacks are SLOWED but NOT closed — deferred work gated on cross-host
	// infra. This Kind is APPENDED after the existing three so the integer
	// Kind values of the existing three stay byte-identical for the prior
	// guards.
	WireIntegrityLamportSkewPoisoning
)

func (e *WireIntegrityError) Error() string {
	switch e.Kind {
	case WireIntegrityDigestMismatch:
		return fmt.Sprintf("wire-integrity violation: SHA-256(payload) does not equal PayloadDigest on entity %q from origin %x (on-wire %x, recomputed %x)",
			e.EntityID, e.OriginNodeID, e.OnWireDigest, e.RecomputedDigest)
	case WireIntegrityDotOriginMismatch:
		return fmt.Sprintf("wire-integrity violation: causal-dot attribution mismatch: DotNodeID != OriginNodeID on entity %q (origin %x, dot %x) — the origin must vouch for its own counter-space",
			e.EntityID, e.OriginNodeID, e.DotNodeID)
	case WireIntegrityFieldUnread:
		return fmt.Sprintf("wire-integrity violation: contract field %q unread off the wire on entity %q from origin %x (refusing zero-fill — silent fall-through; capnp err: %s)",
			e.Field, e.EntityID, e.OriginNodeID, e.ReadErrText)
	case WireIntegrityLamportSkewPoisoning:
		return fmt.Sprintf("wire-integrity violation: Lamport skew poisoning: inbound DotCounter %d exceeds the receiver's bound %d (lamport %d + rate-envelope %d + slack %d) on entity %q from origin %x dot %x — a far-future DotCounter stamps the receiver's clock to brick future writes (Byzantine threat model; incremental-ratcheting and Sybil-burst attacks are only partially closed)",
			e.InboundDotCounter, e.ComputedBound, e.ReceiverLamport,
			uint64(math.Ceil(e.ObservedInboundRate*e.HorizonSeconds)), e.AbsoluteSlack,
			e.EntityID, e.OriginNodeID, e.DotNodeID)
	default:
		return fmt.Sprintf("wire-integrity violation (kind %d, field %q) on entity %q from origin %x", int(e.Kind), e.Field, e.EntityID, e.OriginNodeID)
	}
}

// readFieldError wraps a capnp read error from a contract field into a
// WireIntegrityError of kind FieldUnread so the seam's contract reads never
// fall through to zero on a malformed frame. The fieldName is diagnostic.
func readFieldError(entityID string, originNodeID [16]byte, fieldName string, readErr error) *WireIntegrityError {
	errText := ""
	if readErr != nil {
		errText = readErr.Error()
	}
	return &WireIntegrityError{
		EntityID:     entityID,
		OriginNodeID: originNodeID,
		Field:        fieldName,
		ReadErrText:  errText,
		Kind:         WireIntegrityFieldUnread,
	}
}

// ReconstructEntry is the wire-integrity enforcement seam. It takes a
// decoded capnp_schema.CRDTDeltaEvent and returns either a fully-validated
// ReconstructedEntry or a typed *WireIntegrityError.
//
// CONTRACT (the seam enforces all three — none optional):
//
// 1. Read all 12 wire fields: PayloadDigest, OriginNodeID, DotNodeID,
// DotCounter, H3Index, SystemTime, ValidTimeStart, ValidTimeEnd,
// AssertionTime, DecisionTime, EntityId, Payload. No zero-fill of fields
// the schema carries — a read failure on any field returns a typed error
// rather than leaving the field silently at its zero value (the
// silent-fall-through failure mode).
//
// 2. Cross-validate PayloadDigest == SHA-256(payload): recompute
// sha256.Sum256([]byte(payload)) and bytes.Equal against the wire's
// PayloadDigest. On mismatch return *WireIntegrityError with diagnostic
// context (entityID + originNodeID + on-wire and recomputed digests).
//
// 3. Do NOT couple to Join. The seam produces a validated ReconstructedEntry;
// it does not apply it. Join consumes the seam's output via a Seq.
//
// The signature returns ReconstructedEntry BY VALUE rather than a pointer. The
// prior *ReconstructedEntry allocated one heap object per reconstructed element
// — 100 allocs/batch at N=100 — for a type whose sole consumers
// (crdt_apply.go, crdt_apply_batch.go) read its fields by value
// (rec.Entry.OriginNodeID / rec.EntityID / rec.Entry) and never take &rec or
// nil-check the pointer. Returning by value eliminates the per-element pointer
// alloc (ADR-0014).
//
// The zero value ReconstructedEntry{} replaces the prior nil return on error, so
// the "failed reconstruction" state stays unambiguous to a caller (the non-nil
// error is the signal; the zero value entry is discarded). The value type is
// comparable (2 strings + the all-value CRDTEntry), so test-site nil checks
// translate faithfully to `== ReconstructedEntry{}` — no weakening.
func ReconstructEntry(ev capnp_schema.CRDTDeltaEvent) (ReconstructedEntry, error) {
	// ── Read EntityId and OriginNodeID first — they are the diagnostic ──
	// context every subsequent failure carries. Reading them up-front means a
	// wire-read failure on ANY later field still reports which entity+origin
	// committed it — the context a decode-time rejection would lose.
	//
	// OriginNodeID is read before EntityId so a malformed EntityId does not
	// strip the diagnostic of its peer identity.
	var originNodeID [16]byte
	{
		raw, err := ev.OriginNodeID()
		if err != nil || len(raw) != len(originNodeID) {
			return ReconstructedEntry{}, &WireIntegrityError{
				EntityID:     "",
				OriginNodeID: originNodeID,
				Kind:         WireIntegrityFieldUnread,
			}
		}
		copy(originNodeID[:], raw)
	}

	var entityID string
	{
		got, err := ev.EntityId()
		if err != nil {
			return ReconstructedEntry{}, readFieldError(entityID, originNodeID, "EntityId", err)
		}
		entityID = got
	}

	// ── Field-by-field reads; each returns a typed FieldUnread error on read ──
	// failure rather than zero-filling. Reading the field off the wire and
	// populating the CRDTEntry in one step keeps the zero-fill hazard visible
	// at the line of each field — there is no later bulk-populate pass that
	// could silently skip a field.
	var rec CRDTEntry

	rawDigest, err := ev.PayloadDigest()
	if err != nil || len(rawDigest) != len(rec.PayloadDigest) {
		return ReconstructedEntry{}, readFieldError(entityID, originNodeID, "PayloadDigest", err)
	}
	copy(rec.PayloadDigest[:], rawDigest)

	rawDot, err := ev.DotNodeID()
	if err != nil || len(rawDot) != len(rec.DotNodeID) {
		return ReconstructedEntry{}, readFieldError(entityID, originNodeID, "DotNodeID", err)
	}
	copy(rec.DotNodeID[:], rawDot)

	// ── attribution check (runs before the digest check) ──
	// The dot/origin equality is the attribution contract: the causal dot the
	// wire carries MUST be stamped by the frame's own origin (DotNodeID ==
	// OriginNodeID, byte-equal [16]byte). A frame whose dot is from a
	// different counter-space than its origin is either a buggy peer or a
	// hostile one trying to attribute a foreign dot to an origin that did not
	// mint it. The check runs here — right after DotNodeID is read off the
	// wire and BEFORE the SHA-256 cross-validation — for three reasons:
	// (a) the [16]byte comparison is cheaper than SHA-256 recomputation,
	// (b) a doubly-corrupt frame (both dot/origin mismatch AND digest
	// mismatch) reports DotOriginMismatch FIRST (the cheapest-to-
	// detect violation surfaces first),
	// (c) the seam's diagnostic payoff surfaces earlier on the
	// attribution failure.
	// Mutation C (re-order behind the digest check) MUST make the
	// doubly-corrupt Case 4 fail red — the ordering is enforced by guards,
	// not by accident.
	if rec.DotNodeID != originNodeID {
		return ReconstructedEntry{}, &WireIntegrityError{
			EntityID:     entityID,
			OriginNodeID: originNodeID,
			DotNodeID:    rec.DotNodeID,
			Kind:         WireIntegrityDotOriginMismatch,
		}
	}

	rec.OriginNodeID = originNodeID
	rec.DotCounter = ev.DotCounter()
	rec.H3Index = ev.H3Index()
	rec.SystemTime = ev.SystemTime()
	rec.ValidTimeStart = ev.ValidTimeStart()
	rec.ValidTimeEnd = ev.ValidTimeEnd()
	rec.AssertionTime = ev.AssertionTime()
	rec.DecisionTime = ev.DecisionTime()

	// ── Zero-copy Payload read ──
	// ev.PayloadBytes() routes to capnp Ptr.TextBytes(), which returns a slice
	// DIRECTLY into the segment arena (capnp pointer.go TextBytes `return b` —
	// no string(b) allocation, unlike ev.Payload()'s Ptr.Text() `return
	// string(b)`). The immediate consumer is sha256.Sum256, which takes a []byte
	// — feeding the zero-copy bytes directly removes the hidden []byte(string)
	// conversion the prior `sha256.Sum256([]byte(payload))` paid on every delta
	// (the conversion alloc is wrapped inside the argument, invisible to a
	// naive `make()` grep — ADR-0014).
	//
	// INVARIANT: the production path DISCARDS rec.Payload (crdt_apply.go and
	// crdt_apply_batch.go read rec.Entry and rec.EntityID only — zero
	// references to rec.Payload). The payload bytes are retained ONCE as a Go
	// string for the ReconstructedEntry.Payload field the tests assert
	// (crdt_reconstruct_test.go). That string copy is the same string(b) the
	// prior ev.Payload() paid, so the zero-copy read removes the []byte(string)
	// conversion for SHA and leaves the retained-field string copy
	// byte-identical — both source the same segment bytes, so
	// string(payloadBytes) == the original string(b).
	//
	// UAF safety: payloadBytes aliases the segment arena. SHA consumes and
	// discards it before this function returns; the only retained artifact is
	// the string(payloadBytes) copy (independent heap bytes, not the alias). The
	// caller's deferred msg.Release AFTER ReconstructEntry returns is therefore
	// UAF-safe — exactly the invariant the prior code already relied on for the
	// [16]byte copies. The Release contract is unchanged.
	var payloadBytes []byte
	{
		got, err := ev.PayloadBytes()
		if err != nil {
			return ReconstructedEntry{}, readFieldError(entityID, originNodeID, "Payload", err)
		}
		payloadBytes = got
	}

	// ── Cross-validate PayloadDigest == SHA-256(payload) ──
	// The integrity check that was long assumed but never enforced. Recompute
	// SHA-256 over the actual payload bytes read off the wire and compare to
	// the on-wire PayloadDigest with a constant-time-ish comparison (bytes.Equal
	// short-circuits on the first differing byte; correctness of the check does
	// not depend on the comparison being constant-time, only on the recompute
	// happening at all). Mismatch returns a typed WireIntegrityError carrying
	// every diagnostic that must not be lost. A neutered bytes.Equal
	// (e.g. always returning nil) misses the mismatch and the test's
	// mismatched-pair case catches the regression — see crdt_reconstruct_test.go.
	//
	// SHA is fed the ZERO-COPY payloadBytes directly — no []byte(string)
	// conversion (the alloc the prior sha256.Sum256([]byte(payload)) paid
	// on every delta is gone). The bytes alias the segment arena here, but
	// sha256.Sum256 copies them into its [32]byte return by value before this
	// function returns, so the result outlives the arena Release.
	recomputed := sha256.Sum256(payloadBytes)
	if !bytes.Equal(recomputed[:], rec.PayloadDigest[:]) {
		return ReconstructedEntry{}, &WireIntegrityError{
			EntityID:         entityID,
			OriginNodeID:     originNodeID,
			OnWireDigest:     rec.PayloadDigest,
			RecomputedDigest: recomputed,
			Kind:             WireIntegrityDigestMismatch,
		}
	}

	return ReconstructedEntry{
		EntityID: entityID,
		Payload:  string(payloadBytes),
		Entry:    rec,
	}, nil
}
