// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Package sync reconstructs CRDT entries from decoded wire events in this file.
// ReconstructEntry reads every contract field, verifies that DotNodeID matches
// OriginNodeID, and checks PayloadDigest against SHA-256 of the payload. A
// malformed field or failed check returns a WireIntegrityError with the entity,
// origin, and values needed to diagnose the frame.
//
// Reconstruction is separate from the merge in Join. The apply paths validate
// an event before passing its entry to Join (ADR-0045 §7).
package sync

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math"

	capnp_schema "github.com/hr18vk/sovereign/api/capnp/api/capnp"
)

// ReconstructedEntry contains the entity ID, payload, and CRDT entry read from
// a decoded CRDTDeltaEvent. CRDTEntry retains only PayloadDigest; Payload keeps
// the source bytes available to callers that need them after validation.
type ReconstructedEntry struct {
	EntityID string
	Payload  string
	Entry    CRDTEntry
}

// WireIntegrityError reports a payload digest mismatch, dot/origin mismatch,
// excessive Lamport skew, or a wire field that could not be read. Callers can
// use errors.As to inspect the entity, origin, and values involved in the
// failure. Reconstruction retains this context instead of rejecting a frame
// during decode, before its entity and origin are available.
type WireIntegrityError struct {
	// EntityID identifies the rejected frame.
	EntityID string
	// OriginNodeID identifies its claimed sender.
	OriginNodeID [16]byte
	// OnWireDigest is the digest supplied by the wire event.
	OnWireDigest [32]byte
	// RecomputedDigest is SHA-256 of the received payload.
	RecomputedDigest [32]byte
	// DotNodeID records the causal dot for an attribution or skew failure.
	// It is empty for field-read and digest failures.
	DotNodeID [16]byte
	// Field names an unreadable contract field. It is empty for other kinds.
	Field string
	// ReadErrText preserves the underlying capnp error when available.
	ReadErrText string
	// The remaining fields describe a Lamport skew rejection. They are zero for
	// earlier failures because the bound is evaluated only after field,
	// attribution, and digest validation succeeds.
	//
	// InboundDotCounter is the received value that exceeded the bound.
	InboundDotCounter uint64
	// ReceiverLamport is the Lamport value in the caller's snapshot.
	ReceiverLamport uint64
	// ComputedBound is ReceiverLamport plus the rate envelope and AbsoluteSlack.
	ComputedBound uint64
	// ObservedInboundRate is the rate EWMA used to compute the bound.
	ObservedInboundRate float64
	// HorizonSeconds is the rate-envelope window used to compute the bound.
	HorizonSeconds float64
	// AbsoluteSlack is the fixed allowance added to the bound.
	AbsoluteSlack uint64
	// Kind identifies the failed integrity check.
	Kind WireIntegrityErrorKind
}

// WireIntegrityErrorKind classifies the integrity failure.
type WireIntegrityErrorKind int

const (
	// WireIntegrityDigestMismatch means PayloadDigest does not equal SHA-256
	// of the received payload.
	WireIntegrityDigestMismatch WireIntegrityErrorKind = iota
	// WireIntegrityFieldUnread means a contract field could not be read or had
	// the wrong length. Reconstruction returns an error rather than zero-filling
	// the field.
	WireIntegrityFieldUnread
	// WireIntegrityDotOriginMismatch means DotNodeID differs from OriginNodeID.
	// An origin may use only its own causal counter space (ADR-0045 §7).
	WireIntegrityDotOriginMismatch
	// WireIntegrityLamportSkewPoisoning means DotCounter exceeds the receiver's
	// snapshot-derived bound. Rejection prevents the value from advancing and
	// persisting through Join. Incremental ratcheting and Sybil bursts remain
	// possible; this check alone does not stop them.
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
		return fmt.Sprintf("wire-integrity violation: Lamport skew poisoning: inbound DotCounter %d exceeds the receiver's bound %d (lamport %d + rate-envelope %d + slack %d) on entity %q from origin %x dot %x — a far-future DotCounter advances the receiver's clock and prevents future writes; incremental-ratcheting and Sybil-burst attacks remain possible",
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

// ReconstructEntry validates and reconstructs a decoded CRDTDeltaEvent. It
// reads all 12 contract fields: PayloadDigest, OriginNodeID, DotNodeID,
// DotCounter, H3Index, SystemTime, ValidTimeStart, ValidTimeEnd, AssertionTime,
// DecisionTime, EntityId, and Payload. A read failure or wrong-length ID or
// digest returns WireIntegrityFieldUnread instead of a zero-filled entry.
// DotNodeID must equal OriginNodeID, and PayloadDigest must equal SHA-256 of
// the payload.
//
// On success it returns the reconstructed value without applying it to Join.
// On failure it returns the zero value and a non-nil error. Returning the
// result by value avoids one heap allocation per reconstructed element; its
// callers read fields directly and do not need a pointer (ADR-0014 §2, §8).
func ReconstructEntry(ev capnp_schema.CRDTDeltaEvent) (ReconstructedEntry, error) {
	// Read OriginNodeID and EntityId first so later failures retain their
	// diagnostic context. OriginNodeID comes first so a malformed EntityId
	// still leaves the sender ID available.
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

	// Read each field directly into its destination. Any failure returns
	// FieldUnread rather than leaving a zero-filled field.
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

	// The causal dot must belong to the frame origin (ADR-0045 §7). Check the
	// fixed-size IDs before hashing the payload. A frame with both attribution
	// and digest errors therefore reports the attribution mismatch first.
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

	// PayloadBytes aliases the capnp segment and avoids converting the payload
	// to a string before hashing it. SHA-256 finishes before this function
	// returns. The returned Payload string copies the bytes, so it remains valid
	// after the caller releases the message (ADR-0014 §7(f), §8).
	var payloadBytes []byte
	{
		got, err := ev.PayloadBytes()
		if err != nil {
			return ReconstructedEntry{}, readFieldError(entityID, originNodeID, "Payload", err)
		}
		payloadBytes = got
	}

	// Compare the received digest with SHA-256 of the segment bytes. The digest
	// is a public integrity check, so bytes.Equal need not be constant-time.
	// The computed digest is a value result and outlives the segment.
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
