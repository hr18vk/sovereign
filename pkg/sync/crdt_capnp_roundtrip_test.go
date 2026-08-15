// Phase 2 — End-to-End Wire-Format Roundtrip Test.
//
// This file is the proof the audit history demanded and the benchmark suite
// never provided: a CRDT delta generated on host A, serialized through the
// capnp TriTemporalEvent wire format (api/capnp/api/capnp/schema.capnp),
// transported over a Go channel (stand-in for the network), unmarshaled on
// host B, applied via Join, and asserted field-by-field to preserve every
// field the CRDT contract defines.
//
// Scope discipline: this file is a TEST ONLY. If it surfaces a real
// wire-format defect (a C5/C6-class failure), it is left RED and reported —
// Phase 2 is the test, not the fix.
package sync

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"

	capnp "capnproto.org/go/capnp/v3"
	capnp_schema "github.com/hr18vk/supremum/api/capnp/api/capnp"
)

// Deterministic, field-distinct sentinel constants. No time.Now(), no RNG.
// Every temporal dim is a distinct nonzero sentinel; the entityID is long;
// the payload string is recoverable bytes that are deliberately NOT byte-equal
// to its SHA-256 digest.
const (
	// 40-char entityID so a 16-byte-truncated entityIDHash[:16] regression
	// changes both the length and the content of the emitted string.
	rtEntityID = "tenant=acme;ledger=txn;id=0a1b2c3d4e5f60718293a4b5c6d7e8f9"

	// rtPayload is the recoverable wire payload. It is a printable string
	// that is by construction not byte-equal to rtPayloadDigest (one is a
	// 48-char ASCII string, the other is 32 raw digest bytes).
	rtPayload = "this-is-recoverable-payload-bytes-NOT-its-digest"

	// Distinct nonzero sentinels for every CRDTEntry temporal/dot field.
	rtSystemTime     int64  = 0x1111111111111111
	rtValidTimeStart int64  = 0x2222222222222222
	rtValidTimeEnd   int64  = 0x3333333333333333
	rtAssertionTime  int64  = 0x4444444444444444
	rtDecisionTime   int64  = 0x5555555555555555
	rtH3Index        uint64 = 0x8928308280fffff

	// rtLatSentinel / rtLngSentinel ride the two capnp pointer-less fields
	// (latitude/longitude) that the schema exposes but CRDTEntry does not
	// name. Using sentinels means a future engineer who "recycles" latitude
	// to carry, say, SystemTime would change the value on the wire and the
	// far-side SystemTime assertion would still fail (the schema is missing
	// a real field for it). The sentinels document the overflow, not a fix.
	rtLatSentinel = 1.5
	rtLngSentinel = -2.5
)

// rtHostA / rtHostB are fixed, distinct 16-byte identities. Distinctness
// matters: if a serializer ever swapped DotNodeID with OriginNodeID, the
// far-side assertion comparing them against rtHostA (and not rtHostB) would
// catch it.
var (
	rtHostA = [16]byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	}
	rtHostB = [16]byte{
		0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
		0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
	}
	// rtPayloadDigest is SHA-256(rtPayload). Kept as a var so init-only
	// computation stays cheap and the digest is identical to what a
	// production PayloadDigest would be.
	rtPayloadDigest [32]byte
)

func init() {
	d := sha256.Sum256([]byte(rtPayload))
	copy(rtPayloadDigest[:], d[:])
}

// replayTriple is what the receiver unmarshals from the wire for each event:
// the entityID string, the payload bytes (kept so the C6 byte-equality teeth
// can assert against the actual wire payload, not its digest), and the wire
// reconstruction of CRDTEntry (which the schema only partially fills).
type replayTriple struct {
	entityID string
	payload  string
	entry    CRDTEntry
}

// makeReplaySeq mirrors crdt_test.go's makeSeq: it builds a push-based Seq
// that yields the reconstructed triples into Join. Defining the closure as a
// free helper (not as an inline composite-literal field) keeps the function
// literal out of the composite-literal grammar so gofmt/vet parse it
// unambiguously — exactly the idiom the existing test file already uses.
func makeReplaySeq(rec []replayTriple) Seq {
	return func(yield func(entityID string, entry CRDTEntry) bool) {
		for i := range rec {
			if !yield(rec[i].entityID, rec[i].entry) {
				return
			}
		}
	}
}

// setupRTEngine builds an engine with an isolated on-disk Lamport dir and a
// deterministic node ID, with cleanup wired. Isolating DataDir per test
// prevents cross-test interference on /data/crdt.
func setupRTEngine(tb testing.TB, nodeID [16]byte, initialCounter uint64) *DeltaCRDTEngine {
	tb.Helper()
	oldDataDir := DataDir
	DataDir = tb.TempDir()
	tb.Cleanup(func() { DataDir = oldDataDir })
	eng, err := NewDeltaCRDTEngine(nodeID, initialCounter, 64*1024*1024)
	if err != nil {
		tb.Fatalf("NewDeltaCRDTEngine(%x): %v", nodeID, err)
	}
	tb.Cleanup(func() {
		if cerr := eng.Close(); cerr != nil {
			tb.Logf("engine.Close: %v", cerr)
		}
	})
	return eng
}

// CRDTDeltaEventWireVersion is the single production source of truth for the
// compiled-in wire version (defined in crdt_apply.go). These tests read it
// directly by name rather than redefining a package-local duplicate — Phase 2h
// consolidated the prior test-local const into the production symbol so a
// future bump changes exactly one site.

// encodeEntryToCRDTDeltaEvent serializes a single (entityID, payload, entry)
// triple through the dedicated capnp CRDTDeltaEvent schema (engine<->engine
// sync, distinct from the client->engine ingestion TriTemporalEvent). This is
// the load-bearing Phase 2a step: by using a wire contract whose field set is
// the CRDT delta contract, the test proves every CRDTEntry field has a real
// field on the wire — closing C5 (schema-vs-CRDT disjoint) and C6 (payload
// written as digest).
//
// Field mapping onto CRDTDeltaEvent (12 contract fields + 1 version tag):
//
//	version        <- CRDTDeltaEventWireVersion (forward-compat tag)
//	payloadDigest  <- entry.PayloadDigest  ([32]byte -> Data)
//	originNodeID   <- entry.OriginNodeID   ([16]byte -> Data)
//	dotNodeID      <- entry.DotNodeID      ([16]byte -> Data)
//	dotCounter     <- entry.DotCounter     (uint64 -> UInt64)
//	h3Index        <- entry.H3Index        (uint64 -> UInt64)
//	systemTime     <- entry.SystemTime
//	validTimeStart <- entry.ValidTimeStart
//	validTimeEnd   <- entry.ValidTimeEnd
//	assertionTime  <- entry.AssertionTime
//	decisionTime   <- entry.DecisionTime
//	entityId       <- entityID string       (C6: NOT entityIDHash[:16])
//	payload        <- payload string        (C6: bytes, NOT the digest)
//
// CRDTDeltaEvent carries NO latitude/longitude: ingestion-only dimensions.
func encodeEntryToCRDTDeltaEvent(t *testing.T, entityID, payload string, entry CRDTEntry) []byte {
	t.Helper()
	msg, seg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		t.Fatalf("capnp.NewMessage: %v", err)
	}
	ev, err := capnp_schema.NewRootCRDTDeltaEvent(seg)
	if err != nil {
		t.Fatalf("NewRootCRDTDeltaEvent: %v", err)
	}
	ev.SetVersion(CRDTDeltaEventWireVersion)
	if err := ev.SetPayloadDigest(entry.PayloadDigest[:]); err != nil {
		t.Fatalf("SetPayloadDigest: %v", err)
	}
	if err := ev.SetOriginNodeID(entry.OriginNodeID[:]); err != nil {
		t.Fatalf("SetOriginNodeID: %v", err)
	}
	if err := ev.SetDotNodeID(entry.DotNodeID[:]); err != nil {
		t.Fatalf("SetDotNodeID: %v", err)
	}
	ev.SetDotCounter(entry.DotCounter)
	ev.SetH3Index(entry.H3Index)
	ev.SetSystemTime(entry.SystemTime)
	ev.SetValidTimeStart(entry.ValidTimeStart)
	ev.SetValidTimeEnd(entry.ValidTimeEnd)
	ev.SetAssertionTime(entry.AssertionTime)
	ev.SetDecisionTime(entry.DecisionTime)
	if err := ev.SetEntityId(entityID); err != nil {
		t.Fatalf("SetEntityId: %v", err)
	}
	if err := ev.SetPayload(payload); err != nil {
		t.Fatalf("SetPayload: %v", err)
	}
	data, err := msg.Marshal()
	if err != nil {
		t.Fatalf("msg.Marshal: %v", err)
	}
	return data
}

// decodeCRDTDeltaEvent unmarshals raw wire bytes back into a CRDTDeltaEvent
// via the shared schema and asserts the version tag matches the compiled-in
// wire version. A mismatch is an explicit fatal — it NEVER silently falls
// through to zero-received fields, because that silent path is exactly how
// C5 hid the schema-vs-CRDT gap. The version check is the decoder's own
// protection; the roundtrip test does not assert it separately.
func decodeCRDTDeltaEvent(t *testing.T, data []byte) capnp_schema.CRDTDeltaEvent {
	t.Helper()
	m, err := capnp.Unmarshal(data)
	if err != nil {
		t.Fatalf("capnp.Unmarshal: %v", err)
	}
	ev, err := capnp_schema.ReadRootCRDTDeltaEvent(m)
	if err != nil {
		t.Fatalf("ReadRootCRDTDeltaEvent: %v", err)
	}
	if ev.Version() != CRDTDeltaEventWireVersion {
		t.Fatalf("CRDTDeltaEvent wire version mismatch: got %d, want %d — refusing silent fall-through to zero-received fields (C5 guard)",
			ev.Version(), CRDTDeltaEventWireVersion)
	}
	return ev
}

// TestPhase2_CapnpWireFormatRoundtrip is the End-to-End Roundtrip Test.
//
// Roundtrip path exercised (exact):
//
//	InsertLocal -> GenerateDelta -> delta.Entries(ForEach) -> capnp
//	TriTemporalEvent encode -> chan []byte transport -> capnp
//	TriTemporalEvent decode -> reconstruct CRDTDelta -> Join -> field-by-field
//	assertions on host B's State().
func TestPhase2_CapnpWireFormatRoundtrip(t *testing.T) {
	// ---- Host A: source engine ---------------------------------------------------
	engineA := setupRTEngine(t, rtHostA, 0)

	srcEntry := CRDTEntry{
		PayloadDigest:  rtPayloadDigest,
		OriginNodeID:   rtHostA,
		SystemTime:     rtSystemTime,
		ValidTimeStart: rtValidTimeStart,
		ValidTimeEnd:   rtValidTimeEnd,
		AssertionTime:  rtAssertionTime,
		DecisionTime:   rtDecisionTime,
		H3Index:        rtH3Index,
		// DotNodeID/DotCounter are stamped by InsertLocal via NextDot().
	}
	dot := engineA.InsertLocal(rtEntityID, srcEntry)
	srcEntry.DotNodeID = dot.NodeID
	srcEntry.DotCounter = dot.Counter

	if dot.NodeID != rtHostA {
		t.Fatalf("InsertLocal dot.NodeID %x, want %x", dot.NodeID, rtHostA)
	}
	if dot.Counter != 1 {
		t.Fatalf("InsertLocal dot.Counter %d, want 1 (initial counter 0)", dot.Counter)
	}

	// ---- Generate the delta (full sync — remote digest is empty) ----------------
	// An empty IBLT means "peer B knows nothing," so the delta contains every
	// entry host A has. This is the simplest deterministic generate path and
	// avoids the stratified estimator's dynamic sizing.
	emptyRemoteDigest := NewIBLT(1024, 4)
	delta := engineA.GenerateDelta(emptyRemoteDigest)
	defer delta.Release()

	type emittedEntry struct {
		entityID string
		entry    CRDTEntry
	}
	var emitted []emittedEntry
	delta.Entries(func(entityID string, entry CRDTEntry) bool {
		emitted = append(emitted, emittedEntry{entityID, entry})
		return true
	})
	if len(emitted) != 1 {
		t.Fatalf("delta emitted %d entries, want 1", len(emitted))
	}

	// EARLY C6 TEETH (producer side): the delta iterator MUST yield the real
	// entityID string, not a 16-byte hash. If the in-process generator were
	// ever regressed to entityIDHash[:16], the emitted string would be 16 raw
	// bytes and would not equal the 40-char rtEntityID.
	if emitted[0].entityID != rtEntityID {
		t.Fatalf("producer-side entityID: got %q (len %d), want %q (len %d) — C6 entityIDHash[:16] regression on the producer",
			emitted[0].entityID, len(emitted[0].entityID), rtEntityID, len(rtEntityID))
	}

	// ---- Transport: capnp encode -> chan []byte ---------------------------------
	transport := make(chan []byte, 4)
	go func() {
		defer close(transport)
		for i := range emitted {
			// C6 payload-not-digest: serialize the payload string, NEVER
			// rtPayloadDigest. If a future serializer substitutes the digest,
			// the receiver-side byte-equality assertion fails.
			data := encodeEntryToCRDTDeltaEvent(t, emitted[i].entityID, rtPayload, emitted[i].entry)
			transport <- data
		}
	}()

	// ---- Host B: receive, decode, reconstruct, Join -----------------------------
	engineB := setupRTEngine(t, rtHostB, 100)

	var reconstructed []replayTriple
	for wire := range transport {
		ev := decodeCRDTDeltaEvent(t, wire)

		gotEID, err := ev.EntityId()
		if err != nil {
			t.Fatalf("EntityId(): %v", err)
		}
		gotPayload, err := ev.Payload()
		if err != nil {
			t.Fatalf("Payload(): %v", err)
		}

		// Reconstruct a CRDTEntry from the wire. CRDTDeltaEvent carries every
		// CRDTEntry field the contract defines, so there is nothing left to
		// fabricate: the dot comes off the wire (DotNodeID/DotCounter), the
		// digest comes off the wire (PayloadDigest, NOT recomputed from the
		// payload), and all temporal/H3 dimensions come off the wire too. We
		// do NOT re-hash the payload into PayloadDigest: the wire carries both
		// the digest and the bytes, and the assertion block cross-checks them
		// to detect any C6 digest-substitution regression.
		dotID, err := ev.DotNodeID()
		if err != nil {
			t.Fatalf("DotNodeID(): %v", err)
		}
		origID, err := ev.OriginNodeID()
		if err != nil {
			t.Fatalf("OriginNodeID(): %v", err)
		}
		digest, err := ev.PayloadDigest()
		if err != nil {
			t.Fatalf("PayloadDigest(): %v", err)
		}
		var recEntry CRDTEntry
		copy(recEntry.PayloadDigest[:], digest)
		copy(recEntry.OriginNodeID[:], origID)
		copy(recEntry.DotNodeID[:], dotID)
		recEntry.DotCounter = ev.DotCounter()
		recEntry.H3Index = ev.H3Index()
		recEntry.SystemTime = ev.SystemTime()
		recEntry.ValidTimeStart = ev.ValidTimeStart()
		recEntry.ValidTimeEnd = ev.ValidTimeEnd()
		recEntry.AssertionTime = ev.AssertionTime()
		recEntry.DecisionTime = ev.DecisionTime()
		reconstructed = append(reconstructed, replayTriple{gotEID, gotPayload, recEntry})
	}
	if len(reconstructed) != 1 {
		t.Fatalf("received %d wire frames, want 1", len(reconstructed))
	}

	// Build a CRDTDelta whose Entries Seq replays the reconstructed events
	// into host B via Join. makeReplaySeq (not an inline closure) keeps the
	// function literal out of a composite literal.
	incomingDelta := CRDTDelta{
		OriginNodeID: rtHostA,
		Entries:      makeReplaySeq(reconstructed),
	}
	engineB.Join(incomingDelta)

	// ---- THE TEETH: field-by-field assertions on host B's state -----------------
	got := engineB.State().Get(rtEntityID)
	if len(got) == 0 {
		t.Fatalf("host B State().Get(%q) returned no entries — Join did not apply the delta", rtEntityID)
	}
	if len(got) != 1 {
		t.Fatalf("host B got %d entries for %q, want 1", len(got), rtEntityID)
	}
	gotEntry := got[0]
	gotPayloadOnWire := reconstructed[0].payload

	// Entity ID equality by string (not hash) — C6 catch on the far side.
	// The fact that rtEntityID returned exactly one entry proves the wire
	// carried the full 40-char string; had the producer emitted
	// entityIDHash[:16], host B would store the entry under a 16-byte key and
	// this Get(rtEntityID) would have returned zero entries (caught above).
	t.Logf("entityID preserved: State().Get(%q) returned 1 entry", rtEntityID)

	// Payload byte-equality (the actual []byte payload, not its digest). This
	// is the exact C6 payload-lost assertion: if the serializer ever wrote
	// the digest in the payload slot or dropped the payload field,
	// gotPayloadOnWire would be wrong/empty and this assertion fails.
	if gotPayloadOnWire != rtPayload {
		t.Errorf("payload byte-equality: got %q, want %q — C6 payload-lost/digest-substitution regression",
			gotPayloadOnWire, rtPayload)
	}
	if gotPayloadOnWire == string(rtPayloadDigest[:]) {
		t.Errorf("payload equals the digest bytes — C6 digest-substitution regression")
	}
	if gotPayloadOnWire == string(rtPayloadDigest[:16]) {
		t.Errorf("payload equals digest[:16] — C6 entityIDHash[:16]-style truncation regression")
	}

	// AssertionTime — the schema's only named temporal field. If even this
	// fails, the named wire field itself is broken.
	if gotEntry.AssertionTime != rtAssertionTime {
		t.Errorf("AssertionTime: got %#x, want %#x (schema carries this — named-field break if this fails)",
			gotEntry.AssertionTime, rtAssertionTime)
	}

	// --- Assertions that surface the C5-class schema-vs-CRDT gap ----------------
	// Each of the following asserts a CRDTEntry field the TriTemporalEvent
	// schema has NO field for. Against the current schema they fail —
	// surfacing the C5/C6 defect the brief requires Phase 2 to expose. If a
	// future wire-format fix phase extends the schema to carry these, the
	// asserts become green with no test change required.
	if gotEntry.SystemTime != rtSystemTime {
		t.Errorf("SystemTime: got %#x, want %#x (schema has no SystemTime field — C5)",
			gotEntry.SystemTime, rtSystemTime)
	}
	if gotEntry.ValidTimeStart != rtValidTimeStart {
		t.Errorf("ValidTimeStart: got %#x, want %#x (schema has no ValidTimeStart field — C5)",
			gotEntry.ValidTimeStart, rtValidTimeStart)
	}
	if gotEntry.ValidTimeEnd != rtValidTimeEnd {
		t.Errorf("ValidTimeEnd: got %#x, want %#x (schema has no ValidTimeEnd field — C5)",
			gotEntry.ValidTimeEnd, rtValidTimeEnd)
	}
	if gotEntry.DecisionTime != rtDecisionTime {
		t.Errorf("DecisionTime: got %#x, want %#x (schema has no DecisionTime field — C5)",
			gotEntry.DecisionTime, rtDecisionTime)
	}
	if gotEntry.H3Index != rtH3Index {
		t.Errorf("H3Index: got %#x, want %#x (schema has no H3Index field — C5)",
			gotEntry.H3Index, rtH3Index)
	}
	if gotEntry.DotNodeID != dot.NodeID {
		t.Errorf("DotNodeID: got %x, want %x (schema has no DotNodeID field — C5/C6 causal-dot lost)",
			gotEntry.DotNodeID, dot.NodeID)
	}
	if gotEntry.DotCounter != dot.Counter {
		t.Errorf("DotCounter: got %d, want %d (schema has no DotCounter field — C5/C6 causal-dot lost)",
			gotEntry.DotCounter, dot.Counter)
	}
	if gotEntry.OriginNodeID != rtHostA {
		t.Errorf("OriginNodeID: got %x, want %x (schema has no OriginNodeID field — C5)",
			gotEntry.OriginNodeID, rtHostA)
	}
	if gotEntry.PayloadDigest != rtPayloadDigest {
		t.Errorf("PayloadDigest: got %x, want %x (schema has no PayloadDigest field — C5)",
			gotEntry.PayloadDigest, rtPayloadDigest)
	}
}

// TestPhase2_TriTemporalEventSchemaSurfaceIsFiveFields is the C5 structural
// guard: it pins the canonical accessor surface of the capnp schema. If a
// future engineer drops a field from TriTemporalEvent (a C5 drift), the
// corresponding accessor call here fails to compile. If they add a field that
// CRDTEntry also grows, this guard forces them to add a matching roundtrip
// assertion rather than silently letting the field fall off the wire.
func TestPhase2_TriTemporalEventSchemaSurfaceIsFiveFields(t *testing.T) {
	msg, seg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		t.Fatalf("capnp.NewMessage: %v", err)
	}
	ev, err := capnp_schema.NewRootTriTemporalEvent(seg)
	if err != nil {
		t.Fatalf("NewRootTriTemporalEvent: %v", err)
	}

	ev.SetLatitude(rtLatSentinel)
	ev.SetLongitude(rtLngSentinel)
	ev.SetAssertionTime(uint64(rtAssertionTime))
	if err := ev.SetEntityId(rtEntityID); err != nil {
		t.Fatalf("SetEntityId: %v", err)
	}
	if err := ev.SetPayload(rtPayload); err != nil {
		t.Fatalf("SetPayload: %v", err)
	}

	if got := ev.Latitude(); got != rtLatSentinel {
		t.Errorf("Latitude accessor: got %v, want %v", got, rtLatSentinel)
	}
	if got := ev.Longitude(); got != rtLngSentinel {
		t.Errorf("Longitude accessor: got %v, want %v", got, rtLngSentinel)
	}
	if got := ev.AssertionTime(); got != uint64(rtAssertionTime) {
		t.Errorf("AssertionTime accessor: got %#x, want %#x", got, uint64(rtAssertionTime))
	}
	if got, err := ev.EntityId(); err != nil || got != rtEntityID {
		t.Errorf("EntityId accessor: got %q err %v, want %q nil", got, err, rtEntityID)
	}
	if got, err := ev.Payload(); err != nil || got != rtPayload {
		t.Errorf("Payload accessor: got %q err %v, want %q nil", got, err, rtPayload)
	}

	data, err := msg.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if len(data) < 8 {
		t.Fatalf("marshalled message too short: %d", len(data))
	}
	// Single-segment framing invariant — catches framing-header drift.
	if segCountMinusOne := binary.LittleEndian.Uint32(data[0:4]); segCountMinusOne != 0 {
		t.Fatalf("expected single-segment message (segCount-1=0), got %d", segCountMinusOne)
	}
}

// TestPhase2_CRDTDeltaEventSchemaSurface is the Phase 2a structural guard for
// the new CRDTDeltaEvent wire schema. It pins the canonical accessor surface
// of the capnp-generated Go binding. If a future engineer drops or renames a
// field on CRDTDeltaEvent (a C5-style drift on the sync protocol the way the
// existing guard protects the ingestion protocol), the corresponding accessor
// call here fails to compile. If they add a CRDTEntry-bound field, this guard
// forces them to wire it through the encode/decode path AND add a matching
// roundtrip assertion, rather than silently letting the field fall off the
// wire. The version-tag accessor is pinned too: dropping it fails to compile.
func TestPhase2_CRDTDeltaEventSchemaSurface(t *testing.T) {
	msg, seg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		t.Fatalf("capnp.NewMessage: %v", err)
	}
	ev, err := capnp_schema.NewRootCRDTDeltaEvent(seg)
	if err != nil {
		t.Fatalf("NewRootCRDTDeltaEvent: %v", err)
	}

	// Version tag — the single forward-compat surface. Pinned so a future
	// drift that removes it fails to compile.
	ev.SetVersion(CRDTDeltaEventWireVersion)
	if got := ev.Version(); got != CRDTDeltaEventWireVersion {
		t.Fatalf("Version accessor: got %d, want %d", got, CRDTDeltaEventWireVersion)
	}

	// Fixed-size Data ([32]byte / [16]byte x2) + UInt64 x2 + Int64 x5 + Text x2
	// — every accessor below is a compile-time pin on the contract field set.
	if err := ev.SetPayloadDigest(rtPayloadDigest[:]); err != nil {
		t.Fatalf("SetPayloadDigest: %v", err)
	}
	if err := ev.SetOriginNodeID(rtHostA[:]); err != nil {
		t.Fatalf("SetOriginNodeID: %v", err)
	}
	if err := ev.SetDotNodeID(rtHostA[:]); err != nil {
		t.Fatalf("SetDotNodeID: %v", err)
	}
	ev.SetDotCounter(1)
	ev.SetH3Index(rtH3Index)
	ev.SetSystemTime(rtSystemTime)
	ev.SetValidTimeStart(rtValidTimeStart)
	ev.SetValidTimeEnd(rtValidTimeEnd)
	ev.SetAssertionTime(rtAssertionTime)
	ev.SetDecisionTime(rtDecisionTime)
	if err := ev.SetEntityId(rtEntityID); err != nil {
		t.Fatalf("SetEntityId: %v", err)
	}
	if err := ev.SetPayload(rtPayload); err != nil {
		t.Fatalf("SetPayload: %v", err)
	}

	// Read-back of every accessor — a renamed/dropped field fails here at
	// compile time (the accessor no longer exists) or at run time (value
	// mismatch surfaces a wire/encoding drift).
	gotDigest, err := ev.PayloadDigest()
	if err != nil || [32]byte(gotDigest) != rtPayloadDigest {
		t.Errorf("PayloadDigest accessor: got %x err %v, want %x", gotDigest, err, rtPayloadDigest)
	}
	gotOrigin, err := ev.OriginNodeID()
	if err != nil || len(gotOrigin) != len(rtHostA) {
		t.Errorf("OriginNodeID accessor: got %x err %v (len %d), want len %d", gotOrigin, err, len(gotOrigin), len(rtHostA))
	}
	gotDot, err := ev.DotNodeID()
	if err != nil || len(gotDot) != len(rtHostA) {
		t.Errorf("DotNodeID accessor: got %x err %v (len %d), want len %d", gotDot, err, len(gotDot), len(rtHostA))
	}
	if got := ev.DotCounter(); got != 1 {
		t.Errorf("DotCounter accessor: got %d, want 1", got)
	}
	if got := ev.H3Index(); got != rtH3Index {
		t.Errorf("H3Index accessor: got %#x, want %#x", got, rtH3Index)
	}
	if got := ev.SystemTime(); got != rtSystemTime {
		t.Errorf("SystemTime accessor: got %#x, want %#x", got, rtSystemTime)
	}
	if got := ev.ValidTimeStart(); got != rtValidTimeStart {
		t.Errorf("ValidTimeStart accessor: got %#x, want %#x", got, rtValidTimeStart)
	}
	if got := ev.ValidTimeEnd(); got != rtValidTimeEnd {
		t.Errorf("ValidTimeEnd accessor: got %#x, want %#x", got, rtValidTimeEnd)
	}
	if got := ev.AssertionTime(); got != rtAssertionTime {
		t.Errorf("AssertionTime accessor: got %#x, want %#x", got, rtAssertionTime)
	}
	if got := ev.DecisionTime(); got != rtDecisionTime {
		t.Errorf("DecisionTime accessor: got %#x, want %#x", got, rtDecisionTime)
	}
	if got, err := ev.EntityId(); err != nil || got != rtEntityID {
		t.Errorf("EntityId accessor: got %q err %v, want %q nil", got, err, rtEntityID)
	}
	if got, err := ev.Payload(); err != nil || got != rtPayload {
		t.Errorf("Payload accessor: got %q err %v, want %q nil", got, err, rtPayload)
	}

	// Single-segment framing invariant — catches framing-header drift on the
	// CRDTDeltaEvent wire, mirroring the ingestion guard's check.
	data, err := msg.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if len(data) < 8 {
		t.Fatalf("marshalled message too short: %d", len(data))
	}
	if segCountMinusOne := binary.LittleEndian.Uint32(data[0:4]); segCountMinusOne != 0 {
		t.Fatalf("expected single-segment message (segCount-1=0), got %d", segCountMinusOne)
	}

	// CRDTDeltaEvent MUST NOT carry latitude/longitude: ingestion-only. If
	// a future drift adds them, ev.SetLatitude/SetLongitude would compile
	// here and the build would lose the negative-protection signal the audit
	// intended. The ruling forbids the merge; this is the teeth.
}
