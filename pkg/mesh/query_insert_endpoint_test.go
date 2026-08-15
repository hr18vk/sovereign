package mesh

// Day-12.5 — the production-flow round-trip tooth (the post-hoc G-I2 closure).
//
// The Day-12 teeth (query_test.go) proved the Resolver.AsOf ↔ LocalFS ↔ Arrow
// seam by calling bridge.PutLocal(.., queryTestEntry(..)) DIRECTLY — a custom
// CRDTEntry with a real open-ended ValidTime range (queryValidEndNs ≈ 9e18).
// That seam is sound. But the Day-12 audit (live-reproduced this session, byte-
// verified) found that the PRODUCTION HTTP write path, handleInsert
// (control.go), stamped `entry := eng.CRDTEntry{}` — all-zero ValidTime, so the
// persisted row's [validStart, validEnd) = [0, 0) interval was EMPTY by
// construction, and AsOf's Filter 3 (query.go:360: `validTimeNs >= validEnd`)
// skipped it for EVERY query point. POST /v1/insert wonder=... → 200, GET
// /v1/get → 200 present:true, GET /v1/query → 404 — the round-trip advertised
// by ADR-0017 did NOT close through the HTTP surface. The teeth passed only
// because they BYPASSED handleInsert; they never exercised
// POST /v1/insert → GET /v1/query.
//
// This tooth closes that gap: it drives the REAL production flow end-to-end
// through httptest — POST /v1/insert → handleInsert stamps the Day-12.5
// open-ended ValidTime default → InsertLocalEvents → bridge.PutLocal (durable
// + fsync'd) → the interval-triggered AppendCheckpoint writes the dot-bearing
// image + the l0/*.arrow query index (the Day-11 wired seam) → the Resolver
// over the SAME LocalFS reads it back via /v1/query → the handler returns 200
// with the HONEST digest (no fabricated payload — Law V).
//
// RED→GREEN (chronology, the Day-12 prompt's discipline):
//   RED  (un-fix control): stashing the Day-12.5 handleInsert patch makes
//        handleInsert re-stamp CRDTEntry{} → the row's ValidTime range is empty
//        → /v1/query 404s on the just-written event. The tooth asserts that
//        404 to PROVE the pre-fix behavior is the production failure (NOT a
//        constructed failure).
//   GREEN(post-fix): the Day-12.5 open-ended default stamps
//        ValidTimeEnd = OpenEndedValidEndNs → the interval is non-empty →
//        /v1/query 200 with the persisted digest → the round-trip CLOSES.
//
// The honest framing (Law V): the open-ended default is the DOCUMENTED default
// for a DOCUMENTED absence — a client that asserts no bitemporal window means
// "valid from write-time, indefinitely" (the only semantics a non-bitemporal
// write API can honestly carry). It is NOT a fabricated range asserted as if
// the client had claimed it; the bitemporal opt-in (valid_from_ns /
// valid_for_ns) lets a client override it explicitly. Disclosed in ADR-0017 §6.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hr18vk/supremum/internal/database"
	"github.com/hr18vk/supremum/pkg/durability"
	"github.com/hr18vk/supremum/pkg/identity"
	eng "github.com/hr18vk/supremum/pkg/sync"
)

// insertRoundTripHarness builds the production-shaped runtime: a durable
// DeltaCRDTEngine + a Bridge with checkpointInterval=1 (an AppendCheckpoint +
// snapshot+index on EVERY PutLocal, mirroring --wal-checkpoint-interval 1 in
// the live drive), SetSnapshotter(lfs, true) so the checkpoint writes the
// dot-bearing image AND the l0/*.arrow query index, a Gossiper over the bridge
// (the /v1/insert path goes through gossiper.InsertLocalEvents), a Resolver
// over the SAME lfs (the read path), and a ControlServer with the resolver
// wired (the /v1/query path). It returns the httptest server so the tooth
// drives the REAL HTTP flow.
//
// checkpointInterval=1 is load-bearing: PutLocal triggers AppendCheckpoint
// internally after the WAL append (bridge.go:211), so a single POST /v1/insert
// writes BOTH the durable WAL record AND the l0 query index — the production
// flow /v1/query needs to read. No manual AppendCheckpoint call in the tooth
// (that would re-introduce the bypass).
func insertRoundTripHarness(t *testing.T) (srv *httptest.Server, lfs *durability.LocalFS) {
	t.Helper()
	const interval uint64 = 1 // one PutLocal → one checkpoint+snapshot+index

	eng.DataDir = t.TempDir()
	engine, err := eng.NewDeltaCRDTEngine(queryTestNodeID, 1, queryTestArenaSize)
	if err != nil {
		t.Fatalf("NewDeltaCRDTEngine: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })

	walPath := t.TempDir() + "/rt.wal"
	wal, err := durability.OpenWAL(walPath)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	t.Cleanup(func() { _ = wal.Close() })

	lfsRoot := t.TempDir() + "/snap"
	lfs, err = durability.NewLocalFS(lfsRoot)
	if err != nil {
		t.Fatalf("NewLocalFS: %v", err)
	}

	bridge := durability.NewBridge(engine, wal, interval)
	bridge.SetSnapshotter(lfs, true) // recovery image + Arrow query index per checkpoint

	// Gossiper over the bridge (the /v1/insert routing path). No identity dir
	// is needed for the insert-only flow; identity.NewDirectory is the same
	// zero-arg ctor main.go passes for the single-node case.
	g := NewGossiper(nil, nil, engine, identity.NewDirectory())
	g.SetBridge(bridge)

	resolver := database.NewResolver(lfs, lfs, database.NewJemallocAllocator(), "local", database.DefaultResolverConfig())

	cs := NewControlServer(g, queryTestNodeID, nil, nil)
	cs.SetResolver(resolver)
	srv = httptest.NewServer(cs.Handler())
	t.Cleanup(srv.Close)
	return srv, lfs
}

// insertViaHTTP POSTs /v1/insert with the legacy 2-field body (no bitemporal
// opt-in) — EXACTLY the body the live drive used and EXACTLY the body the SDK +
// existing control_test teeth use. The Day-12.5 fix's default (open-ended
// ValidTime) applies; that is what this tooth exercises (the production
// surface, not the bypass).
func insertViaHTTP(t *testing.T, srv *httptest.Server, key, val string) (int, []byte) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"key": key, "val": val})
	resp, err := http.Post(srv.URL+"/v1/insert", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /v1/insert: %v", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /v1/insert body: %v", err)
	}
	return resp.StatusCode, b
}

// TestQuery_InsertEndpointToQueryEndpoint_RoundTrip is DAY-12.5 T-I2 — the
// load-bearing POST /v1/insert → GET /v1/query production round-trip. It is
// the tooth the Day-12 T1 should have been: it drives the REAL write surface
// (handleInsert), NOT bridge.PutLocal with a hand-tuned queryTestEntry.
//
// What it proves (GREEN post-fix):
//
//	(1) the write landed durably (200 + a non-zero DotHex from handleInsert);
//	(2) the index row is on disk at the byte-correct prefix
//	    (l0/{hex(sha256(key)[:8])}/);
//	(3) GET /v1/query returns 200 with the SAME PayloadDigestInline the write
//	    produced (sha256(val) — the honest digest, NOT a fabricated payload);
//	(4) the round-trip is CLOSED through the HTTP surface — the production
//	    claim ADR-0017 advertises.
//
// What it does NOT prove (honest scope):
//   - a client-asserted bitemporal window (the opt-in valid_from_ns / valid_for_ns
//     branch) — a separate tooth would exercise the explicit-window path; here
//     the default-only path is load-bearing (it's the SDK + live-drive surface).
//   - crash-recover-then-query — the existing TestQuery_ResilientAfterBounded
//     Recovery_HistorySurvivesCrash (T2) covers the crash arc, but bypasses
//     handleInsert the same way; closing that combination is a Day-12.5+ tooth.
//
// RED control (the pre-fix failure is the production signature): at the un-fixed
// HEAD (stashed handleInsert re-stamping CRDTEntry{}), the same POST + GET yields
// a 404 "not found" on the just-written event — the exact behavior the live drive
// reproduced. The tooth's RED control RUNS the un-fix behavior in a subtest that
// stamps a zero-valid-range entry via a SECOND httptest path... but that would
// require a code-path the fix deliberately removed, so the RED is verified by
// stash+run (Law II, byte-verified pre/post), not by a fabricated RED subtest.
func TestQuery_InsertEndpointToQueryEndpoint_RoundTrip(t *testing.T) {
	const key = "i2-wonder"
	const val = "day12-read-half"

	srv, lfs := insertRoundTripHarness(t)

	// (1) POST /v1/insert — the production write, NO bitemporal opt-in (the
	// Day-12.5 default applies). 200 + a non-zero DotHex.
	status, body := insertViaHTTP(t, srv, key, val)
	if status != http.StatusOK {
		t.Fatalf("POST /v1/insert returned %d, want 200: %s", status, body)
	}
	var ins insertResponse
	if err := json.Unmarshal(body, &ins); err != nil {
		t.Fatalf("decode insert body: %v (body=%s)", err, body)
	}
	if ins.DotHex == "" || ins.DotHex == strings.Repeat("0", 48) {
		t.Fatalf("insert body DotHex = %q, want a non-empty non-zero receipt (the write is durable)", ins.DotHex)
	}

	// (2) The index row is on disk at the byte-correct prefix. l0 listing is a
	// WITNESS that the WRITE half closed (Day-11 wired the Snapshotter; Day-12
	// wired the Resolver; Day 12.5 stamps the ValidTime default so the READ
	// half sees the row). It is NOT a fabricated-assertion of round-trip
	// success — the (3)/(4) asserts below are the load-bearing proof.
	expectedPrefix := l0PrefixDir(key)
	keys, err := lfs.ListObjects(context.Background(), "local", "l0/"+expectedPrefix+"/", 0)
	if err != nil {
		t.Fatalf("ListObjects l0/%s/: %v", expectedPrefix, err)
	}
	if len(keys) == 0 {
		t.Fatalf("WITNESS INDEX MISSING: no l0/%s/*.arrow on disk (AppendCheckpoint did NOT flush the index — the Day-11 seam is unwired, OR handleInsert did not route through the bridge)", expectedPrefix)
	}
	t.Logf("WITNESS INDEX: %d l0 file(s) under l0/%s/ on disk", len(keys), expectedPrefix)

	// (3) GET /v1/query — POST time. valid_time = NOW (the write's
	// ValidTimeStart defaulted to write-time, which is <= now), tx_time = NOW
	// (the write's SystemTime <= now — Filter 2 admits it). The row's open-
	// ended ValidTimeEnd (OpenEndedValidEndNs) dominates valid_time → Filter 3
	// admits it → AsOf returns the persisted event.
	now := time.Now().UTC()
	qStatus, qBody := queryGet(t, srv, key, now, now)
	if qStatus != http.StatusOK {
		t.Fatalf("GET /v1/query returned %d, want 200 (the round-trip is CLOSED): %s",
			qStatus, qBody)
	}
	var qr queryResponse
	if err := json.Unmarshal(qBody, &qr); err != nil {
		t.Fatalf("decode query body: %v (body=%s)", err, qBody)
	}
	if !qr.Present {
		t.Fatalf("query response Present = false, want true (AsOf found the row)")
	}
	if qr.EntityID != key {
		t.Fatalf("query EntityID = %q, want %q", qr.EntityID, key)
	}
	// (4) the HONEST digest round-trips verbatim — NOT a fabricated payload
	// value (the G06.e guard). The index stores the real digest + a SENTRY
	// body; AsOf echoes the digest. sha256(val) is the digest handleInsert's
	// InsertLocalEvents path stamps (bridge.go:182 sha256(payload)).
	wantDigest := sha256sumHex(val)
	if qr.PayloadDigestHex != wantDigest {
		t.Fatalf("round-trip digest BROKEN:\n  got  = %s\n  want = %s\n"+
			"The persisted Arrow row's PayloadDigest must equal sha256(val) — the WRITE's honest digest. A mismatch means either the write stamped a different digest (a fabrication) OR the read decoded it wrong (a data-loss seam).",
			qr.PayloadDigestHex, wantDigest)
	}
	// Law V: the query response MUST NOT carry a payload field — the index
	// stores a SENTRY body; echoing one would be the G06.e fabrication.
	if hasPayloadField(qBody) {
		t.Fatalf("G06.e fabrication: query response carries a 'payload' field (the index stores a SENTRY body — the handler must echo the digest ONLY, not a value)")
	}
	t.Logf("DAY-12.5 T-I2 GREEN: POST /v1/insert → GET /v1/query closed: digest %s round-tripped verbatim (the production HTTP round-trip is CLOSED).",
		qr.PayloadDigestHex)
}

// l0PrefixDir computes the SAME hash prefix the write path uses to key the
// l0/{prefix}/ dir: hex(sha256(entityID)[:8]). It mirrors memtable.go's key
// layout (Override 8.4) and l0_flusher.go's dir naming. Used as a WITNESS of
// the write-path byte-identity (Law II), NOT as a read-side assertion (AsOf
// does its own hash computation).
func l0PrefixDir(entityID string) string {
	full := sha256sumRaw(entityID)
	return hexEncode8(full[:8])
}

// sha256sumHex returns the lowercase hex sha256 of s (the honest digest the
// write stamps from the payload and the read echoes back).
func sha256sumHex(s string) string {
	full := sha256sumRaw(s)
	return hexEncode32(full[:])
}

// sha256sumRaw returns the raw 32-byte sha256 of s. Hoisted so the tooth does
// not import crypto/sha256 inline (mirrors query_test.go's queryDigest).
func sha256sumRaw(s string) [32]byte {
	// local sha256 — avoid adding a new top-of-file import; reuse the package's
	// existing crypto/sha256 import via a thin local alias.
	return queryDigest(s)
}

// hexEncode8 / hexEncode32 — lowercase hex for the 8- and 32-byte slices.
func hexEncode8(b []byte) string  { return hexLower(b) }
func hexEncode32(b []byte) string { return hexLower(b) }

// hexLower is the lowercase hex encoder (avoids importing encoding/hex only for
// this tooth; query_test.go already relies on the package's hex import).
func hexLower(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = digits[v>>4]
		out[i*2+1] = digits[v&0xf]
	}
	return string(out)
}
