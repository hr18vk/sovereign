// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// This test drives POST /v1/insert through GET /v1/query using the production
// handlers, Bridge, snapshotter, LocalFS, and Resolver. Calling bridge.PutLocal
// directly would not cover handleInsert's valid-time defaults.
//
// An insert without valid_from_ns or valid_for_ns means valid from write time
// with no end. handleInsert therefore sets ValidTimeEnd to OpenEndedValidEndNs.
// Leaving both valid-time fields zero would construct the empty interval [0, 0),
// which AsOf excludes at every query time (ADR-0017 §6).
//
// A checkpoint interval of one persists the WAL record and schedules the
// dot-bearing image and Arrow index after each insert. The query response must
// return the stored payload digest; the index has a SENTRY body, not the original
// payload.

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

	"github.com/hr18vk/sovereign/internal/database"
	"github.com/hr18vk/sovereign/pkg/durability"
	"github.com/hr18vk/sovereign/pkg/identity"
	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// insertRoundTripHarness connects a durable engine, WAL, Bridge, LocalFS,
// Resolver, and ControlServer in the same arrangement as the node. Its checkpoint
// interval is one, so PutLocal schedules both the recovery image and the l0
// Arrow index after the WAL append. The test uses the resulting httptest server
// rather than calling AppendCheckpoint or Resolver.AsOf directly.
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

// insertViaHTTP posts the two-field insert body used by the SDK. Omitting the
// optional valid-time fields exercises handleInsert's open-ended default.
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

// TestQuery_InsertEndpointToQueryEndpoint_RoundTrip writes through handleInsert
// and reads the result through /v1/query. It requires a non-zero dot receipt, an
// Arrow file under l0/{hex(sha256(key)[:8])}/, and the SHA-256 payload digest in
// the query response. A payload field would not come from the SENTRY-bodied
// index and therefore fails the test.
//
// This covers the default valid-time path used by the SDK. Explicit
// valid_from_ns/valid_for_ns windows and crash recovery between insert and query
// are outside this test's scope.
func TestQuery_InsertEndpointToQueryEndpoint_RoundTrip(t *testing.T) {
	const key = "insert-roundtrip-key"
	const val = "read-half"

	srv, lfs := insertRoundTripHarness(t)

	// (1) POST /v1/insert — the production write, no bitemporal opt-in (the
	// default applies). 200 + a non-zero DotHex.
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

	// PutLocal returns after its WAL fsync, while drainCheckpoints writes the
	// query tier asynchronously. Poll for the expected Arrow object with a
	// deadline rather than treating the index as synchronously visible.
	expectedPrefix := l0PrefixDir(key)
	var keys []string
	ckptDeadline := time.Now().Add(10 * time.Second)
	for {
		var err error
		keys, err = lfs.ListObjects(context.Background(), "local", "l0/"+expectedPrefix+"/", 0)
		if err != nil {
			t.Fatalf("ListObjects l0/%s/: %v", expectedPrefix, err)
		}
		if len(keys) > 0 {
			break
		}
		if time.Now().After(ckptDeadline) {
			t.Fatalf("after 10s no l0/%s/*.arrow exists; the checkpoint did not flush the insert through the Bridge", expectedPrefix)
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Logf("found %d l0 file(s) under l0/%s/", len(keys), expectedPrefix)

	// Query at the current valid and transaction times. The insert's default
	// interval starts at write time and has no end, so AsOf must select the row.
	now := time.Now().UTC()
	qStatus, qBody := queryGet(t, srv, key, now, now)
	if qStatus != http.StatusOK {
		t.Fatalf("GET /v1/query returned %d, want 200: %s", qStatus, qBody)
	}
	var qr queryResponse
	if err := json.Unmarshal(qBody, &qr); err != nil {
		t.Fatalf("decode query body: %v (body=%s)", err, qBody)
	}
	if !qr.Present {
		t.Fatalf("query response Present=false, want true")
	}
	if qr.EntityID != key {
		t.Fatalf("query EntityID = %q, want %q", qr.EntityID, key)
	}
	wantDigest := sha256sumHex(val)
	if qr.PayloadDigestHex != wantDigest {
		t.Fatalf("query digest = %s, want sha256(val) = %s\n"+
			"The Arrow row must preserve the digest written by handleInsert.",
			qr.PayloadDigestHex, wantDigest)
	}
	if hasPayloadField(qBody) {
		t.Fatalf("query response contains a payload field, but the SENTRY-bodied index supports only the digest")
	}
	t.Logf("insert-to-query round trip returned digest %s", qr.PayloadDigestHex)
}

// l0PrefixDir returns hex(sha256(entityID)[:8]), the directory prefix used by
// memtable.go and l0_flusher.go for a single-entity flush.
func l0PrefixDir(entityID string) string {
	full := sha256sumRaw(entityID)
	return hexEncode8(full[:8])
}

// sha256sumHex returns the lowercase hexadecimal SHA-256 digest of s.
func sha256sumHex(s string) string {
	full := sha256sumRaw(s)
	return hexEncode32(full[:])
}

// sha256sumRaw shares the query harness's digest implementation.
func sha256sumRaw(s string) [32]byte {
	return queryDigest(s)
}

func hexEncode8(b []byte) string  { return hexLower(b) }
func hexEncode32(b []byte) string { return hexLower(b) }

// hexLower encodes b as lowercase hexadecimal.
func hexLower(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = digits[v>>4]
		out[i*2+1] = digits[v&0xf]
	}
	return string(out)
}
