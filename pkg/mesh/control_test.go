// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hr18vk/sovereign/pkg/durability"
	"github.com/hr18vk/sovereign/pkg/identity"
	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// TestControlInsert_WALFailureReturns503 checks the durability acknowledgment
// contract. Closing the WAL makes the next AppendMutation write and fsync fail.
// InsertLocalEvents then returns a zero CausalDot, and handleInsert must return
// HTTP 503 with an empty DotHex rather than acknowledge a non-durable write.
func TestControlInsert_WALFailureReturns503(t *testing.T) {
	// Bind a real durability Bridge, as --wal-path does. InsertLocalEvents
	// routes through PutLocal and AppendMutation. The insert path uses only
	// the bridge, payload cache, and engine, so a nil PeerSet and an
	// httptest.Server are sufficient; no TLS listener is needed.
	eng.DataDir = t.TempDir()
	engine, err := eng.NewDeltaCRDTEngine(test503NodeID, 1, 64*1024*1024)
	if err != nil {
		t.Fatalf("NewDeltaCRDTEngine: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })

	walPath := filepath.Join(t.TempDir(), "wal-fail.wal")
	wal, err := durability.OpenWAL(walPath)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	bridge := durability.NewBridge(engine, wal, 0)
	g := NewGossiper(nil, nil, engine, identity.NewDirectory())
	g.SetBridge(bridge)

	// Pre-close the WAL so the next AppendMutation write and Sync both fail,
	// as they would after a disk or I/O error. PutLocal returns the error and
	// InsertLocalEvents converts it to the zero-dot signal. The test decodes
	// the HTTP response below to check that no receipt is returned.
	if err := wal.Close(); err != nil {
		t.Fatalf("pre-close WAL (force failure): %v", err)
	}

	cs := NewControlServer(g, test503NodeID, nil, nil)
	srv := httptest.NewServer(cs.Handler())
	t.Cleanup(srv.Close)

	body, _ := json.Marshal(map[string]string{"key": "soft", "val": "fail"})
	resp, err := http.Post(srv.URL+"/v1/insert", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /v1/insert: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("ACK-before-durability breach: WAL-failed insert returned HTTP %d, want 503 (the guard must refuse to ACK a non-durable write)", resp.StatusCode)
	}
	var r insertResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		t.Fatalf("decode 503 body: %v", err)
	}
	if r.DotHex != "" {
		t.Fatalf("503 body DotHex = %q, want empty (no receipt for a non-durable write)", r.DotHex)
	}
}

// TestControlInsert_DurableWriteReturns200 checks that an active bridge and
// open WAL produce HTTP 200 with a non-empty, nonzero DotHex. The failure guard
// must not reject a durable write.
func TestControlInsert_DurableWriteReturns200(t *testing.T) {
	eng.DataDir = t.TempDir()
	engine, err := eng.NewDeltaCRDTEngine(test503NodeID, 1, 64*1024*1024)
	if err != nil {
		t.Fatalf("NewDeltaCRDTEngine: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })

	walPath := filepath.Join(t.TempDir(), "wal-ok.wal")
	wal, err := durability.OpenWAL(walPath)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	t.Cleanup(func() { _ = wal.Close() })
	bridge := durability.NewBridge(engine, wal, 0)
	g := NewGossiper(nil, nil, engine, identity.NewDirectory())
	g.SetBridge(bridge)

	cs := NewControlServer(g, test503NodeID, nil, nil)
	srv := httptest.NewServer(cs.Handler())
	t.Cleanup(srv.Close)

	body, _ := json.Marshal(map[string]string{"key": "soft", "val": "durable"})
	resp, err := http.Post(srv.URL+"/v1/insert", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /v1/insert: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("durable insert returned HTTP %d, want 200 (the guard must not false-fire on a healthy durable write)", resp.StatusCode)
	}
	var r insertResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		t.Fatalf("decode 200 body: %v", err)
	}
	if r.DotHex == "" || r.DotHex == allZeroHex() {
		t.Fatalf("200 body DotHex = %q, want a non-empty non-zero receipt for a durable write", r.DotHex)
	}
}

// test503NodeID is a deterministic, nonzero 16-byte node ID. A healthy dot
// carries this ID and therefore cannot equal the zero CausalDot sentinel.
var test503NodeID = [16]byte{0x50, 0x53, 0x30, 0x33}

// allZeroHex encodes a zero CausalDot: a zero 16-byte NodeID followed by a
// zero eight-byte counter, for 48 hexadecimal zeros in total.
func allZeroHex() string { return strings.Repeat("0", 48) }
