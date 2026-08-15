package mesh

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hr18vk/supremum/pkg/durability"
	"github.com/hr18vk/supremum/pkg/identity"
	eng "github.com/hr18vk/supremum/pkg/sync"
)

// TestControlInsert_WALFailureReturns503 is the Day-8.5 STEP-3b ACK-contract
// tooth. It proves the handleInsert guard (control.go STEP-1): when the
// durability Bridge's origin PutLocal fsync-fails, InsertLocalEvents returns a
// zero CausalDot, and handleInsert MUST return HTTP 503 — NOT a lying 200 +
// all-zero DotHex. The forced failure is the production-shaped one: the WAL
// file is pre-closed so the next AppendMutation's f.Write/fsync errors. This
// is the exact contract Stop:1 closes; before it, a WAL-failed write was ACKed
// 200 with a zero dot receipt (the ACK-before-durability breach).
func TestControlInsert_WALFailureReturns503(t *testing.T) {
	// Build a Gossiper bound to a TRUE durability Bridge (the production
	// --wal-path path). InsertLocalEvents routes through PutLocal →
	// AppendMutation (fsync). A gossiper with a nil PeerSet is safe for the
	// /v1/insert path: InsertLocalEvents touches only g.bridge + g.cache +
	// g.engine, never g.peers (verified: grep). The engine + identity are the
	// only dependencies of /v1/insert; no TLS listener is needed (we hit
	// ControlServer.Handler() over an httptest.Server, not a tls.Listen).
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

	// FORCE THE DURABILITY FAILURE: pre-close the WAL so the very next
	// AppendMutation's f.Write + f.Sync both error. This is the exact
	// production failure mode (a disk-full or I/O error on the WAL). PutLocal
	// returns the error; InsertLocalEvents surfaces it as eng.CausalDot{};
	// handleInsert MUST return 503. WITH the STEP-1 fix an un-closed WAL's
	// first PutLocal still succeeds (the engine.InsertLocal mints the dot
	// BEFORE AppendMutation, so a successful write leaves the dot valid even
	// though the WAL append later fails) — THAT is the contract: a zero dot on
	// a FSYNC-FAILED write, surfaced as 503. So we must close the WAL AND
	// confirm the resulting dot is zero, else the tooth guards the wrong thing.
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
		t.Fatalf("ACK-before-durability breach: WAL-failed insert returned HTTP %d, want 503 (the STEP-1 guard must refuse to ACK a non-durable write)", resp.StatusCode)
	}
	var r insertResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		t.Fatalf("decode 503 body: %v", err)
	}
	if r.DotHex != "" {
		t.Fatalf("503 body DotHex = %q, want empty (no receipt for a non-durable write)", r.DotHex)
	}
}

// TestControlInsert_DurableWriteReturns200 is the positive control for the
// ACK-contract: a healthy durable write (bridge active, WAL open) MUST return
// 200 with a non-empty DotHex — so the STEP-1 guard does NOT false-fire on the
// happy path. This is the red→green anchor: this tooth is green at HEAD (pre-
// fix) AND green after STEP-1 (the guard is conservative — durable writes pass
// straight through to the 200 branch).
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
		t.Fatalf("durable insert returned HTTP %d, want 200 (the STEP-1 guard must NOT false-fire on a healthy durable write)", resp.StatusCode)
	}
	var r insertResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		t.Fatalf("decode 200 body: %v", err)
	}
	if r.DotHex == "" || r.DotHex == allZeroHex() {
		t.Fatalf("200 body DotHex = %q, want a non-empty non-zero receipt for a durable write", r.DotHex)
	}
}

// test503NodeID is a deterministic, distinct-from-origin 16-byte nodeID for the
// 503 tooth's engine (NOT the rcvOriginNodeID — a fresh, self-consistent ID so
// the engine's localNodeID is non-zero, guaranteeing a healthy minted dot can
// never equal the zero sentinel eng.CausalDot{}).
var test503NodeID = [16]byte{0x50, 0x53, 0x30, 0x33}

// allZeroHex is the 48-char all-'0' string (the hex of a zero CausalDot:
// 16-byte NodeID || 8-byte counter, both zero = 48 zero hex chars). A durable
// write's dot carries the non-zero localNodeID, so its hex never equals this.
func allZeroHex() string { return strings.Repeat("0", 48) }
