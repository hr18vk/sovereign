package transport

import (
	"encoding/binary"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hr18vk/supremum/internal/database"

	capnp "capnproto.org/go/capnp/v3"
	capnp_schema "github.com/hr18vk/supremum/api/capnp/api/capnp"
)

// TestParseMessages_RealClient_EndToEnd connects a live TCP client to the
// EPOLLET server, sends a Cap'n Proto TriTemporalEvent, and verifies the
// server parses it via the pinned zero-copy path and hands a structurally
// correct event to the handler — the == proof that runtime.Pinner + the
// generated bindings + SingleSegment arena agree end-to-end.
func TestParseMessages_RealClient_EndToEnd(t *testing.T) {
	allocator := database.NewJemallocAllocator()

	var got atomic.Value // stores a parsed TriTemporalEvent copy-snapshot

	handler := func(event capnp_schema.TriTemporalEvent) error {
		// Snapshot the parsed fields while Pinner holds the backing memory.
		lat := event.Latitude()
		lng := event.Longitude()
		ast := event.AssertionTime()
		eid, _ := event.EntityId()
		pl, _ := event.Payload()
		got.Store(struct {
			Lat, Lng      float64
			AssertionTime uint64
			EntityID      string
			Payload       string
		}{lat, lng, ast, eid, pl})
		return nil
	}

	server := NewEpollServer(allocator, handler)

	// Pick a fixed port by listening then capturing the bound addr is not
	// available without an ioctl; use ephemeral by binding the socket first.
	// Simpler: open a Unix socket in a temp path — deterministic address.
	sockPath := "/tmp/supremum-test-" + t.Name() + ".sock"
	addr := "unix:" + sockPath

	errCh := make(chan error, 1)
	go func() { errCh <- server.ListenAndServe(addr) }()
	// Give the server a beat to bind.
	time.Sleep(50 * time.Millisecond)

	// Dial the Unix socket and send a single TriTemporalEvent.
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		server.Shutdown()
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	data := buildTestMessage(t, 37.7749, -122.4194, 1719907200000, "entity-test-001", "subscription enrollment")
	if _, err := conn.Write(data); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Wait for the handler to fire (poll up to 2s).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if v := got.Load(); v != nil {
			s := v.(struct {
				Lat, Lng      float64
				AssertionTime uint64
				EntityID      string
				Payload       string
			})
			if s.Lat != 37.7749 || s.Lng != -122.4194 || s.AssertionTime != 1719907200000 ||
				s.EntityID != "entity-test-001" || s.Payload != "subscription enrollment" {
				t.Fatalf("handler got wrong event: %+v", s)
			}
			server.Shutdown()
			<-errCh
			return
		}
		time.Sleep(5 * time.Millisecond)
	}

	server.Shutdown()
	t.Fatal("handler did not fire within 2s — pinned zero-copy ingest path dead")
}

// Reference: buildTestMessage is defined in capnp_server_test.go. Silence
// unused-import warnings for symbols only referenced via that file.
var _ = binary.LittleEndian
var _ = capnp.NewMessage
