// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package transport

import (
	"encoding/binary"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hr18vk/sovereign/internal/database"

	capnp "capnproto.org/go/capnp/v3"
	capnp_schema "github.com/hr18vk/sovereign/api/capnp/api/capnp"
)

// TestParseMessages_RealClient_EndToEnd sends a TriTemporalEvent over a Unix
// domain socket and verifies the field values received by the handler.
func TestParseMessages_RealClient_EndToEnd(t *testing.T) {
	allocator := database.NewJemallocAllocator()

	var got atomic.Value // stores value copies of the parsed event fields

	handler := func(event capnp_schema.TriTemporalEvent) error {
		// Copy the fields before the event becomes invalid on return.
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

	// A Unix socket gives the client a deterministic address without needing
	// to discover a TCP listener's ephemeral port.
	sockPath := "/tmp/sovereign-test-" + t.Name() + ".sock"
	addr := "unix:" + sockPath

	errCh := make(chan error, 1)
	go func() { errCh <- server.ListenAndServe(addr) }()
	// Allow the listener to bind before dialing.
	time.Sleep(50 * time.Millisecond)

	// Send one TriTemporalEvent to the listener.
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

	// Poll for the handler for up to two seconds.
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
	t.Fatal("handler did not receive the event within 2 seconds")
}

// buildTestMessage is defined in capnp_server_test.go. These references retain
// the encoding-related imports used by this test file.
var _ = binary.LittleEndian
var _ = capnp.NewMessage
