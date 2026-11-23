// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// These tests cover per-sweep peer counts, digest request and response bytes,
// and shipped payload bytes. A two-node loopback mesh supplies real traffic;
// the heartbeat assertion checks that the same measurements appear in the log.
// The bytesBlind control suppresses byte accounting without suppressing sends,
// so the byte assertions have a reachable failure mode.

import (
	"log"
	"os"
	"strings"
	"testing"
)

func TestP1BiiiSweepTermsGreen(t *testing.T) {
	h := newStratifiedHarness(t, true) // Loopback TLS with live readers and responders.
	defer h.close()
	h.insertEvents(t, 20) // Ten entries on each node make the roots diverge.
	st := h.gA.AntiEntropySweep(h.ctx)
	if st.firedPeers != 1 {
		t.Fatalf("firedPeers=%d, want 1 for the single live peer", st.firedPeers)
	}
	if st.gatedSkips != 0 {
		t.Fatalf("gatedSkips=%d, want 0 because the first sweep has no previous gate root", st.gatedSkips)
	}
	if st.shippedBytes <= 0 {
		t.Fatalf("shippedBytes=%d, want a positive count for frames sent to the live peer", st.shippedBytes)
	}
	if st.shippedBytes < 70 {
		t.Fatalf("shippedBytes=%d, want at least the approximately 70-byte payload floor for 10 entries", st.shippedBytes)
	}
	if st.digestReqBytes <= 0 {
		t.Fatalf("digestReqBytes=%d, want a positive count for the stratified digest request", st.digestReqBytes)
	}
	// Drive sweepOnce until its periodic heartbeat emits the measurement fields.
	var buf quintetLogBuf
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	for r := 0; r < 100; r++ {
		h.gA.sweepOnce(h.ctx)
		h.gB.sweepOnce(h.ctx)
	}
	buf.mu.Lock()
	all := buf.buf.String()
	buf.mu.Unlock()
	var line string
	for _, l := range strings.Split(all, "\n") {
		if strings.Contains(l, "sweep round=") {
			line = l
		}
	}
	if line == "" {
		t.Fatalf("no heartbeat line after 100 sweepOnce rounds")
	}
	for _, tok := range []string{" fired=", " gated_sweep=", " ship_bytes=", " digest_req_bytes=", " resp_bytes="} {
		if !strings.Contains(line, tok) {
			t.Fatalf("heartbeat line is missing %s: %q", tok, line)
		}
	}
}

// TestP1BiiiBytesBlindNeuter checks that bytesBlind suppresses both per-sweep
// byte totals while frames are still sent and the fired-peer count is retained.
func TestP1BiiiBytesBlindNeuter(t *testing.T) {
	h := newStratifiedHarness(t, true)
	defer h.close()
	h.insertEvents(t, 20)
	h.gA.bytesBlind.Store(true)
	defer h.gA.bytesBlind.Store(false)
	st := h.gA.AntiEntropySweep(h.ctx)
	if st.shippedBytes != 0 || st.digestReqBytes != 0 {
		t.Fatalf("blind control: shippedBytes=%d digestReqBytes=%d, want both zero with firedPeers=%d", st.shippedBytes, st.digestReqBytes, st.firedPeers)
	}
	if st.firedPeers != 1 {
		t.Fatalf("blind control: firedPeers=%d, want 1 because byte accounting does not gate sends", st.firedPeers)
	}
}
