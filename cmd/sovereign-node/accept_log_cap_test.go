// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package main

// accept_log_cap_test.go — a post-review regression guard:
// the per-Accept log line is CAPPED (the first 8
// per conn + every 1024th), so the 100-node relay path cannot re-create the
// log storm on the accept side (120,354 lines on one node in one run
// pre-cap).

import "testing"

func TestAcceptLogLine_Capped(t *testing.T) {
	// The diagnostic window: the first 8 Accepts always log.
	for n := int64(1); n <= 8; n++ {
		if !acceptLogLine(n) {
			t.Fatalf("accept #%d must log (the diagnostic window)", n)
		}
	}
	// The storm zone: 9..1023 must be silent.
	for n := int64(9); n < 1024; n++ {
		if acceptLogLine(n) {
			t.Fatalf("accept #%d must NOT log (the cap); the missLogCap=8 class applies to the accept side too", n)
		}
	}
	// The heartbeat: every 1024th logs (liveness at volume).
	for _, n := range []int64{1024, 2048, 3072} {
		if !acceptLogLine(n) {
			t.Fatalf("accept #%d must log (the 1024-heartbeat)", n)
		}
	}
	if acceptLogLine(1025) {
		t.Fatal("accept #1025 must not log")
	}
}
