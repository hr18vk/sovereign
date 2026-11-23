// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package main

// acceptLogLine limits per-connection Accept logs to the first 8 and every
// 1024th thereafter. Verdict metrics retain the full count. Before this cap,
// one node in a 100-node relay run emitted 120,354 Accept lines.

import "testing"

func TestAcceptLogLine_Capped(t *testing.T) {
	// The first eight Accepts provide an initial diagnostic window.
	for n := int64(1); n <= 8; n++ {
		if !acceptLogLine(n) {
			t.Fatalf("accept #%d must log within the initial window", n)
		}
	}
	for n := int64(9); n < 1024; n++ {
		if acceptLogLine(n) {
			t.Fatalf("accept #%d must be suppressed before the next interval", n)
		}
	}
	for _, n := range []int64{1024, 2048, 3072} {
		if !acceptLogLine(n) {
			t.Fatalf("accept #%d must log at the 1024-accept interval", n)
		}
	}
	if acceptLogLine(1025) {
		t.Fatal("accept #1025 must not log")
	}
}
