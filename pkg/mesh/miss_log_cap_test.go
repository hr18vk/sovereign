// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// Per-ship payload and relay miss logs are limited to missLogCap entries by
// default. SOVEREIGN_MISS_LOG_CAP overrides that limit when a Gossiper is
// constructed; an unset or invalid value keeps the default (ADR-0071).
//
// These tests insert entries directly into the engine, bypassing the relay
// cache, and count the resulting payload-miss lines. The sweep's aggregate miss
// counter must include every miss regardless of the log limit.

import (
	"fmt"
	"log"
	"os"
	"testing"

	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// P1BivDrive constructs the harness after the environment is set, inserts 20
// cached entries split across two nodes and 10 uncached entries on node A, then
// runs one sweep on A. It returns the payload-miss line count and the sweep's
// aggregate miss count. NewGossiper reads SOVEREIGN_MISS_LOG_CAP once.
func P1BivDrive(t *testing.T) (missLines int, aggregate int) {
	t.Helper()
	h := newStratifiedHarness(t, true)
	defer h.close()
	h.insertEvents(t, 20)
	for i := 0; i < 10; i++ {
		e := eng.CRDTEntry{
			SystemTime: int64(1_700_000_000 + 100 + i),
			H3Index:    uint64(100 + i),
		}
		h.engineA.InsertLocal(fmt.Sprintf("p1biv-orphan-%d", i), e)
	}
	var buf quintetLogBuf
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	st := h.gA.AntiEntropySweep(h.ctx)
	return buf.count("payload miss"), st.payloadMisses
}

// TestP1BivMissLogCapLift checks that a limit of 100 logs all 10 uncached
// entries and leaves the aggregate miss count independent of the log limit.
func TestP1BivMissLogCapLift(t *testing.T) {
	t.Setenv("SOVEREIGN_MISS_LOG_CAP", "100")
	missLines, aggregate := P1BivDrive(t)
	if missLines != 10 {
		t.Fatalf("SOVEREIGN_MISS_LOG_CAP=100 produced %d payload-miss lines, want 10", missLines)
	}
	if aggregate < 10 {
		t.Fatalf("payloadMisses=%d, want at least 10 with log limit 100", aggregate)
	}
}

// TestP1BivMissLogCapBoundaryBinds checks that a limit of three emits exactly
// three lines rather than merely raising the default limit.
func TestP1BivMissLogCapBoundaryBinds(t *testing.T) {
	t.Setenv("SOVEREIGN_MISS_LOG_CAP", "3")
	missLines, aggregate := P1BivDrive(t)
	if missLines != 3 {
		t.Fatalf("SOVEREIGN_MISS_LOG_CAP=3 produced %d payload-miss lines, want 3", missLines)
	}
	if aggregate < 10 {
		t.Fatalf("payloadMisses=%d, want at least 10 with log limit 3", aggregate)
	}
}
