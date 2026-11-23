// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package database

import (
	"context"
	"testing"
	"time"

	"github.com/hr18vk/sovereign/internal/index"
)

// TestSecondaryIndex_CurrentStateContract verifies the current-state contract
// documented on QueryByH3, QueryBySystemTime, and CurrentState.
// A standard index receives two observations: entity e1 in cell A at sys=100,
// then a move to cell B at sys=200 (with valid windows covering the queried
// validTime). Two queries are tested at tx=150:
//   - cell A at tx=150 (before the move): the entity was in A at sys=100, but
//     the move removed A from the current-state index, returning 0 rows as a
//     disclosed under-approximation (no false positives).
//   - systime after=90 at tx=150: the entity's resolved sys=100 is >= 90 and
//     latest.sys=200 retains it as a candidate, returning 1 row at sys=100.
//
// Negative control: retaining old cells on move would return 1 row for cell A.
func TestSecondaryIndex_CurrentStateContract(t *testing.T) {
	ix := index.NewWith(index.DefaultShards, index.DefaultEpochNs)
	ix.Apply(index.Record{EntityID: "moved", H3Index: 0xEE01, SystemTime: 100})
	ix.Apply(index.Record{EntityID: "moved", H3Index: 0xEE02, SystemTime: 200})
	live := secondaryQueryLiveStub{events: map[string][]LiveEvent{
		"moved": {
			{SystemTime: 100, ValidTimeStart: 50, ValidTimeEnd: 400, AssertionTime: 100, H3Index: 0xEE01},
			{SystemTime: 200, ValidTimeStart: 50, ValidTimeEnd: 400, AssertionTime: 200, H3Index: 0xEE02},
		},
	}}
	r := newSecondaryQueryResolver(t, live, 4096)
	r.SetSecondaryIndexSource(ix)
	ctx := context.Background()
	valid := time.Unix(0, 100)
	tx := time.Unix(0, 150)
	// The H3 under-approximation: the entity was in 0xEE01 at
	// tx=150; the move to 0xEE02 dropped it from the candidate set.
	rows, disc, err := r.QueryByH3(ctx, 0xEE01, valid, tx)
	if err != nil {
		t.Fatalf("CurrentStateContract: unexpected error: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("CurrentStateContract: cell 0xEE01 at tx=150 returned %d rows, want 0 — the index must key current placements (a historical-retention change must update the contract and this test)", len(rows))
	}
	if !disc.CurrentState {
		t.Fatalf("CurrentStateContract: the H3 disclosure must carry CurrentState=true")
	}
	// The systime sharp edge: the same entity at the same past tx
	// resolves at sys=100 >= 90 and must be returned.
	rows2, disc2, err := r.QueryBySystemTime(ctx, time.Unix(0, 90), valid, tx)
	if err != nil {
		t.Fatalf("CurrentStateContract: systime error: %v", err)
	}
	if len(rows2) != 1 || rows2[0].SystemTime != 100 {
		t.Fatalf("CurrentStateContract: systime after=90 at tx=150 returned %d rows, want exactly 1 at sys=100 — the monotone-key exactness broke", len(rows2))
	}
	if !disc2.CurrentState {
		t.Fatalf("CurrentStateContract: the systime disclosure must carry CurrentState=true")
	}
}
