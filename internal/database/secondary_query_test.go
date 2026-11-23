// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package database

// Unit tests for cross-entity secondary index resolver composition
// (QueryByH3 and QueryBySystemTime).
//
// An empty durable store paired with a stub LiveSource exercises the resolver
// and trimming paths end-to-end without importing internal index or sync
// internals across packages.

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

// secondaryQueryNoopLister is the empty durable tier (following the earlier
// hNoopLister precedent): ListObjects returns nothing, Download fails.
type secondaryQueryNoopLister struct{}

func (secondaryQueryNoopLister) ListObjects(ctx context.Context, bucket, prefix string, maxKeys int) ([]string, error) {
	return nil, nil
}

func (secondaryQueryNoopLister) Download(ctx context.Context, bucket, key string) (io.ReadCloser, error) {
	return io.NopCloser(nil), errors.New("secondary-query: empty durable tier never downloads")
}

// secondaryQueryErrLister makes every AsOf call fail with a transient IO
// error (the list fails before any scan) — the error class exercised by
// TestSecondaryQuery_IOErrorReturnedNotSkipped.
type secondaryQueryErrLister struct{}

func (secondaryQueryErrLister) ListObjects(ctx context.Context, bucket, prefix string, maxKeys int) ([]string, error) {
	return nil, errors.New("secondary-query: injected transient S3 listing failure")
}

func (secondaryQueryErrLister) Download(ctx context.Context, bucket, key string) (io.ReadCloser, error) {
	return io.NopCloser(nil), errors.New("secondary-query: unreachable")
}

// secondaryQueryLiveStub is the fixed live tier: per entity, it returns the
// rows LiveRead provides (Filter2's SystemTime <= txTimeNs is applied by the
// real AsOf — the stub only carries the rows).
type secondaryQueryLiveStub struct{ events map[string][]LiveEvent }

func (f secondaryQueryLiveStub) LiveRead(ctx context.Context, entityID string, txTimeNs int64) ([]LiveEvent, error) {
	return f.events[entityID], nil
}

// secondaryQueryIndexStub is the fixed candidate source (the
// SecondaryIndexSource the resolver binds — the interface the test owns,
// exactly as the cmd bind does with the concrete index).
type secondaryQueryIndexStub struct {
	cells    map[uint64][]string
	sysCands []string
	entities int
	tie      uint64
	cd       uint64
	degraded bool
}

func (f *secondaryQueryIndexStub) CandidatesByH3(cell uint64) []string { return f.cells[cell] }
func (f *secondaryQueryIndexStub) CandidatesBySysTime(afterT int64) []string {
	return f.sysCands
}
func (f *secondaryQueryIndexStub) IndexHealth() (int, uint64, uint64, bool) {
	return f.entities, f.tie, f.cd, f.degraded
}

// newSecondaryQueryResolver builds a resolver over the empty durable tier
// plus the fixed live tier, with MaxRangeRows = maxRows.
func newSecondaryQueryResolver(t *testing.T, live secondaryQueryLiveStub, maxRows int) *Resolver {
	t.Helper()
	cfg := DefaultResolverConfig()
	cfg.LiveSource = live
	cfg.MaxRangeRows = maxRows
	return NewResolver(secondaryQueryNoopLister{}, secondaryQueryNoopLister{}, NewJemallocAllocator(), "secondary-query", cfg)
}

// secondaryQueryFixture builds the exactness test shape: two true members of
// 0xEE01, one tie entity (equal sys in 0xEE04 then 0xEE01 — the resolver's
// winner is first-encountered-arbitrary, so the h3 filter must trim it from
// whichever cell it did not win), and one future-dated write (sys past the
// query's txTime — a candidate that resolves to ErrEntityNotFound and must
// be skipped, never an error).
func secondaryQueryFixture() (secondaryQueryLiveStub, map[string][]LiveEvent) {
	ev := func(h3 uint64, sys int64) LiveEvent {
		return LiveEvent{SystemTime: sys, ValidTimeStart: 1, ValidTimeEnd: 2000, AssertionTime: sys, H3Index: h3}
	}
	events := map[string][]LiveEvent{
		"a":      {ev(0xEE01, 500)},
		"b":      {ev(0xEE01, 501)},
		"tie":    {ev(0xEE04, 501), ev(0xEE01, 501)}, // the tie: both cells at one sys
		"future": {ev(0xEE01, 10_000)},               // invisible at txTime=900
	}
	return secondaryQueryLiveStub{events: events}, events
}

// TestSecondaryQuery_H3ExactnessAndTieTrim — the composition never returns a
// wrong row: a false candidate (the tie's losing cell) is trimmed, a
// future-dated candidate is skipped, and every true member survives.
// Negative control: the test harness rewrites the trim `if ev.H3Index != cell`
// to `if true` (a buildable runtime injection) — the trim then skips every
// candidate and this test fails at 0 rows (an over-trim; the earlier
// under-trim narrative — the tie surviving — was incorrect).
func TestSecondaryQuery_H3ExactnessAndTieTrim(t *testing.T) {
	live, _ := secondaryQueryFixture()
	r := newSecondaryQueryResolver(t, live, 4096)
	r.SetSecondaryIndexSource(&secondaryQueryIndexStub{
		cells:    map[uint64][]string{0xEE01: {"a", "b", "tie", "future"}, 0xEE04: {"tie"}},
		entities: 4,
	})
	ctx := context.Background()
	valid := time.Unix(0, 1000)
	tx := time.Unix(0, 900)

	rows, disc, err := r.QueryByH3(ctx, 0xEE01, valid, tx)
	if err != nil {
		t.Fatalf("H3ExactnessAndTieTrim: unexpected error: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("H3ExactnessAndTieTrim: got %d rows (%v), want exactly the 2 true members — a false candidate survived or a true member was lost", len(rows), rowIDs(rows))
	}
	seen := map[string]bool{}
	for _, row := range rows {
		seen[row.EntityID] = true
		if row.H3Index != 0xEE01 {
			t.Fatalf("H3ExactnessAndTieTrim: a row from the wrong cell survived the trim: %s h3=%x", row.EntityID, row.H3Index)
		}
	}
	if !seen["a"] || !seen["b"] {
		t.Fatalf("H3ExactnessAndTieTrim: true member lost (a=%v b=%v)", seen["a"], seen["b"])
	}
	if seen["future"] {
		t.Fatalf("H3ExactnessAndTieTrim: the future-dated row must be skipped at txTime=900, not returned")
	}
	if disc.Candidates != 4 {
		t.Fatalf("H3ExactnessAndTieTrim: disclosure candidates=%d, want 4", disc.Candidates)
	}
	// The tie's other cell: the 0xEE04 query finds the tie entity exactly
	// (whichever cell the resolver picked, exactly one cell's query returns
	// it — never both, never neither).
	rows04, _, err := r.QueryByH3(ctx, 0xEE04, valid, tx)
	if err != nil {
		t.Fatalf("H3ExactnessAndTieTrim: 0xEE04 query errored: %v", err)
	}
	got04 := rowIDs(rows04)
	if len(rows04) > 1 || (len(rows04) == 1 && got04[0] != "tie") {
		t.Fatalf("H3ExactnessAndTieTrim: the 0xEE04 query must return at most the tie entity, got %v", got04)
	}
}

func rowIDs(rows []*TriTemporalEvent) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.EntityID
	}
	return out
}

// TestSecondaryQuery_IOErrorReturnedNotSkipped — a transient IO/timeout
// error in the resolve fails the query loudly; it is never silently skipped
// into an under-approximate (wrong) answer.
// Negative control: the test harness rewrites the skip to the forbidden
// `if err != nil { continue }` pattern — the query returns zero rows with a
// nil error and this test fails (that is the exact defect the forbidden
// pattern permits).
func TestSecondaryQuery_IOErrorReturnedNotSkipped(t *testing.T) {
	live, _ := secondaryQueryFixture()
	cfg := DefaultResolverConfig()
	cfg.LiveSource = live
	r := NewResolver(secondaryQueryErrLister{}, secondaryQueryErrLister{}, NewJemallocAllocator(), "secondary-query", cfg)
	r.SetSecondaryIndexSource(&secondaryQueryIndexStub{cells: map[uint64][]string{0xEE01: {"a", "b"}}})
	_, _, err := r.QueryByH3(context.Background(), 0xEE01, time.Unix(0, 1000), time.Unix(0, 900))
	if err == nil {
		t.Fatalf("IOErrorReturnedNotSkipped: the injected IO error was swallowed (nil error) — the forbidden `if err != nil { continue }` defect: an under-approximate answer dressed as success")
	}
	if errors.Is(err, ErrEntityNotFound) {
		t.Fatalf("IOErrorReturnedNotSkipped: the IO error was misclassified as a skip")
	}
}

// TestSecondaryQuery_DisabledAndDegradedRefused — an unwired or degraded
// index refuses the query.
func TestSecondaryQuery_DisabledAndDegradedRefused(t *testing.T) {
	live, _ := secondaryQueryFixture()
	r := newSecondaryQueryResolver(t, live, 4096)
	if _, _, err := r.QueryByH3(context.Background(), 1, time.Unix(0, 1), time.Unix(0, 1)); !errors.Is(err, ErrSecondaryIndexDisabled) {
		t.Fatalf("DisabledAndDegradedRefused: an unwired source must return ErrSecondaryIndexDisabled, got %v", err)
	}
	r.SetSecondaryIndexSource(&secondaryQueryIndexStub{cells: map[uint64][]string{1: {"a"}}, degraded: true})
	if _, _, err := r.QueryByH3(context.Background(), 1, time.Unix(0, 1), time.Unix(0, 1)); !errors.Is(err, ErrSecondaryIndexDegraded) {
		t.Fatalf("DisabledAndDegradedRefused: a degraded index must return ErrSecondaryIndexDegraded (the loud refuse — never a silently incomplete answer), got %v", err)
	}
}

// TestSecondaryQuery_TruncationAndSysTimeFilter — the MaxRangeRows
// amplification guard (the Range precedent) plus the QueryBySystemTime trim.
func TestSecondaryQuery_TruncationAndSysTimeFilter(t *testing.T) {
	live, _ := secondaryQueryFixture()
	r := newSecondaryQueryResolver(t, live, 1) // MaxRangeRows=1
	r.SetSecondaryIndexSource(&secondaryQueryIndexStub{
		cells:    map[uint64][]string{0xEE01: {"a", "b"}},
		sysCands: []string{"a", "b"},
	})
	ctx := context.Background()
	valid := time.Unix(0, 1000)
	tx := time.Unix(0, 900)
	rows, disc, err := r.QueryByH3(ctx, 0xEE01, valid, tx)
	if err != nil || len(rows) != 1 || !disc.Truncated {
		t.Fatalf("TruncationAndSysTimeFilter: want 1 row + truncated=true (the amplification guard), got %d rows, truncated=%v, err=%v", len(rows), disc.Truncated, err)
	}
	// QueryBySystemTime(after=501): both candidates; 'a' (sys 500) is trimmed
	// by the resolved-row filter — only 'b' survives.
	rows, _, err = r.QueryBySystemTime(ctx, time.Unix(0, 501), valid, tx)
	if err != nil {
		t.Fatalf("TruncationAndSysTimeFilter: unexpected error: %v", err)
	}
	if len(rows) != 1 || rows[0].EntityID != "b" {
		t.Fatalf("TruncationAndSysTimeFilter: want exactly b (sys 501 >= after), got %v", rowIDs(rows))
	}
}
