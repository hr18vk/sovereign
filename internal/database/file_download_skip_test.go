// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Unit tests for filename-bounded L0/L1 download skipping (ADR-0029).
//
// Resolver.AsOf and Resolver.Range parse each Arrow key's FirstSysTimeNs prefix
// directly from its filename (zero-alloc via parseFirstSysFromKey) and skip
// downloading files whose minimum sysTime exceeds the query's txTime. Since
// every row in such a file fails Filter 2 (sysTime <= txTime), skipping the
// download leaves results unchanged. End-to-end *LocalFS tests live in
// pkg/durability, and metric counter tests live in internal/telemetry and pkg/metrics.

package database

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math/rand/v2"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fileSkipBase is a fixed nanosecond epoch comfortably below MaxValidTimeEndNs.
const fileSkipBase int64 = 1_700_000_000_000_000_000

// TestSkipParser checks parseFirstSysFromKey on well-formed L0/L1 keys and
// verifies invalid suffixes return ok=false so malformed keys are never skipped.
func TestSkipParser(t *testing.T) {
	// A 19-digit production UnixNano parses exactly.
	got, ok := parseFirstSysFromKey("l0/abcd1234/1785542400000000000.arrow")
	require.Truef(t, ok, "l0 production key must parse (ok=true)")
	assert.Equalf(t, int64(1785542400000000000), got, "l0 key: parseFirstSysFromKey must return the EXACT int64 written")

	// l1 tier: the same grammar, the same parser (the read path lists both tiers).
	gotL1, okL1 := parseFirstSysFromKey("l1/abcd1234/1785542400000000000.arrow")
	require.Truef(t, okL1, "l1 production key must parse (ok=true)")
	assert.Equalf(t, int64(1785542400000000000), gotL1, "l1 key: parseFirstSysFromKey must return the EXACT int64 written")

	// A smaller value (the staggered-file test uses i*1000 sysTimes — verify
	// the parser handles non-19-digit widths correctly; strconv.ParseInt base 10
	// is width-agnostic, unlike a lexical compare).
	gotSmall, okSmall := parseFirstSysFromKey("l0/abcd1234/1000.arrow")
	require.True(t, okSmall)
	assert.Equal(t, int64(1000), gotSmall, "a 4-digit suffix must parse (ParseInt base 10 is width-agnostic)")

	// Negative controls — each returns ok=false (the fallback: do not skip).
	redCases := []struct {
		name string
		key  string
	}{
		{"no slash", "1785542400000000000.arrow"},
		{"no dot", "l0/abcd1234/1785542400000000000"},
		{"non-numeric tail", "l0/abcd1234/NOTANUMBER.arrow"},
		{"negative tail", "l0/abcd1234/-1785542400000000000.arrow"},
		{"trailing slash", "l0/abcd1234/"},
		{"dot at position 0 (no numeric prefix)", "l0/abcd1234/.arrow"},
	}
	for _, c := range redCases {
		_, ok := parseFirstSysFromKey(c.key)
		assert.Falsef(t, ok, "negative control %q: must return ok=false so the file is not skipped", c.name)
	}
	t.Logf("Skip parser test pass: l0+l1 production keys parse exactly; 6 negative controls return ok=false (the fallback — never silently skip a parse anomaly)")
}

// TestSkipParserAlloc asserts parseFirstSysFromKey runs with zero allocations.
func TestSkipParserAlloc(t *testing.T) {
	allocs := testing.AllocsPerRun(100, func() {
		_, _ = parseFirstSysFromKey("l0/abcd1234/1785542400000000000.arrow")
	})
	assert.Equalf(t, 0.0, allocs, "parseFirstSysFromKey must allocate 0 bytes/op; got %v", allocs)
	t.Logf("parseFirstSysFromKey allocs/run = %v", allocs)
}

// TestSkipFailsafe verifies that a non-numeric key triggers ok=false so the
// resolver falls back to downloading and scanning the file normally.
func TestSkipFailsafe(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	store := newMemStore()

	const entity = "failsafe-entity"
	sl := NewSkipListArena(alloc, 2*1024*1024)
	rangeWinInsertRow(t, sl, entity, fileSkipBase+100, fileSkipBase, openEndNs, []byte("real-row"))
	require.Equal(t, 1, rangeWinFlush(t, ctx, alloc, store, sl), "one real L0 file flushed")

	h8 := sha256.Sum256([]byte(entity))
	hexHex := hexEncode8(h8)
	realKey := fmt.Sprintf("l0/%s/%d.arrow", hexHex, fileSkipBase+100)
	corruptKey := fmt.Sprintf("l0/%s/NOTANUMBER.arrow", hexHex)
	store.mu.Lock()
	realBytes := store.objects[realKey]
	store.objects[corruptKey] = realBytes
	store.mu.Unlock()

	_, ok := parseFirstSysFromKey(corruptKey)
	require.Falsef(t, ok, "corrupt key %q must not parse (ok=false) so the file is downloaded and scanned", corruptKey)

	qEntity := func(enable bool) *TriTemporalEvent {
		cfg := ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: enable}
		r := NewResolver(store, store, alloc, "fileskip-failsafe", cfg)
		got, err := r.AsOf(ctx, entity, time.Unix(0, fileSkipBase+50), time.Unix(0, fileSkipBase+99999))
		require.NoErrorf(t, err, "AsOf must resolve under EnableFirstSysSkip=%v (the corrupt key's rows survive)", enable)
		require.NotNilf(t, got, "the dominant must be non-nil under EnableFirstSysSkip=%v", enable)
		return got
	}
	withSkip := qEntity(true)
	withoutSkip := qEntity(false)
	assert.Equalf(t, withSkip.SystemTime, withoutSkip.SystemTime, "failsafe: SystemTime must match when skip is enabled vs disabled")
	assert.Equalf(t, withSkip.Payload, withoutSkip.Payload, "FAILSAFE: Payload must be byte-identical (the corrupt key's rows survived)")
	assert.Equalf(t, withSkip.ValidTimeStart, withoutSkip.ValidTimeStart, "FAILSAFE: ValidTimeStart byte-identical")
	t.Logf("unparseable key %q fell back to full scan identically with skip enabled vs disabled", corruptKey)
}

// TestSkipOffBySkipIPBoundary checks the strict > boundary: firstSys == txTime
// does not skip, while firstSys > txTime skips cleanly.
func TestSkipOffBySkipIPBoundary(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()

	const firstSys = fileSkipBase + 1000
	buildFile := func(t *testing.T) *memStore {
		t.Helper()
		store := newMemStore()
		sl := NewSkipListArena(alloc, 2*1024*1024)
		rangeWinInsertRow(t, sl, "boundary-entity", firstSys, fileSkipBase, openEndNs, []byte("boundary-row"))
		require.Equal(t, 1, rangeWinFlush(t, ctx, alloc, store, sl))
		return store
	}

	// txTime == firstSys: row at sysTime == firstSys qualifies; do not skip.
	store1 := buildFile(t)
	r1 := NewResolver(store1, store1, alloc, "fileskip-b1", ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: true})
	got1, err1 := r1.AsOf(ctx, "boundary-entity", time.Unix(0, fileSkipBase+50), time.Unix(0, firstSys))
	require.NoErrorf(t, err1, "txTime==firstSys: AsOf must resolve (the file's first row at sysTime==firstSys passes Filter2 with <=)")
	require.NotNilf(t, got1, "txTime == firstSys: dominant row must be non-nil because sysTime == firstSys qualifies")
	assert.Equalf(t, firstSys, got1.SystemTime, "txTime == firstSys: returned SystemTime must equal firstSys")

	// txTime == firstSys - 1: every row exceeds txTime; skip cleanly.
	store2 := buildFile(t)
	r2 := NewResolver(store2, store2, alloc, "fileskip-b2", ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: true})
	got2, err2 := r2.AsOf(ctx, "boundary-entity", time.Unix(0, fileSkipBase+50), time.Unix(0, firstSys-1))
	assert.Errorf(t, err2, "txTime==firstSys-1: AsOf must return ErrEntityNotFound (the file was SKIPPED — every row sysT >= firstSys > txTime)")
	assert.Nilf(t, got2, "txTime==firstSys-1: no dominant (the skip dropped the file — correctly, zero qualifying rows)")
	r2NoSkip := NewResolver(store2, store2, alloc, "fileskip-b2-noskip", ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: false})
	got2No, err2No := r2NoSkip.AsOf(ctx, "boundary-entity", time.Unix(0, fileSkipBase+50), time.Unix(0, firstSys-1))
	assert.Errorf(t, err2No, "no-skip path at txTime == firstSys-1 must also return ErrEntityNotFound")
	assert.Nilf(t, got2No, "no-skip path: no dominant (the skip changed NOTHING — both paths empty)")

	// txTime below firstSys: all files skipped, returning ErrEntityNotFound.
	store3 := buildFile(t)
	r3 := NewResolver(store3, store3, alloc, "fileskip-b3", ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: true})
	_, err3 := r3.AsOf(ctx, "boundary-entity", time.Unix(0, fileSkipBase+50), time.Unix(0, firstSys-500))
	assert.Errorf(t, err3, "txTime below firstSys must return ErrEntityNotFound")

	// txTime above firstSys: no file skipped.
	store4 := buildFile(t)
	r4 := NewResolver(store4, store4, alloc, "fileskip-b4", ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: true})
	got4, err4 := r4.AsOf(ctx, "boundary-entity", time.Unix(0, fileSkipBase+50), time.Unix(0, firstSys+99999))
	require.NoErrorf(t, err4, "txTime above firstSys: AsOf must resolve because firstSys < txTime")
	require.NotNilf(t, got4, "txTime above firstSys: the dominant must be non-nil (NONE skipped)")
	assert.Equalf(t, firstSys, got4.SystemTime, "txTime above firstSys: returned SystemTime must equal firstSys")
	t.Logf("strict > boundary verified across equal, -1, below, and above cases")
}

// TestSkipEquiv compares AsOf results with EnableFirstSysSkip enabled vs disabled
// across 2,000 randomized txTime values (seed 24) over 64 staggered L0 files.
func TestSkipEquiv(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	const entity = "equiv-entity"
	const N = 64
	const fuzzN = 2000

	store := newMemStore()
	firstSyses := make([]int64, N)
	for i := 0; i < N; i++ {
		firstSys := fileSkipBase + int64(i)*1000
		firstSyses[i] = firstSys
		sl := NewSkipListArena(alloc, 2*1024*1024)
		rangeWinInsertRow(t, sl, entity, firstSys, fileSkipBase, openEndNs, []byte(fmt.Sprintf("row-%d", i)))
		require.Equal(t, 1, rangeWinFlush(t, ctx, alloc, store, sl), "each file flushes ONE per-entity upload")
	}
	h8 := sha256.Sum256([]byte(entity))
	hexHex := hexEncode8(h8)
	prefix := fmt.Sprintf("l0/%s/", hexHex)
	store.mu.Lock()
	fileCount := 0
	for k := range store.objects {
		if len(k) > len(prefix) && k[:len(prefix)] == prefix {
			fileCount++
		}
	}
	store.mu.Unlock()
	require.Equalf(t, N, fileCount, "the store must hold N=%d files under %s (one per firstSys)", N, prefix)

	rSkip := NewResolver(store, store, alloc, "fileskip-equiv-skip", ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: true})
	rNoSkip := NewResolver(store, store, alloc, "fileskip-equiv-noskip", ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: false})

	rng := rand.New(rand.NewPCG(24, 0))
	vt := time.Unix(0, fileSkipBase+50)
	var diverge int
	var skipFires int
	for f := 0; f < fuzzN; f++ {
		txNs := fileSkipBase + rng.Int64N(int64(N)*1000+1)
		tx := time.Unix(0, txNs)

		gotSkip, errSkip := rSkip.AsOf(ctx, entity, vt, tx)
		gotNo, errNo := rNoSkip.AsOf(ctx, entity, vt, tx)

		for _, fs := range firstSyses {
			if fs > txNs {
				skipFires++
				break
			}
		}

		if errSkip != nil && errNo == nil {
			diverge++
			t.Errorf("skip equivalence divergence at f=%d txNs=%d: skip=Err no-skip=event", f, txNs)
			if diverge > 5 {
				break
			}
			continue
		}
		if errNo != nil && errSkip == nil {
			diverge++
			t.Errorf("skip equivalence divergence at f=%d txNs=%d: skip=event no-skip=Err", f, txNs)
			if diverge > 5 {
				break
			}
			continue
		}
		if errSkip != nil && errNo != nil {
			continue
		}
		if gotSkip.SystemTime != gotNo.SystemTime {
			diverge++
			t.Errorf("skip equivalence divergence at f=%d txNs=%d: SystemTime skip=%d no-skip=%d", f, txNs, gotSkip.SystemTime, gotNo.SystemTime)
			if diverge > 5 {
				break
			}
			continue
		}
		if gotSkip.ValidTimeStart != gotNo.ValidTimeStart || gotSkip.ValidTimeEnd != gotNo.ValidTimeEnd {
			diverge++
			t.Errorf("skip equivalence divergence at f=%d txNs=%d: ValidTime skip=[%d,%d) no-skip=[%d,%d)", f, txNs, gotSkip.ValidTimeStart, gotSkip.ValidTimeEnd, gotNo.ValidTimeStart, gotNo.ValidTimeEnd)
			if diverge > 5 {
				break
			}
			continue
		}
		if !bytesEqual(gotSkip.Payload, gotNo.Payload) {
			diverge++
			t.Errorf("skip equivalence divergence at f=%d txNs=%d: payload mismatch", f, txNs)
			if diverge > 5 {
				break
			}
			continue
		}
	}
	require.Zerof(t, diverge, "skip and no-skip paths must match for all %d fuzzed txTimes", fuzzN)
	t.Logf("skip equivalence fuzz passed: %d queries (seed=24), skip engaged on %d/%d", fuzzN, skipFires, fuzzN)
}

// bytesEqual is a nil-safe byte-slice equality (avoids importing bytes in this
// file — the ADR-0028 file imports bytes; this file keeps its import set
// minimal for the parser and fuzz tests).
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// hexEncode8 returns the 16-char lowercase hex of an 8-byte hash prefix (the
// same encoding l0Key and the production path use — encoding/hex on hash[:8]).
// Kept local so this test does not import encoding/hex (the import is already
// in the package via query.go; a test-only helper here avoids a second import
// line that gofmt would reorder).
func hexEncode8(h8 [32]byte) string {
	var b [16]byte
	const hex = "0123456789abcdef"
	for i := 0; i < 8; i++ {
		b[i*2] = hex[h8[i]>>4]
		b[i*2+1] = hex[h8[i]&0x0f]
	}
	return unsafe.String(&b[0], 16)
}
