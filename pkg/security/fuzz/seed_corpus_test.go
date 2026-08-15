package fuzz

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/hr18vk/supremum/pkg/attribution"
	"github.com/hr18vk/supremum/pkg/mesh"
	eng "github.com/hr18vk/supremum/pkg/sync"
)

// seed_corpus_test.go is Edit C — TWO non-fuzz teeth that gate the corpus itself
// (NOT the fuzz runs):
//
//   1. TestSeedCorpusIsValid (T-FUZZ-CORPUS-REPRODUCIBLE) — asserts every
//      committed testdata/fuzz/FuzzX/*.txt seed runs through the matching
//      unmarshaler / DispatchFrame in corpus-only mode (NO mutation) WITHOUT
//      PANICKING. A malformed seed that returns an error is EXPECTED (the
//      adversarial seeds are malformed by design — the corpus's POINT); only a
//      PANIC fails the tooth (a committed seed that crashes the unmarshaler is a
//      corpus DEFECT, not a coverage shape — Law II reproducibility).
//
//   2. TestBugInjectControlProof (T-FUZZ-BUG-INJECT-CONTROL) — the Day-25 Law 5
//      / Day-31 T-PQ-KEM-CLASSICAL-CONTROL mold: PROVES the harness is NOT a
//      tautology by demonstrating a deliberately-injected panic IS catchable on
//      a real input shape (the contrast: the REAL UnmarshalIBLT returns an error
//      on the length-bomb seed; a BUG-INJECTED copy that skips the bounds guard
//      PANICS with an out-of-bounds slice index; the test recovers the panic and
//      asserts it fired). A fuzz that could not catch an injected panic is a
//      no-op runner (the Day-31 KEM-CLASSICAL-CONTROL refutation class).
//
// Both teeth are GREEN in `go test ./pkg/security/fuzz/` (no -fuzz flag needed).

// fuzzTargetNames is the canonical list of fuzz targets this package ships. It
// is the SSoT the corpus tooth iterates (a default target whose testdata/ dir is
// missing fails the tooth — a coverage hole, not a silent skip).
var fuzzTargetNames = []string{
	"FuzzDispatchFrame",
	"FuzzUnmarshalRelayEnvelope",
	"FuzzUnmarshalBatchEnvelope",
	"FuzzUnmarshalHybridFrame",
	"FuzzUnmarshalStrataEstimator",
	"FuzzUnmarshalIBLT",
	"FuzzBugInjectControl", // the build-tagged bug-inject target (corpus optional in default build)
}

// runSeedNoPanic runs the seed through the matching target's call shape in
// corpus-only mode (NO mutation) and returns nil if the call returned (with OR
// without an error — a malformed seed returning an error is EXPECTED) or a
// non-nil error if the call PANICKED (a committed seed that crashes is a defect).
func runSeedNoPanic(target string, seed []byte) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = corpusPanicError{target: target, val: r}
		}
	}()
	switch target {
	case "FuzzDispatchFrame":
		_ = mesh.DispatchFrame(seed, [16]byte{}, nopSink{}, nopDigester{})
	case "FuzzUnmarshalRelayEnvelope":
		_, _ = attribution.UnmarshalRelayEnvelope(seed)
	case "FuzzUnmarshalBatchEnvelope":
		_, _ = attribution.UnmarshalBatchEnvelope(seed)
	case "FuzzUnmarshalHybridFrame":
		_, _ = attribution.UnmarshalHybridFrame(seed)
	case "FuzzUnmarshalStrataEstimator":
		_, _ = eng.UnmarshalStrataEstimator(seed)
	case "FuzzUnmarshalIBLT":
		_, _ = eng.UnmarshalIBLT(seed)
	case "FuzzBugInjectControl":
		// The bug-inject corpus seeds are operator-only (the build-tagged target
		// consumes them); the default-build tooth does NOT parse them (the
		// TestBugInjectControlProof tooth covers the inject proof directly).
	}
	return nil
}

// corpusPanicError wraps a recovered panic so the tooth reports it as a failure.
// Field order packs the 16B iface (val) before the 16B string header (target)
// so the struct is 24B not 32B (fieldalignment-clean — the Day-33 gate is
// NET-NEUTRAL; this is a test-only struct, never on a hot path, but the gate
// counts new debt so the reorder is required). See memory
// fieldalignment_fix_is_destructive — manual reorder, NEVER `fieldalignment -fix`.
type corpusPanicError struct {
	val    any
	target string
}

func (e corpusPanicError) Error() string {
	if s, ok := e.val.(string); ok {
		return e.target + " corpus seed panic: " + s
	}
	return e.target + " corpus seed panic: " + sprintAny(e.val)
}

func sprintAny(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return "<non-string panic value>"
}

// TestSeedCorpusIsValid is T-FUZZ-CORPUS-REPRODUCIBLE. It walks every
// testdata/fuzz/FuzzX/ corpus dir, reads each committed seed, and runs it
// through the matching target in corpus-only mode (NO mutation). The tooth
// asserts NO committed seed PANICS (a seed that crashes is a corpus defect —
// Law II). A malformed seed returning an error is EXPECTED (the adversarial
// seeds are malformed by design). It counts the seeds per target so the report's
// corpus COUNT is a NUMBER (Law V), not "enough".
func TestSeedCorpusIsValid(t *testing.T) {
	totalSeeds := 0
	for _, target := range fuzzTargetNames {
		dir := filepath.Join("testdata", "fuzz", target)
		entries, err := os.ReadDir(dir)
		if err != nil {
			// FuzzBugInjectControl's corpus is optional in the default build
			// (the target is build-tagged); a missing dir for it is fine. For
			// the 6 default targets the corpus MUST exist (M4 — committed).
			if target == "FuzzBugInjectControl" {
				t.Logf("T-FUZZ-CORPUS-REPRODUCIBLE: %s corpus dir absent (build-tagged target, default-skipped) — OK", dir)
				continue
			}
			t.Fatalf("T-FUZZ-CORPUS-REPRODUCIBLE: missing corpus dir %s (M4 — the seed corpus is COMMITTED, not git-ignored): %v", dir, err)
		}
		count := 0
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			seed, derr := readSeedFile(filepath.Join(dir, e.Name()))
			if derr != nil {
				t.Fatalf("T-FUZZ-CORPUS-REPRODUCIBLE: read seed %s/%s: %v", target, e.Name(), derr)
			}
			if perr := runSeedNoPanic(target, seed); perr != nil {
				t.Fatalf("T-FUZZ-CORPUS-REPRODUCIBLE: seed %s/%s PANICKED the target (a committed seed that crashes is a corpus DEFECT, Law II): %v", target, e.Name(), perr)
			}
			count++
		}
		totalSeeds += count
		if target == "FuzzBugInjectControl" {
			// The bug-inject target's corpus is present (the build-tagged target
			// consumes it under -tags fuzzbuginject); the DEFAULT build does NOT
			// run its seeds through a real unmarshaler (runSeedNoPanic's
			// FuzzBugInjectControl case is a no-op — the bug copy is behind the
			// build tag). The tooth asserts the corpus is PRESENT + PARSEABLE (the
			// readSeedFile call above already validated the file format); the
			// no-panic proof is TestBugInjectControlProof under the build tag.
			t.Logf("T-FUZZ-CORPUS-REPRODUCIBLE: %s — %d committed seeds present + parseable (the no-panic proof is TestBugInjectControlProof under -tags fuzzbuginject)", target, count)
			continue
		}
		t.Logf("T-FUZZ-CORPUS-REPRODUCIBLE: %s — %d committed seeds run cleanly (no panic)", target, count)
	}
	t.Logf("T-FUZZ-CORPUS-REPRODUCIBLE: TOTAL committed corpus seeds across all default targets = %d", totalSeeds)
}

// seedBuilderFor returns the SINGLE-SOURCE-OF-TRUTH seed list for a target — the
// same []byte slice the target's f.Add(...) calls AND the on-disk corpus files
// both derive from (the desync discipline seeds_test.go's top-doc names). The
// byte-equality tooth TestSeedCorpusMatchesBuilders re-derives the corpus from
// these lists + asserts the on-disk files match byte-for-byte, so a hand-broken
// seed OR a builder mutated without regenerating the corpus fails the tooth
// (Law II — the invariant the §1 docstring claims). Returns nil for
// FuzzBugInjectControl in the DEFAULT build (its builder bugInjectSeeds is
// behind the fuzzbuginject build tag; the byte-equality check for it runs ONLY
// under -tags fuzzbuginject — the same opt-in discipline as the no-panic proof).
func seedBuilderFor(target string) [][]byte {
	switch target {
	case "FuzzDispatchFrame":
		return dispatchSeeds()
	case "FuzzUnmarshalRelayEnvelope":
		return relaySeeds()
	case "FuzzUnmarshalBatchEnvelope":
		return batchSeeds()
	case "FuzzUnmarshalHybridFrame":
		return hybridSeeds()
	case "FuzzUnmarshalStrataEstimator":
		return strataSeeds()
	case "FuzzUnmarshalIBLT":
		return ibltSeeds()
	case "FuzzBugInjectControl":
		return bugInjectSeedsOrNil() // build-tagged; nil in the default build
	}
	return nil
}

// TestSeedCorpusMatchesBuilders is T-FUZZ-CORPUS-BYTE-IDENTITY — the desync
// discipline ENFORCEMENT (the Day-33 /ruthless-auditor finding: the
// TestSeedCorpusIsValid tooth only enforces no-panic, NOT builder↔corpus
// byte-equality, despite seeds_test.go's docstring claiming it did). This tooth
// closes that enforcement gap: for each target it re-derives the seed list from
// the builder aggregator (seedBuilderFor — the SAME list the target's f.Add
// consumes), reads the on-disk testdata/fuzz/FuzzX/*.txt corpus files in lexical
// (= index) order, and asserts:
//
//   - COUNT match (the builder list length == the on-disk file count) — a
//     builder seed not materialized OR a corpus file not in the builder is a
//     desync.
//   - BYTE-EQUALITY per index (the Nth builder seed == the Nth on-disk file's
//     parsed bytes) — a hand-edited corpus file OR a builder mutated without
//     regenerating the corpus is a desync.
//
// The byte-equality is the load-bearing check: it proves the committed corpus is
// BYTE-FAITHFUL to the builders (a fuzz finding reproduced from the corpus is
// reproducible from the builders, and vice versa — Law II). The order matters:
// the corpus generator wrote seed-0.txt..seed-N.txt in builder-list order, so a
// reordered corpus (same set, different order) fails the per-index byte-equality
// (a reordered corpus would still pass a set-equality check but is a desync — the
// per-index check is the stronger invariant).
//
// FuzzBugInjectControl is build-tagged: its builder (bugInjectSeeds) exists ONLY
// under -tags fuzzbuginject, so in the DEFAULT build seedBuilderFor returns nil
// for it + this tooth SKIPS it with an honest log (the byte-equality check for it
// runs under the build tag — the same opt-in discipline as the no-panic proof).
func TestSeedCorpusMatchesBuilders(t *testing.T) {
	totalMatched := 0
	for _, target := range fuzzTargetNames {
		builder := seedBuilderFor(target)
		if builder == nil {
			// FuzzBugInjectControl in the default build: the builder is behind the
			// fuzzbuginject tag. The byte-equality check for it runs under the tag;
			// the default build skips it (the corpus is still PRESENT + PARSEABLE —
			// TestSeedCorpusIsValid covers that).
			t.Logf("T-FUZZ-CORPUS-BYTE-IDENTITY: %s — builder absent in default build (build-tagged); byte-equality enforced under -tags fuzzbuginject", target)
			continue
		}
		dir := filepath.Join("testdata", "fuzz", target)
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("T-FUZZ-CORPUS-BYTE-IDENTITY: missing corpus dir %s: %v", dir, err)
		}
		// Collect the seed files in NUMERIC-index order. The generator wrote
		// seed-0.txt, seed-1.txt, … seed-10.txt. LEXICAL sort of the bare names
		// would put "seed-10.txt" BEFORE "seed-2.txt" (because '1' < '2') — WRONG
		// for a target with >=11 seeds (Dispatch has 11). The per-index
		// byte-equality requires the Nth file to match the Nth builder seed, so the
		// files MUST be ordered by the integer in the filename (seed-N.txt → N),
		// NOT lexically. A corpus file whose name does not match seed-<int>.txt is a
		// corrupt corpus (fails the parse below).
		type seedFile struct {
			name  string
			index int
		}
		var files []seedFile
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			idx, ok := parseSeedIndex(e.Name())
			if !ok {
				t.Fatalf("T-FUZZ-CORPUS-BYTE-IDENTITY: %s — corpus file %q does not match seed-<int>.txt (a corrupt corpus): %v", target, e.Name(), err)
			}
			files = append(files, seedFile{name: e.Name(), index: idx})
		}
		sort.Slice(files, func(i, j int) bool { return files[i].index < files[j].index })
		if len(files) != len(builder) {
			t.Fatalf("T-FUZZ-CORPUS-BYTE-IDENTITY: %s — COUNT desync (builder=%d seeds, corpus=%d files); a builder seed not materialized OR a corpus file not in the builder is a desync (Law II)", target, len(builder), len(files))
		}
		for i, sf := range files {
			if sf.index != i {
				t.Fatalf("T-FUZZ-CORPUS-BYTE-IDENTITY: %s — corpus index GAP at position %d (file %s has index %d, expected %d); a missing seed-N.txt file is a desync (Law II)", target, i, sf.name, sf.index, i)
			}
			diskSeed, derr := readSeedFile(filepath.Join(dir, sf.name))
			if derr != nil {
				t.Fatalf("T-FUZZ-CORPUS-BYTE-IDENTITY: %s — read seed %s: %v", target, sf.name, derr)
			}
			if !bytesEqual(diskSeed, builder[i]) {
				t.Fatalf("T-FUZZ-CORPUS-BYTE-IDENTITY: %s — BYTE desync at index %d (%s): builder=%d bytes (magic %x…) vs corpus=%d bytes (magic %x…); a hand-edited corpus file OR a builder mutated without regenerating the corpus is a desync (Law II)", target, i, sf.name, len(builder[i]), magicPrefix(builder[i]), len(diskSeed), magicPrefix(diskSeed))
			}
		}
		totalMatched += len(builder)
		t.Logf("T-FUZZ-CORPUS-BYTE-IDENTITY: %s — %d builder seeds byte-match the %d committed corpus files (byte-faithful, no desync)", target, len(builder), len(files))
	}
	t.Logf("T-FUZZ-CORPUS-BYTE-IDENTITY: TOTAL builder↔corpus byte-matched seeds = %d", totalMatched)
}

// bytesEqual is a nil-safe byte slice equality (bytes.Equal panics on nil vs
// empty in older Go; this is explicit so a 0-byte builder seed {} matches a
// 0-byte corpus seed []byte("")).
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

// magicPrefix returns the first min(4, len(b)) bytes of b as a hex prefix for
// the desync error message (the magic is the diagnostic — a desync on the magic
// is the most likely failure mode + the most actionable).
func magicPrefix(b []byte) uint32 {
	n := len(b)
	if n > 4 {
		n = 4
	}
	var p uint32
	for i := 0; i < n; i++ {
		p = p<<8 | uint32(b[i])
	}
	return p
}

// parseSeedIndex extracts the integer index from a seed-N.txt filename. Returns
// (idx, true) for "seed-0.txt".."seed-999.txt" + (0, false) for any other shape
// (a corrupt corpus file the tooth rejects). The numeric index is the sort key
// for the per-index byte-equality (lexical sort mis-orders seed-10.txt before
// seed-2.txt — the trap the FIRST tooth draft fell into).
func parseSeedIndex(name string) (int, bool) {
	const prefix = "seed-"
	const suffix = ".txt"
	if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, suffix) {
		return 0, false
	}
	num := name[len(prefix) : len(name)-len(suffix)]
	if num == "" {
		return 0, false
	}
	idx := 0
	for _, c := range num {
		if c < '0' || c > '9' {
			return 0, false
		}
		idx = idx*10 + int(c-'0')
	}
	return idx, true
}

// readSeedFile parses the go-fuzz on-disk corpus file format:
//
//	go test fuzz v1
//	[]byte("...")
//
// (an optional trailing newline is tolerated). The body is a Go string literal
// (the seed bytes encoded as a quoted Go string). It is the EXACT format
// `go test -fuzz` writes when it finds a crashing input, so a corpus file this
// tooth reads is byte-identical to what the fuzzer re-loads.
func readSeedFile(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseGofuzzCorpusEntry(raw)
}

// parseGofuzzCorpusEntry extracts the []byte seed from a go-fuzz corpus file's
// raw bytes. The format is a header line ("go test fuzz v1") + a body line of
// the form `[]byte("...")`. The string literal is unquoted with Go's own strconv
// rules (handles escapes) so binary seeds round-trip faithfully.
func parseGofuzzCorpusEntry(raw []byte) ([]byte, error) {
	s := string(raw)
	// Strip the header line.
	if idx := strings.IndexByte(s, '\n'); idx >= 0 {
		s = s[idx+1:]
	}
	// The body is `[]byte("...")` — extract the quoted string literal.
	open := strings.Index(s, `("`)
	if open < 0 {
		return nil, errCorruptSeed
	}
	rest := s[open+2:]
	close := strings.LastIndex(rest, `")`)
	if close < 0 {
		return nil, errCorruptSeed
	}
	literal := rest[:close]
	// Unquote the Go string literal (handles \xNN, \n, \\, etc.).
	return unquoteGoString(literal)
}
