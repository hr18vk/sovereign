// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package fuzz

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/hr18vk/sovereign/pkg/attribution"
	"github.com/hr18vk/sovereign/pkg/mesh"
	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// The corpus tests run without fuzz mutation. TestSeedCorpusIsValid parses each
// committed seed and calls the matching default target directly; malformed input
// may return an error, but a panic fails the test. TestSeedCorpusMatchesBuilders
// separately compares file counts, numeric indices, and bytes with the builders
// used by each target's f.Add calls.

// fuzzTargetNames lists every target with a committed corpus. A missing
// directory fails for the six default targets rather than silently reducing
// coverage. The fault-injection corpus is optional in the default build.
var fuzzTargetNames = []string{
	"FuzzDispatchFrame",
	"FuzzUnmarshalRelayEnvelope",
	"FuzzUnmarshalBatchEnvelope",
	"FuzzUnmarshalHybridFrame",
	"FuzzUnmarshalStrataEstimator",
	"FuzzUnmarshalIBLT",
	"FuzzBugInjectControl", // the build-tagged fault-injection target (corpus optional in default build)
}

// runSeedNoPanic calls the selected target once without mutation. Ordinary
// parse errors are ignored; a recovered panic becomes the returned error.
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
		// The fault-injected implementation is deliberately not called here.
		// TestBugInjectControlProof exercises it under fuzzbuginject; the outer
		// corpus test still parses these files in either build.
	}
	return nil
}

// corpusPanicError identifies the target and value from a recovered panic.
// Placing val before target groups the pointer-bearing words first and leaves
// the string length in the final word, reducing the GC pointer-scanning prefix.
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

// TestSeedCorpusIsValid reads every committed seed and calls its matching
// default target once without mutation. A malformed seed may return an error;
// a panic fails the test. Per-target logs record the number of files checked.
func TestSeedCorpusIsValid(t *testing.T) {
	totalSeeds := 0
	for _, target := range fuzzTargetNames {
		dir := filepath.Join("testdata", "fuzz", target)
		entries, err := os.ReadDir(dir)
		if err != nil {
			// The fault-injection target is absent from the default build, so
			// its directory is optional. All six default targets require one.
			if target == "FuzzBugInjectControl" {
				t.Logf("seed-corpus: %s is absent; skipping the build-tagged target", dir)
				continue
			}
			t.Fatalf("seed-corpus: read required corpus directory %s: %v", dir, err)
		}
		count := 0
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			seed, derr := readSeedFile(filepath.Join(dir, e.Name()))
			if derr != nil {
				t.Fatalf("seed-corpus: read seed %s/%s: %v", target, e.Name(), derr)
			}
			if perr := runSeedNoPanic(target, seed); perr != nil {
				t.Fatalf("seed-corpus: committed seed %s/%s panicked: %v", target, e.Name(), perr)
			}
			count++
		}
		totalSeeds += count
		if target == "FuzzBugInjectControl" {
			// The reads above establish presence and format. The tagged control
			// checks the fault-injected call's behavior separately.
			t.Logf("seed-corpus: %s has %d committed seeds with valid corpus syntax", target, count)
			continue
		}
		t.Logf("seed-corpus: %s ran %d committed seeds without a panic", target, count)
	}
	t.Logf("seed-corpus: checked %d committed seeds in total", totalSeeds)
}

// seedBuilderFor returns the same seed list used by the selected target's f.Add
// calls. TestSeedCorpusMatchesBuilders compares this list with the on-disk
// corpus. The fault-injection builder is behind fuzzbuginject, so its default-
// build stub returns nil and the comparison is skipped.
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

// TestSeedCorpusMatchesBuilders compares each target's builder list with its
// committed files. The counts must match, filenames must have contiguous numeric
// indices starting at zero, and each file's decoded bytes must equal the builder
// seed at that index. Numeric ordering matters because lexical order places
// seed-10.txt before seed-2.txt.
//
// The default build skips FuzzBugInjectControl because its builder is behind
// fuzzbuginject. A tagged run applies the same comparison to that corpus.
func TestSeedCorpusMatchesBuilders(t *testing.T) {
	totalMatched := 0
	for _, target := range fuzzTargetNames {
		builder := seedBuilderFor(target)
		if builder == nil {
			// Only the fault-injection target has a nil default-build builder.
			t.Logf("corpus-byte-identity: %s has no builder in the default build; comparison requires -tags fuzzbuginject", target)
			continue
		}
		dir := filepath.Join("testdata", "fuzz", target)
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("corpus-byte-identity: read corpus directory %s: %v", dir, err)
		}
		// Sort by the numeric filename index so seed-10.txt follows seed-9.txt.
		// Any other filename shape is rejected.
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
				t.Fatalf("corpus-byte-identity: %s has corpus file %q; want seed-<int>.txt: %v", target, e.Name(), err)
			}
			files = append(files, seedFile{name: e.Name(), index: idx})
		}
		sort.Slice(files, func(i, j int) bool { return files[i].index < files[j].index })
		if len(files) != len(builder) {
			t.Fatalf("corpus-byte-identity: %s has %d builder seeds but %d corpus files", target, len(builder), len(files))
		}
		for i, sf := range files {
			if sf.index != i {
				t.Fatalf("corpus-byte-identity: %s has index gap at position %d: file %s has index %d, want %d", target, i, sf.name, sf.index, i)
			}
			diskSeed, derr := readSeedFile(filepath.Join(dir, sf.name))
			if derr != nil {
				t.Fatalf("corpus-byte-identity: %s: read seed %s: %v", target, sf.name, derr)
			}
			if !bytesEqual(diskSeed, builder[i]) {
				t.Fatalf("corpus-byte-identity: %s differs at index %d (%s): builder=%d bytes (magic %x…), corpus=%d bytes (magic %x…)", target, i, sf.name, len(builder[i]), magicPrefix(builder[i]), len(diskSeed), magicPrefix(diskSeed))
			}
		}
		totalMatched += len(builder)
		t.Logf("corpus-byte-identity: %s matched %d builder seeds to %d committed files", target, len(builder), len(files))
	}
	t.Logf("corpus-byte-identity: matched %d seeds in total", totalMatched)
}

// bytesEqual compares length and contents, treating nil and empty slices as
// equal so an empty builder seed matches an empty corpus entry.
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

// magicPrefix packs up to the first four bytes into the integer printed by the
// mismatch diagnostic. Short inputs produce a correspondingly shorter prefix.
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

// parseSeedIndex extracts the decimal index from seed-N.txt. It rejects missing
// or non-numeric indices and filenames without the required prefix and suffix.
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

// readSeedFile reads a Go fuzz corpus entry and decodes its []byte value:
//
//	go test fuzz v1
//	[]byte("...")
//
// An optional trailing newline is tolerated.
func readSeedFile(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseGofuzzCorpusEntry(raw)
}

// parseGofuzzCorpusEntry skips the first line, extracts the literal between
// the []byte("...") wrapper, and applies Go's unquoting rules to recover the
// original bytes.
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
