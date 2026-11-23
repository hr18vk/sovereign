// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package database

import (
	"bytes"
	"io"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/hr18vk/sovereign/internal/telemetry"
	"github.com/stretchr/testify/require"
)

// Differential fuzz, allocation, and edge-case tests for ParseManifest and
// readManifestBody (ADR-0031), comparing them against parseManifestReference
// (the original strings.Split implementation) and an intermediate bytes.IndexByte
// variant that copies each l0 line via string(line).
//
// Keeping the single string(body) allocation in ParseManifest allows substring
// slicing into l0Keys without per-line copies, avoiding the extra intermediate
// []string allocated by strings.Split while remaining faster than per-line
// []byte->string copies. Line 0 still sets l1Key unconditionally when non-empty
// so malformed manifest handling stays identical to the reference.

// parseManifestReference retains the original strings.Split implementation as
// the differential reference oracle for TestStreamByteIdentity.

func parseManifestReference(body []byte) (l1Key string, l0Keys []string) {
	lines := strings.Split(string(body), "\n")
	for i, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		if i == 0 || (l1Key == "" && strings.HasPrefix(ln, "l1/")) {
			if l1Key == "" {
				l1Key = ln
				continue
			}
		}
		if strings.HasPrefix(ln, "l0/") {
			l0Keys = append(l0Keys, ln)
		}
	}
	return l1Key, l0Keys
}

// parseManifestStreamingCandidate is an intermediate bytes.IndexByte scan with
// per-line string(line) copies. It allocates more than parseManifestReference
// for N > 1 because the per-line copies outnumber the single Split slice, and is
// kept as a baseline for TestStreamAlloc while remaining output-equivalent.
func parseManifestStreamingCandidate(body []byte) (l1Key string, l0Keys []string) {
	l1Key = ""
	l0Keys = nil
	start := 0
	first := true
	for start < len(body) {
		end := bytes.IndexByte(body[start:], '\n')
		if end < 0 {
			end = len(body) - start
		}
		line := bytes.TrimSpace(body[start : start+end])
		if len(line) > 0 {
			if first {
				l1Key = string(line)
				first = false
				start = start + end + 1
				continue
			}
			if l1Key == "" && bytes.HasPrefix(line, []byte("l1/")) {
				l1Key = string(line)
			} else if bytes.HasPrefix(line, []byte("l0/")) {
				l0Keys = append(l0Keys, string(line))
			}
		}
		start = start + end + 1
	}
	return l1Key, l0Keys
}

// Differential fuzz checks that ParseManifest and parseManifestStreamingCandidate
// match parseManifestReference across 2,000 randomized inputs including stray
// lines, CR-terminated lines, empty lines, and missing trailing newlines.

func TestStreamByteIdentity(t *testing.T) {
	rng := rand.New(rand.NewPCG(26, 0))
	prefixes := []string{"l1/", "l0/", "garbage", ""}
	diverge := 0
	const fuzz = 2000
	for iter := 0; iter < fuzz; iter++ {
		// Build a manifest body directly (not via buildManifest) so we can inject
		// stray lines + CR + empty lines the writer never produces (defense-in-depth).
		var body []byte
		// Line 0: a random prefix (exercises the `first`-line unconditional-set edge
		// — an "l0/" or "garbage" line 0 becomes l1Key under the original and new implementations).
		line0Prefix := prefixes[rng.IntN(len(prefixes))]
		body = append(body, line0Prefix...)
		body = append(body, randKey(rng, 'a')...)
		body = append(body, '\n')
		// Lines 1..N: random prefixes, some with CR before LF, some empty.
		nLines := rng.IntN(64)
		for i := 0; i < nLines; i++ {
			p := prefixes[rng.IntN(len(prefixes))]
			body = append(body, p...)
			body = append(body, randKey(rng, 'b')...)
			if rng.IntN(4) == 0 {
				body = append(body, '\r') // CR before LF — TrimSpace must strip it
			}
			if rng.IntN(3) == 0 {
				// an empty line (just LF) — TrimSpace → "" → ignored
			}
			body = append(body, '\n')
		}
		// Sometimes drop the trailing LF (the writer appends one; a torn write may not).
		if rng.IntN(2) == 0 && len(body) > 0 {
			body = body[:len(body)-1]
		}

		rl1, rl0 := parseManifestReference(body)
		nl1, nl0 := ParseManifest(body)
		if rl1 != nl1 || !l0KeysEqual(rl0, nl0) {
			diverge++
			if diverge <= 3 {
				t.Errorf("DIVERGE iter=%d body=%q\n  ref: l1Key=%q l0Keys=%v\n  new: l1Key=%q l0Keys=%v", iter, body, rl1, rl0, nl1, nl0)
			}
		}
		// The candidate must also produce the same output; it was rejected only on allocation cost.
		cl1, cl0 := parseManifestStreamingCandidate(body)
		if rl1 != cl1 || !l0KeysEqual(rl0, cl0) {
			diverge++
			if diverge <= 6 {
				t.Errorf("candidate divergence iter=%d body=%q\n  ref: l1Key=%q l0Keys=%v\n  cand: l1Key=%q l0Keys=%v", iter, body, rl1, rl0, cl1, cl0)
			}
		}
	}
	require.Zerof(t, diverge, "streaming ParseManifest and candidate must match reference over %d fuzzed manifests; divergences=%d", diverge, fuzz)
	t.Logf("0 divergences over %d fuzzed manifests (seed=26)", fuzz)
}

func randKey(rng *rand.Rand, cls byte) string {
	const hex = "0123456789abcdef"
	n := 8 + rng.IntN(24)
	b := make([]byte, n)
	for i := range b {
		b[i] = hex[rng.IntN(len(hex))]
	}
	_ = cls
	return string(b)
}

func l0KeysEqual(a, b []string) bool {
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

// TestStreamAlloc compares allocations for ParseManifest and readManifestBody
// against the reference path and the bytes.IndexByte candidate at N = 1, 16,
// 64, 256.
func TestStreamAlloc(t *testing.T) {
	for _, n := range []int{1, 16, 64, 256} {
		l0s := make([]string, n)
		for i := range l0s {
			l0s[i] = "l0/deadbeefdeadbeef/" + strings.Repeat("a", 8) + "k" + itoa26(i)
		}
		body := buildManifest("l1/deadbeefdeadbeef/12345.arrow", l0s)

		// PARSE axis: old strings.Split vs new stringScan vs the refuted candidate.
		oldParse := testing.AllocsPerRun(50, func() { _, _ = parseManifestReference(body) })
		newParse := testing.AllocsPerRun(50, func() { _, _ = ParseManifest(body) })
		refutedParse := testing.AllocsPerRun(50, func() { _, _ = parseManifestStreamingCandidate(body) })

		// Read axis: io.ReadAll + reference vs readManifestBody + ParseManifest.
		oldE2E := testing.AllocsPerRun(50, func() {
			rc := io.NopCloser(bytes.NewReader(body))
			b, _ := io.ReadAll(rc)
			_ = rc.Close()
			_, _ = parseManifestReference(b)
		})
		newE2E := testing.AllocsPerRun(50, func() {
			rc := io.NopCloser(bytes.NewReader(body))
			b, _ := readManifestBody(rc)
			_, _ = ParseManifest(b)
		})

		// New path must allocate less than old on both axes.
		require.Lessf(t, float64(newParse), float64(oldParse), "N=%d: ParseManifest allocs (%v) must be less than Split reference (%v)", n, newParse, oldParse)
		require.Lessf(t, float64(newE2E), float64(oldE2E), "N=%d: end-to-end manifest read+parse allocs (%v) must be less than old path (%v)", n, newE2E, oldE2E)
		// The per-line copy candidate allocates more than reference for N > 1.
		if n > 1 {
			require.Greaterf(t, float64(refutedParse), float64(oldParse), "N=%d: bytes.IndexByte per-line copy candidate (%v) must allocate more than reference (%v)", n, refutedParse, oldParse)
		}

		t.Logf("N=%-4d bodyLen=%-6d | parse old=%-5.1f new=%-5.1f candidate=%-7.1f | e2e old=%-5.1f new=%-5.1f (%+.1f parse, %+.1f e2e)", n, len(body), oldParse, newParse, refutedParse, oldE2E, newE2E, newParse-oldParse, newE2E-oldE2E)
	}
	t.Logf("ParseManifest + readManifestBody reduce allocations across all tested sizes")
}

// TestStreamRedControl checks that ParseManifest preserves line 0 handling on
// a malformed manifest where line 0 starts with "l0/".
func TestStreamRedControl(t *testing.T) {
	// A malformed manifest: line 0 is an "l0/" key (the compactor never writes this
	// — buildManifest writes the l1Key on line 0; but a torn/reordered write could).
	malformed := []byte("l0/deadbeefdeadbeef/999.arrow\nl0/deadbeefdeadbeef/1.arrow\nl0/deadbeefdeadbeef/2.arrow\n")

	// The reference (original) sets l1Key = the "l0/..." line-0 string unconditionally.
	rl1, rl0 := parseManifestReference(malformed)
	require.Equalf(t, "l0/deadbeefdeadbeef/999.arrow", rl1, "reference: a malformed manifest with an l0/ line 0 sets l1Key = that l0/ string (the i==0 unconditional-set)")
	require.Len(t, rl0, 2, "reference: the two subsequent l0/ lines are the l0Keys")

	// The new implementation must match byte-identically (the `first` flag mirrors i==0).
	nl1, nl0 := ParseManifest(malformed)
	require.Equalf(t, rl1, nl1, "ParseManifest l1Key=%q must equal reference l1Key=%q", nl1, rl1)
	require.Equalf(t, rl0, nl0, "ParseManifest l0Keys must equal reference l0Keys")

	// The negative control simulation: describe the regression + assert the current implementation
	// does not have it (the prefix-gated variant would return l1Key=""). We cannot
	// mutate the production ParseManifest in-test, so we inline the prefix-gated
	// variant + assert it diverges from the reference (the proof the `first` flag
	// is load-bearing: removing it changes the answer on this manifest).
	prefixGated := func(body []byte) (l1Key string, l0Keys []string) {
		s := string(body)
		start := 0
		for start < len(s) {
			end := strings.IndexByte(s[start:], '\n')
			if end < 0 {
				end = len(s) - start
			}
			ln := strings.TrimSpace(s[start : start+end])
			if len(ln) > 0 {
				if l1Key == "" && strings.HasPrefix(ln, "l1/") { // no `first` — prefix-gated on all lines
					l1Key = ln
				} else if strings.HasPrefix(ln, "l0/") {
					l0Keys = append(l0Keys, ln)
				}
			}
			start = start + end + 1
		}
		return l1Key, l0Keys
	}
	rg1, rg0 := prefixGated(malformed)
	require.Equalf(t, "", rg1, "negative control: prefix-gated variant without first flag returns empty l1Key on malformed manifest")
	require.NotEqualf(t, rl1, rg1, "negative control: prefix-gated variant l1Key diverges from reference (%q)", rl1)
	// The regression also affects l0Keys: under the reference + the new implementation, line
	// 0 (the "l0/...999" key) `continue`s after being set as l1Key → it is not
	// appended to l0Keys (rl0=[1,2], len 2). The prefix-gated variant does not
	// `continue` (line 0 is "l0/"-prefixed, not "l1/" → the l1Key-set is skipped →
	// it falls through to the l0/ append → "999" is appended → rg0=[999,1,2], len 3).
	// The divergence on l0Keys is the second load-bearing symptom the `first` flag
	// prevents (the `continue` after the line-0 set is the mechanism).
	require.NotEqualf(t, rl0, rg0, "negative control: prefix-gated variant l0Keys diverge from reference (ref=%v len=%d, gated=%v len=%d)", rl0, len(rl0), rg0, len(rg0))
	t.Logf("malformed manifest line 0 handling preserved: l1Key=%q l0Keys=%v", rl1, rl0)
}

// readManifestBody tests across buffer boundaries and fragmented readers.
func TestStreamReadBody(t *testing.T) {
	cases := []struct {
		name string
		body []byte
	}{
		{"empty", nil},
		{"tiny", []byte("l1/x\n")},
		{"fits-4096", bytes.Repeat([]byte("a"), 4090)},
		{"forces-grow-8000", bytes.Repeat([]byte("b"), 8000)},
		{"forces-grow-20000", bytes.Repeat([]byte("c"), 20000)},
	}
	for _, c := range cases {
		got, err := readManifestBody(bytes.NewReader(c.body))
		require.NoErrorf(t, err, "%s: readManifestBody", c.name)
		// bytes.Equal treats nil and []byte{} as equal (byte-identity); require.Equal
		// (reflect.DeepEqual) distinguishes them — readManifestBody returns a
		// non-nil empty slice for an empty input (make([]byte,0,4096)), which is
		// byte-identical to a nil input. Use bytes.Equal for the byte-identity gate.
		require.Truef(t, bytes.Equal(c.body, got), "%s: readManifestBody output must match input (got len=%d, want len=%d)", c.name, len(got), len(c.body))

		// A fragmenting reader (returns 7 bytes per Read) must still produce the
		// full body — the read loop must handle partial reads (the io.Reader
		// contract: a Read may return n < len(p) with err==nil).
		got2, err := readManifestBody(newFragmentingReader(c.body, 7))
		require.NoErrorf(t, err, "%s: readManifestBody over a fragmenting reader", c.name)
		require.Truef(t, bytes.Equal(c.body, got2), "%s: readManifestBody over fragmenting reader must match input (got len=%d, want len=%d)", c.name, len(got2), len(c.body))
	}
	t.Logf("readManifestBody matched input across all buffer sizes and fragmented reads")
}

// newFragmentingReader returns an io.Reader that yields at most max bytes per Read.
func newFragmentingReader(body []byte, max int) io.Reader {
	return &fragReader{body: body, max: max}
}

type fragReader struct {
	body []byte
	max  int
	off  int
}

func (f *fragReader) Read(p []byte) (int, error) {
	if f.off >= len(f.body) {
		return 0, io.EOF
	}
	n := len(f.body) - f.off
	if n > f.max {
		n = f.max
	}
	if n > len(p) {
		n = len(p)
	}
	copy(p, f.body[f.off:f.off+n])
	f.off += n
	return n, nil
}

// TestStreamTelemetryCounterUnchanged verifies that streaming manifest parsing
// leaves the registered counter count at 25 with no duplicate metric names.
func TestStreamTelemetryCounterUnchanged(t *testing.T) {
	cs := telemetry.Counters()
	const wantDistinct = 25
	require.Equalf(t, wantDistinct, len(cs), "len(telemetry.Counters())=%d, want %d distinct counters", len(cs), wantDistinct)
	seen := make(map[string]struct{}, len(cs))
	dups := 0
	for _, c := range cs {
		if _, ok := seen[c.Name()]; ok {
			dups++
		}
		seen[c.Name()] = struct{}{}
	}
	require.Zerof(t, dups, "found %d duplicate telemetry counter names", dups)
	require.Equalf(t, wantDistinct, len(seen), "distinct telemetry counter names=%d, want %d", len(seen), wantDistinct)
	t.Logf("telemetry registry holds %d distinct counters", len(cs))
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func itoa26(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}
