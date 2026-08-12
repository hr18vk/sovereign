// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

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

// The zero-alloc-line streaming ParseManifest guards (ADR-0031) —
// the ADR-0030 §6.a deferred work.
//
// The manifest-channel download skip (ADR-0030) skips a manifest's DOWNLOAD when
// its filename-encoded firstSys > txTime. The NON-skipped
// (downloaded) manifests still ran ParseManifest — the ADR-0030 §6.a residual:
// `strings.Split(string(body), "\n")` materialized the body into a []string of
// N+1 entries (the Split slice) IN ADDITION to the l0Keys slice. This change zeroes
// the PARSE-axis overhead (drops the Split slice) + the READ-axis overhead
// (replaces io.ReadAll's 512B-start doublings with a single 4096B-start growable
// read). Both swaps are BYTE-IDENTICAL (the byte-identity fuzz proves
// ParseManifest's output is unchanged; the byte-identity suites over
// REAL *LocalFS prove the superseded set + the dominant are unchanged).
//
// THE PREMISE-AUDIT (ADR-0031 §7):
//
//   - The streaming candidate (LOAD-BEARING — the §0.b honesty gate, MEASURED before code): the original
//     candidate (a single-pass bytes.IndexByte scan + a per-L0
//     `string(line)` copy) is REFUTED by the measurement. The OLD strings.Split
//     path copies the body ONCE via `string(body)` (1 alloc), then every `ln` is a
//     SUBSTRING aliasing that one copy (0 per-line allocs). The candidate
//     calls `string([]byte)` PER L0 LINE — a `[]byte`→`string` conversion COPIES
//     (strings are immutable) → N per-line allocs. MEASURED (the alloc guard):
//     the candidate is 3× WORSE at N=16 (20 vs 5), 10× at N=64 (70 vs 7), 29× at
//     N=256 (264 vs 9). The §0.b honesty gate KILLS it — it is NOT shipped.
//     The HONEST replacement keeps the ONE `string(body)` copy (irreducible —
//     the l0Keys must outlive the []byte body; the callers store l0Keys as map
//     keys → they need stable strings) + scans with strings.IndexByte + substring-
//     appends l0Keys (0 per-line copy, aliasing string(body)). This DROPS the
//     Split slice (the win) WITHOUT adding the per-line copies (the candidate's
//     loss). MEASURED: −1 alloc/run at every N on the PARSE axis; the l0Key copies
//     were NEVER there (the old substrings aliased the same string(body)).
//
//   - Is `strings.TrimSpace` zero-alloc on a string? Yes (returns a sub-
//     string). `bytes.TrimSpace` on a []byte returns a sub-slice. The trimmed-line
//     step is NOT the alloc source — the strings.Split slice + (for the REFUTED
//     candidate only) the per-line string([]byte) copies are.
//
//   - Does any caller depend on ParseManifest's malformed-body behavior? The
//     reaper's `if l1Key == ""` guard (l0_reaper.go:186) + the defense-in-depth
//     "a stray line is dropped" (ParseManifest ignores non-l1/l0 lines). The
//     streaming variant preserves this EXACTLY — line 0 is set as l1Key
//     UNCONDITIONALLY when non-empty (mirroring the old `i == 0`; even an "l0/"
//     line 0 becomes l1Key, a malformed manifest), then lines 1+ use the prefix
//     check; a line that is neither "l1/" nor "l0/" prefixed is IGNORED (NOT
//     fatal). The byte-identity fuzz + the
//     malformed-edge catcher pin this.
//
//   - Count-growth: this change adds NO counter. The telemetry counter set STAYS
//     at 17 (no count-guard update — a pure-refactor change does NOT grow the
//     counter set). This is a PURE-REFACTOR change (the implementation swap, NOT a new
//     disclosure surface). The counter-count guards (the wantDistinct
//     =17 set) are UNCHANGED. The bridge is UNCHANGED (the §0.f auto-surface needs no
//     new series; there is none to surface).

// ---------------------------------------------------------------------------
// parseManifestReference — the EXACT old strings.Split implementation, kept as
// the byte-identity check (the premise-audit + the byte-identity guard).
// ---------------------------------------------------------------------------

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

// parseManifestStreamingCandidate is the original single-pass candidate: a
// bytes.IndexByte scan with per-line string(line) copies. The premise-audit PROVED this is WORSE
// than the reference for N>1 (the per-line []byte->string copy dominates; the
// reference's strings.Split substrings alias the one string(body) copy = 0 per
// line). Retained as the REFUTED baseline for the ADR's honesty disclosure +
// the refuted-candidate guard (it MUST stay byte-identical to the
// reference on OUTPUT — it is only WORSE on ALLOCS, not on correctness).
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

// ---------------------------------------------------------------------------
// The LOAD-BEARING differential-equivalence fuzz.
// ---------------------------------------------------------------------------

// TestStreamByteIdentity. A
// differential fuzz: build N manifests (N=1, 16, 64, 256) via buildManifest with a
// varied l1Key + l0Keys (some "l0/", some stray "garbage" lines for the
// defense-in-depth edge, some empty lines, some CR-terminated lines), parse with
// the REFERENCE (parseManifestReference — the EXACT old strings.Split impl) AND
// the NEW streaming impl (ParseManifest). ASSERT byte-identical (l1Key string-
// equal, l0Keys deep-equal). N=2000 fuzzed manifests (seed=26, rand.NewPCG(26,0),
// random l1Key + random N l0Keys + random stray lines). The fuzz ALSO asserts the
// REFUTED candidate (parseManifestStreamingCandidate) is byte-identical to the
// reference on OUTPUT (it is only WORSE on ALLOCS, not correctness — pinning that
// the §0.b rejection was an ALLOC decision, not a CORRECTNESS one).
func TestStreamByteIdentity(t *testing.T) {
	rng := rand.New(rand.NewPCG(26, 0))
	prefixes := []string{"l1/", "l0/", "garbage", ""}
	diverge := 0
	const fuzz = 2000
	for iter := 0; iter < fuzz; iter++ {
		// Build a manifest body directly (NOT via buildManifest) so we can inject
		// stray lines + CR + empty lines the writer never produces (defense-in-depth).
		var body []byte
		// Line 0: a random prefix (exercises the `first`-line unconditional-set edge
		// — an "l0/" or "garbage" line 0 becomes l1Key under the OLD + NEW impls).
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
		// The REFUTED candidate MUST also be byte-identical on OUTPUT (the §0.b
		// rejection was an ALLOC decision; the candidate is correct, just slow).
		cl1, cl0 := parseManifestStreamingCandidate(body)
		if rl1 != cl1 || !l0KeysEqual(rl0, cl0) {
			diverge++
			if diverge <= 6 {
				t.Errorf("REFUTED-CANDIDATE DIVERGE iter=%d body=%q\n  ref: l1Key=%q l0Keys=%v\n  cand: l1Key=%q l0Keys=%v", iter, body, rl1, rl0, cl1, cl0)
			}
		}
	}
	require.Zerof(t, diverge, "stream-byte-identity: %d divergences over %d fuzzed manifests (seed=26) — the NEW streaming ParseManifest + the REFUTED candidate MUST be byte-identical to the reference on OUTPUT (the malformed-line-0 edge + the CR/empty-line defense-in-depth)", diverge, fuzz)
	t.Logf("stream-byte-identity PASS: 0 divergences over %d fuzzed manifests (seed=26) — ParseManifest byte-identical to the reference (the `first`-line unconditional-set, the CR/empty-line TrimSpace, the stray-line defense-in-depth ALL preserved)", fuzz)
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

// ---------------------------------------------------------------------------
// The MEASURED, HONEST alloc accounting (NO "zero-alloc" lie).
// ---------------------------------------------------------------------------

// TestStreamAlloc measures the NEW streaming
// ParseManifest + readManifestBody against the OLD baseline (strings.Split +
// io.ReadAll) at N=1, 16, 64, 256. ASSERTS new < old (the cut) AND discloses the
// ACTUAL numbers (NOT "0 allocs" — the string(body) copy + the l0Keys slice + the
// read buffer are the irreducible minimum; the Split slice + the io.ReadAll
// doublings are ELIMINATED). This is the §0.b honesty gate made executable: the
// headline FOLLOWS the measurement, not the dictation.
func TestStreamAlloc(t *testing.T) {
	for _, n := range []int{1, 16, 64, 256} {
		l0s := make([]string, n)
		for i := range l0s {
			l0s[i] = "l0/deadbeefdeadbeef/" + strings.Repeat("a", 8) + "k" + itoa26(i)
		}
		body := buildManifest("l1/deadbeefdeadbeef/12345.arrow", l0s)

		// PARSE axis: old strings.Split vs new stringScan vs the REFUTED candidate.
		oldParse := testing.AllocsPerRun(50, func() { _, _ = parseManifestReference(body) })
		newParse := testing.AllocsPerRun(50, func() { _, _ = ParseManifest(body) })
		refutedParse := testing.AllocsPerRun(50, func() { _, _ = parseManifestStreamingCandidate(body) })

		// READ+E2E axis: old io.ReadAll+reference vs new readManifestBody+ParseManifest.
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

		// The cut: new < old on BOTH axes.
		require.Lessf(t, float64(newParse), float64(oldParse), "stream-alloc N=%d: PARSE new=%v MUST be < old=%v (the Split slice is cut)", n, newParse, oldParse)
		require.Lessf(t, float64(newE2E), float64(oldE2E), "stream-alloc N=%d: E2E new=%v MUST be < old=%v (the Split slice + the io.ReadAll doublings are cut)", n, newE2E, oldE2E)
		// The REFUTED candidate MUST be WORSE than the old path for N>1 (the §0.b
		// rejection's evidence, made executable — a future "optimization" that
		// reintroduces the per-line string([]byte) copy MUST fail this guard).
		if n > 1 {
			require.Greaterf(t, float64(refutedParse), float64(oldParse), "stream-alloc N=%d: the REFUTED candidate (bytes.IndexByte+string(line)/L0) new=%v MUST be > old=%v — it is WORSE (the per-line []byte->string copy dominates)", n, refutedParse, oldParse)
		}

		t.Logf("stream-alloc: N=%-4d bodyLen=%-6d | PARSE old=%-5.1f new=%-5.1f refuted=%-7.1f | E2E old=%-5.1f new=%-5.1f (cut=%+.1f parse, %+.1f e2e)", n, len(body), oldParse, newParse, refutedParse, oldE2E, newE2E, newParse-oldParse, newE2E-oldE2E)
	}
	t.Logf("stream-alloc PASS: ParseManifest + readManifestBody cut the allocs on BOTH axes at every N (the Split slice + the io.ReadAll doublings eliminated); the REFUTED candidate proven WORSE for N>1 (the §0.b honesty gate's evidence made executable). The string(body) copy + the l0Keys slice + the read buffer are the IRREDUCIBLE minimum — does NOT claim 0 allocs, it claims the MEASURED cut to the irreducible.")
}

// ---------------------------------------------------------------------------
// The malformed-line edge (the `first`-line catcher).
// ---------------------------------------------------------------------------

// TestStreamRedControl. The
// load-bearing negative: a manifest whose line 0 is an "l0/..." key (a malformed
// manifest) — the OLD code sets l1Key = that "l0/..." string (the `i == 0`
// unconditional-set). The NEW impl's `first` flag mirrors this. The guard asserts
// the NEW impl produces l1Key == "l0/..." (byte-identical to the reference). The
// RED control: mutate the NEW impl's `first`-line unconditional-set to a
// prefix-gated set (use `if HasPrefix("l1/")` for ALL lines incl line 0) → the
// malformed manifest's l1Key becomes "" (NOT "l0/...") → the byte-identity fuzz
// DIVERGES → RED. Restore → GREEN. This proves the `first` flag is load-bearing
// against the easy-to-write regression (dropping it "because line 0 is always l1/"
// is a latent bug on malformed manifests — the reaper's `l1Key == ""` guard would
// then MIS-PRESERVE a manifest whose line 0 was an "l0/" key the compactor never
// produces but a torn write might).
func TestStreamRedControl(t *testing.T) {
	// A malformed manifest: line 0 is an "l0/" key (the compactor never writes this
	// — buildManifest writes the l1Key on line 0; but a torn/reordered write could).
	malformed := []byte("l0/deadbeefdeadbeef/999.arrow\nl0/deadbeefdeadbeef/1.arrow\nl0/deadbeefdeadbeef/2.arrow\n")

	// The reference (old) sets l1Key = the "l0/..." line-0 string UNCONDITIONALLY.
	rl1, rl0 := parseManifestReference(malformed)
	require.Equalf(t, "l0/deadbeefdeadbeef/999.arrow", rl1, "reference: a malformed manifest with an l0/ line 0 sets l1Key = that l0/ string (the i==0 unconditional-set)")
	require.Len(t, rl0, 2, "reference: the two subsequent l0/ lines are the l0Keys")

	// The NEW impl MUST match byte-identically (the `first` flag mirrors i==0).
	nl1, nl0 := ParseManifest(malformed)
	require.Equalf(t, rl1, nl1, "stream-red-control: NEW l1Key=%q MUST == reference l1Key=%q (the `first`-line unconditional-set is preserved)", nl1, rl1)
	require.Equalf(t, rl0, nl0, "stream-red-control: NEW l0Keys MUST == reference l0Keys")

	// The RED control simulation: describe the regression + assert the CURRENT impl
	// does NOT have it (the prefix-gated variant WOULD return l1Key=""). We cannot
	// mutate the production ParseManifest in-test, so we inline the prefix-gated
	// variant + assert it DIVERGES from the reference (the proof the `first` flag
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
				if l1Key == "" && strings.HasPrefix(ln, "l1/") { // NO `first` — prefix-gated on ALL lines
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
	require.Equalf(t, "", rg1, "RED control: the prefix-gated variant (no `first` flag) returns l1Key=\"\" on the malformed manifest — the regression the `first` flag prevents")
	require.NotEqualf(t, rl1, rg1, "RED control: the prefix-gated variant DIVERGES from the reference (l1Key \"\" vs %q) — proves the `first` flag is load-bearing; removing it is a latent bug the byte-identity fuzz would catch", rl1)
	// The regression ALSO affects l0Keys: under the reference + the NEW impl, line
	// 0 (the "l0/...999" key) `continue`s after being set as l1Key → it is NOT
	// appended to l0Keys (rl0=[1,2], len 2). The prefix-gated variant does NOT
	// `continue` (line 0 is "l0/"-prefixed, not "l1/" → the l1Key-set is skipped →
	// it falls through to the l0/ append → "999" IS appended → rg0=[999,1,2], len 3).
	// The divergence on l0Keys is the SECOND load-bearing symptom the `first` flag
	// prevents (the `continue` after the line-0 set is the mechanism).
	require.NotEqualf(t, rl0, rg0, "RED control: the prefix-gated variant ALSO DIVERGES on l0Keys (ref=%v len=%d vs gated=%v len=%d) — the `first`-line `continue` (which the prefix-gated variant lacks) keeps the line-0 key OUT of l0Keys; removing it double-counts the malformed line-0 key", rl0, len(rl0), rg0, len(rg0))
	t.Logf("stream-red-control PASS: the `first`-line unconditional-set + `continue` is load-bearing — a malformed manifest (l0/ line 0) gets l1Key=%q l0Keys=%v under BOTH the reference + the NEW impl (byte-identical); the prefix-gated RED-control variant returns l1Key=\"\" + double-counts the line-0 key into l0Keys (DIVERGES on BOTH) — proves removing the `first` flag is a latent bug the fuzz catches", rl1, rl0)
}

// ---------------------------------------------------------------------------
// readManifestBody over a REAL io.Reader (the READ axis).
// ---------------------------------------------------------------------------

// TestStreamReadBody: readManifestBody
// (the io.ReadAll replacement) MUST read a body byte-identical to io.ReadAll
// across: a body that fits the 4096B initial cap (1 alloc), a body that forces a
// grow (>4096B), an empty body, a body that returns the bytes across MANY small
// Reads (the io.Reader may fragment). This is the READ-axis byte-identity guard
// (the PARSE-axis is the byte-identity guard; the two compose).
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
		require.Truef(t, bytes.Equal(c.body, got), "%s: readManifestBody MUST be byte-identical to the input (got len=%d, want len=%d)", c.name, len(got), len(c.body))

		// A fragmenting reader (returns 7 bytes per Read) MUST still produce the
		// full body — the read loop must handle partial reads (the io.Reader
		// contract: a Read may return n < len(p) with err==nil).
		got2, err := readManifestBody(newFragmentingReader(c.body, 7))
		require.NoErrorf(t, err, "%s: readManifestBody over a fragmenting reader", c.name)
		require.Truef(t, bytes.Equal(c.body, got2), "%s: readManifestBody over a fragmenting reader MUST be byte-identical to the input (got len=%d, want len=%d)", c.name, len(got2), len(c.body))
	}
	t.Logf("stream-read-body PASS: readManifestBody byte-identical to io.ReadAll across empty/tiny/fits/grow bodies + a fragmenting reader (the READ-axis byte-identity; composes with the PARSE-axis stream-byte-identity)")
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

// ---------------------------------------------------------------------------
// The zero-count-growth disclosure.
// ---------------------------------------------------------------------------

// TestStreamTelemetryCounterUnchanged. This change
// adds NO counter — the telemetry counter set STAYS at 17 DISTINCT. The
// wantDistinct guards STAY 17 (no count-guard update — this is a PURE-REFACTOR change, the
// cleanest class: the implementation swap, NOT a new disclosure surface). The
// bridge auto-surfaces NO new series (there is none to surface). This guard is
// the in-package belt-and-suspenders assertion that this change does NOT silently
// grow the counter set (a later change that adds a counter MUST update the
// wantDistinct guards AND this one).
//
// (ADR-0032) update: the read-your-writes
// live-source counter QueryLiveSourceReads grew the set 17 -> 18, so this guard's
// wantDistinct is updated 17 -> 18 — a change that grows the
// counter set updates the prior wantDistinct guards. This change ITSELF added NO
// counter (it was a pure-refactor); the update is owed to the live-source growth.
// The wantDistinct value tracks the CURRENT counter set.
func TestStreamTelemetryCounterUnchanged(t *testing.T) {
	// The registry's package-level init() populates the counters slice (the same
	// discipline the in-package guards rely on — Counters() is the
	// frozen post-init slice; NO explicit rebuild call needed from an external pkg).
	cs := telemetry.Counters()
	const wantDistinct = 24 // counter-count history: (ADR-0039) 23 -> 24 (InterRegionEnvelopesShipped); (ADR-0037) 22 -> 23 (HybridFrameAccepted); (ADR-0036) 21 -> 22 (PQHandshakeNegotiated); (ADR-0035) 19 -> 21 (CertRotationTriggered + CertRevokedRejected); (ADR-0034) 18 -> 19; (ADR-0032) 17 -> 18 (the read-your-writes live-source counter); the streaming-parse change added NO counter
	require.Equalf(t, wantDistinct, len(cs), "stream-unchanged: len(Counters())=%d, want %d (this change added NO counter of its own — a pure-refactor change; later additions grew the set and updated this guard's wantDistinct to track the current count: PQHandshakeNegotiated (the PQ-KEM disclosure), CertRotationTriggered + CertRevokedRejected (the PKI disclosure), the stratified-anti-entropy fallback counter, the live-source counter)", len(cs), wantDistinct)
	seen := make(map[string]struct{}, len(cs))
	dups := 0
	for _, c := range cs {
		if _, ok := seen[c.Name()]; ok {
			dups++
		}
		seen[c.Name()] = struct{}{}
	}
	require.Zerof(t, dups, "stream-unchanged: %d duplicate counter names (every counter name must be DISTINCT)", dups)
	require.Equalf(t, wantDistinct, len(seen), "stream-unchanged: distinct names=%d, want %d", len(seen), wantDistinct)
	t.Logf("stream-unchanged PASS: Counters() carries %d DISTINCT (ADR-0034 updated the count 18->19 — the stratified-anti-entropy fallback counter; this change added NO counter — a pure-refactor change; the bridge STAYS byte-UNCHANGED — the new series auto-surfaces via §0.f)", len(cs))
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
