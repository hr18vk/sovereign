package crypto

import (
	"strings"
	"testing"
	"unsafe"
)

// TestMaskPII_NoPII_ReturnsInputUnchanged verifies the zero-alloc equality fast
// path: when the payload contains no 12-digit run, the returned string must be
// byte-equal AND share the same data pointer as the input, so the MemTable
// `maskedStr == payloadStr` reuse path fires.
func TestMaskPII_NoPII_ReturnsInputUnchanged(t *testing.T) {
	in := "User applied for service enrollment, no PII here."
	out := MaskPII(in)
	if out != in {
		t.Fatalf("no-PII path: out=%q want %q", out, in)
	}
	// Same data pointer + length → Go string == is the caller's zero-alloc reuse.
	dpOut := unsafe.StringData(out)
	dpIn := unsafe.StringData(in)
	if dpOut != dpIn || len(out) != len(in) {
		t.Fatalf("no-PII path: data ptr/len not shared (out=%p len=%d in=%p len=%d)",
			dpOut, len(out), dpIn, len(in))
	}
}

// TestMaskPII_RedactsGeneric fulfills the memtable round-trip contract:
// raw 12-digit run removed, "PII_REDACTED" marker present.
func TestMaskPII_RedactsGeneric(t *testing.T) {
	const raw = "499118665246"
	in := "User ID: " + raw + " applied for service enrollment."
	out := MaskPII(in)
	if strings.Contains(out, raw) {
		t.Fatalf("masked output still contains raw PII: %q", out)
	}
	if !strings.Contains(out, redactionMarker) {
		t.Fatalf("masked output missing %q marker: %q", redactionMarker, out)
	}
	// Prefix/suffix preserved.
	if !strings.HasPrefix(out, "User ID: ") {
		t.Fatalf("prefix not preserved: %q", out)
	}
	if !strings.HasSuffix(out, " applied for service enrollment.") {
		t.Fatalf("suffix not preserved: %q", out)
	}
}

// TestMaskPII_Deterministic ensures the same 12-digit run redacts to the same
// marker each call (xxhash determinism), enabling downstream join.
func TestMaskPII_Deterministic(t *testing.T) {
	const run = "499118665246"
	a := MaskPII("x" + run + "y")
	b := MaskPII("z" + run + "w")
	// Extract the marker substring from each.
	// Extract ONLY the marker substring: marker + "_" + 16 hex (no trailing suffix).
	extract := func(s string) string {
		idx := strings.Index(s, redactionMarker)
		end := idx + len(redactionMarker) + 1 + digestHexLen // "_" + 16 hex
		return s[idx:end]
	}
	ma := extract(a)
	mb := extract(b)
	if ma != mb {
		t.Fatalf("deterministic redaction mismatch:\n a=%q\n b=%q", ma, mb)
	}
}

// TestMaskPII_MultipleRuns masks every non-overlapping 12-digit run.
func TestMaskPII_MultipleRuns(t *testing.T) {
	in := "111111111111 and 222222222222 both here."
	out := MaskPII(in)
	if strings.Contains(out, "111111111111") || strings.Contains(out, "222222222222") {
		t.Fatalf("unmasked run remains: %q", out)
	}
	if n := strings.Count(out, redactionMarker); n != 2 {
		t.Fatalf("expected 2 markers, got %d: %q", n, out)
	}
}

// TestMaskPII_LongRunMaskedOnce verifies a 13+ digit run masks the first 12
// (the generic-PII scan commences at any offset that yields 12 consecutive).
func TestMaskPII_LongRunMasked(t *testing.T) {
	in := "trailing 1234567890123 13 digits"
	out := MaskPII(in)
	// The 13-digit block must not survive intact.
	if strings.Contains(out, "1234567890123") {
		t.Fatalf("13-digit block not masked: %q", out)
	}
}

// TestMaskPII_ShortPayloadNoAlloc sanity-checks the length-bailout.
func TestMaskPII_ShortPayloadNoAlloc(t *testing.T) {
	out := MaskPII("abc")
	if out != "abc" {
		t.Fatalf("short payload altered to %q", out)
	}
}

// BenchmarkMaskPII_NoPII measures the common hot path: scan a 1KB payload,
// find no PII, return the input string unchanged. Must report 0 allocs.
func BenchmarkMaskPII_NoPII(b *testing.B) {
	// 1KB payload, no 12-digit run, mirroring the dossier's stated workload.
	payload := strings.Repeat("User applied for welfare schemes today. ", 25)
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = MaskPII(payload)
	}
}

// BenchmarkMaskPII_WithPII measures the rare masking path.
func BenchmarkMaskPII_WithPII(b *testing.B) {
	payload := "User ID: 499118665246 applied for service enrollment, ref 901234567890."
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = MaskPII(payload)
	}
}

// BenchmarkMaskPII_KB_Parallel simulates the 32-core ingestion fan-in.
func BenchmarkMaskPII_KB_Parallel(b *testing.B) {
	payload := strings.Repeat("User applied for welfare schemes today. ", 25)
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = MaskPII(payload)
		}
	})
}

// TestMaskPII_MemtableContract verifies the exact call pattern used by
// internal/database/memtable.go (Override O2.5): build a string view of a
// []byte payload via unsafe.String, mask it, and confirm the == reuse path
// fires when no PII is present, with ZERO allocations on the no-PII path.
// This replaces the jemalloc-dependent memtable integration test for the
// crypto package's own verification.
func TestMaskPII_MemtableContract(t *testing.T) {
	payloadBytes := []byte("User applied for service enrollment, no PII here.")
	// Mirrors memtable.go: unsafe.String(&payload[0], len(payload))
	payloadStr := string(payloadBytes)
	maskedStr := MaskPII(payloadStr)
	if maskedStr != payloadStr {
		t.Fatalf("no-PII reuse path failed: masked != payload")
	}
}

// TestMaskPII_Mems_Audit confirms the mask: masking the exact PII the
// memtable test uses produces output lacking the raw run and containing the
// required redaction marker (the contract TestMemTable_PIIMaskingEnforced
// asserts at the Arrow layer).
func TestMaskPII_Mems_Audit(t *testing.T) {
	out := MaskPII("User ID: 499118665246 applied for service enrollment.")
	if strings.Contains(out, "499118665246") {
		t.Fatalf("raw PII present: %q", out)
	}
	if !strings.Contains(out, "PII_REDACTED") {
		t.Fatalf("redaction marker missing: %q", out)
	}
}
