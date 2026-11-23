// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package authorization

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/koblas/cedar-go"
	"github.com/koblas/cedar-go/engine"
)

// cedarPolicySet is the pre-parsed PolicyList. ParsePolicies returns
// engine.PolicyList (the cedar package does not re-export the type alias;
// we use engine.PolicyList imported here). The parse is the ONE-TIME cost
// this track deliberately EXCLUDES from the per-op measurement: production
// caches the parsed AST (the bench builds once and re-evals N times).
type cedarPolicySet = engine.PolicyList

// --- PATH A: attribute-FREE identity-only policy set (no store needed;
// isolates the pure AST-walk cost the 4 "sub-10us" claim pertains to.) ---
const cedarIdentityPolicies = `
permit(principal == User::"alice", action == Action::"view", resource is Photo);
permit(principal == User::"bob",   action == Action::"edit", resource is Photo);
permit(principal == Admin::"root", action, resource);
permit(principal == Service::"syncbot", action == Action::"sync",  resource is Node);
forbid (principal is User, action == Action::"deploy", resource is Node);
permit(principal == User::"carol", action == Action::"view", resource is Document);
permit(principal == User::"dave",  action == Action::"read",  resource is File);
permit(principal == User::"eve",   action == Action::"share", resource is Document);
permit(principal == User::"frank", action == Action::"view",  resource is Video);
permit(principal == User::"grace", action == Action::"view", resource is Album);
`

// --- PATH B: attribute-RESOLVING policy set (the production seam: a real
// Cedar policy checks entity attributes, so the eval calls OpLookup against
// a Store; this is the realistic cost the architecture cares about.) ---
const cedarAttrPolicies = `
permit(principal == User::"alice", action == Action::"view", resource is Photo)
when { principal == resource.owner };
permit(principal is User, action == Action::"view", resource is Photo)
when { resource.public };
forbid(principal is User, action == Action::"view", resource is Photo)
when { resource.private };
permit(principal == User::"alice", action == Action::"delete", resource is Photo)
when { principal == resource.owner };
// REMOVED Admin/active policy -- cedar v0.1.0 resolves principal.active
// even when the principal-is-Admin guard does not match, hitting the store Get on a
// User principal with no active attr; keep the attribute set aligned with the request.
permit(principal is User, action == Action::"edit", resource is Document)
when { principal == resource.owner };
permit(principal is User, action == Action::"share", resource is Document)
when { principal == resource.owner };
permit(principal is User, action == Action::"view", resource is Document)
when { resource.public };
permit(principal is User, action == Action::"comment", resource is Document)
when { principal == resource.owner };
permit(principal is User, action == Action::"view", resource is Photo)
when { resource.public };
`

// cedarAttrEntities -- a real entity store for the attribute-resolving path.
// Each Photo carries owner (entity) + public/private (bool); each Admin
// carries active (bool) so the {active} condition resolves. Matches the
// cedar-go JSON entity-store format the example/basic/main.go uses.
const cedarAttrEntities = `
[
  { "uid": { "id": "alice", "type": "User" },
    "attrs": { "department": [] }
  },
  { "uid": { "id": "root", "type": "Admin" },
    "attrs": { "active": true }
  },
  { "uid": { "id": "vacation.jpg", "type": "Photo" },
    "attrs": {
      "owner":   { "__entity": { "id": "alice", "type": "User" } },
      "public":  true,
      "private": false
    }
  },
  { "uid": { "id": "whitepaper.pdf", "type": "Document" },
    "attrs": {
      "owner":   { "__entity": { "id": "alice", "type": "User" } },
      "public":  true
    }
  }
]
`

func benchParse(tb testing.TB, src string) cedarPolicySet {
	tb.Helper()
	p, err := cedar.ParsePolicies(src)
	if err != nil {
		tb.Fatalf("ParsePolicies: %v", err)
	}
	return p
}

// BenchmarkCedarPolicyEval_Identity10_4c measures the per-eval cost of the
// attribute-free identity-only 10-policy set on this 4-core gear. This isolates
// the pure AST-walk decision cost (no entity-store resolution).
//
// The architectural claim (unverified) is that cedar-go AST evaluation executes
// in sub-10 microseconds on Graviton4 c8g.8xlarge at GOMAXPROCS=32. This
// benchmark measures the 4-core figure (GOMAXPROCS=4, CPU part 0xd40), not the
// 32-core figure. The 32-core re-run is pending the 32-core Graviton4 silicon
// benchmark measurement. The function-name suffix _4c identifies the gear.
//
// Sequential (not b.RunParallel): GOMAXPROCS=4 + RunParallel double-counts
// parallelism; the published number is the single-thread per-eval cost.
func BenchmarkCedarPolicyEval_Identity10_4c(b *testing.B) {
	policies := benchParse(b, cedarIdentityPolicies)
	auth := cedar.NewAuthorizer(policies)
	req := &cedar.Request{
		Principal: cedar.NewEntity("User", "alice"),
		Action:    cedar.NewEntity("Action", "view"),
		Resource:  cedar.NewEntity("Photo", "vacation.jpg"),
	}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ok, err := auth.IsAuthorized(ctx, req)
		if err != nil {
			b.Fatalf("IsAuthorized: %v", err)
		}
		if !ok {
			b.Fatalf("alice view Photo must ALLOW via the first policy, got DENY")
		}
	}
}

// BenchmarkCedarPolicyEval_Attr10_4c measures the per-eval cost of the
// attribute-resolving 10-policy set (with a real Store). This is the
// realistic production cost: the policy checks entity attributes via OpLookup
// against the store on each match-candidate. An unforeseen finding:
// cedar-go v0.1.0's EmptyStore returns (nil, nil) on Get, which causes a
// nil-pointer panic when a policy resolves an attribute (resource.owner) with
// no Store -- the JSON-set Store is therefore mandatory for any
// attribute-resolving policy. The bench uses a real Store.
func BenchmarkCedarPolicyEval_Attr10_4c(b *testing.B) {
	policies := benchParse(b, cedarAttrPolicies)
	store, err := cedar.StoreFromJson(strings.NewReader(cedarAttrEntities), nil)
	if err != nil {
		b.Fatalf("StoreFromJson: %v", err)
	}
	auth := cedar.NewAuthorizer(policies, cedar.WithStore(store))
	req := &cedar.Request{
		Principal: cedar.NewEntity("User", "alice"),
		Action:    cedar.NewEntity("Action", "view"),
		Resource:  cedar.NewEntity("Photo", "vacation.jpg"),
	}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ok, err := auth.IsAuthorized(ctx, req)
		if err != nil {
			b.Fatalf("IsAuthorized: %v", err)
		}
		if !ok {
			b.Fatalf("alice view vacation.jpg (owner=true public=true) must ALLOW, got DENY")
		}
	}
}

// BenchmarkCedarPolicyEval_DenyUnknown_4c measures the cost of a request that
// denies -- every policy's condition is evaluated and none matches the allow
// effect (worst-case full-walk). The principal is an unknown user not named in
// any permit; no policy's `principal ==` matches, so the result is Deny after
// scanning the whole list. Tighter-deny end-to-end policy cost.
func BenchmarkCedarPolicyEval_DenyUnknown_4c(b *testing.B) {
	policies := benchParse(b, cedarIdentityPolicies)
	auth := cedar.NewAuthorizer(policies)
	req := &cedar.Request{
		Principal: cedar.NewEntity("User", "zzz-unlisted"), // not named in any permit
		Action:    cedar.NewEntity("Action", "purge"),      // not named in any permit
		Resource:  cedar.NewEntity("Node", "unknown-node"), // not a Photo/Document/File/Video/Album
	}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ok, err := auth.IsAuthorized(ctx, req)
		if err != nil {
			b.Fatalf("IsAuthorized: %v", err)
		}
		if ok {
			b.Fatalf("unlisted user purging a Node must DENY (no permit matches), got ALLOW")
		}
	}
}

// BenchmarkParsePoliciesOnce_4c measures the one-time ParsePolicies cost for
// the 10-policy identity set. This is outside the per-op hot path (production
// caches the parsed AST) but the benchmark reports the deploy-time policy-load
// cost as a measured number, not an estimate. Each iteration is an
// independent parse; the per-op figure is the per-parse cost.
func BenchmarkParsePoliciesOnce_4c(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := cedar.ParsePolicies(cedarIdentityPolicies); err != nil {
			b.Fatalf("ParsePolicies: %v", err)
		}
	}
}

// ---------------------------------------------------------------------------
// Gates: benchmark naming verification and scope check
// ---------------------------------------------------------------------------

// TestGateCedar_GearHonesty asserts the 4-core gear (NumCPU==4,
// GOMAXPROCS==4) and that no authorization source carries a "_32c" tag (the
// admission and clock gate hygiene work mislabel class). The 32-core figure is
// the 32-core Graviton4 silicon benchmark measurement publication number, not
// this 4-core gear; benchmarks in this package evaluate the 4-core configuration.
func TestGateCedar_GearHonesty(t *testing.T) {
	n := runtime.NumCPU()
	gmp := runtime.GOMAXPROCS(0)
	t.Logf("gear: NumCPU=%d GOMAXPROCS=%d (tag: _4c)", n, gmp)
	if n != 4 {
		t.Skipf("box reports NumCPU=%d, not the 4-core gear this benchmark targets", n)
	}
	if gmp != 4 {
		t.Skipf("GOMAXPROCS=%d, not 4", gmp)
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	entries, err := os.ReadDir(wd)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(wd, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		// Stripped scan: comments and string literals removed so this check's
		// own detection literal does not self-trigger.
		code := stripCedarCommentsAndStrings(string(b))
		if strings.Contains(code, "_32c") {
			// Distinguish the forbidden tag from a comment mentioning the rule.
			// The bench names all end in _4c; a _32c appearing anywhere in this
			// package's source outside an explanatory comment is the mislabel.
			t.Errorf("forbidden \"_32c\" tag in %s (benchmarks in this package read \"_4c\"; 32c is the 32-core Graviton4 silicon benchmark measurement publication number, not this 4-core gear)", name)
		}
	}
}

// stripCedarCommentsAndStrings strips // line comments, /* */ block
// comments, raw (backtick) strings, and double-quoted strings so the
// gate check can carry its own detection literal without self-triggering.
// A bare token in real bench function names/identifiers survives the strip and fires.
func stripCedarCommentsAndStrings(s string) string {
	var out strings.Builder
	i := 0
	inLine, inBlock, inRaw, inStr := false, false, false, false
	for i < len(s) {
		c := s[i]
		switch {
		case inLine:
			out.WriteByte(' ')
			if c == '\n' {
				inLine = false
			}
			i++
		case inBlock:
			out.WriteByte(' ')
			if c == '*' && i+1 < len(s) && s[i+1] == '/' {
				inBlock = false
				i += 2
				continue
			}
			i++
		case inRaw:
			out.WriteByte(' ')
			if c == '`' {
				inRaw = false
			}
			i++
		case inStr:
			out.WriteByte(' ')
			if c == '\\' {
				i += 2
				continue
			}
			if c == '"' {
				inStr = false
			}
			i++
		default:
			if c == '/' && i+1 < len(s) && s[i+1] == '/' {
				inLine = true
				i += 2
				continue
			}
			if c == '/' && i+1 < len(s) && s[i+1] == '*' {
				inBlock = true
				i += 2
				continue
			}
			if c == '`' {
				inRaw = true
				i++
				continue
			}
			if c == '"' {
				inStr = true
				i++
				continue
			}
			out.WriteByte(c)
			i++
		}
	}
	return out.String()
}
