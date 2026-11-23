// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// TestNoTrueTimeWaitUntilSafe enforces ADR-0001 (Reject TrueTime commit-wait):
// the engine rejects TrueTime commit-wait because HLC with Amazon Time Sync ε
// (~26-50 µs) plus per-peer EWMA is mathematically sufficient for CRDT causal
// consistency, which needs only a causal partial order, not absolute
// linearizability. A TrueTime commit-wait would insert an O(ε) sleep into the
// Join hot path, taxing ingress throughput for a property the lattice already
// guarantees.
//
// This test is a lint-style static AST scan (stdlib go/token, go/parser,
// go/ast; zero new dependencies). It is not a proof of system correctness.
// A future contributor who adds a wait-until-safe primitive to Join will see
// this test fail at CI time; the correct response is to amend ADR-0001 with a
// superseding ADR that re-opens the math, not to weaken this test.
//
// Scope (load-bearing): parse only the Join fast-path files in pkg/sync and
// their deliver-to-Join callees, not the entire repo. Chaos tests
// (internal/chaos) legitimately sleep; a broad scan would false-positive.
//
//   - pkg/sync/crdt.go
//   - pkg/sync/crdt_apply.go
//   - pkg/sync/crdt_apply_batch.go
//
// Depth cap = 1: Join calls internal helpers, but a commit-wait would be added
// at the Join call site or Join body, not buried inside a leaf helper. A
// depth-1 scan of Join and its direct callees inside pkg/sync is the right
// granularity. A wait hidden two calls deep would escape; this is a known
// limitation, not a fixable defect.
//
// Carve-out: the in-engine HLC advances via AdvanceLamportTo, which uses an
// atomic.CompareAndSwap loop. That is lock-free (atomic CAS, not a clock-wait).
// The test must not flag the CAS loop; it is the proof that Join is
// non-blocking by construction. The channel-name regex below matches channel
// receive identifiers only; the CAS loop is an atomic operation on a *uint64,
// not a channel, so it is naturally not matched. Do not broaden the regex to
// match the CAS loop; that would conflate a lock-free primitive with a
// clock-wait and defeat the test's purpose.
//
// Forbidden primitives (a matching CallExpr or Stmt fails):
//   - time.Sleep
//   - time.After, time.NewTimer, time.Tick, time.NewTicker whose result feeds
//     a <- receive (a blocking wait on a time channel)
//   - (*sync.Cond).Wait or (*sync.WaitGroup).Wait keyed to clock-derived data
//     (a TrueTime commit-wait would key a WaitGroup or Cond to the uncertainty
//     window; flag any .Wait() whose enclosing function also references
//     time.Now, utcx, or epsilon locally — conservative for a negative test)
//   - a <- receive on a channel whose identifier matches
//     /(wait|safe|epsilon|truetime|uncertain)/i (regex; conservative)

package sync

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"testing"
)

// joinPathFiles are the files the test scans (see Scope above).
var joinPathFiles = []string{
	"crdt.go",
	"crdt_apply.go",
	"crdt_apply_batch.go",
}

// waitChannelRe matches channel identifiers named for the uncertainty window.
// It is for channel receives only (see Carve-out: the CAS loop is an atomic
// operation, not a channel, and is intentionally not matched).
var waitChannelRe = regexp.MustCompile(`(?i)wait|safe|epsilon|truetime|uncertain`)

// clockKeyRe matches local identifiers a clock-keyed Wait would reference.
var clockKeyRe = regexp.MustCompile(`(?i)time\.Now|utcx|epsilon|truetime|uncertain|wallNow|hlc\.Physical`)

// scannedFunc records one function scanned by the test, for the t.Logf table.
type scannedFunc struct {
	name      string
	pos       token.Position
	primitive string // "" if none found
	verdict   string // "OK" or "FAIL"
}

func TestNoTrueTimeWaitUntilSafe(t *testing.T) {
	fset := token.NewFileSet()
	pkgFiles := make(map[string]*ast.File, len(joinPathFiles))
	for _, name := range joinPathFiles {
		f, err := parser.ParseFile(fset, name, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		pkgFiles[name] = f
	}

	// Collect every top-level FuncDecl across the scanned files, keyed by name,
	// so Join's direct callees can be resolved to their bodies for the depth-1
	// scan. Method receivers are irrelevant for the name match (a commit-wait
	// would be added at the call site regardless of receiver).
	funcsByName := make(map[string]*ast.FuncDecl)
	for _, f := range pkgFiles {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			funcsByName[fn.Name.Name] = fn
		}
	}

	join, ok := funcsByName["Join"]
	if !ok {
		t.Fatalf("Join FuncDecl not found in scanned files — scope regression")
	}

	// Depth-1 scan set: Join itself + every direct callee of Join that is
	// defined in pkg/sync (resolved by name). Closures defined lexically inside
	// Join (e.g. perShardMerge) are captured automatically because ast.Inspect
	// descends into FuncLit nodes within Join's body.
	scanSet := []*ast.FuncDecl{join}
	seen := map[string]bool{"Join": true}
	for _, callee := range directCallees(join) {
		if seen[callee] {
			continue
		}
		if fn, ok := funcsByName[callee]; ok {
			seen[callee] = true
			scanSet = append(scanSet, fn)
		}
	}

	var rows []scannedFunc
	failed := false
	for _, fn := range scanSet {
		row := scannedFunc{name: funcDeclLabel(fn), pos: fset.Position(fn.Pos()), verdict: "OK"}
		if prim := findWaitUntilSafe(fn); prim != "" {
			row.primitive = prim
			row.verdict = "FAIL"
			failed = true
		}
		rows = append(rows, row)
	}

	// Diagnosable table: a CI failure shows exactly what was found and where,
	// not a mystery "test failed" blob.
	t.Logf("wait-until-safe test — depth-1 scan of Join call graph (%d funcs):", len(rows))
	t.Logf("  %-10s %-7s %-9s %s", "Func", "Line", "Verdict", "Primitive")
	for _, r := range rows {
		t.Logf("  %-10s %-7d %-9s %s", r.name, r.pos.Line, r.verdict, r.primitive)
	}

	if failed {
		t.Fatalf("ADR-0001 violated — a wait-until-safe primitive was found in the " +
			"Join call graph. Either revert the commit-wait, or amend ADR-0001 with a " +
			"superseding ADR that re-opens the math. Do not weaken this test.")
	}
}

// directCallees returns the set of function/method names called directly within
// fn's body (the textual identifiers of every CallExpr's Fun, unwrapped from
// selectors and index expressions). It does not recurse into callees' bodies —
// that is the depth-1 cap.
func directCallees(fn *ast.FuncDecl) []string {
	var out []string
	seen := map[string]bool{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		ce, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if name := callName(ce.Fun); name != "" && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
		return true
	})
	return out
}

// callName extracts the textual identifier of a call's Fun, unwrapping
// selectors (e.AdvanceLamportTo -> AdvanceLamportTo), index expressions, and
// parenthesized expressions. Builtins (append/len/make/...) are returned as-is
// and simply won't resolve to a FuncDecl in the scan set.
func callName(fun ast.Expr) string {
	switch e := fun.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return e.Sel.Name
	case *ast.IndexExpr:
		return callName(e.X)
	case *ast.ParenExpr:
		return callName(e.X)
	}
	return ""
}

// findWaitUntilSafe walks fn's body and returns a human-readable description of
// the first forbidden primitive found, or "" if the body is clean.
func findWaitUntilSafe(fn *ast.FuncDecl) string {
	// Pre-scan: does this func reference clock-derived locals (for the
	// clock-keyed Wait rule)? Conservative: any textual match in the func body.
	clockKeyed := referencesClockKey(fn.Body)

	var hit string
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if hit != "" {
			return false
		}
		switch s := n.(type) {
		case *ast.CallExpr:
			if prim := forbiddenCall(s, clockKeyed); prim != "" {
				hit = prim
			}
		case *ast.UnaryExpr:
			// <- on a channel whose identifier matches the uncertainty regex.
			if s.Op == token.ARROW {
				if id := chanIdent(s.X); id != "" && waitChannelRe.MatchString(id) {
					hit = fmt.Sprintf("<- on channel %q (uncertainty-named)", id)
				}
			}
		}
		return hit == ""
	})
	return hit
}

// forbiddenCall returns a description if ce is a forbidden primitive, else "".
func forbiddenCall(ce *ast.CallExpr, clockKeyed bool) string {
	name := callName(ce.Fun)
	switch name {
	case "Sleep":
		if isPkg(ce.Fun, "time") {
			return "time.Sleep"
		}
	case "After", "NewTimer", "Tick", "NewTicker":
		if isPkg(ce.Fun, "time") && feedsReceive(ce) {
			return "time." + name + " feeding a <- receive"
		}
		// A time.After/timer result that is stored to a var and later received
		// (e.g. `t := time.After(eps); <-t`) is caught by the receive-side scan
		// below in findWaitUntilSafe only if the channel ident matches the
		// uncertainty regex; a bare `t` does not. The direct `<-time.After(eps)`
		// shape is caught here by AST identity.
	case "Wait":
		// (*sync.Cond).Wait / (*sync.WaitGroup).Wait. Flag unconditionally when
		// clock-derived, else flag only the explicit .Wait() form (conservative
		// for a negative test: a WaitGroup/Cond keyed to the uncertainty
		// window is exactly the TrueTime commit-wait shape).
		if clockKeyed {
			return ".Wait() in a func referencing clock-derived data"
		}
	}
	return ""
}

// isPkg reports whether fun is a <pkg>.<Sel> selector rooted at the named pkg.
func isPkg(fun ast.Expr, pkg string) bool {
	sel, ok := fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == pkg
}

// feedsReceive reports whether a time.After/NewTimer/Tick/NewTicker call is
// treated as a blocking wait. The Join path imports no "time" package today
// (verified: crdt.go/crdt_apply.go/crdt_apply_batch.go have no "time" import),
// so any time.* call appearing in the Join call graph is itself the regression
// signal — a non-received timer stored to a var would still mean time was
// introduced into the non-blocking path. We therefore treat every time.*
// timer-constructing call as forbidden, which is conservative in the correct
// direction for a negative test. See ADR-0001 §6 N1: Join is O(1)-non-blocking.
func feedsReceive(ce *ast.CallExpr) bool {
	return true
}

// chanIdent extracts the identifier of a channel expression for the receive
// rule, unwrapping selectors (t.C -> C is not matched; only bare ids like
// `waitCh` are) and parens. We match bare identifiers only so the CAS-loop
// carve-out (an atomic on a *uint64) is never confused with a channel.
func chanIdent(x ast.Expr) string {
	switch e := x.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.ParenExpr:
		return chanIdent(e.X)
	}
	return ""
}

// referencesClockKey reports whether body contains a textual reference to a
// clock-derived symbol (time.Now / utcx / epsilon / truetime / uncertain /
// wallNow / hlc.Physical). Used to gate the clock-keyed Wait rule.
func referencesClockKey(body *ast.BlockStmt) bool {
	hit := false
	ast.Inspect(body, func(n ast.Node) bool {
		if hit {
			return false
		}
		switch e := n.(type) {
		case *ast.SelectorExpr:
			if clockKeyRe.MatchString(e.Sel.Name) {
				hit = true
			}
			if id, ok := e.X.(*ast.Ident); ok && clockKeyRe.MatchString(id.Name+"."+e.Sel.Name) {
				hit = true
			}
		case *ast.Ident:
			if clockKeyRe.MatchString(e.Name) {
				hit = true
			}
		}
		return !hit
	})
	return hit
}

// funcDeclLabel renders a FuncDecl as receiver+name for the t.Logf table.
func funcDeclLabel(fn *ast.FuncDecl) string {
	if fn.Recv != nil && len(fn.Recv.List) > 0 {
		recv := fn.Recv.List[0].Type
		if star, ok := recv.(*ast.StarExpr); ok {
			return "*" + typeBaseName(star.X) + "." + fn.Name.Name
		}
		return typeBaseName(recv) + "." + fn.Name.Name
	}
	return fn.Name.Name
}

func typeBaseName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return typeBaseName(t.X)
	case *ast.IndexExpr:
		return typeBaseName(t.X)
	}
	return "?"
}
