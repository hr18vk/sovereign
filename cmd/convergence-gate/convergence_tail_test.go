// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package main

import (
	"testing"
)

// TestConvergence_TailRows_NoLie checks the three tail-ordering invariants:
// the injection source is excluded, nodes that never converged sort first, and
// converged nodes follow in descending atMs order. The large convergenceNeverMs
// sentinel is essential: a conventional -1 sentinel would sort the worst nodes
// last and hide them from the tail report.
func TestConvergence_TailRows_NoLie(t *testing.T) {
	mk := func(idx int, region string) node { return node{idx: idx, region: region} }
	nodes := []node{
		mk(0, "us-east-1"), // injection source; excluded from the tail
		mk(1, "us-east-1"),
		mk(2, "eu-west-1"),
		mk(3, "ap-southeast-2"),
		mk(4, "ap-southeast-2"),
	}
	// Node 4 has no convergence timestamp. Node 3 is the slowest recorded node.
	firstConvergedAtMs := map[int]int64{1: 1200, 2: 3400, 3: 9000}

	rows := convergenceComputeTailRows(nodes, firstConvergedAtMs)

	if len(rows) != len(nodes)-1 {
		t.Fatalf("got %d tail rows, want %d with the seed excluded", len(rows), len(nodes)-1)
	}
	for _, r := range rows {
		if r.idx == 0 {
			t.Fatalf("seed appears in tail rows: %+v", r)
		}
	}

	// The unrecorded node comes first, followed by decreasing timestamps.
	want := []struct {
		idx  int
		atMs int64
	}{{4, convergenceNeverMs}, {3, 9000}, {2, 3400}, {1, 1200}}
	if len(rows) != len(want) {
		t.Fatalf("got %d rows, want %d", len(rows), len(want))
	}
	for i, w := range want {
		if rows[i].idx != w.idx || rows[i].atMs != w.atMs {
			t.Fatalf("row %d = %+v, want idx=%d atMs=%d in worst-first order", i, rows[i], w.idx, w.atMs)
		}
	}

	// Distinct times make the descending-order assertion sensitive to reversals.
	if !(rows[1].atMs > rows[2].atMs && rows[2].atMs > rows[3].atMs) {
		t.Fatalf("converged rows are not strictly descending: %+v", rows)
	}
}

// TestConvergence_TailRows_AllNeverConverged exercises a region with no
// convergence timestamps. Every non-seed row must carry convergenceNeverMs, and
// convergenceReportTail must skip min/p50/max indexing for the empty region
// instead of panicking.
func TestConvergence_TailRows_AllNeverConverged(t *testing.T) {
	mk := func(idx int, region string) node { return node{idx: idx, region: region} }
	nodes := []node{mk(0, "us-east-1"), mk(1, "ap-southeast-2"), mk(2, "ap-southeast-2")}
	rows := convergenceComputeTailRows(nodes, map[int]int64{})
	if len(rows) != 2 {
		t.Fatalf("got %d non-seed rows, want 2", len(rows))
	}
	for _, r := range rows {
		if r.atMs != convergenceNeverMs {
			t.Fatalf("row %+v does not carry convergenceNeverMs", r)
		}
	}
	convergenceReportTail(nodes, map[int]int64{}, 0)
}
