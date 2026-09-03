// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

//go:build race

package mesh_test

// raceEnabled is true when the `race` build tag is active (go test -race).
// The pkg/metrics/race_enabled_test.go precedent, mirrored for the
// loopback guards: -race instrumentation slows the VirtualNet delivery
// goroutines ~20x on a 4-core box, so the per-round quiesce window must
// scale (the ROUND cap — the topology property under test — never changes).
const raceEnabled = true
