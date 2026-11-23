// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

//go:build race

package mesh

// quintetRaceBuild selects the race-detector workload for the challenge-answer
// budget test. Signing 66,560 responses with race instrumentation can starve
// the readers' rolling 300 ms windows, so that build retains the margin,
// per-key, and concurrent mini-wave cases but skips the full composition case.
const quintetRaceBuild = true
