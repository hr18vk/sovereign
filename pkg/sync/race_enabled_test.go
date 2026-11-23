// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

//go:build race

package sync

// raceEnabled reports whether the race build tag is active. Tests use it to
// reduce scheduling-heavy workloads and to skip allocation counts that race
// detector instrumentation would distort.
const raceEnabled = true
