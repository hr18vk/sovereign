// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

//go:build !race

package sync

// raceEnabled selects allocation assertions that run without race-detector
// instrumentation. The race-tagged companion file defines the true variant.
const raceEnabled = false
