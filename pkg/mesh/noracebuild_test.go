// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

//go:build !race

package mesh

// quintetRaceBuild is false without the race detector. The declined-connection
// tests run their full wave counts and exact composition and drop totals; the
// race build uses the smaller bounds documented in racebuild_test.go.
const quintetRaceBuild = false
