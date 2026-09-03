// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

//go:build !race

package mesh_test

// raceEnabled is false in clean builds (the pkg/metrics precedent).
const raceEnabled = false
