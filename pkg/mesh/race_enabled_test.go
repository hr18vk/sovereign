// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

//go:build race

package mesh_test

// raceEnabled lets the loopback mesh tests extend their delivery windows under
// the race detector. The round limits and topology assertions stay unchanged.
const raceEnabled = true
