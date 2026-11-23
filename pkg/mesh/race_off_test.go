// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

//go:build !race

package mesh

// deferRaceEnabled lets the defer tests run their 10,000-key per-frame cases
// in default builds.
const deferRaceEnabled = false
