// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// raceEnabled selects the non-race latency assertion in the ingest test. The
// race-tagged companion file selects the more permissive assertion instead.

//go:build !race
// +build !race

package metrics

const raceEnabled = false
