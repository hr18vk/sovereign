// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// raceEnabled lets the ingest test use a wider latency bucket under the race
// detector. Detector instrumentation shifts cheap-reject samples to the right,
// while the signed-frame samples remain in a separate, higher-latency population.

//go:build race
// +build race

package metrics

const raceEnabled = true
