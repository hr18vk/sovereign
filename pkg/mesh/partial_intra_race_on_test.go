// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

//go:build race

package mesh

// viewRaceEnabled selects the 36-node census workload under the race detector.
// Building and driving the 100-node workload with race instrumentation exceeds
// useful test deadlines; an environment gate can still force that workload.
// The smaller mesh runs the same assertions and byte stream.
const viewRaceEnabled = true
