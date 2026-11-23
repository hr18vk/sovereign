// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

//go:build race

package mesh

// deferRaceEnabled lets the defer tests skip the 10,000-key per-frame cases
// under the race detector, where per-frame verification prevents convergence
// within a useful test deadline. The batched 10,000-key case and the smaller
// negative controls still run with race instrumentation.
const deferRaceEnabled = true
