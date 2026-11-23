// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

//go:build !fuzzbuginject

package fuzz

// bugInjectSeedsOrNil returns nil without the fuzzbuginject build tag, so
// TestSeedCorpusMatchesBuilders skips byte comparison for the fault-injection
// target. TestSeedCorpusIsValid still checks that its committed files parse.
// The tagged implementation in bug_inject_test.go returns the actual seeds and
// enables both the byte comparison and the deterministic control.
//
// The complementary build constraints compile exactly one implementation.
func bugInjectSeedsOrNil() [][]byte {
	return nil
}
