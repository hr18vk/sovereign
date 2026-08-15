//go:build !fuzzbuginject

package fuzz

// bugInjectSeedsOrNil returns nil in the DEFAULT build (the bug-inject target's
// seed builder bugInjectSeeds lives in bug_inject_test.go, which is behind the
// `fuzzbuginject` build tag — so the builder does NOT exist in the default
// build). The byte-equality tooth TestSeedCorpusMatchesBuilders calls this for
// FuzzBugInjectControl: in the default build it returns nil → the tooth SKIPS
// the byte-equality check for that target with an honest log (the corpus is
// still PRESENT + PARSEABLE — TestSeedCorpusIsValid covers the no-panic
// property); under -tags fuzzbuginject the build-tagged override in
// bug_inject_test.go returns the real bugInjectSeeds() list + the byte-equality
// check runs. This is the SAME opt-in discipline as the no-panic proof
// (TestBugInjectControlProof): the bug-inject path is operator-opt-in, the
// default build does NOT compile it (so the bug-injected unmarshaler copy NEVER
// ships in the production binary).
//
// The build-tag exclusion (!fuzzbuginject) ensures ONLY ONE of this file or
// bug_inject_test.go compiles per build — no redeclaration.
func bugInjectSeedsOrNil() [][]byte {
	return nil
}
