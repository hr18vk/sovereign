// raceEnabled is false in clean builds and true when the `race` build tag
// is active (go test -race). Canonical Go idiom for tests that must skip
// themselves under -race because the race detector perturbs the
// measurement they take — see TestHotPathZeroAllocations for the specific
// case (testing.AllocsPerRun's heap-alloc count is inflated by shadow-
// memory descriptor allocs for pointer/length conversions such as
// unsafe.String(&buf[0], 8) in makeBinaryKey at physics_test.go:82; those
// allocs are counted by AllocsPerRun but are NOT engine allocations, so
// the "got 2" reading under -race is a measurement-instrumentation
// artifact, not a Zero-GC-mandate breach).

//go:build race
// +build race

package sync

const raceEnabled = true
