// raceEnabled is false in clean builds. The race-tagged companion file
// race_enabled_test.go declares the true form, selected only under
// `go test -race`. Canonical Go idiom for tests that must skip themselves
// under -race; see race_enabled_test.go and TestHotPathZeroAllocations.

//go:build !race
// +build !race

package sync

const raceEnabled = false
