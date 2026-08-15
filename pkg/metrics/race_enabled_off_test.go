// raceEnabled is false in clean builds. The race-tagged companion file
// race_enabled_test.go declares the true form, selected only under
// `go test -race`. See race_enabled_test.go for the perturbation rationale.

//go:build !race
// +build !race

package metrics

const raceEnabled = false
