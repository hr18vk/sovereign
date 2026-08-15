// raceEnabled is true when the `race` build tag is active (go test -race). The
// race detector perturbs the cheap-gate-reject latency floor: a DropMalformed
// frame that returns sub-1us in a clean build returns ~5-10us under -race (the
// shadow-memory bookkeeping on every memory access). The bimodality tooth
// (two separated populations) still holds under -race, but the cheap-reject
// population shifts right, so the le=1e-06 sub-1us assertion is gated to clean
// builds only. Canonical Go idiom (mirrors pkg/sync/race_enabled_test.go).

//go:build race
// +build race

package metrics

const raceEnabled = true
