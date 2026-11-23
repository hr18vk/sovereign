// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package main

// Flag parsing leaves the partial-view, region-aware, and phase-jitter options
// disabled by default. Configuration validation rejects --partial-intra-view
// without --region-aware and accepts valid combinations.

import (
	"strings"
	"testing"
)

func TestRegionFlags_DefaultOffAndOrphanGuard(t *testing.T) {
	cfg, err := parseFlags([]string{"--selftest"})
	if err != nil {
		t.Fatalf("parseFlags(bare): %v", err)
	}
	if cfg.partialIntraViewEnable {
		t.Fatalf("--partial-intra-view parsed true with no flag — default is off")
	}
	if cfg.regionAwareEnable {
		t.Fatalf("--region-aware parsed true with no flag — default is off")
	}
	if cfg.sweepPhaseJitterEnabled {
		t.Fatalf("--sweep-phase-jitter parsed true with no flag — default is off")
	}

	orphan := &nodeConfig{partialIntraViewEnable: true}
	if err := validatePartialIntraViewConfig(orphan); err == nil {
		t.Fatalf("--partial-intra-view without --region-aware must fail (the flag is a no-op without it)")
	} else if !strings.Contains(err.Error(), "--partial-intra-view requires --region-aware") {
		t.Fatalf("wrong error text (got %q) — the message must name both flags", err.Error())
	}

	legal := &nodeConfig{partialIntraViewEnable: true, regionAwareEnable: true}
	if err := validatePartialIntraViewConfig(legal); err != nil {
		t.Fatalf("--partial-intra-view with --region-aware must boot (got %q)", err.Error())
	}

	regionOnly := &nodeConfig{regionAwareEnable: true}
	if err := validatePartialIntraViewConfig(regionOnly); err != nil {
		t.Fatalf("--region-aware without the view is legal (got %q)", err.Error())
	}

	cfg2, err := parseFlags([]string{"--selftest", "--partial-intra-view"})
	if err != nil {
		t.Fatalf("parseFlags(--partial-intra-view): %v", err)
	}
	if !cfg2.partialIntraViewEnable || cfg2.regionAwareEnable {
		t.Fatalf("parseFlags: --partial-intra-view parsed view=%v regionAware=%v — flag surface miswired", cfg2.partialIntraViewEnable, cfg2.regionAwareEnable)
	}

	cfgJ, err := parseFlags([]string{"--selftest", "--sweep-phase-jitter"})
	if err != nil {
		t.Fatalf("parseFlags(--sweep-phase-jitter): %v", err)
	}
	if !cfgJ.sweepPhaseJitterEnabled {
		t.Fatalf("parseFlags: --sweep-phase-jitter parsed false — flag surface miswired")
	}

	if err := validatePartialIntraViewConfig(cfg2); err == nil {
		t.Fatalf("parsed orphan config must fail the guard")
	}
}
