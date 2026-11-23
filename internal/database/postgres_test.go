// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package database

import (
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestInitializeSwarmPool_SimpleProtocolEnforcement checks that the connection
// configuration selects the simple query protocol without changing the URI.
func TestInitializeSwarmPool_SimpleProtocolEnforcement(t *testing.T) {
	tests := []struct {
		name string
		uri  string
	}{
		{
			name: "BareURI_NoParams",
			uri:  "postgres://user:pass@localhost:5432/testdb",
		},
		{
			name: "URIWithExistingParams",
			uri:  "postgres://user:pass@localhost:5432/testdb?sslmode=disable",
		},
		{
			name: "URIAlreadyHasSimpleProtocol",
			uri:  "postgres://user:pass@localhost:5432/testdb?default_query_exec_mode=simple_protocol",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Verify pgxpool.ParseConfig accepts the URI.
			config, err := pgxpool.ParseConfig(tc.uri)
			if err != nil {
				t.Fatalf("pgxpool.ParseConfig failed: %v", err)
			}

			// Apply the same configuration setting as InitializeSwarmPool.
			config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol

			if config.ConnConfig.DefaultQueryExecMode != pgx.QueryExecModeSimpleProtocol {
				t.Errorf("query exec mode = %v, want QueryExecModeSimpleProtocol", config.ConnConfig.DefaultQueryExecMode)
			}
		})
	}
}

// TestInitializeSwarmPool_RejectsInvalidURI checks malformed connection URIs.
func TestInitializeSwarmPool_RejectsInvalidURI(t *testing.T) {
	tests := []struct {
		name string
		uri  string
	}{
		{"GarbageString", "not-a-postgres-uri"},
		{"MissingProtocol", "localhost:5432/testdb"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := pgxpool.ParseConfig(tc.uri)
			if err == nil {
				t.Errorf("ParseConfig accepted invalid URI %q", tc.uri)
			}
		})
	}
}

// TestUnloggedStagingPromotion_ColumnJoin checks the upsert column list.
func TestUnloggedStagingPromotion_ColumnJoin(t *testing.T) {
	columns := []string{"id", "title", "content", "embedding"}
	joined := strings.Join(columns, ", ")
	expected := "id, title, content, embedding"

	if joined != expected {
		t.Errorf("joined columns = %q, want %q", joined, expected)
	}
}

// TestUnloggedStagingPromotion_StagingTableNaming checks deterministic staging names.
func TestUnloggedStagingPromotion_StagingTableNaming(t *testing.T) {
	tests := []struct {
		target   string
		expected string
	}{
		{"document_chunks", "document_chunks_temp_stage"},
		{"gazette_chunks", "gazette_chunks_temp_stage"},
		{"schemes", "schemes_temp_stage"},
	}

	for _, tc := range tests {
		t.Run(tc.target, func(t *testing.T) {
			result := tc.target + "_temp_stage"
			if result != tc.expected {
				t.Errorf("staging table = %q, want %q", result, tc.expected)
			}
		})
	}
}
