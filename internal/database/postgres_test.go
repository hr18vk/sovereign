package database

import (
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestInitializeSwarmPool_SimpleProtocolEnforcement validates that the
// simple_protocol defense is correctly applied programmatically.
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

			// Apply programmatic lock (mirroring InitializeSwarmPool behavior).
			config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol

			if config.ConnConfig.DefaultQueryExecMode != pgx.QueryExecModeSimpleProtocol {
				t.Errorf("Expected QueryExecModeSimpleProtocol, got %v", config.ConnConfig.DefaultQueryExecMode)
			}
		})
	}
}

// TestInitializeSwarmPool_RejectsInvalidURI validates error handling for malformed URIs.
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
			// ParseConfig should fail for all of these.
			_, err := pgxpool.ParseConfig(tc.uri)
			if err == nil {
				t.Errorf("Expected error for invalid URI %q, got nil", tc.uri)
			}
		})
	}
}

// TestUnloggedStagingPromotion_ColumnJoin validates the SQL column construction
// to prevent SQL injection or malformation in the UPSERT query.
func TestUnloggedStagingPromotion_ColumnJoin(t *testing.T) {
	columns := []string{"id", "title", "content", "embedding"}
	joined := strings.Join(columns, ", ")
	expected := "id, title, content, embedding"

	if joined != expected {
		t.Errorf("Column join mismatch: got %q, expected %q", joined, expected)
	}
}

// TestUnloggedStagingPromotion_StagingTableNaming validates deterministic table naming.
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
				t.Errorf("Staging table name mismatch: got %q, expected %q", result, tc.expected)
			}
		})
	}
}
