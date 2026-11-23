// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Package database provides PostgreSQL connection and bulk-ingestion helpers.
// Pools use simple_protocol to avoid prepared-statement collisions under
// PgBouncer transaction pooling. Bulk ingestion copies rows into a temporary
// staging table before upserting them into the target table.
package database

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// InitializeSwarmPool creates a PostgreSQL connection pool for PgBouncer.
// Setting simple_protocol on the parsed configuration avoids modifying the URI,
// whose password may contain URL-special characters.
func InitializeSwarmPool(ctx context.Context, connectionURI string) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(connectionURI)
	if err != nil {
		return nil, fmt.Errorf("failed to parse connection string: %w", err)
	}

	// Apply the execution mode to the parsed configuration used by the pool.
	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize connection pool: %w", err)
	}

	return pool, nil
}

// UnloggedStagingPromotion executes a multi-row bulk upsert through a
// session-scoped temporary table. COPY avoids per-row INSERT planning and WAL
// logging for staging rows; promotion into the target is a normal WAL-logged
// INSERT.
//
// Each session has its own temporary schema, so concurrent calls can use the
// same staging name. ON COMMIT DROP removes the staging table at commit.
func UnloggedStagingPromotion(ctx context.Context, pool *pgxpool.Pool, targetTable string, conflictConstraint string, columns []string, payload [][]any) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // No-op after commit (returns ErrTxClosed).

	// Session-scoped staging table — invisible to other connections.
	// Name collisions are impossible because each session has its own pg_temp schema.
	tempStage := fmt.Sprintf("%s_temp_stage", targetTable)

	// Create the staging table in this session's temporary schema. LIKE ...
	// INCLUDING ALL copies the target's indexes and constraints; ON COMMIT DROP
	// cleans up the table when the transaction commits.
	createTempSQL := fmt.Sprintf(
		"CREATE TEMPORARY TABLE %s (LIKE %s INCLUDING ALL) ON COMMIT DROP;",
		tempStage, targetTable,
	)
	if _, err := tx.Exec(ctx, createTempSQL); err != nil {
		return fmt.Errorf("failed to create temporary staging table: %w", err)
	}

	// COPY streams the payload without planning an INSERT for every row.
	copyCount, err := tx.CopyFrom(
		ctx,
		pgx.Identifier{tempStage},
		columns,
		pgx.CopyFromRows(payload),
	)
	if err != nil {
		return fmt.Errorf("failed to execute CopyFromRows: %w", err)
	}

	if int(copyCount) != len(payload) {
		return fmt.Errorf("failed to copy all rows: copied %d out of %d", copyCount, len(payload))
	}

	// Promote all staged rows in one set-based upsert.
	cols := strings.Join(columns, ", ")
	upsertSQL := fmt.Sprintf(`
		INSERT INTO %s (%s)
		SELECT %s FROM %s
		ON CONFLICT ON CONSTRAINT %s
		DO UPDATE SET extracted_entities = EXCLUDED.extracted_entities;
	`, targetTable, cols, cols, tempStage, conflictConstraint)

	if _, err := tx.Exec(ctx, upsertSQL); err != nil {
		return fmt.Errorf("failed to promote staging data: %w", err)
	}

	// Commit also drops the temporary staging table.
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}
