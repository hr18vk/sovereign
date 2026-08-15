// Package database implements the PostgreSQL substrate for the Ingestion Engine.
// It enforces the simple_protocol execution mode to prevent PgBouncer transaction
// pooling session collisions, and implements the Temporary Staging Promotion pattern
// to bypass WAL serialization bottlenecks during civilizational-scale bulk ingestion.
package database

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// InitializeSwarmPool creates a new PostgreSQL connection pool optimized for PgBouncer.
//
// ARCHITECTURAL MANDATE: simple_protocol is enforced programmatically on the
// parsed ConnConfig struct. We do NOT manipulate the raw URI string, as production
// passwords may contain URL-special characters (?, @, &, #) that would corrupt
// naive string.Contains/append logic.
func InitializeSwarmPool(ctx context.Context, connectionURI string) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(connectionURI)
	if err != nil {
		return nil, fmt.Errorf("failed to parse connection string: %w", err)
	}

	// Single, authoritative enforcement point. No URI mutation needed.
	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize connection pool: %w", err)
	}

	return pool, nil
}

// UnloggedStagingPromotion executes a multi-row bulk UPSERT operation via a
// session-scoped temporary table, bypassing WAL and statement planning.
//
// ARCHITECTURAL FIXES (v2):
//  1. Uses CREATE TEMPORARY TABLE instead of CREATE UNLOGGED TABLE.
//     Temp tables write to pg_temp_N (session-local catalog), NOT pg_class.
//     This eliminates AccessExclusiveLock contention on the shared system catalog.
//  2. Temp tables are session-scoped — two transactions can use identical names
//     without collision, solving the swarm concurrency name collision.
//  3. ON COMMIT DROP ensures automatic cleanup even on error paths.
//  4. No explicit DROP TABLE needed — the transaction commit handles it.
func UnloggedStagingPromotion(ctx context.Context, pool *pgxpool.Pool, targetTable string, conflictConstraint string, columns []string, payload [][]any) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // No-op after commit (returns ErrTxClosed).

	// Session-scoped staging table — invisible to other connections.
	// Name collisions are impossible because each session has its own pg_temp schema.
	tempStage := fmt.Sprintf("%s_temp_stage", targetTable)

	// Step 1: Create session-scoped temporary staging table.
	// ON COMMIT DROP ensures automatic cleanup when the transaction commits.
	// LIKE ... INCLUDING ALL replicates indexes and constraints from the target.
	// Writes to pg_temp_N catalog — NO contention on shared pg_class.
	createTempSQL := fmt.Sprintf(
		"CREATE TEMPORARY TABLE %s (LIKE %s INCLUDING ALL) ON COMMIT DROP;",
		tempStage, targetTable,
	)
	if _, err := tx.Exec(ctx, createTempSQL); err != nil {
		return fmt.Errorf("failed to create temporary staging table: %w", err)
	}

	// Step 2: Stream payload via COPY protocol (bypasses SQL parse/plan).
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

	// Step 3: Set-based promotion into production table.
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

	// Step 4: Commit — ON COMMIT DROP auto-sterilizes the temp table.
	// No explicit DROP TABLE needed.
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}
