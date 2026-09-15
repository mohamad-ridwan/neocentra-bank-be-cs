package database

import (
	"context"
	"fmt"
	"log"

	"github.com/jackc/pgx/v5/pgxpool"
)

// AutoMigrate ensures necessary tables and indexes exist on startup
func AutoMigrate(ctx context.Context, pool *pgxpool.Pool) error {
	if pool == nil {
		return nil
	}

	query := `
	CREATE TABLE IF NOT EXISTS verifications (
		verification_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		customer_id UUID NOT NULL REFERENCES customers(customer_id) ON DELETE CASCADE,
		verification_type VARCHAR(50) NOT NULL DEFAULT 'EMAIL_REGISTRATION',
		code INT NOT NULL CHECK (code >= 10000 AND code <= 99999),
		expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_verifications_lookup ON verifications(verification_id, customer_id, code);
	CREATE INDEX IF NOT EXISTS idx_verifications_expires_at ON verifications(expires_at);
	`

	_, err := pool.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to run automigrate for verifications: %w", err)
	}

	log.Println("[INFO] Database AutoMigrate executed successfully (table 'verifications' verified).")
	return nil
}
