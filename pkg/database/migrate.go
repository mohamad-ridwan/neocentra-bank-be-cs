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

	-- Ensure password_hash exists on customers table
	ALTER TABLE customers ADD COLUMN IF NOT EXISTS password_hash VARCHAR(255) NOT NULL DEFAULT '';

	-- Ensure account_product_type_enum exists
	DO $$ BEGIN
		IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'account_product_type_enum') THEN
			CREATE TYPE account_product_type_enum AS ENUM ('REGULAR_SAVINGS', 'PRIORITY_SAVINGS', 'STUDENT_SAVINGS');
		END IF;
	END $$;

	-- Enhance accounts table for in-app onboarding & PIN security
	ALTER TABLE accounts
		ALTER COLUMN account_number TYPE VARCHAR(20),
		ADD COLUMN IF NOT EXISTS product_type account_product_type_enum NOT NULL DEFAULT 'REGULAR_SAVINGS',
		ADD COLUMN IF NOT EXISTS pin_hash VARCHAR(255) NOT NULL DEFAULT '',
		ADD COLUMN IF NOT EXISTS pin_attempts INT NOT NULL DEFAULT 0,
		ADD COLUMN IF NOT EXISTS pin_locked_until TIMESTAMP WITH TIME ZONE NULL,
		ADD COLUMN IF NOT EXISTS pin_updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		ADD COLUMN IF NOT EXISTS branch_code VARCHAR(10) NOT NULL DEFAULT '001',
		ADD COLUMN IF NOT EXISTS kyc_reference_id UUID NULL REFERENCES kyc_verifications(kyc_id);

	CREATE UNIQUE INDEX IF NOT EXISTS idx_accounts_account_number_unique 
		ON accounts(account_number) 
		WHERE account_number IS NOT NULL AND account_number <> '';

	CREATE INDEX IF NOT EXISTS idx_accounts_customer_status 
		ON accounts(customer_id, status);

	CREATE INDEX IF NOT EXISTS idx_accounts_pin_lookup 
		ON accounts(account_id) 
		INCLUDE (pin_hash, pin_attempts, pin_locked_until);
	`

	_, err := pool.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to run automigrate: %w", err)
	}

	log.Println("[INFO] Database AutoMigrate executed successfully (tables, accounts, and PIN security verified).")
	return nil
}
