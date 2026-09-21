-- ============================================================================
-- MIGRATION: v3_enhance_accounts_and_pin.up.sql
-- Penyesuaian Tabel ACCOUNTS untuk In-App Onboarding & Security PIN
-- ============================================================================

-- 1. Tambah tipe produk tabungan jika belum ada
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'account_product_type_enum') THEN
        CREATE TYPE account_product_type_enum AS ENUM ('REGULAR_SAVINGS', 'PRIORITY_SAVINGS', 'STUDENT_SAVINGS');
    END IF;
END $$;

-- 2. Modifikasi / Pembaruan Tabel accounts
ALTER TABLE accounts
    ALTER COLUMN account_number TYPE VARCHAR(20),
    ADD COLUMN IF NOT EXISTS product_type account_product_type_enum NOT NULL DEFAULT 'REGULAR_SAVINGS',
    ADD COLUMN IF NOT EXISTS pin_hash VARCHAR(255) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS pin_attempts INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS pin_locked_until TIMESTAMP WITH TIME ZONE NULL,
    ADD COLUMN IF NOT EXISTS pin_updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    ADD COLUMN IF NOT EXISTS branch_code VARCHAR(10) NOT NULL DEFAULT '001',
    ADD COLUMN IF NOT EXISTS kyc_reference_id UUID NULL REFERENCES kyc_verifications(kyc_id);

-- 3. Indeks Performa & Keamanan
CREATE UNIQUE INDEX IF NOT EXISTS idx_accounts_account_number_unique 
    ON accounts(account_number) 
    WHERE account_number IS NOT NULL AND account_number <> '';

CREATE INDEX IF NOT EXISTS idx_accounts_customer_status 
    ON accounts(customer_id, status);

CREATE INDEX IF NOT EXISTS idx_accounts_pin_lookup 
    ON accounts(account_id) 
    INCLUDE (pin_hash, pin_attempts, pin_locked_until);
