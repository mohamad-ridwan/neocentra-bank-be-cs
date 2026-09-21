-- ============================================================================
-- Migration: Add password_hash column to customers table
-- ============================================================================
ALTER TABLE customers ADD COLUMN IF NOT EXISTS password_hash VARCHAR(255) NOT NULL DEFAULT '';
