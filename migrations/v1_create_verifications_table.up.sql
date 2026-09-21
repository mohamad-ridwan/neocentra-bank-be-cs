-- ============================================================================
-- TABEL VERIFICATIONS (Penyimpanan Kode Verifikasi Multi-Purpose)
-- ============================================================================
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
