-- ============================================================================
-- TABEL KMS_KEYSETS (Penyimpanan Keyset Google Tink Terenkripsi)
-- ============================================================================
CREATE TYPE kms_key_status AS ENUM ('ACTIVE', 'ROTATING', 'RETIRED');

CREATE TABLE kms_keysets (
    keyset_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_name VARCHAR(50) UNIQUE NOT NULL, -- Contoh: 'customer_pii_keyset'
    encrypted_keyset BYTEA NOT NULL,     -- Tink Keyset JSON yang di-envelope dengan Master KEK
    primary_key_id BIGINT NOT NULL,      -- ID Kunci utama saat ini yang dipakai untuk ENKRIPSI
    version INT NOT NULL DEFAULT 1,      -- Versi rotasi kunci (v1, v2, dst)
    status kms_key_status NOT NULL DEFAULT 'ACTIVE',
    rotation_interval_days INT NOT NULL DEFAULT 90, -- Interval rotasi (misal 90 hari)
    last_rotated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indeks pencarian cepat nama keyset
CREATE UNIQUE INDEX idx_kms_key_name ON kms_keysets(key_name);
