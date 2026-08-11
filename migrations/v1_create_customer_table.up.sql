CREATE TYPE customer_status_enum AS ENUM ('PENDING_VERIFICATION', 'ACTIVE', 'REJECTED', 'SUSPENDED');

-- ============================================================================
-- 2. TABEL CUSTOMERS (Data Induk Nasabah)
-- ============================================================================
CREATE TABLE customers (
    customer_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    nik BYTEA UNIQUE NOT NULL,
    full_name BYTEA NOT NULL,
    email BYTEA UNIQUE NOT NULL,
    phone_number BYTEA UNIQUE NOT NULL,
    address BYTEA NOT NULL,
    status customer_status_enum NOT NULL DEFAULT 'PENDING_VERIFICATION',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 3. Tambah indeks pada kolom lama (email)
CREATE UNIQUE INDEX idx_customers_email ON customers(email);

-- 4. Tambah indeks pada kolom baru (status)
CREATE INDEX idx_customers_status ON customers(status);
CREATE INDEX idx_customers_pending ON customers(status) WHERE status = 'PENDING_VERIFICATION';