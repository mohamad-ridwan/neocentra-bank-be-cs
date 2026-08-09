-- ============================================================================
-- 1. ENUM TYPES (Definisi Status Sistem)
-- ============================================================================
CREATE TYPE customer_status_enum AS ENUM ('PENDING_VERIFICATION', 'ACTIVE', 'REJECTED', 'SUSPENDED');
CREATE TYPE kyc_status_enum AS ENUM ('PENDING', 'APPROVED', 'REJECTED');
CREATE TYPE account_status_enum AS ENUM ('PENDING_KYC', 'ACTIVE', 'SUSPENDED', 'CLOSED');
CREATE TYPE transaction_status_enum AS ENUM ('PENDING', 'PROCESSING', 'SUCCESS', 'FAILED', 'REVERSED');
CREATE TYPE transaction_type_enum AS ENUM ('INTERBANK_OUT', 'INTERBANK_IN');

-- ============================================================================
-- 2. TABEL CUSTOMERS (Data Induk Nasabah)
-- ============================================================================
CREATE TABLE customers (
    customer_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    nik VARCHAR(16) UNIQUE NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    phone_number VARCHAR(20) UNIQUE NOT NULL,
    address TEXT NOT NULL,
    status customer_status_enum NOT NULL DEFAULT 'PENDING_VERIFICATION',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- 3. TABEL KYC_VERIFICATIONS (Proses Verifikasi Data Calon Nasabah)
-- ============================================================================
CREATE TABLE kyc_verifications (
    kyc_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id UUID NOT NULL REFERENCES customers(customer_id) ON DELETE CASCADE,
    ktp_image_url TEXT NOT NULL,
    selfie_image_url TEXT NOT NULL,
    status kyc_status_enum NOT NULL DEFAULT 'PENDING',
    rejection_reason TEXT,
    verified_by UUID, -- Foreign key ke tabel admin/officer jika ada
    verified_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- 4. TABEL ACCOUNTS (Rekening Nasabah)
-- ============================================================================
CREATE TABLE accounts (
    account_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id UUID NOT NULL REFERENCES customers(customer_id),
    account_number VARCHAR(20) UNIQUE, -- Diisi SETELAH KYC APPROVED
    balance NUMERIC(18, 2) NOT NULL DEFAULT 0.00 CHECK (balance >= 0),
    currency VARCHAR(3) NOT NULL DEFAULT 'IDR',
    status account_status_enum NOT NULL DEFAULT 'PENDING_KYC',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- 5. TABEL REF_BANKS (Referensi Bank Tujuan/Asal untuk Antarbank)
-- ============================================================================
CREATE TABLE ref_banks (
    bank_code VARCHAR(10) PRIMARY KEY, -- Contoh: '002' (BRI), '008' (Mandiri), '014' (BCA)
    bank_name VARCHAR(100) NOT NULL,
    swift_code VARCHAR(11),
    bi_fast_code VARCHAR(20)
);

-- ============================================================================
-- 6. TABEL TRANSACTIONS (Transaksi Transfer Antarbank)
-- ============================================================================
CREATE TABLE transactions (
    transaction_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    reference_number VARCHAR(50) UNIQUE NOT NULL, -- Kode unik transaksi perbankan
    source_account_id UUID NOT NULL REFERENCES accounts(account_id),
    destination_bank_code VARCHAR(10) NOT NULL REFERENCES ref_banks(bank_code),
    destination_account_number VARCHAR(30) NOT NULL,
    destination_account_name VARCHAR(100) NOT NULL,
    amount NUMERIC(18, 2) NOT NULL CHECK (amount > 0),
    admin_fee NUMERIC(18, 2) NOT NULL DEFAULT 0.00 CHECK (admin_fee >= 0),
    transaction_type transaction_type_enum NOT NULL,
    status transaction_status_enum NOT NULL DEFAULT 'PENDING',
    failure_reason TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- 7. INDEXES (Optimasi Performa Query)
-- ============================================================================
CREATE INDEX idx_customers_nik ON customers(nik);
CREATE INDEX idx_accounts_account_number ON accounts(account_number);
CREATE INDEX idx_transactions_source_acc ON transactions(source_account_id);
CREATE INDEX idx_transactions_ref_num ON transactions(reference_number);
CREATE INDEX idx_kyc_customer_status ON kyc_verifications(customer_id, status);