package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"customer-service/internal/domain"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type VerificationRepository struct {
	pool *pgxpool.Pool
}

func NewVerificationRepository(pool *pgxpool.Pool) *VerificationRepository {
	return &VerificationRepository{pool: pool}
}

func (r *VerificationRepository) CreateVerification(ctx context.Context, v *domain.Verification) error {
	query := `
		INSERT INTO verifications (verification_id, customer_id, verification_type, code, expires_at, created_at)
		VALUES (COALESCE(NULLIF($1, '')::uuid, gen_random_uuid()), $2, $3, $4, $5, CURRENT_TIMESTAMP)
		RETURNING verification_id, created_at
	`

	var verificationID string
	var createdAt time.Time

	err := r.pool.QueryRow(
		ctx,
		query,
		v.VerificationID,
		v.CustomerID,
		v.VerificationType,
		v.Code,
		v.ExpiresAt,
	).Scan(&verificationID, &createdAt)
	if err != nil {
		// Self-healing: jika tabel belum terbuat (SQLSTATE 42P01), otomatis jalankan DDL pembuatan tabel
		if strings.Contains(err.Error(), "42P01") || strings.Contains(err.Error(), "does not exist") {
			createTableQuery := `
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
			if _, execErr := r.pool.Exec(ctx, createTableQuery); execErr == nil {
				// Retry query
				retryErr := r.pool.QueryRow(
					ctx,
					query,
					v.VerificationID,
					v.CustomerID,
					v.VerificationType,
					v.Code,
					v.ExpiresAt,
				).Scan(&verificationID, &createdAt)
				if retryErr == nil {
					v.VerificationID = verificationID
					v.CreatedAt = createdAt
					return nil
				}
			}
		}
		return fmt.Errorf("failed to insert verification: %w", err)
	}

	v.VerificationID = verificationID
	v.CreatedAt = createdAt
	return nil
}

func (r *VerificationRepository) FindVerification(ctx context.Context, verificationID string, customerID string, code int) (*domain.Verification, error) {
	query := `
		SELECT verification_id, customer_id, verification_type, code, expires_at, created_at
		FROM verifications
		WHERE verification_id = $1 AND customer_id = $2 AND code = $3
	`

	var v domain.Verification
	err := r.pool.QueryRow(ctx, query, verificationID, customerID, code).Scan(
		&v.VerificationID,
		&v.CustomerID,
		&v.VerificationType,
		&v.Code,
		&v.ExpiresAt,
		&v.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrVerificationNotFound
		}
		return nil, fmt.Errorf("failed to query verification: %w", err)
	}

	return &v, nil
}

func (r *VerificationRepository) DeleteVerification(ctx context.Context, verificationID string) error {
	query := `DELETE FROM verifications WHERE verification_id = $1`
	_, err := r.pool.Exec(ctx, query, verificationID)
	if err != nil {
		return fmt.Errorf("failed to delete verification: %w", err)
	}
	return nil
}
