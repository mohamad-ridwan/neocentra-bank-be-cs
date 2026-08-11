package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type KMSRepository struct {
	pool *pgxpool.Pool
}

func NewKMSRepository(pool *pgxpool.Pool) *KMSRepository {
	return &KMSRepository{pool: pool}
}

func (r *KMSRepository) GetKeysetByName(ctx context.Context, keyName string) ([]byte, int, error) {
	query := `SELECT encrypted_keyset, version FROM kms_keysets WHERE key_name = $1`
	var encryptedKeyset []byte
	var version int

	err := r.pool.QueryRow(ctx, query, keyName).Scan(&encryptedKeyset, &version)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, 0, fmt.Errorf("keyset '%s' not found", keyName)
		}
		return nil, 0, fmt.Errorf("query GetKeysetByName failed: %w", err)
	}

	return encryptedKeyset, version, nil
}

func (r *KMSRepository) SaveKeyset(ctx context.Context, keyName string, encryptedKeyset []byte, primaryKeyID uint32, version int) error {
	query := `
		INSERT INTO kms_keysets (key_name, encrypted_keyset, primary_key_id, version, status, updated_at)
		VALUES ($1, $2, $3, $4, 'ACTIVE', CURRENT_TIMESTAMP)
	`
	_, err := r.pool.Exec(ctx, query, keyName, encryptedKeyset, int64(primaryKeyID), version)
	if err != nil {
		return fmt.Errorf("insert SaveKeyset failed: %w", err)
	}
	return nil
}

func (r *KMSRepository) UpdateKeyset(ctx context.Context, keyName string, encryptedKeyset []byte, primaryKeyID uint32, version int) error {
	query := `
		UPDATE kms_keysets
		SET encrypted_keyset = $1, primary_key_id = $2, version = $3, last_rotated_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
		WHERE key_name = $4
	`
	_, err := r.pool.Exec(ctx, query, encryptedKeyset, int64(primaryKeyID), version, keyName)
	if err != nil {
		return fmt.Errorf("update UpdateKeyset failed: %w", err)
	}
	return nil
}
