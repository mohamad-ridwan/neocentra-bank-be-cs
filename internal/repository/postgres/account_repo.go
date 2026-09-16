package postgres

import (
	"context"
	"fmt"
	"time"

	"customer-service/internal/domain"

	"github.com/jackc/pgx/v5/pgxpool"
)

type AccountRepository struct {
	pool *pgxpool.Pool
}

func NewAccountRepository(pool *pgxpool.Pool) *AccountRepository {
	return &AccountRepository{pool: pool}
}

func (r *AccountRepository) FindAccountsByCustomerID(ctx context.Context, customerID string) ([]domain.Account, error) {
	if r.pool == nil {
		return nil, fmt.Errorf("database pool is not connected")
	}

	query := `
		SELECT account_id, customer_id, COALESCE(account_number, ''), balance, currency, status, created_at, updated_at
		FROM accounts
		WHERE customer_id = $1
		ORDER BY created_at DESC
	`

	rows, err := r.pool.Query(ctx, query, customerID)
	if err != nil {
		return nil, fmt.Errorf("failed to query accounts for customer: %w", err)
	}
	defer rows.Close()

	var accounts []domain.Account
	for rows.Next() {
		var acc domain.Account
		var statusStr string
		var createdAt, updatedAt time.Time

		if err := rows.Scan(
			&acc.AccountID,
			&acc.CustomerID,
			&acc.AccountNumber,
			&acc.Balance,
			&acc.Currency,
			&statusStr,
			&createdAt,
			&updatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan account row: %w", err)
		}

		acc.Status = domain.AccountStatus(statusStr)
		acc.CreatedAt = createdAt
		acc.UpdatedAt = updatedAt

		accounts = append(accounts, acc)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed iterating account rows: %w", err)
	}

	return accounts, nil
}
