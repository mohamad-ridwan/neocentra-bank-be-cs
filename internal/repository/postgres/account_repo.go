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
		SELECT account_id, customer_id, COALESCE(account_number, ''), balance, currency, status,
		       COALESCE(product_type::text, 'REGULAR_SAVINGS'), COALESCE(branch_code, '001'), created_at, updated_at
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
		var statusStr, prodTypeStr string
		var createdAt, updatedAt time.Time

		if err := rows.Scan(
			&acc.AccountID,
			&acc.CustomerID,
			&acc.AccountNumber,
			&acc.Balance,
			&acc.Currency,
			&statusStr,
			&prodTypeStr,
			&acc.BranchCode,
			&createdAt,
			&updatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan account row: %w", err)
		}

		acc.Status = domain.AccountStatus(statusStr)
		acc.ProductType = domain.AccountProductType(prodTypeStr)
		acc.CreatedAt = createdAt
		acc.UpdatedAt = updatedAt

		accounts = append(accounts, acc)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed iterating account rows: %w", err)
	}

	return accounts, nil
}

func (r *AccountRepository) CreateAccount(ctx context.Context, acc *domain.Account) error {
	if r.pool == nil {
		return fmt.Errorf("database pool is not connected")
	}

	query := `
		INSERT INTO accounts (
			customer_id, account_number, balance, currency, status,
			product_type, branch_code, pin_hash, pin_attempts, pin_locked_until,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		RETURNING account_id, created_at, updated_at
	`

	if acc.Currency == "" {
		acc.Currency = "IDR"
	}
	if acc.BranchCode == "" {
		acc.BranchCode = "001"
	}
	if acc.ProductType == "" {
		acc.ProductType = domain.ProductTypeRegularSavings
	}

	return r.pool.QueryRow(
		ctx,
		query,
		acc.CustomerID,
		acc.AccountNumber,
		acc.Balance,
		acc.Currency,
		string(acc.Status),
		string(acc.ProductType),
		acc.BranchCode,
		acc.PINHash,
		acc.PINAttempts,
		acc.PINLockedUntil,
	).Scan(&acc.AccountID, &acc.CreatedAt, &acc.UpdatedAt)
}

func (r *AccountRepository) FindAccountByID(ctx context.Context, accountID string) (*domain.Account, error) {
	if r.pool == nil {
		return nil, fmt.Errorf("database pool is not connected")
	}

	query := `
		SELECT account_id, customer_id, COALESCE(account_number, ''), balance, currency, status,
		       COALESCE(product_type::text, 'REGULAR_SAVINGS'), COALESCE(branch_code, '001'),
		       pin_hash, pin_attempts, pin_locked_until, created_at, updated_at
		FROM accounts
		WHERE account_id = $1
	`

	var acc domain.Account
	var statusStr, prodTypeStr string
	var createdAt, updatedAt time.Time

	err := r.pool.QueryRow(ctx, query, accountID).Scan(
		&acc.AccountID,
		&acc.CustomerID,
		&acc.AccountNumber,
		&acc.Balance,
		&acc.Currency,
		&statusStr,
		&prodTypeStr,
		&acc.BranchCode,
		&acc.PINHash,
		&acc.PINAttempts,
		&acc.PINLockedUntil,
		&createdAt,
		&updatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("account not found: %w", err)
	}

	acc.Status = domain.AccountStatus(statusStr)
	acc.ProductType = domain.AccountProductType(prodTypeStr)
	acc.CreatedAt = createdAt
	acc.UpdatedAt = updatedAt

	return &acc, nil
}

func (r *AccountRepository) FindAccountByNumber(ctx context.Context, accountNumber string) (*domain.Account, error) {
	if r.pool == nil {
		return nil, fmt.Errorf("database pool is not connected")
	}

	query := `
		SELECT account_id, customer_id, COALESCE(account_number, ''), balance, currency, status,
		       COALESCE(product_type::text, 'REGULAR_SAVINGS'), COALESCE(branch_code, '001'),
		       pin_hash, pin_attempts, pin_locked_until, created_at, updated_at
		FROM accounts
		WHERE account_number = $1
	`

	var acc domain.Account
	var statusStr, prodTypeStr string
	var createdAt, updatedAt time.Time

	err := r.pool.QueryRow(ctx, query, accountNumber).Scan(
		&acc.AccountID,
		&acc.CustomerID,
		&acc.AccountNumber,
		&acc.Balance,
		&acc.Currency,
		&statusStr,
		&prodTypeStr,
		&acc.BranchCode,
		&acc.PINHash,
		&acc.PINAttempts,
		&acc.PINLockedUntil,
		&createdAt,
		&updatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("account not found: %w", err)
	}

	acc.Status = domain.AccountStatus(statusStr)
	acc.ProductType = domain.AccountProductType(prodTypeStr)
	acc.CreatedAt = createdAt
	acc.UpdatedAt = updatedAt

	return &acc, nil
}

func (r *AccountRepository) UpdatePINAttempts(ctx context.Context, accountID string, attempts int, lockedUntil *time.Time) error {
	if r.pool == nil {
		return fmt.Errorf("database pool is not connected")
	}

	query := `
		UPDATE accounts
		SET pin_attempts = $1, pin_locked_until = $2, updated_at = CURRENT_TIMESTAMP
		WHERE account_id = $3
	`

	_, err := r.pool.Exec(ctx, query, attempts, lockedUntil, accountID)
	return err
}

func (r *AccountRepository) ResetPINAttempts(ctx context.Context, accountID string) error {
	if r.pool == nil {
		return fmt.Errorf("database pool is not connected")
	}

	query := `
		UPDATE accounts
		SET pin_attempts = 0, pin_locked_until = NULL, updated_at = CURRENT_TIMESTAMP
		WHERE account_id = $1
	`

	_, err := r.pool.Exec(ctx, query, accountID)
	return err
}

func (r *AccountRepository) HasActiveAccount(ctx context.Context, customerID string) (bool, error) {
	if r.pool == nil {
		return false, fmt.Errorf("database pool is not connected")
	}

	query := `
		SELECT EXISTS (
			SELECT 1 FROM accounts 
			WHERE customer_id = $1 AND status = 'ACTIVE'
		)
	`

	var exists bool
	err := r.pool.QueryRow(ctx, query, customerID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check active account: %w", err)
	}

	return exists, nil
}
