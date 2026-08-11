package postgres

import (
	"context"
	"fmt"
	"time"

	"customer-service/internal/domain"

	"github.com/jackc/pgx/v5/pgxpool"
)

type CustomerRepository struct {
	pool *pgxpool.Pool
}

func NewCustomerRepository(pool *pgxpool.Pool) *CustomerRepository {
	return &CustomerRepository{pool: pool}
}

func (r *CustomerRepository) CreateCustomer(ctx context.Context, customer *domain.Customer) error {
	query := `
		INSERT INTO customers (nik, full_name, email, phone_number, address, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		RETURNING customer_id, created_at, updated_at
	`

	var customerID string
	var createdAt, updatedAt time.Time

	err := r.pool.QueryRow(
		ctx,
		query,
		customer.NIK,
		customer.FullName,
		customer.Email,
		customer.PhoneNumber,
		customer.Address,
		string(customer.Status),
	).Scan(&customerID, &createdAt, &updatedAt)

	if err != nil {
		return fmt.Errorf("failed to insert customer: %w", err)
	}

	customer.CustomerID = customerID
	customer.CreatedAt = createdAt
	customer.UpdatedAt = updatedAt

	return nil
}

func (r *CustomerRepository) ExistsByNIK(ctx context.Context, nik string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM customers WHERE nik = $1)`
	var exists bool
	err := r.pool.QueryRow(ctx, query, nik).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check NIK existence: %w", err)
	}
	return exists, nil
}

func (r *CustomerRepository) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM customers WHERE email = $1)`
	var exists bool
	err := r.pool.QueryRow(ctx, query, email).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check Email existence: %w", err)
	}
	return exists, nil
}

func (r *CustomerRepository) ExistsByPhone(ctx context.Context, phone string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM customers WHERE phone_number = $1)`
	var exists bool
	err := r.pool.QueryRow(ctx, query, phone).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check Phone existence: %w", err)
	}
	return exists, nil
}
