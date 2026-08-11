package postgres

import (
	"context"
	"fmt"
	"time"

	"customer-service/internal/domain"

	"github.com/jackc/pgx/v5/pgxpool"
)

type PIIDecryptor interface {
	DecryptPII(ciphertext []byte, aad string) (string, error)
}

type CustomerRepository struct {
	pool      *pgxpool.Pool
	decryptor PIIDecryptor
}

func NewCustomerRepository(pool *pgxpool.Pool, decryptor ...PIIDecryptor) *CustomerRepository {
	repo := &CustomerRepository{pool: pool}
	if len(decryptor) > 0 {
		repo.decryptor = decryptor[0]
	}
	return repo
}

func (r *CustomerRepository) SetDecryptor(decryptor PIIDecryptor) {
	r.decryptor = decryptor
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
	if r.decryptor == nil {
		query := `SELECT EXISTS(SELECT 1 FROM customers WHERE nik = $1)`
		var exists bool
		err := r.pool.QueryRow(ctx, query, nik).Scan(&exists)
		if err != nil {
			return false, fmt.Errorf("failed to check NIK existence: %w", err)
		}
		return exists, nil
	}

	query := `SELECT nik FROM customers`
	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return false, fmt.Errorf("failed to check NIK existence: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var encNIK []byte
		if err := rows.Scan(&encNIK); err != nil {
			return false, fmt.Errorf("failed to scan NIK: %w", err)
		}

		plain, err := r.decryptor.DecryptPII(encNIK, "customer_nik_aad")
		if err != nil {
			plain, err = r.decryptor.DecryptPII(encNIK, "customer_pii")
		}
		if err == nil && plain == nik {
			return true, nil
		}
	}

	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("failed iterating NIK rows: %w", err)
	}

	return false, nil
}

func (r *CustomerRepository) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	if r.decryptor == nil {
		query := `SELECT EXISTS(SELECT 1 FROM customers WHERE email = $1)`
		var exists bool
		err := r.pool.QueryRow(ctx, query, email).Scan(&exists)
		if err != nil {
			return false, fmt.Errorf("failed to check Email existence: %w", err)
		}
		return exists, nil
	}

	query := `SELECT email FROM customers`
	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return false, fmt.Errorf("failed to check Email existence: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var encEmail []byte
		if err := rows.Scan(&encEmail); err != nil {
			return false, fmt.Errorf("failed to scan Email: %w", err)
		}

		plain, err := r.decryptor.DecryptPII(encEmail, "customer_email_aad")
		if err != nil {
			plain, err = r.decryptor.DecryptPII(encEmail, "customer_pii")
		}
		if err == nil && plain == email {
			return true, nil
		}
	}

	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("failed iterating Email rows: %w", err)
	}

	return false, nil
}

func (r *CustomerRepository) ExistsByPhone(ctx context.Context, phone string) (bool, error) {
	if r.decryptor == nil {
		query := `SELECT EXISTS(SELECT 1 FROM customers WHERE phone_number = $1)`
		var exists bool
		err := r.pool.QueryRow(ctx, query, phone).Scan(&exists)
		if err != nil {
			return false, fmt.Errorf("failed to check Phone existence: %w", err)
		}
		return exists, nil
	}

	query := `SELECT phone_number FROM customers`
	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return false, fmt.Errorf("failed to check Phone existence: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var encPhone []byte
		if err := rows.Scan(&encPhone); err != nil {
			return false, fmt.Errorf("failed to scan Phone: %w", err)
		}

		plain, err := r.decryptor.DecryptPII(encPhone, "customer_phone_number_aad")
		if err != nil {
			plain, err = r.decryptor.DecryptPII(encPhone, "customer_pii")
		}
		if err == nil && plain == phone {
			return true, nil
		}
	}

	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("failed iterating Phone rows: %w", err)
	}

	return false, nil
}
