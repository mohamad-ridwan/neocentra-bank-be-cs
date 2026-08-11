package usecase

import (
	"context"

	"customer-service/internal/domain"
)

type CustomerRepository interface {
	CreateCustomer(ctx context.Context, customer *domain.Customer) error
	ExistsByNIK(ctx context.Context, nik string) (bool, error)
	ExistsByEmail(ctx context.Context, email string) (bool, error)
	ExistsByPhone(ctx context.Context, phone string) (bool, error)
}
