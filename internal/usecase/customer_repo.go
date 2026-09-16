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
	UpdateCustomerStatus(ctx context.Context, customerID string, status domain.CustomerStatus) error
	FindCustomerByIdentifier(ctx context.Context, identifier string) (*domain.Customer, *DecryptedCustomerPII, error)
}

type DecryptedCustomerPII struct {
	CustomerID  string
	NIK         string
	FullName    string
	Email       string
	PhoneNumber string
	Address     string
	Status      string
}
