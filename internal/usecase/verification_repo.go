package usecase

import (
	"context"
	"customer-service/internal/domain"
)

type VerificationRepository interface {
	CreateVerification(ctx context.Context, v *domain.Verification) error
	FindVerification(ctx context.Context, verificationID string, customerID string, code int) (*domain.Verification, error)
	DeleteVerification(ctx context.Context, verificationID string) error
}
