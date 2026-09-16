package usecase

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"customer-service/internal/domain"
	"customer-service/internal/security"
)

type AccountRepository interface {
	FindAccountsByCustomerID(ctx context.Context, customerID string) ([]domain.Account, error)
}

type AccountUseCase struct {
	accountRepo      AccountRepository
	transitDecryptor *security.TransitDecryptor
}

func NewAccountUseCase(repo AccountRepository, transitDec ...*security.TransitDecryptor) *AccountUseCase {
	uc := &AccountUseCase{
		accountRepo: repo,
	}
	if len(transitDec) > 0 && transitDec[0] != nil {
		uc.transitDecryptor = transitDec[0]
	}
	return uc
}

func (u *AccountUseCase) GetAccountsByCustomerID(ctx context.Context, customerID string) ([]domain.Account, error) {
	customerID = strings.TrimSpace(customerID)
	if customerID == "" {
		return nil, errors.New("customer_id wajib disertakan")
	}

	if u.accountRepo == nil {
		return nil, errors.New("account repository belum terhubung")
	}

	return u.accountRepo.FindAccountsByCustomerID(ctx, customerID)
}

// GetAccountsEncrypted mengambil data akun dan mengenkripsi payload dengan RSA Server Envelope
// Format wire: [ 256B RSA-Priv-Key ] + [ 12B IV ] + [ Ciphertext + 16B Tag ]
// Frontend dapat mendekripsinya secara deterministik menggunakan .env:L4 (EXPO_PUBLIC_SERVER_RSA_PUBLIC_KEY)
func (u *AccountUseCase) GetAccountsEncrypted(ctx context.Context, customerID string) ([]byte, error) {
	accounts, err := u.GetAccountsByCustomerID(ctx, customerID)
	if err != nil {
		return nil, err
	}

	respJSON, err := json.Marshal(ginHAccounts{
		Success: true,
		Data:    accounts,
	})
	if err != nil {
		return nil, fmt.Errorf("gagal serialize accounts: %w", err)
	}

	if u.transitDecryptor == nil || u.transitDecryptor.GetPrivateKey() == nil {
		return nil, errors.New("transit encryptor server private key belum dikonfigurasi")
	}

	return security.EncryptServerEnvelope(u.transitDecryptor.GetPrivateKey(), respJSON)
}

type ginHAccounts struct {
	Success bool             `json:"success"`
	Data    []domain.Account `json:"data"`
}
