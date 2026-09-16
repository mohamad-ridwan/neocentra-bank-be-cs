package usecase

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"customer-service/internal/domain"
	"customer-service/internal/dto"
	"customer-service/internal/security"
	"customer-service/internal/util"
)

type AccountRepository interface {
	FindAccountsByCustomerID(ctx context.Context, customerID string) ([]domain.Account, error)
	CreateAccount(ctx context.Context, acc *domain.Account) error
	FindAccountByID(ctx context.Context, accountID string) (*domain.Account, error)
	FindAccountByNumber(ctx context.Context, accountNumber string) (*domain.Account, error)
	UpdatePINAttempts(ctx context.Context, accountID string, attempts int, lockedUntil *time.Time) error
	ResetPINAttempts(ctx context.Context, accountID string) error
	HasActiveAccount(ctx context.Context, customerID string) (bool, error)
}

type CustomerStatusUpdater interface {
	UpdateCustomerStatus(ctx context.Context, customerID string, status domain.CustomerStatus) error
}

type AccountUseCase struct {
	accountRepo      AccountRepository
	customerRepo     CustomerStatusUpdater
	transitDecryptor *security.TransitDecryptor
	jwtSecret        string
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

func (u *AccountUseCase) SetCustomerRepo(repo CustomerStatusUpdater) {
	u.customerRepo = repo
}

func (u *AccountUseCase) SetJWTSecret(secret string) {
	u.jwtSecret = secret
}

func (u *AccountUseCase) resolvePIN(encryptedPIN, plainPIN string) (string, error) {
	if plainPIN != "" {
		return plainPIN, nil
	}

	if encryptedPIN == "" {
		return "", errors.New("PIN transaksi wajib disertakan")
	}

	if u.transitDecryptor == nil {
		// Jika transitDecryptor tidak ada, anggap raw PIN jika sudah numerik
		return encryptedPIN, nil
	}

	// Coba decode base64 jika encryptedPIN berupa base64 string
	rawCipher, err := base64.StdEncoding.DecodeString(encryptedPIN)
	if err != nil {
		// Jika bukan standard base64, coba decode raw base64 tanpa padding
		rawCipher, err = base64.RawStdEncoding.DecodeString(encryptedPIN)
	}

	if err == nil && len(rawCipher) >= security.MinTransitPayloadSize {
		decrypted, decErr := u.transitDecryptor.DecryptRawTransitPayload(rawCipher)
		if decErr == nil && len(decrypted) > 0 {
			return string(decrypted), nil
		}
	}

	// Fallback jika dikirimkan sebagai plaintext
	return encryptedPIN, nil
}

// OpenAccount memproses pembukaan rekening baru dengan validasi, hashing PIN Argon2id, pembuatan nomor rekening Luhn, dan elevasi hak akses
func (u *AccountUseCase) OpenAccount(ctx context.Context, customerID string, req dto.OpenAccountRequest) (*dto.OpenAccountResponseData, *dto.SessionElevationData, error) {
	customerID = strings.TrimSpace(customerID)
	if customerID == "" {
		return nil, nil, errors.New("customer_id wajib disertakan")
	}

	if u.accountRepo == nil {
		return nil, nil, errors.New("account repository belum terhubung")
	}

	// 1. Cek apakah pengguna sudah memiliki rekening aktif
	hasActive, err := u.accountRepo.HasActiveAccount(ctx, customerID)
	if err != nil {
		return nil, nil, fmt.Errorf("gagal memeriksa status rekening nasabah: %w", err)
	}
	if hasActive {
		return nil, nil, errors.New("nasabah sudah memiliki rekening aktif")
	}

	// 2. Dekripsi / ekstraksi PIN transaksi
	pin, err := u.resolvePIN(req.EncryptedPIN, req.PIN)
	if err != nil {
		return nil, nil, err
	}

	// 3. Validasi kekuatan PIN
	if err := util.ValidatePINStrength(pin); err != nil {
		return nil, nil, err
	}

	// 4. Hash PIN dengan Argon2id
	pinHash, err := util.HashPIN(pin)
	if err != nil {
		return nil, nil, fmt.Errorf("gagal mengamankan PIN: %w", err)
	}

	// 5. Tentukan tipe produk tabungan & kode cabang
	productType := domain.AccountProductType(req.ProductType)
	if productType == "" {
		productType = domain.ProductTypeRegularSavings
	}
	branchCode := req.BranchCode
	if branchCode == "" {
		branchCode = "001"
	}

	// 6. Generate nomor rekening unik 12 digit (Luhn)
	accountNumber, err := util.GenerateAccountNumber(branchCode, productType)
	if err != nil {
		return nil, nil, fmt.Errorf("gagal membuat nomor rekening: %w", err)
	}

	// 7. Simpan akun ke database
	newAccount := &domain.Account{
		CustomerID:    customerID,
		AccountNumber: accountNumber,
		Balance:       0.00,
		Currency:      "IDR",
		Status:        domain.AccountStatusActive,
		ProductType:   productType,
		BranchCode:    branchCode,
		PINHash:       pinHash,
		PINAttempts:   0,
	}

	if err := u.accountRepo.CreateAccount(ctx, newAccount); err != nil {
		return nil, nil, fmt.Errorf("gagal menyimpan rekening baru: %w", err)
	}

	// 8. Update status nasabah menjadi ACTIVE jika belum aktif
	if u.customerRepo != nil {
		_ = u.customerRepo.UpdateCustomerStatus(ctx, customerID, domain.StatusActive)
	}

	// 9. Generate Elevated Token JWT (ROLE_CUSTOMER_TRANSACTIONAL)
	elevatedToken, err := security.GenerateSessionToken(
		customerID,
		"ROLE_CUSTOMER_TRANSACTIONAL",
		u.jwtSecret,
		true,
		"ACTIVE",
		newAccount.AccountID,
		newAccount.AccountNumber,
		24*time.Hour,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("gagal membuat token elevasi sesi: %w", err)
	}

	responseData := &dto.OpenAccountResponseData{
		AccountID:     newAccount.AccountID,
		AccountNumber: newAccount.AccountNumber,
		Currency:      newAccount.Currency,
		Balance:       newAccount.Balance,
		ProductType:   string(newAccount.ProductType),
		Status:        string(newAccount.Status),
		CreatedAt:     newAccount.CreatedAt,
	}

	sessionData := &dto.SessionElevationData{
		ElevatedToken: elevatedToken,
		Role:          "ROLE_CUSTOMER_TRANSACTIONAL",
	}

	return responseData, sessionData, nil
}

// VerifyPIN memverifikasi PIN transaksi, mengecek proteksi brute force (3x kesalahan = kunci 15 menit), dan menerbitkan token otorisasi transaksi
func (u *AccountUseCase) VerifyPIN(ctx context.Context, customerID string, req dto.VerifyPINRequest) (*dto.VerifyPINResponseData, int, error) {
	if u.accountRepo == nil {
		return nil, 0, errors.New("account repository belum terhubung")
	}

	accountID := strings.TrimSpace(req.AccountID)
	if accountID == "" {
		return nil, 0, errors.New("account_id wajib disertakan")
	}

	acc, err := u.accountRepo.FindAccountByID(ctx, accountID)
	if err != nil {
		return nil, 0, fmt.Errorf("rekening tidak ditemukan: %w", err)
	}

	// 1. Cek apakah rekening sedang terkunci akibat brute force
	if locked, _ := util.IsAccountLocked(acc.PINLockedUntil); locked {
		return nil, 0, util.ErrPINLocked
	}

	// 2. Dekripsi PIN yang dikirim
	pin, err := u.resolvePIN(req.EncryptedPIN, req.PIN)
	if err != nil {
		return nil, 0, err
	}

	// 3. Verifikasi hash Argon2id
	valid, err := util.VerifyPIN(pin, acc.PINHash)
	if err != nil || !valid {
		// Tambah percobaan salah
		attempts := acc.PINAttempts + 1
		if attempts >= util.MaxPINAttempts {
			lockedUntil := time.Now().Add(util.LockoutDuration)
			_ = u.accountRepo.UpdatePINAttempts(ctx, acc.AccountID, attempts, &lockedUntil)
			return nil, 0, util.ErrPINLocked
		}

		_ = u.accountRepo.UpdatePINAttempts(ctx, acc.AccountID, attempts, nil)
		remaining := util.MaxPINAttempts - attempts
		return nil, remaining, util.ErrPINMismatch
	}

	// 4. Jika PIN valid, reset attempts ke 0
	_ = u.accountRepo.ResetPINAttempts(ctx, acc.AccountID)

	// 5. Terbitkan ephemeral transaction authorization token (valid 60 detik)
	txAuthToken, _ := security.GenerateVerificationToken(customerID, acc.AccountID, u.jwtSecret, 60*time.Second)

	return &dto.VerifyPINResponseData{
		IsValid:              true,
		TransactionAuthToken: txAuthToken,
		ExpiresInSeconds:     60,
	}, 0, nil
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
