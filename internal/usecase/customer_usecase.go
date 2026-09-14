package usecase

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"customer-service/internal/domain"
	"customer-service/internal/dto"
	"customer-service/internal/security"

	"github.com/go-playground/validator/v10"
	"golang.org/x/sync/errgroup"
)

const (
	AAD_NIK       = "customer_nik_aad"
	AAD_FULL_NAME = "customer_full_name_aad"
	AAD_EMAIL     = "customer_email_aad"
	AAD_PHONE     = "customer_phone_number_aad"
	AAD_ADDRESS   = "customer_address_aad"
)

type CustomerUseCase struct {
	customerRepo     CustomerRepository
	kmsService       *LocalKMSService
	workerPool       *WorkerPool
	validate         *validator.Validate
	transitDecryptor *security.TransitDecryptor
}

func NewCustomerUseCase(
	repo CustomerRepository,
	kms *LocalKMSService,
	wp *WorkerPool,
	transitDec ...*security.TransitDecryptor,
) *CustomerUseCase {
	uc := &CustomerUseCase{
		customerRepo: repo,
		kmsService:   kms,
		workerPool:   wp,
		validate:     validator.New(),
	}
	if len(transitDec) > 0 && transitDec[0] != nil {
		uc.transitDecryptor = transitDec[0]
	}
	return uc
}

func (u *CustomerUseCase) SetTransitDecryptor(d *security.TransitDecryptor) {
	u.transitDecryptor = d
}

func (u *CustomerUseCase) HasTransitDecryptor() bool {
	return u.transitDecryptor != nil
}


// RegisterNewCustomerRaw mendekripsi raw binary transit payload (Pola 1: RSA-OAEP + AES-256-GCM)
func (u *CustomerUseCase) RegisterNewCustomerRaw(
	ctx context.Context,
	rawBody []byte,
) (*dto.RegisterCustomerResponseData, error) {
	if u.transitDecryptor == nil {
		return nil, errors.New("transit decryptor is not configured")
	}

	// 1. Dekripsi raw transit body via transitDecryptor
	decryptedJSON, err := u.transitDecryptor.DecryptRawTransitPayload(rawBody)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", domain.ErrInvalidDecryption, err)
	}

	// 2. Unmarshal JSON plaintext ke PlaintextRegisterCustomer
	var plainDTO dto.PlaintextRegisterCustomer
	if err := json.Unmarshal(decryptedJSON, &plainDTO); err != nil {
		return nil, fmt.Errorf("format JSON hasil dekripsi tidak valid: %w", err)
	}

	// 3. Proses registrasi
	return u.processRegistration(ctx, plainDTO)
}

func (u *CustomerUseCase) RegisterNewCustomer(
	ctx context.Context,
	req dto.EncryptedRegisterCustomerRequest,
) (*dto.RegisterCustomerResponseData, error) {
	log.Println("1. RegisterNewCustomer: Start")

	// 1. Dekripsi Payload Encrypted dari Client
	nikPlain, err := u.kmsService.DecryptPII(req.NIK, AAD_NIK)
	if err != nil {
		if plain, errFallback := u.kmsService.DecryptPII(req.NIK, "customer_pii"); errFallback == nil {
			nikPlain = plain
		} else {
			return nil, fmt.Errorf("%w: NIK dekripsi gagal: %v", domain.ErrInvalidDecryption, err)
		}
	}

	fullNamePlain, err := u.kmsService.DecryptPII(req.FullName, AAD_FULL_NAME)
	if err != nil {
		if plain, errFallback := u.kmsService.DecryptPII(req.FullName, "customer_pii"); errFallback == nil {
			fullNamePlain = plain
		} else {
			return nil, fmt.Errorf("%w: FullName dekripsi gagal: %v", domain.ErrInvalidDecryption, err)
		}
	}

	emailPlain, err := u.kmsService.DecryptPII(req.Email, AAD_EMAIL)
	if err != nil {
		if plain, errFallback := u.kmsService.DecryptPII(req.Email, "customer_pii"); errFallback == nil {
			emailPlain = plain
		} else {
			return nil, fmt.Errorf("%w: Email dekripsi gagal: %v", domain.ErrInvalidDecryption, err)
		}
	}

	phonePlain, err := u.kmsService.DecryptPII(req.PhoneNumber, AAD_PHONE)
	if err != nil {
		if plain, errFallback := u.kmsService.DecryptPII(req.PhoneNumber, "customer_pii"); errFallback == nil {
			phonePlain = plain
		} else {
			return nil, fmt.Errorf("%w: PhoneNumber dekripsi gagal: %v", domain.ErrInvalidDecryption, err)
		}
	}

	addressPlain, err := u.kmsService.DecryptPII(req.Address, AAD_ADDRESS)
	if err != nil {
		if plain, errFallback := u.kmsService.DecryptPII(req.Address, "customer_pii"); errFallback == nil {
			addressPlain = plain
		} else {
			return nil, fmt.Errorf("%w: Address dekripsi gagal: %v", domain.ErrInvalidDecryption, err)
		}
	}

	plainDTO := dto.PlaintextRegisterCustomer{
		NIK:         nikPlain,
		FullName:    fullNamePlain,
		Email:       emailPlain,
		PhoneNumber: phonePlain,
		Address:     addressPlain,
	}

	return u.processRegistration(ctx, plainDTO)
}

func (u *CustomerUseCase) processRegistration(
	ctx context.Context,
	plainDTO dto.PlaintextRegisterCustomer,
) (*dto.RegisterCustomerResponseData, error) {
	// Normalisasi nomor telepon lokal Indonesia ke standar internasional E.164 (+628xxxx)
	phone := strings.TrimSpace(plainDTO.PhoneNumber)
	phone = strings.ReplaceAll(phone, " ", "")
	phone = strings.ReplaceAll(phone, "-", "")
	if strings.HasPrefix(phone, "0") {
		plainDTO.PhoneNumber = "+62" + phone[1:]
	} else if strings.HasPrefix(phone, "62") {
		plainDTO.PhoneNumber = "+" + phone
	} else if !strings.HasPrefix(phone, "+") && phone != "" {
		plainDTO.PhoneNumber = "+62" + phone
	} else {
		plainDTO.PhoneNumber = phone
	}

	if err := u.validate.Struct(plainDTO); err != nil {
		return nil, fmt.Errorf("validasi format data gagal: %w", err)
	}

	// 3. Parallel DB Uniqueness Check (Fan-Out/Fan-In via errgroup)
	g, gCtx := errgroup.WithContext(ctx)

	targetNIK := plainDTO.NIK
	g.Go(func() error {
		exists, err := u.customerRepo.ExistsByNIK(gCtx, targetNIK)
		if err != nil {
			return err
		}
		if exists {
			return domain.ErrDuplicateNIK
		}
		return nil
	})

	targetEmail := plainDTO.Email
	g.Go(func() error {
		exists, err := u.customerRepo.ExistsByEmail(gCtx, targetEmail)
		if err != nil {
			return err
		}
		if exists {
			return domain.ErrDuplicateEmail
		}
		return nil
	})

	targetPhone := plainDTO.PhoneNumber
	g.Go(func() error {
		exists, err := u.customerRepo.ExistsByPhone(gCtx, targetPhone)
		if err != nil {
			return err
		}
		if exists {
			return domain.ErrDuplicatePhone
		}
		return nil
	})

	if err := g.Wait(); err != nil {
		return nil, err
	}

	// 4. Enkripsi Ulang PII Data Simpanan DB (Biner BYTEA murni)
	encNIKBytes, err := u.kmsService.EncryptPII(plainDTO.NIK, AAD_NIK)
	if err != nil {
		return nil, fmt.Errorf("gagal mengenkripsi NIK: %w", err)
	}
	encFullNameBytes, err := u.kmsService.EncryptPII(plainDTO.FullName, AAD_FULL_NAME)
	if err != nil {
		return nil, fmt.Errorf("gagal mengenkripsi FullName: %w", err)
	}
	encEmailBytes, err := u.kmsService.EncryptPII(plainDTO.Email, AAD_EMAIL)
	if err != nil {
		return nil, fmt.Errorf("gagal mengenkripsi Email: %w", err)
	}
	encPhoneBytes, err := u.kmsService.EncryptPII(plainDTO.PhoneNumber, AAD_PHONE)
	if err != nil {
		return nil, fmt.Errorf("gagal mengenkripsi Phone: %w", err)
	}
	encAddressBytes, err := u.kmsService.EncryptPII(plainDTO.Address, AAD_ADDRESS)
	if err != nil {
		return nil, fmt.Errorf("gagal mengenkripsi Address: %w", err)
	}

	// 5. Simpan Record ke Database PostgreSQL (Status: PENDING_VERIFICATION)
	customer := &domain.Customer{
		NIK:         encNIKBytes,
		FullName:    encFullNameBytes,
		Email:       encEmailBytes,
		PhoneNumber: encPhoneBytes,
		Address:     encAddressBytes,
		Status:      domain.StatusPendingVerification,
	}

	if err := u.customerRepo.CreateCustomer(ctx, customer); err != nil {
		return nil, fmt.Errorf("gagal menyimpan data nasabah ke database: %w", err)
	}

	// 6. Enqueue Background Task ke Worker Pool (Non-blocking)
	if u.workerPool != nil {
		u.workerPool.Enqueue(AsyncTaskJob{
			Type:       TaskTypeAuditLog,
			CustomerID: customer.CustomerID,
			CreatedAt:  time.Now(),
		})
		u.workerPool.Enqueue(AsyncTaskJob{
			Type:       TaskTypeEmailNotify,
			CustomerID: customer.CustomerID,
			CreatedAt:  time.Now(),
		})
	}

	// 7. Format Response DTO (Field ciphertext biner []byte hasil simpanan DB)
	return &dto.RegisterCustomerResponseData{
		CustomerID:  customer.CustomerID,
		NIK:         customer.NIK,
		FullName:    customer.FullName,
		Email:       customer.Email,
		PhoneNumber: customer.PhoneNumber,
		Status:      string(customer.Status),
		CreatedAt:   customer.CreatedAt.Format(time.RFC3339),
	}, nil
}
