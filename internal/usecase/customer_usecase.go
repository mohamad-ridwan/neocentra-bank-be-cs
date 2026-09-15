package usecase

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"strings"
	"time"

	"customer-service/internal/domain"
	"customer-service/internal/dto"
	"customer-service/internal/security"
	"customer-service/internal/service"
	"customer-service/internal/util"

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
	verificationRepo VerificationRepository
	mailService      service.MailService
	emailValidator   service.GoogleEmailValidator
	kmsService       *LocalKMSService
	workerPool       *WorkerPool
	validate         *validator.Validate
	transitDecryptor *security.TransitDecryptor
	jwtSecret        string
}

func NewCustomerUseCase(
	repo CustomerRepository,
	kms *LocalKMSService,
	wp *WorkerPool,
	verificationRepo VerificationRepository,
	mailSvc service.MailService,
	emailValidator service.GoogleEmailValidator,
	jwtSecret string,
	transitDec ...*security.TransitDecryptor,
) *CustomerUseCase {
	uc := &CustomerUseCase{
		customerRepo:     repo,
		verificationRepo: verificationRepo,
		mailService:      mailSvc,
		emailValidator:   emailValidator,
		kmsService:       kms,
		workerPool:       wp,
		validate:         validator.New(),
		jwtSecret:        jwtSecret,
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

	// 1. Dekripsi raw transit body via transitDecryptor dan ekstrak sessionKey
	decryptedJSON, _, err := u.transitDecryptor.DecryptRawTransitPayloadWithKey(rawBody)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", domain.ErrInvalidDecryption, err)
	}

	// 2. Unmarshal JSON plaintext ke PlaintextRegisterCustomer
	var plainDTO dto.PlaintextRegisterCustomer
	if err := json.Unmarshal(decryptedJSON, &plainDTO); err != nil {
		return nil, fmt.Errorf("format JSON hasil dekripsi tidak valid: %w", err)
	}

	// 3. Proses registrasi ke PostgreSQL
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

	// 2. Validasi Akun Email Google Sebelum Menyimpan Data ke Database
	if u.emailValidator != nil {
		if err := u.emailValidator.ValidateGoogleEmail(ctx, plainDTO.Email); err != nil {
			return nil, domain.ErrInvalidEmailGoogle
		}
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

	// 6. Generate 5-Digit Verification Code (10000 - 99999) & Simpan ke Table Verifications
	var verificationID string
	if u.verificationRepo != nil {
		// Generate cryptographic 5-digit number
		codeBig, err := rand.Int(rand.Reader, big.NewInt(90000))
		codeInt := 10000
		if err == nil {
			codeInt = int(codeBig.Int64()) + 10000
		}

		verification := &domain.Verification{
			CustomerID:       customer.CustomerID,
			VerificationType: "EMAIL_REGISTRATION",
			Code:             codeInt,
			ExpiresAt:        time.Now().Add(1 * time.Minute),
		}

		if err := u.verificationRepo.CreateVerification(ctx, verification); err != nil {
			return nil, fmt.Errorf("gagal menyimpan kode verifikasi: %w", err)
		}
		verificationID = verification.VerificationID

		// 7. Kirim Email 5-Digit Kode Verifikasi via wneessen/go-mail
		if u.mailService != nil {
			go func(toEmail, name string, code int) {
				_ = u.mailService.SendVerificationCode(context.Background(), toEmail, name, code)
			}(plainDTO.Email, plainDTO.FullName, codeInt)
		}
	}

	// 8. Enqueue Background Task ke Worker Pool (Non-blocking)
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

	// 9. Generate JWT verificationToken dengan durasi 1 menit
	jwtToken, err := security.GenerateVerificationToken(customer.CustomerID, verificationID, u.jwtSecret, 1*time.Minute)
	if err != nil {
		return nil, fmt.Errorf("gagal membuat verification token: %w", err)
	}

	// 10. Samarkan Email Response (misalnya u***r@example.co)
	maskedEmail := util.MaskEmail(plainDTO.Email)

	return &dto.RegisterCustomerResponseData{
		VerificationToken: jwtToken,
		Email:             maskedEmail,
	}, nil
}

func (u *CustomerUseCase) VerifyCustomer(ctx context.Context, req dto.VerifyCustomerRequest) (*dto.VerifyCustomerResponse, error) {
	if u.verificationRepo == nil {
		return nil, errors.New("layanan verifikasi belum dikonfigurasi")
	}

	// 1. Ekstrak dan validasi JWT Verification Token
	claims, err := security.ParseVerificationToken(req.VerificationToken, u.jwtSecret)
	if err != nil {
		return nil, err
	}

	// 2. Parse 5-digit code string to int
	var codeInt int
	_, err = fmt.Sscanf(req.Code, "%d", &codeInt)
	if err != nil || codeInt < 10000 || codeInt > 99999 {
		return nil, domain.ErrVerificationNotFound
	}

	// 3. Cari entri di tabel verifications berdasarkan {customer_id, verification_id, code}
	v, err := u.verificationRepo.FindVerification(ctx, claims.VerificationID, claims.CustomerID, codeInt)
	if err != nil {
		return nil, domain.ErrVerificationNotFound
	}

	// 4. Periksa apakah waktu kadaluarsa sudah lewat (1 menit)
	if time.Now().After(v.ExpiresAt) {
		_ = u.verificationRepo.DeleteVerification(ctx, v.VerificationID)
		return nil, domain.ErrVerificationExpired
	}

	// 5. Hapus row verifikasi dari tabel verifications agar tidak menjadi spam/reusable
	_ = u.verificationRepo.DeleteVerification(ctx, v.VerificationID)

	// 6. Update status customer menjadi ACTIVE
	if err := u.customerRepo.UpdateCustomerStatus(ctx, claims.CustomerID, domain.StatusActive); err != nil {
		return nil, fmt.Errorf("gagal mengaktifkan akun nasabah: %w", err)
	}

	return &dto.VerifyCustomerResponse{
		Success: true,
		Message: "Akun anda berhasil di verifikasi",
	}, nil
}
