package usecase_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"customer-service/internal/domain"
	"customer-service/internal/dto"
	
	"customer-service/internal/usecase"
)

type MockCustomerRepository struct {
	customers map[string]*domain.Customer
	niks      map[string]bool
	emails    map[string]bool
	phones    map[string]bool
}

func mockCustomerRepo() *MockCustomerRepository {
	return &MockCustomerRepository{
		customers: make(map[string]*domain.Customer),
		niks:      make(map[string]bool),
		emails:    make(map[string]bool),
		phones:    make(map[string]bool),
	}
}

func (m *MockCustomerRepository) CreateCustomer(ctx context.Context, customer *domain.Customer) error {
	customer.CustomerID = "mock-uuid-1234-5678"
	customer.CreatedAt = time.Now()
	customer.UpdatedAt = time.Now()
	m.customers[customer.CustomerID] = customer
	m.niks["3271012345670001"] = true
	m.emails["budi@gmail.com"] = true
	m.phones["+6281234567890"] = true
	return nil
}

func (m *MockCustomerRepository) ExistsByNIK(ctx context.Context, nik string) (bool, error) {
	return m.niks[nik], nil
}

func (m *MockCustomerRepository) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	return m.emails[email], nil
}

func (m *MockCustomerRepository) ExistsByPhone(ctx context.Context, phone string) (bool, error) {
	return m.phones[phone], nil
}

func (m *MockCustomerRepository) UpdateCustomerStatus(ctx context.Context, customerID string, status domain.CustomerStatus) error {
	cust := m.customers[customerID]
	if cust != nil {
		cust.Status = status
		return nil
	}
	return nil
}

type MockVerificationRepository struct {
	verifications map[string]*domain.Verification
}

func newMockVerificationRepo() *MockVerificationRepository {
	return &MockVerificationRepository{
		verifications: make(map[string]*domain.Verification),
	}
}

func (m *MockVerificationRepository) CreateVerification(ctx context.Context, v *domain.Verification) error {
	v.VerificationID = "mock-verif-id-999"
	v.CreatedAt = time.Now()
	m.verifications[v.VerificationID] = v
	return nil
}

func (m *MockVerificationRepository) FindVerification(ctx context.Context, verificationID string, customerID string, code int) (*domain.Verification, error) {
	v, ok := m.verifications[verificationID]
	if !ok || v.CustomerID != customerID || v.Code != code {
		return nil, domain.ErrVerificationNotFound
	}
	return v, nil
}

func (m *MockVerificationRepository) DeleteVerification(ctx context.Context, verificationID string) error {
	delete(m.verifications, verificationID)
	return nil
}

type MockMailService struct {
	SentEmails []string
	SentCodes  []int
}

func (m *MockMailService) SendVerificationCode(ctx context.Context, toEmail, customerName string, code int) error {
	m.SentEmails = append(m.SentEmails, toEmail)
	m.SentCodes = append(m.SentCodes, code)
	return nil
}

type MockEmailValidator struct {
	ShouldFail bool
}

func (m *MockEmailValidator) ValidateGoogleEmail(ctx context.Context, email string) error {
	if m.ShouldFail || strings.Contains(email, "invalid") {
		return domain.ErrInvalidEmailGoogle
	}
	return nil
}

func TestCustomerUseCase_RegisterNewCustomer(t *testing.T) {
	kmsRepo := mockRepo()
	masterKey := "super-secret-master-key-32bytes!"
	kmsService, err := usecase.NewLocalKMSService(masterKey, kmsRepo)
	if err != nil {
		t.Fatalf("failed to init KMS: %v", err)
	}

	custRepo := mockCustomerRepo()
	verifRepo := newMockVerificationRepo()
	mailSvc := &MockMailService{}
	emailVal := &MockEmailValidator{}
	workerPool := usecase.NewWorkerPool(2, 10)
	defer workerPool.Shutdown(context.Background())

	jwtSecret := "test-jwt-secret-key"
	uc := usecase.NewCustomerUseCase(custRepo, kmsService, workerPool, verifRepo, mailSvc, emailVal, jwtSecret)

	// Encrypt sample payload from client side
	nikEnc, _ := kmsService.EncryptPII("3271012345670001", usecase.AAD_NIK)
	nameEnc, _ := kmsService.EncryptPII("Budi Santoso", usecase.AAD_FULL_NAME)
	emailEnc, _ := kmsService.EncryptPII("budi@gmail.com", usecase.AAD_EMAIL)
	phoneEnc, _ := kmsService.EncryptPII("+6281234567890", usecase.AAD_PHONE)
	addressEnc, _ := kmsService.EncryptPII("Jl. Jendral Sudirman No. 10, Jakarta", usecase.AAD_ADDRESS)

	req := dto.EncryptedRegisterCustomerRequest{
		NIK:         nikEnc,
		FullName:    nameEnc,
		Email:       emailEnc,
		PhoneNumber: phoneEnc,
		Address:     addressEnc,
	}

	ctx := context.Background()

	// 1. Success Registration
	resp, err := uc.RegisterNewCustomer(ctx, req)
	if err != nil {
		t.Fatalf("expected successful registration, got err: %v", err)
	}

	if resp.Email == "" {
		t.Errorf("expected non-empty masked email in response")
	}
	if !strings.Contains(resp.Email, "***") {
		t.Errorf("expected masked email, got: %s", resp.Email)
	}
	if resp.VerificationToken == "" {
		t.Errorf("expected non-empty verificationToken in response")
	}

	savedCust := custRepo.customers["mock-uuid-1234-5678"]
	if savedCust == nil {
		t.Fatalf("expected customer to be saved in repository")
	}
	if savedCust.Status != domain.StatusPendingVerification {
		t.Errorf("expected status PENDING_VERIFICATION, got %s", savedCust.Status)
	}

	// 2. Test Verification flow
	savedVerif := verifRepo.verifications["mock-verif-id-999"]
	if savedVerif == nil {
		t.Fatalf("expected verification record to be created")
	}

	verifResp, err := uc.VerifyCustomer(ctx, dto.VerifyCustomerRequest{
		VerificationToken: resp.VerificationToken,
		Code:              string([]byte{byte('0' + savedVerif.Code/10000), byte('0' + (savedVerif.Code/1000)%10), byte('0' + (savedVerif.Code/100)%10), byte('0' + (savedVerif.Code/10)%10), byte('0' + savedVerif.Code%10)}),
	})
	if err != nil {
		t.Fatalf("expected successful verification, got err: %v", err)
	}
	if !verifResp.Success {
		t.Errorf("expected verification success to be true")
	}
	if savedCust.Status != domain.StatusActive {
		t.Errorf("expected customer status to be ACTIVE, got %s", savedCust.Status)
	}
}

func TestCustomerUseCase_RejectInvalidGoogleEmail(t *testing.T) {
	kmsRepo := mockRepo()
	masterKey := "super-secret-master-key-32bytes!"
	kmsService, _ := usecase.NewLocalKMSService(masterKey, kmsRepo)

	custRepo := mockCustomerRepo()
	verifRepo := newMockVerificationRepo()
	mailSvc := &MockMailService{}
	emailVal := &MockEmailValidator{ShouldFail: true}
	jwtSecret := "test-jwt-secret-key"
	uc := usecase.NewCustomerUseCase(custRepo, kmsService, nil, verifRepo, mailSvc, emailVal, jwtSecret)

	nikEnc, _ := kmsService.EncryptPII("3271012345670002", usecase.AAD_NIK)
	nameEnc, _ := kmsService.EncryptPII("Budi Invalid", usecase.AAD_FULL_NAME)
	emailEnc, _ := kmsService.EncryptPII("budi@invalid.com", usecase.AAD_EMAIL)
	phoneEnc, _ := kmsService.EncryptPII("+6281234567891", usecase.AAD_PHONE)
	addressEnc, _ := kmsService.EncryptPII("Jl. Melati No. 5", usecase.AAD_ADDRESS)

	req := dto.EncryptedRegisterCustomerRequest{
		NIK:         nikEnc,
		FullName:    nameEnc,
		Email:       emailEnc,
		PhoneNumber: phoneEnc,
		Address:     addressEnc,
	}

	_, err := uc.RegisterNewCustomer(context.Background(), req)
	if err != domain.ErrInvalidEmailGoogle {
		t.Fatalf("expected ErrInvalidEmailGoogle, got: %v", err)
	}
}
