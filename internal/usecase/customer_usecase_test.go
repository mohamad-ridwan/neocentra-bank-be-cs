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
	// Mark plain keys from mock test context if needed or store
	m.niks["3271012345670001"] = true
	m.emails["budi@example.com"] = true
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

func TestCustomerUseCase_RegisterNewCustomer(t *testing.T) {
	kmsRepo := mockRepo()
	masterKey := "super-secret-master-key-32bytes!"
	kmsService, err := usecase.NewLocalKMSService(masterKey, kmsRepo)
	if err != nil {
		t.Fatalf("failed to init KMS: %v", err)
	}

	custRepo := mockCustomerRepo()
	workerPool := usecase.NewWorkerPool(2, 10)
	defer workerPool.Shutdown(context.Background())

	uc := usecase.NewCustomerUseCase(custRepo, kmsService, workerPool)

	// Encrypt sample payload from client side
	nikEnc, _ := kmsService.EncryptPII("3271012345670001", usecase.AAD_NIK)
	nameEnc, _ := kmsService.EncryptPII("Budi Santoso", usecase.AAD_FULL_NAME)
	emailEnc, _ := kmsService.EncryptPII("budi@example.com", usecase.AAD_EMAIL)
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

	if resp.CustomerID != "mock-uuid-1234-5678" {
		t.Errorf("expected customer id mock-uuid-1234-5678, got %s", resp.CustomerID)
	}

	if resp.Status != string(domain.StatusPendingVerification) {
		t.Errorf("expected status PENDING_VERIFICATION, got %s", resp.Status)
	}

	// 2. Duplicate Registration Test
	_, err = uc.RegisterNewCustomer(ctx, req)
	if err == nil {
		t.Fatalf("expected error on duplicate registration, got nil")
	}

	// 3. Invalid Decryption Test
	invalidReq := req
	invalidReq.NIK = []byte("invalid-binary-bytes!!")
	_, err = uc.RegisterNewCustomer(ctx, invalidReq)
	if err == nil || !strings.Contains(err.Error(), "dekripsi gagal") {
		t.Errorf("expected decryption error, got: %v", err)
	}
}
