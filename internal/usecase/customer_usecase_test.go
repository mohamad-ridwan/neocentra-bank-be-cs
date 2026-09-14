package usecase_test

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"strings"
	"testing"
	"time"

	"customer-service/internal/domain"
	"customer-service/internal/dto"
	"customer-service/internal/security"
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

	if len(resp.Email) == 0 {
		t.Errorf("expected non-empty encrypted email bytes in response")
	}

	savedCust := custRepo.customers["mock-uuid-1234-5678"]
	if savedCust == nil {
		t.Fatalf("expected customer to be saved in repository")
	}

	if savedCust.Status != domain.StatusPendingVerification {
		t.Errorf("expected status PENDING_VERIFICATION, got %s", savedCust.Status)
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

func TestCustomerUseCase_RegisterNewCustomerRaw_HybridEncryption(t *testing.T) {
	kmsRepo := mockRepo()
	masterKey := "super-secret-master-key-32bytes!"
	kmsService, err := usecase.NewLocalKMSService(masterKey, kmsRepo)
	if err != nil {
		t.Fatalf("failed to init KMS: %v", err)
	}

	custRepo := mockCustomerRepo()
	workerPool := usecase.NewWorkerPool(2, 10)
	defer workerPool.Shutdown(context.Background())

	// Generate RSA key pair for transit encryption
	privKey, pubKey, err := security.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	transitDec := security.NewTransitDecryptor(privKey)
	uc := usecase.NewCustomerUseCase(custRepo, kmsService, workerPool, transitDec)

	// Plaintext registration payload from mobile app
	customerJSON := []byte(`{
		"nik": "3201012345670001",
		"full_name": "Siti Nurhaliza",
		"email": "siti.nurhaliza@example.com",
		"phone_number": "+6281298765432",
		"address": "Jl. Gatot Subroto No. 50, Jakarta",
		"password": "SecurePassword123!"
	}`)

	// Encrypt using hybrid RSA-OAEP + AES-256-GCM (Pola 1)
	encryptedRawBody, sessionKey, err := security.EncryptRawTransitPayloadWithKey(pubKey, customerJSON)
	if err != nil {
		t.Fatalf("failed to encrypt hybrid payload: %v", err)
	}

	ctx := context.Background()

	// 1. Success Registration via Raw Hybrid Payload
	resp, err := uc.RegisterNewCustomerRaw(ctx, encryptedRawBody)
	if err != nil {
		t.Fatalf("expected successful raw registration, got: %v", err)
	}

	if len(resp.Email) == 0 {
		t.Errorf("expected non-empty encrypted email bytes in response")
	}

	// Verify that response email can be decrypted with sessionKey (Option A: Transit Shared Secret)
	if len(resp.Email) < 28 {
		t.Fatalf("expected response email length >= 28 bytes, got %d", len(resp.Email))
	}
	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		t.Fatalf("failed to create cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("failed to create gcm: %v", err)
	}
	iv := resp.Email[:12]
	ct := resp.Email[12:]
	decEmailBytes, err := gcm.Open(nil, iv, ct, nil)
	if err != nil {
		t.Fatalf("failed to decrypt response email with sessionKey: %v", err)
	}
	if string(decEmailBytes) != "siti.nurhaliza@example.com" {
		t.Errorf("expected decrypted response email siti.nurhaliza@example.com, got %s", string(decEmailBytes))
	}

	// Verify that the stored customer in repo was encrypted using Tink KMS Keyset
	savedCust := custRepo.customers["mock-uuid-1234-5678"]
	if savedCust == nil {
		t.Fatal("expected customer to be saved in repository")
	}

	if savedCust.Status != domain.StatusPendingVerification {
		t.Errorf("expected status PENDING_VERIFICATION, got %s", savedCust.Status)
	}

	// Decrypt using KMS service to verify data-at-rest Tink preservation
	decNIK, err := kmsService.DecryptPII(savedCust.NIK, usecase.AAD_NIK)
	if err != nil {
		t.Fatalf("failed to decrypt saved NIK with KMS: %v", err)
	}
	if decNIK != "3201012345670001" {
		t.Errorf("expected saved NIK 3201012345670001, got %s", decNIK)
	}

	// 2. Corrupted Payload Error
	corrupted := append([]byte(nil), encryptedRawBody...)
	corrupted[len(corrupted)-1] ^= 0xFF
	_, err = uc.RegisterNewCustomerRaw(ctx, corrupted)
	if err == nil {
		t.Fatal("expected error on corrupted raw payload, got nil")
	}
}

func TestCustomerUseCase_PhoneNumberNormalization_LocalFormat(t *testing.T) {
	kmsRepo := mockRepo()
	masterKey := "super-secret-master-key-32bytes!"
	kmsService, err := usecase.NewLocalKMSService(masterKey, kmsRepo)
	if err != nil {
		t.Fatalf("failed to init KMS: %v", err)
	}

	custRepo := mockCustomerRepo()
	workerPool := usecase.NewWorkerPool(2, 10)
	defer workerPool.Shutdown(context.Background())

	privKey, pubKey, _ := security.GenerateRSAKeyPair(2048)
	transitDec := security.NewTransitDecryptor(privKey)
	uc := usecase.NewCustomerUseCase(custRepo, kmsService, workerPool, transitDec)

	// Payload with local phone number "081234567890" without +62 prefix
	customerJSON := []byte(`{
		"nik": "3201015555550001",
		"full_name": "Rudi Tabuti",
		"email": "rudi.tabuti@example.com",
		"phone_number": "081234567890",
		"address": "Jl. Melawai Raya No. 12, Jakarta",
		"password": "SecurePassword123!"
	}`)

	encryptedRawBody, err := security.EncryptRawTransitPayload(pubKey, customerJSON)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	ctx := context.Background()
	resp, err := uc.RegisterNewCustomerRaw(ctx, encryptedRawBody)
	if err != nil {
		t.Fatalf("expected successful registration with local phone number, got error: %v", err)
	}

	if len(resp.Email) == 0 {
		t.Errorf("expected non-empty encrypted email bytes in response")
	}

	savedCust := custRepo.customers["mock-uuid-1234-5678"]
	if savedCust == nil {
		t.Fatal("expected customer to be saved")
	}

	decPhone, err := kmsService.DecryptPII(savedCust.PhoneNumber, usecase.AAD_PHONE)
	if err != nil {
		t.Fatalf("failed to decrypt phone with KMS: %v", err)
	}

	if decPhone != "+6281234567890" {
		t.Errorf("expected phone number to be normalized to '+6281234567890', got '%s'", decPhone)
	}
}


