package handler_test

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	delivery "customer-service/internal/delivery/http"
	"customer-service/internal/delivery/http/handler"
	"customer-service/internal/delivery/http/serializer"
	"customer-service/internal/domain"
	"customer-service/internal/dto"
	"customer-service/internal/security"
	"customer-service/internal/usecase"

	"github.com/gin-gonic/gin"
)

type mockCustRepo struct {
	customers map[string]*domain.Customer
}

func (m *mockCustRepo) ExistsByNIK(ctx context.Context, nik string) (bool, error) {
	return false, nil
}
func (m *mockCustRepo) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	return false, nil
}
func (m *mockCustRepo) ExistsByPhone(ctx context.Context, phone string) (bool, error) {
	return false, nil
}
func (m *mockCustRepo) CreateCustomer(ctx context.Context, customer *domain.Customer) error {
	customer.CustomerID = "test-cust-id-123"
	customer.CreatedAt = time.Now()
	return nil
}
func (m *mockCustRepo) UpdateCustomerStatus(ctx context.Context, customerID string, status domain.CustomerStatus) error {
	return nil
}
func (m *mockCustRepo) FindCustomerByIdentifier(ctx context.Context, identifier string) (*domain.Customer, *usecase.DecryptedCustomerPII, error) {
	// Hash dari "Password123#" menggunakan Argon2id
	passHash, _ := security.HashPassword("Password123#")
	return &domain.Customer{
		CustomerID:   "test-cust-id-123",
		PasswordHash: passHash,
		Status:       domain.StatusActive,
	}, &usecase.DecryptedCustomerPII{
		CustomerID:  "test-cust-id-123",
		NIK:         "3271012345670001",
		FullName:    "Budi Santoso",
		Email:       "budi@example.com",
		PhoneNumber: "+6281234567890",
		Status:      "ACTIVE",
	}, nil
}

type mockVerifRepo struct {
	verifications map[string]*domain.Verification
}

func (m *mockVerifRepo) CreateVerification(ctx context.Context, v *domain.Verification) error {
	v.VerificationID = "verif-id-123"
	if m.verifications == nil {
		m.verifications = make(map[string]*domain.Verification)
	}
	m.verifications[v.VerificationID] = v
	return nil
}
func (m *mockVerifRepo) FindVerification(ctx context.Context, verificationID string, customerID string, code int) (*domain.Verification, error) {
	v, ok := m.verifications[verificationID]
	if !ok || v.CustomerID != customerID || v.Code != code {
		return nil, domain.ErrVerificationNotFound
	}
	return v, nil
}
func (m *mockVerifRepo) DeleteVerification(ctx context.Context, verificationID string) error {
	delete(m.verifications, verificationID)
	return nil
}

type mockMailSvc struct{}

func (m *mockMailSvc) SendVerificationCode(ctx context.Context, toEmail, customerName string, code int) error {
	return nil
}

type mockEmailVal struct{}

func (m *mockEmailVal) ValidateGoogleEmail(ctx context.Context, email string) error {
	if strings.Contains(email, "invalid") {
		return domain.ErrInvalidEmailGoogle
	}
	return nil
}

func packTLV(nik, name, email, phone, addr, pwd []byte) []byte {
	var buf []byte
	appendField := func(tag byte, val []byte) {
		buf = append(buf, tag)
		lenBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBytes, uint16(len(val)))
		buf = append(buf, lenBytes...)
		buf = append(buf, val...)
	}
	appendField(serializer.TagNIK, nik)
	appendField(serializer.TagFullName, name)
	appendField(serializer.TagEmail, email)
	appendField(serializer.TagPhoneNumber, phone)
	appendField(serializer.TagAddress, addr)
	appendField(serializer.TagPassword, pwd)
	return buf
}

func generateSignature(method, path string, body []byte, timestamp, nonce string) string {
	bodySha := sha256.Sum256(body)
	bodyHashHex := hex.EncodeToString(bodySha[:])
	stringToSign := fmt.Sprintf("%s:%s:%s:%s:%s", method, path, bodyHashHex, timestamp, nonce)

	signingKey := "neocentra_app_signature_key_2026"
	mac := hmac.New(sha256.New, []byte(signingKey))
	mac.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func TestRouter_RegisterCustomer_Success(t *testing.T) {
	kmsRepo := mockRepo()
	masterKey := "neocentra_mock_master_key_for_testing_32bytes!"
	kmsService, err := usecase.NewLocalKMSService(masterKey, kmsRepo)
	if err != nil {
		t.Fatalf("failed to init KMS: %v", err)
	}

	repo := &mockCustRepo{customers: make(map[string]*domain.Customer)}
	verifRepo := &mockVerifRepo{verifications: make(map[string]*domain.Verification)}
	wp := usecase.NewWorkerPool(2, 10)
	defer wp.Shutdown(context.Background())

	uc := usecase.NewCustomerUseCase(repo, kmsService, wp, verifRepo, &mockMailSvc{}, &mockEmailVal{}, "jwt-secret")
	custHandler := handler.NewCustomerHandler(uc)
	router := delivery.SetupRouter(custHandler, nil)

	// Enkripsi PII transit data
	encNIK, _ := kmsService.EncryptPII("3201010101990001", usecase.AAD_NIK)
	encName, _ := kmsService.EncryptPII("Budi Santoso", usecase.AAD_FULL_NAME)
	encEmail, _ := kmsService.EncryptPII("budi.santoso@neocentra.bank", usecase.AAD_EMAIL)
	encPhone, _ := kmsService.EncryptPII("+6281298765432", usecase.AAD_PHONE)
	encAddr, _ := kmsService.EncryptPII("Jl. Sudirman No. 45, Jakarta", usecase.AAD_ADDRESS)

	tlvBody := packTLV(encNIK, encName, encEmail, encPhone, encAddr, []byte("SecurePassword123!"))

	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	nonce := "random-nonce-12345"
	path := "/api/v1/customers/register"
	sig := generateSignature("POST", path, tlvBody, timestamp, nonce)

	req, _ := http.NewRequest("POST", path, bytes.NewReader(tlvBody))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Timestamp", timestamp)
	req.Header.Set("X-Nonce", nonce)
	req.Header.Set("X-Signature", sig)
	req.Header.Set("X-Idempotency-Key", "idem-test-key-1")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected status 201 Created, got %d. Body: %s", w.Code, w.Body.String())
	}

	var resp dto.RegisterCustomerAPIResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse JSON response: %v", err)
	}

	if !resp.Success {
		t.Errorf("expected success: true, got false")
	}
	if len(resp.Data.Email) == 0 {
		t.Errorf("expected non-empty masked email in response data")
	}
	if len(resp.Data.VerificationToken) == 0 {
		t.Errorf("expected non-empty verificationToken in response data")
	}

	// Test Verify Customer Endpoint
	verifReqBody, _ := json.Marshal(dto.VerifyCustomerRequest{
		VerificationToken: resp.Data.VerificationToken,
		Code:              fmt.Sprintf("%05d", verifRepo.verifications["verif-id-123"].Code),
	})
	vReq, _ := http.NewRequest("POST", "/api/v1/customers/verification", bytes.NewReader(verifReqBody))
	vReq.Header.Set("Content-Type", "application/json")
	vRec := httptest.NewRecorder()
	router.ServeHTTP(vRec, vReq)

	if vRec.Code != http.StatusOK {
		t.Fatalf("expected verification status 200 OK, got %d. Body: %s", vRec.Code, vRec.Body.String())
	}
}

func TestRouter_RejectExpiredTimestamp(t *testing.T) {
	repo := &mockCustRepo{customers: make(map[string]*domain.Customer)}
	masterKey := "neocentra_mock_master_key_for_testing_32bytes!"
	kmsService, _ := usecase.NewLocalKMSService(masterKey, nil)
	uc := usecase.NewCustomerUseCase(repo, kmsService, nil, &mockVerifRepo{}, &mockMailSvc{}, &mockEmailVal{}, "jwt-secret")
	custHandler := handler.NewCustomerHandler(uc)
	router := delivery.SetupRouter(custHandler, nil)

	tlvBody := []byte("dummy")
	expiredTimestamp := time.Now().Add(-5 * time.Minute).UTC().Format(time.RFC3339)
	nonce := "test-nonce"
	path := "/api/v1/customers/register"
	sig := generateSignature("POST", path, tlvBody, expiredTimestamp, nonce)

	req, _ := http.NewRequest("POST", path, bytes.NewReader(tlvBody))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Timestamp", expiredTimestamp)
	req.Header.Set("X-Nonce", nonce)
	req.Header.Set("X-Signature", sig)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized for expired timestamp, got %d", w.Code)
	}
}

func TestRouter_RejectInvalidSignature(t *testing.T) {
	repo := &mockCustRepo{customers: make(map[string]*domain.Customer)}
	masterKey := "neocentra_mock_master_key_for_testing_32bytes!"
	kmsService, _ := usecase.NewLocalKMSService(masterKey, nil)
	uc := usecase.NewCustomerUseCase(repo, kmsService, nil, &mockVerifRepo{}, &mockMailSvc{}, &mockEmailVal{}, "jwt-secret")
	custHandler := handler.NewCustomerHandler(uc)
	router := delivery.SetupRouter(custHandler, nil)

	tlvBody := []byte("dummy")
	timestamp := time.Now().UTC().Format(time.RFC3339)
	nonce := "test-nonce"
	path := "/api/v1/customers/register"

	req, _ := http.NewRequest("POST", path, bytes.NewReader(tlvBody))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Timestamp", timestamp)
	req.Header.Set("X-Nonce", nonce)
	req.Header.Set("X-Signature", "invalid-fake-signature")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized for invalid signature, got %d", w.Code)
	}
}

func TestRouter_PublicRegisterWithHybridEncryptionPola1(t *testing.T) {
	masterKey := "neocentra_mock_master_key_for_testing_32bytes!"
	kmsService, err := usecase.NewLocalKMSService(masterKey, nil)
	if err != nil {
		t.Fatalf("failed to init KMS: %v", err)
	}

	privKey, pubKey, err := security.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	transitDec := security.NewTransitDecryptor(privKey)

	repo := &mockCustRepo{customers: make(map[string]*domain.Customer)}
	verifRepo := &mockVerifRepo{verifications: make(map[string]*domain.Verification)}
	wp := usecase.NewWorkerPool(2, 10)
	defer wp.Shutdown(context.Background())

	uc := usecase.NewCustomerUseCase(repo, kmsService, wp, verifRepo, &mockMailSvc{}, &mockEmailVal{}, "jwt-secret", transitDec)
	custHandler := handler.NewCustomerHandler(uc)
	router := delivery.SetupRouter(custHandler, nil)

	customerJSON := []byte(`{
		"nik": "3201019999990001",
		"full_name": "Ahmad Yani",
		"email": "ahmad.yani@neocentra.bank",
		"phone_number": "+6281312345678",
		"address": "Jl. Merdeka No. 1, Bandung",
		"password": "SecurePassword123!"
	}`)

	rawBody, err := security.EncryptRawTransitPayload(pubKey, customerJSON)
	if err != nil {
		t.Fatalf("failed to encrypt hybrid payload: %v", err)
	}

	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	nonce := "random-nonce-hybrid-1"
	path := "/api/v1/customers/register"
	sig := generateSignature("POST", path, rawBody, timestamp, nonce)

	req, _ := http.NewRequest("POST", path, bytes.NewReader(rawBody))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Timestamp", timestamp)
	req.Header.Set("X-Nonce", nonce)
	req.Header.Set("X-Signature", sig)
	req.Header.Set("X-Idempotency-Key", "idem-hybrid-key-1")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected status 201 Created, got %d. Body: %s", w.Code, w.Body.String())
	}

	var resp dto.RegisterCustomerAPIResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse JSON response: %v", err)
	}

	if !resp.Success {
		t.Errorf("expected success: true, got false")
	}
	if len(resp.Data.Email) == 0 {
		t.Errorf("expected non-empty email in response data")
	}
	if len(resp.Data.VerificationToken) == 0 {
		t.Errorf("expected non-empty verificationToken in response data")
	}
}

type mockKmsRepo struct{}

func mockRepo() *mockKmsRepo {
	return &mockKmsRepo{}
}
func (m *mockKmsRepo) SaveEncryptedKeyset(ctx context.Context, keyName string, encryptedKeyset []byte) error {
	return nil
}
func (m *mockKmsRepo) GetEncryptedKeyset(ctx context.Context, keyName string) ([]byte, error) {
	return nil, nil
}

func (m *mockKmsRepo) GetKeysetByName(ctx context.Context, keyName string) ([]byte, int, error) {
	return nil, 0, nil
}
func (m *mockKmsRepo) SaveKeyset(ctx context.Context, keyName string, encryptedKeyset []byte, primaryKeyID uint32, version int) error {
	return nil
}
func (m *mockKmsRepo) UpdateKeyset(ctx context.Context, keyName string, encryptedKeyset []byte, primaryKeyID uint32, version int) error {
	return nil
}

type mockAccountRepo struct {
	accounts []domain.Account
}

func (m *mockAccountRepo) FindAccountsByCustomerID(ctx context.Context, customerID string) ([]domain.Account, error) {
	return m.accounts, nil
}

func (m *mockAccountRepo) CreateAccount(ctx context.Context, acc *domain.Account) error {
	m.accounts = append(m.accounts, *acc)
	return nil
}

func (m *mockAccountRepo) FindAccountByID(ctx context.Context, accountID string) (*domain.Account, error) {
	for _, acc := range m.accounts {
		if acc.AccountID == accountID {
			return &acc, nil
		}
	}
	return nil, nil
}

func (m *mockAccountRepo) FindAccountByNumber(ctx context.Context, accountNumber string) (*domain.Account, error) {
	for _, acc := range m.accounts {
		if acc.AccountNumber == accountNumber {
			return &acc, nil
		}
	}
	return nil, nil
}

func (m *mockAccountRepo) UpdatePINAttempts(ctx context.Context, accountID string, attempts int, lockedUntil *time.Time) error {
	return nil
}

func (m *mockAccountRepo) ResetPINAttempts(ctx context.Context, accountID string) error {
	return nil
}

func (m *mockAccountRepo) HasActiveAccount(ctx context.Context, customerID string) (bool, error) {
	return len(m.accounts) > 0, nil
}

func TestCustomerHandler_LoginCustomer(t *testing.T) {
	gin.SetMode(gin.TestMode)

	privKey, pubKey, err := security.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}
	transitDec := security.NewTransitDecryptor(privKey)

	repo := &mockCustRepo{}
	kmsService, _ := usecase.NewLocalKMSService("test-master-key-32b-secret!!!!!!", mockRepo())
	wp := usecase.NewWorkerPool(1, 10)
	verifRepo := &mockVerifRepo{}

	uc := usecase.NewCustomerUseCase(repo, kmsService, wp, verifRepo, &mockMailSvc{}, &mockEmailVal{}, "jwt-secret", transitDec)
	accRepo := &mockAccountRepo{
		accounts: []domain.Account{
			{
				AccountID:     "acc-123",
				CustomerID:    "test-cust-id-123",
				AccountNumber: "880912345678",
				Balance:       15000000,
				Currency:      "IDR",
				Status:        domain.AccountStatusActive,
			},
		},
	}
	accUC := usecase.NewAccountUseCase(accRepo, transitDec)
	h := handler.NewCustomerHandler(uc, accUC)

	router := gin.New()
	router.POST("/api/v1/customers/login", h.LoginCustomer)

	loginJSON := []byte(`{"identifier":"budi@example.com","password":"Password123#"}`)
	rawBody, sessionKey, err := security.EncryptRawTransitPayloadWithKey(pubKey, loginJSON)
	if err != nil {
		t.Fatalf("failed to encrypt login payload: %v", err)
	}

	req, _ := http.NewRequest("POST", "/api/v1/customers/login", bytes.NewReader(rawBody))
	req.Header.Set("Content-Type", "application/octet-stream")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200 OK, got %d. Body: %s", w.Code, w.Body.String())
	}

	if w.Header().Get("Content-Type") != "application/octet-stream" {
		t.Errorf("expected Content-Type application/octet-stream, got %s", w.Header().Get("Content-Type"))
	}

	// Decrypt response using sessionKey
	respBytes := w.Body.Bytes()
	decryptedJSON, err := decryptTransitResponse(sessionKey, respBytes)
	if err != nil {
		t.Fatalf("failed to decrypt response: %v", err)
	}

	var resp dto.LoginCustomerResponseData
	if err := json.Unmarshal(decryptedJSON, &resp); err != nil {
		t.Fatalf("failed to unmarshal decrypted JSON: %v", err)
	}

	if resp.CustomerID != "test-cust-id-123" {
		t.Errorf("expected customer_id 'test-cust-id-123', got '%s'", resp.CustomerID)
	}
	if resp.AccessToken == "" {
		t.Errorf("expected non-empty access_token")
	}

	// 2. Test Login dengan password yang salah -> Wajib 401 Unauthorized
	wrongLoginJSON := []byte(`{"identifier":"budi@example.com","password":"WrongPassword123#"}`)
	rawBodyWrong, _, err := security.EncryptRawTransitPayloadWithKey(pubKey, wrongLoginJSON)
	if err != nil {
		t.Fatalf("failed to encrypt wrong login payload: %v", err)
	}

	reqWrong, _ := http.NewRequest("POST", "/api/v1/customers/login", bytes.NewReader(rawBodyWrong))
	reqWrong.Header.Set("Content-Type", "application/octet-stream")

	wWrong := httptest.NewRecorder()
	router.ServeHTTP(wWrong, reqWrong)

	if wWrong.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401 Unauthorized for wrong password, got %d. Body: %s", wWrong.Code, wWrong.Body.String())
	}
}

func TestCustomerHandler_GetAccounts(t *testing.T) {
	gin.SetMode(gin.TestMode)

	privKey, _, err := security.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}
	transitDec := security.NewTransitDecryptor(privKey)

	accRepo := &mockAccountRepo{
		accounts: []domain.Account{
			{
				AccountID:     "acc-123",
				CustomerID:    "test-cust-id-123",
				AccountNumber: "880912345678",
				Balance:       15000000,
				Currency:      "IDR",
				Status:        domain.AccountStatusActive,
			},
		},
	}
	accUC := usecase.NewAccountUseCase(accRepo, transitDec)
	h := handler.NewCustomerHandler(nil, accUC)

	router := gin.New()
	router.POST("/api/v1/accounts", h.GetAccounts)

	jsonBody := []byte(`{"customer_id":"test-cust-id-123"}`)
	req, _ := http.NewRequest("POST", "/api/v1/accounts", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200 OK, got %d. Body: %s", w.Code, w.Body.String())
	}

	if w.Header().Get("Content-Type") != "application/octet-stream" {
		t.Errorf("expected Content-Type application/octet-stream, got %s", w.Header().Get("Content-Type"))
	}
}

func decryptTransitResponse(sessionKey, body []byte) ([]byte, error) {
	if len(body) < 12+16 {
		return nil, fmt.Errorf("body too short")
	}
	iv := body[:12]
	ciphertextWithTag := body[12:]

	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, iv, ciphertextWithTag, nil)
}
