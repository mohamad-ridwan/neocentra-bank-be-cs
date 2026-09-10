package handler_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	delivery "customer-service/internal/delivery/http"
	"customer-service/internal/delivery/http/handler"
	"customer-service/internal/delivery/http/middleware"
	"customer-service/internal/delivery/http/serializer"
	"customer-service/internal/domain"
	"customer-service/internal/dto"
	"customer-service/internal/usecase"

	"context"
)

// Mock customer repository
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
	mac := hmac.New(sha256.New, []byte(middleware.DefaultAppSigningKey))
	mac.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func TestRouter_PublicRegisterWithSecurityHeaders(t *testing.T) {
	// Setup KMS & UseCase
	masterKey := "neocentra_mock_master_key_for_testing_32bytes!"
	kmsService, err := usecase.NewLocalKMSService(masterKey, nil)
	if err != nil {
		t.Fatalf("failed to init KMS: %v", err)
	}

	repo := &mockCustRepo{customers: make(map[string]*domain.Customer)}
	wp := usecase.NewWorkerPool(2, 10)
	defer wp.Shutdown(context.Background())

	uc := usecase.NewCustomerUseCase(repo, kmsService, wp)
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
	if resp.Data.CustomerID != "test-cust-id-123" {
		t.Errorf("expected CustomerID 'test-cust-id-123', got '%s'", resp.Data.CustomerID)
	}
}

func TestRouter_RejectExpiredTimestamp(t *testing.T) {
	repo := &mockCustRepo{customers: make(map[string]*domain.Customer)}
	masterKey := "neocentra_mock_master_key_for_testing_32bytes!"
	kmsService, _ := usecase.NewLocalKMSService(masterKey, nil)
	uc := usecase.NewCustomerUseCase(repo, kmsService, nil)
	custHandler := handler.NewCustomerHandler(uc)
	router := delivery.SetupRouter(custHandler, nil)

	tlvBody := []byte("dummy")
	// Timestamp 5 minutes ago (outside 60s skew window)
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
	uc := usecase.NewCustomerUseCase(repo, kmsService, nil)
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
