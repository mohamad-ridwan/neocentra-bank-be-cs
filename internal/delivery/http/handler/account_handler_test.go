package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"customer-service/internal/delivery/http/handler"
	"customer-service/internal/delivery/http/middleware"
	"customer-service/internal/domain"
	"customer-service/internal/dto"
	"customer-service/internal/security"
	"customer-service/internal/usecase"
	"customer-service/internal/util"

	"github.com/gin-gonic/gin"
)

type mockAccountRepoForHandler struct {
	accounts    map[string]*domain.Account
	activeMap   map[string]bool
	attemptsMap map[string]int
}

func (m *mockAccountRepoForHandler) FindAccountsByCustomerID(ctx context.Context, customerID string) ([]domain.Account, error) {
	return nil, nil
}

func (m *mockAccountRepoForHandler) CreateAccount(ctx context.Context, acc *domain.Account) error {
	acc.AccountID = "acc-test-id-123"
	acc.CreatedAt = time.Now()
	acc.UpdatedAt = time.Now()
	m.accounts[acc.AccountID] = acc
	m.activeMap[acc.CustomerID] = true
	return nil
}

func (m *mockAccountRepoForHandler) FindAccountByID(ctx context.Context, accountID string) (*domain.Account, error) {
	acc, ok := m.accounts[accountID]
	if !ok {
		return nil, domain.ErrCustomerNotFound
	}
	return acc, nil
}

func (m *mockAccountRepoForHandler) FindAccountByNumber(ctx context.Context, accountNumber string) (*domain.Account, error) {
	return nil, nil
}

func (m *mockAccountRepoForHandler) UpdatePINAttempts(ctx context.Context, accountID string, attempts int, lockedUntil *time.Time) error {
	m.attemptsMap[accountID] = attempts
	if acc, ok := m.accounts[accountID]; ok {
		acc.PINAttempts = attempts
		acc.PINLockedUntil = lockedUntil
	}
	return nil
}

func (m *mockAccountRepoForHandler) ResetPINAttempts(ctx context.Context, accountID string) error {
	m.attemptsMap[accountID] = 0
	if acc, ok := m.accounts[accountID]; ok {
		acc.PINAttempts = 0
		acc.PINLockedUntil = nil
	}
	return nil
}

func (m *mockAccountRepoForHandler) HasActiveAccount(ctx context.Context, customerID string) (bool, error) {
	return m.activeMap[customerID], nil
}

func setupTestAccountRouter(h *handler.AccountHandler, jwtSecret string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	v1 := r.Group("/api/v1")
	protected := v1.Group("")
	// Dummy auth context for testing: set user_id and role
	protected.Use(func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader != "" {
			c.Set("user_id", "test-user-uuid-1")
			c.Set("role", c.GetHeader("X-Test-Role"))
		}
		c.Next()
	})

	protected.POST("/accounts/open", middleware.RequireRole("ROLE_CUSTOMER_BASIC", "customer"), h.OpenAccount)
	protected.POST("/accounts/verify-pin", middleware.RequireRole("ROLE_CUSTOMER_TRANSACTIONAL"), h.VerifyPIN)

	return r
}

func TestAccountHandler_OpenAccount_Success(t *testing.T) {
	repo := &mockAccountRepoForHandler{
		accounts:    make(map[string]*domain.Account),
		activeMap:   make(map[string]bool),
		attemptsMap: make(map[string]int),
	}
	uc := usecase.NewAccountUseCase(repo)
	uc.SetJWTSecret("test-secret-key")
	h := handler.NewAccountHandler(uc)
	r := setupTestAccountRouter(h, "test-secret-key")

	reqBody := dto.OpenAccountRequest{
		ProductType: "REGULAR_SAVINGS",
		BranchCode:  "001",
		PIN:         "928374",
	}
	jsonBytes, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/api/v1/accounts/open", bytes.NewReader(jsonBytes))
	req.Header.Set("Authorization", "Bearer test-jwt")
	req.Header.Set("X-Test-Role", "ROLE_CUSTOMER_BASIC")
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected status 201 Created, got %d. Body: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse JSON response: %v", err)
	}

	if resp["success"] != true {
		t.Fatalf("expected success true, got %v", resp["success"])
	}

	data := resp["data"].(map[string]interface{})
	accNum := data["account_number"].(string)
	if len(accNum) != 12 || !util.ValidateLuhn(accNum) {
		t.Fatalf("invalid generated account number: %s", accNum)
	}
}

func TestAccountHandler_OpenAccount_ForbiddenForTransactional(t *testing.T) {
	repo := &mockAccountRepoForHandler{
		accounts:    make(map[string]*domain.Account),
		activeMap:   make(map[string]bool),
		attemptsMap: make(map[string]int),
	}
	uc := usecase.NewAccountUseCase(repo)
	h := handler.NewAccountHandler(uc)
	r := setupTestAccountRouter(h, "test-secret-key")

	reqBody := dto.OpenAccountRequest{
		ProductType: "REGULAR_SAVINGS",
		PIN:         "928374",
	}
	jsonBytes, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/api/v1/accounts/open", bytes.NewReader(jsonBytes))
	req.Header.Set("Authorization", "Bearer test-jwt")
	req.Header.Set("X-Test-Role", "ROLE_CUSTOMER_TRANSACTIONAL") // Should be forbidden to open again
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected status 403 Forbidden, got %d", w.Code)
	}
}

func TestAccountHandler_VerifyPIN_Success(t *testing.T) {
	repo := &mockAccountRepoForHandler{
		accounts:    make(map[string]*domain.Account),
		activeMap:   make(map[string]bool),
		attemptsMap: make(map[string]int),
	}
	pin := "719384"
	hash, _ := util.HashPIN(pin)
	acc := &domain.Account{
		AccountID:     "acc-test-id-123",
		CustomerID:    "test-user-uuid-1",
		AccountNumber: "001107193843",
		PINHash:       hash,
	}
	repo.accounts[acc.AccountID] = acc

	uc := usecase.NewAccountUseCase(repo)
	uc.SetJWTSecret("test-secret-key")
	h := handler.NewAccountHandler(uc)
	r := setupTestAccountRouter(h, "test-secret-key")

	reqBody := dto.VerifyPINRequest{
		AccountID: acc.AccountID,
		PIN:       pin,
	}
	jsonBytes, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/api/v1/accounts/verify-pin", bytes.NewReader(jsonBytes))
	req.Header.Set("Authorization", "Bearer test-jwt")
	req.Header.Set("X-Test-Role", "ROLE_CUSTOMER_TRANSACTIONAL")
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200 OK, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestAccountHandler_OpenAccount_Encrypted_Success(t *testing.T) {
	privKey, pubKey, err := security.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}
	transitDec := security.NewTransitDecryptor(privKey)

	repo := &mockAccountRepoForHandler{
		accounts:    make(map[string]*domain.Account),
		activeMap:   make(map[string]bool),
		attemptsMap: make(map[string]int),
	}
	uc := usecase.NewAccountUseCase(repo, transitDec)
	uc.SetJWTSecret("test-secret-key")
	h := handler.NewAccountHandler(uc)
	r := setupTestAccountRouter(h, "test-secret-key")

	reqBody := dto.OpenAccountRequest{
		ProductType: "REGULAR_SAVINGS",
		BranchCode:  "001",
		PIN:         "928374",
		EmploymentData: &dto.EmploymentDataDTO{
			Occupation:    "Engineer",
			MonthlyIncome: "15000000",
			SourceOfFunds: "Salary",
		},
	}
	jsonBytes, _ := json.Marshal(reqBody)

	// Encrypt payload menggunakan RSA Public Key server
	encryptedPayload, err := security.EncryptRawTransitPayload(pubKey, jsonBytes)
	if err != nil {
		t.Fatalf("failed to encrypt transit payload: %v", err)
	}

	req, _ := http.NewRequest(http.MethodPost, "/api/v1/accounts/open", bytes.NewReader(encryptedPayload))
	req.Header.Set("Authorization", "Bearer test-jwt")
	req.Header.Set("X-Test-Role", "ROLE_CUSTOMER_BASIC")
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Accept", "application/octet-stream")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected status 201 Created, got %d. Body: %s", w.Code, w.Body.String())
	}

	if w.Header().Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("expected Content-Type application/octet-stream, got %s", w.Header().Get("Content-Type"))
	}

	// Verifikasi response biner dapat didekripsi dengan public key
	decryptedBytes, err := security.DecryptServerEnvelope(pubKey, w.Body.Bytes())
	if err != nil {
		t.Fatalf("failed to decrypt server envelope response: %v", err)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(decryptedBytes, &resp); err != nil {
		t.Fatalf("failed to parse decrypted JSON: %v", err)
	}

	if resp["success"] != true {
		t.Fatalf("expected success true, got %v", resp["success"])
	}

	data := resp["data"].(map[string]interface{})
	accNum := data["account_number"].(string)
	if len(accNum) != 12 || !util.ValidateLuhn(accNum) {
		t.Fatalf("invalid generated account number in decrypted payload: %s", accNum)
	}
}

