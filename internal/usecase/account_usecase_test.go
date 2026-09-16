package usecase_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"customer-service/internal/domain"
	"customer-service/internal/dto"
	"customer-service/internal/usecase"
	"customer-service/internal/util"
)

type mockAccRepo struct {
	accounts     map[string]*domain.Account
	activeMap    map[string]bool
	createdAcc   *domain.Account
	attemptsMap  map[string]int
	lockedMap    map[string]*time.Time
}

func newMockAccRepo() *mockAccRepo {
	return &mockAccRepo{
		accounts:    make(map[string]*domain.Account),
		activeMap:   make(map[string]bool),
		attemptsMap: make(map[string]int),
		lockedMap:   make(map[string]*time.Time),
	}
}

func (m *mockAccRepo) FindAccountsByCustomerID(ctx context.Context, customerID string) ([]domain.Account, error) {
	var list []domain.Account
	for _, acc := range m.accounts {
		if acc.CustomerID == customerID {
			list = append(list, *acc)
		}
	}
	return list, nil
}

func (m *mockAccRepo) CreateAccount(ctx context.Context, acc *domain.Account) error {
	acc.AccountID = "acc-mock-uuid-1"
	acc.CreatedAt = time.Now()
	acc.UpdatedAt = time.Now()
	m.accounts[acc.AccountID] = acc
	m.activeMap[acc.CustomerID] = (acc.Status == domain.AccountStatusActive)
	m.createdAcc = acc
	return nil
}

func (m *mockAccRepo) FindAccountByID(ctx context.Context, accountID string) (*domain.Account, error) {
	acc, exists := m.accounts[accountID]
	if !exists {
		return nil, errors.New("account not found")
	}
	return acc, nil
}

func (m *mockAccRepo) FindAccountByNumber(ctx context.Context, accountNumber string) (*domain.Account, error) {
	for _, acc := range m.accounts {
		if acc.AccountNumber == accountNumber {
			return acc, nil
		}
	}
	return nil, errors.New("account not found")
}

func (m *mockAccRepo) UpdatePINAttempts(ctx context.Context, accountID string, attempts int, lockedUntil *time.Time) error {
	m.attemptsMap[accountID] = attempts
	m.lockedMap[accountID] = lockedUntil
	if acc, ok := m.accounts[accountID]; ok {
		acc.PINAttempts = attempts
		acc.PINLockedUntil = lockedUntil
	}
	return nil
}

func (m *mockAccRepo) ResetPINAttempts(ctx context.Context, accountID string) error {
	m.attemptsMap[accountID] = 0
	m.lockedMap[accountID] = nil
	if acc, ok := m.accounts[accountID]; ok {
		acc.PINAttempts = 0
		acc.PINLockedUntil = nil
	}
	return nil
}

func (m *mockAccRepo) HasActiveAccount(ctx context.Context, customerID string) (bool, error) {
	return m.activeMap[customerID], nil
}

type mockCustUpdater struct {
	updatedID     string
	updatedStatus domain.CustomerStatus
}

func (m *mockCustUpdater) UpdateCustomerStatus(ctx context.Context, customerID string, status domain.CustomerStatus) error {
	m.updatedID = customerID
	m.updatedStatus = status
	return nil
}

func TestAccountUseCase_OpenAccount(t *testing.T) {
	repo := newMockAccRepo()
	custUpdater := &mockCustUpdater{}
	uc := usecase.NewAccountUseCase(repo)
	uc.SetCustomerRepo(custUpdater)
	uc.SetJWTSecret("test-secret-key-123")

	// 1. Success opening account with valid PIN
	req := dto.OpenAccountRequest{
		ProductType: "REGULAR_SAVINGS",
		BranchCode:  "001",
		PIN:         "482910",
		EmploymentData: &dto.EmploymentDataDTO{
			Occupation:    "Software Engineer",
			MonthlyIncome: "20000000",
			SourceOfFunds: "Salary",
		},
	}

	resp, sess, err := uc.OpenAccount(context.Background(), "cust-uuid-1", req)
	if err != nil {
		t.Fatalf("unexpected error on OpenAccount: %v", err)
	}

	if resp.AccountNumber == "" || len(resp.AccountNumber) != 12 {
		t.Fatalf("expected 12 digit account number, got %s", resp.AccountNumber)
	}
	if !util.ValidateLuhn(resp.AccountNumber) {
		t.Fatalf("account number fails Luhn checksum: %s", resp.AccountNumber)
	}
	if sess.Role != "ROLE_CUSTOMER_TRANSACTIONAL" {
		t.Fatalf("expected role ROLE_CUSTOMER_TRANSACTIONAL, got %s", sess.Role)
	}
	if sess.ElevatedToken == "" {
		t.Fatalf("expected elevated token, got empty")
	}
	if custUpdater.updatedStatus != domain.StatusActive {
		t.Fatalf("expected customer status to be active, got %s", custUpdater.updatedStatus)
	}

	// 2. Reject double opening for same customer
	_, _, errDup := uc.OpenAccount(context.Background(), "cust-uuid-1", req)
	if errDup == nil {
		t.Fatalf("expected error on duplicate account opening, got nil")
	}

	// 3. Reject weak PIN (sequential)
	reqWeak := dto.OpenAccountRequest{
		ProductType: "REGULAR_SAVINGS",
		PIN:         "123456",
	}
	_, _, errWeak := uc.OpenAccount(context.Background(), "cust-uuid-2", reqWeak)
	if errWeak != util.ErrPINSequential {
		t.Fatalf("expected ErrPINSequential, got %v", errWeak)
	}
}

func TestAccountUseCase_VerifyPIN_BruteForceProtection(t *testing.T) {
	repo := newMockAccRepo()
	uc := usecase.NewAccountUseCase(repo)
	uc.SetJWTSecret("test-secret-key-123")

	// Create account directly
	pin := "837192"
	hash, _ := util.HashPIN(pin)
	acc := &domain.Account{
		CustomerID:    "cust-1",
		AccountNumber: "001108371924",
		Status:        domain.AccountStatusActive,
		PINHash:       hash,
	}
	_ = repo.CreateAccount(context.Background(), acc)

	// Attempt 1: Wrong PIN
	_, rem1, err1 := uc.VerifyPIN(context.Background(), "cust-1", dto.VerifyPINRequest{
		AccountID: acc.AccountID,
		PIN:       "000001",
	})
	if err1 != util.ErrPINMismatch || rem1 != 2 {
		t.Fatalf("expected ErrPINMismatch with 2 remaining attempts, got err=%v, rem=%d", err1, rem1)
	}

	// Attempt 2: Wrong PIN
	_, rem2, err2 := uc.VerifyPIN(context.Background(), "cust-1", dto.VerifyPINRequest{
		AccountID: acc.AccountID,
		PIN:       "000002",
	})
	if err2 != util.ErrPINMismatch || rem2 != 1 {
		t.Fatalf("expected ErrPINMismatch with 1 remaining attempt, got err=%v, rem=%d", err2, rem2)
	}

	// Attempt 3: Wrong PIN -> Lock account
	_, rem3, err3 := uc.VerifyPIN(context.Background(), "cust-1", dto.VerifyPINRequest{
		AccountID: acc.AccountID,
		PIN:       "000003",
	})
	if err3 != util.ErrPINLocked || rem3 != 0 {
		t.Fatalf("expected ErrPINLocked with 0 remaining, got err=%v, rem=%d", err3, rem3)
	}

	// Attempt 4: Even with correct PIN, account is locked!
	_, _, err4 := uc.VerifyPIN(context.Background(), "cust-1", dto.VerifyPINRequest{
		AccountID: acc.AccountID,
		PIN:       pin,
	})
	if err4 != util.ErrPINLocked {
		t.Fatalf("expected ErrPINLocked during lockout period, got %v", err4)
	}
}
