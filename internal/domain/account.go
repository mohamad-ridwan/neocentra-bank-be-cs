package domain

import "time"

type AccountStatus string

const (
	AccountStatusPendingKYC AccountStatus = "PENDING_KYC"
	AccountStatusActive     AccountStatus = "ACTIVE"
	AccountStatusSuspended  AccountStatus = "SUSPENDED"
	AccountStatusClosed     AccountStatus = "CLOSED"
)

type AccountProductType string

const (
	ProductTypeRegularSavings  AccountProductType = "REGULAR_SAVINGS"
	ProductTypePrioritySavings AccountProductType = "PRIORITY_SAVINGS"
	ProductTypeStudentSavings  AccountProductType = "STUDENT_SAVINGS"
)

type Account struct {
	AccountID      string             `json:"account_id"`
	CustomerID     string             `json:"customer_id"`
	AccountNumber  string             `json:"account_number"`
	Balance        float64            `json:"balance"`
	Currency       string             `json:"currency"`
	Status         AccountStatus      `json:"status"`
	ProductType    AccountProductType `json:"product_type"`
	BranchCode     string             `json:"branch_code"`
	PINHash        string             `json:"-"`
	PINAttempts    int                `json:"-"`
	PINLockedUntil *time.Time         `json:"-"`
	PINUpdatedAt   *time.Time         `json:"-"`
	KYCReferenceID *string            `json:"kyc_reference_id,omitempty"`
	CreatedAt      time.Time          `json:"created_at"`
	UpdatedAt      time.Time          `json:"updated_at"`
}
