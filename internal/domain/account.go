package domain

import "time"

type AccountStatus string

const (
	AccountStatusPendingKYC AccountStatus = "PENDING_KYC"
	AccountStatusActive     AccountStatus = "ACTIVE"
	AccountStatusSuspended  AccountStatus = "SUSPENDED"
	AccountStatusClosed     AccountStatus = "CLOSED"
)

type Account struct {
	AccountID     string        `json:"account_id"`
	CustomerID    string        `json:"customer_id"`
	AccountNumber string        `json:"account_number"`
	Balance       float64       `json:"balance"`
	Currency      string        `json:"currency"`
	Status        AccountStatus `json:"status"`
	CreatedAt     time.Time     `json:"created_at"`
	UpdatedAt     time.Time     `json:"updated_at"`
}
