package domain

import (
	"time"
)

type CustomerStatus string

const (
	StatusPendingVerification CustomerStatus = "PENDING_VERIFICATION"
	StatusActive              CustomerStatus = "ACTIVE"
	StatusRejected            CustomerStatus = "REJECTED"
	StatusSuspended           CustomerStatus = "SUSPENDED"
)

type Customer struct {
	CustomerID  string         `json:"customer_id"`
	NIK         string         `json:"nik"`
	FullName    string         `json:"full_name"`
	Email       string         `json:"email"`
	PhoneNumber string         `json:"phone_number"`
	Address     string         `json:"address"`
	Status      CustomerStatus `json:"status"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}
