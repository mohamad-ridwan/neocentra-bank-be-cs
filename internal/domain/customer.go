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
	NIK         []byte         `json:"nik"`
	FullName    []byte         `json:"full_name"`
	Email       []byte         `json:"email"`
	PhoneNumber []byte         `json:"phone_number"`
	Address     []byte         `json:"address"`
	Status      CustomerStatus `json:"status"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}
