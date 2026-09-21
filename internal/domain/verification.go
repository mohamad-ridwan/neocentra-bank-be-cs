package domain

import (
	"errors"
	"time"
)

var (
	ErrVerificationNotFound = errors.New("kode verifikasi tidak ditemukan atau tidak sesuai")
	ErrVerificationExpired  = errors.New("kode verifikasi telah kadaluwarsa")
	ErrInvalidEmailGoogle   = errors.New("email tidak dapat digunakan karena email tersebut tidak valid")
)

type Verification struct {
	VerificationID   string    `json:"verification_id"`
	CustomerID       string    `json:"customer_id"`
	VerificationType string    `json:"verification_type"`
	Code             int       `json:"code"`
	ExpiresAt        time.Time `json:"expires_at"`
	CreatedAt        time.Time `json:"created_at"`
}
