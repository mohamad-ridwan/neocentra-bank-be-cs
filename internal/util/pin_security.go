package util

import (
	"errors"
	"regexp"
	"time"

	"customer-service/internal/security"
)

var (
	ErrPINInvalidFormat  = errors.New("PIN transaksi harus terdiri dari 6 digit angka numerik")
	ErrPINRepetitive     = errors.New("PIN transaksi tidak boleh menggunakan angka berulang yang sama")
	ErrPINSequential     = errors.New("PIN transaksi tidak boleh menggunakan kombinasi angka berurutan")
	ErrPINLocked         = errors.New("rekening terkunci sementara karena salah memasukkan PIN 3 kali")
	ErrPINMismatch       = errors.New("PIN transaksi yang dimasukkan salah")
	numericRegex         = regexp.MustCompile(`^[0-9]{6}$`)
)

const (
	MaxPINAttempts = 3
	LockoutDuration = 15 * time.Minute
)

// ValidatePINStrength memvalidasi apakah format PIN 6 digit kuat dan tidak mudah ditebak
func ValidatePINStrength(pin string) error {
	if !numericRegex.MatchString(pin) {
		return ErrPINInvalidFormat
	}

	// 1. Cek angka berulang identik (e.g. "111111", "000000")
	allSame := true
	for i := 1; i < len(pin); i++ {
		if pin[i] != pin[0] {
			allSame = false
			break
		}
	}
	if allSame {
		return ErrPINRepetitive
	}

	// 2. Cek sekuensial naik (e.g. "123456", "234567")
	isSeqAsc := true
	for i := 1; i < len(pin); i++ {
		if pin[i] != pin[i-1]+1 {
			isSeqAsc = false
			break
		}
	}
	if isSeqAsc {
		return ErrPINSequential
	}

	// 3. Cek sekuensial turun (e.g. "654321", "543210")
	isSeqDesc := true
	for i := 1; i < len(pin); i++ {
		if pin[i] != pin[i-1]-1 {
			isSeqDesc = false
			break
		}
	}
	if isSeqDesc {
		return ErrPINSequential
	}

	return nil
}

// HashPIN mengenkripsi PIN 6-digit menggunakan Argon2id
func HashPIN(pin string) (string, error) {
	if err := ValidatePINStrength(pin); err != nil {
		return "", err
	}
	return security.HashPassword(pin)
}

// VerifyPIN memverifikasi kecocokan antara input PIN dengan hash Argon2id yang tersimpan
func VerifyPIN(pin, encodedHash string) (bool, error) {
	return security.ComparePasswordAndHash(pin, encodedHash)
}

// IsAccountLocked memeriksa apakah akun sedang dalam periode lockout PIN
func IsAccountLocked(lockedUntil *time.Time) (bool, time.Duration) {
	if lockedUntil == nil {
		return false, 0
	}
	now := time.Now()
	if now.Before(*lockedUntil) {
		return true, lockedUntil.Sub(now)
	}
	return false, 0
}
