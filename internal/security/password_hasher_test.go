package security_test

import (
	"testing"

	"customer-service/internal/security"
)

func TestHashPassword_And_ComparePassword(t *testing.T) {
	password := "SecurePassword123#!"

	encodedHash, err := security.HashPassword(password)
	if err != nil {
		t.Fatalf("unexpected error hashing password: %v", err)
	}

	if encodedHash == "" {
		t.Fatalf("expected non-empty encoded hash")
	}

	// 1. Verifikasi dengan password yang benar
	match, err := security.ComparePasswordAndHash(password, encodedHash)
	if err != nil {
		t.Fatalf("unexpected error comparing password: %v", err)
	}
	if !match {
		t.Errorf("expected password to match encoded hash")
	}

	// 2. Verifikasi dengan password yang salah
	wrongPassword := "WrongPassword123#!"
	matchWrong, err := security.ComparePasswordAndHash(wrongPassword, encodedHash)
	if err != nil {
		t.Fatalf("unexpected error comparing wrong password: %v", err)
	}
	if matchWrong {
		t.Errorf("expected wrong password to NOT match")
	}

	// 3. Verifikasi dengan format hash yang rusak
	_, errInvalid := security.ComparePasswordAndHash(password, "invalid_hash_string")
	if errInvalid == nil {
		t.Errorf("expected error for invalid hash format")
	}
}
