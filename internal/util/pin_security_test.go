package util

import (
	"testing"
	"time"
)

func TestValidatePINStrength(t *testing.T) {
	tests := []struct {
		pin     string
		wantErr error
	}{
		{"12345", ErrPINInvalidFormat},
		{"1234567", ErrPINInvalidFormat},
		{"12a456", ErrPINInvalidFormat},
		{"111111", ErrPINRepetitive},
		{"999999", ErrPINRepetitive},
		{"123456", ErrPINSequential},
		{"234567", ErrPINSequential},
		{"654321", ErrPINSequential},
		{"543210", ErrPINSequential},
		{"194827", nil},
		{"837492", nil},
		{"501938", nil},
	}

	for _, tt := range tests {
		t.Run(tt.pin, func(t *testing.T) {
			err := ValidatePINStrength(tt.pin)
			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Fatalf("expected error %v, got %v", tt.wantErr, err)
				}
			} else {
				if err != nil {
					t.Fatalf("expected valid PIN, got error: %v", err)
				}
			}
		})
	}
}

func TestHashAndVerifyPIN(t *testing.T) {
	pin := "839201"
	hash, err := HashPIN(pin)
	if err != nil {
		t.Fatalf("HashPIN error: %v", err)
	}

	valid, err := VerifyPIN(pin, hash)
	if err != nil || !valid {
		t.Fatalf("VerifyPIN expected valid, got valid=%v, err=%v", valid, err)
	}

	wrongPIN := "839202"
	validWrong, err := VerifyPIN(wrongPIN, hash)
	if err != nil {
		t.Fatalf("VerifyPIN error on wrong PIN: %v", err)
	}
	if validWrong {
		t.Fatalf("VerifyPIN expected false for wrong PIN, got true")
	}
}

func TestIsAccountLocked(t *testing.T) {
	future := time.Now().Add(10 * time.Minute)
	locked, dur := IsAccountLocked(&future)
	if !locked || dur <= 0 {
		t.Fatalf("expected locked with positive duration, got locked=%v, dur=%v", locked, dur)
	}

	past := time.Now().Add(-5 * time.Minute)
	lockedPast, _ := IsAccountLocked(&past)
	if lockedPast {
		t.Fatalf("expected not locked for past time, got locked=%v", lockedPast)
	}

	lockedNil, _ := IsAccountLocked(nil)
	if lockedNil {
		t.Fatalf("expected not locked for nil, got locked=%v", lockedNil)
	}
}
