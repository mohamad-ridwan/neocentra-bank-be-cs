package util

import (
	"testing"

	"customer-service/internal/domain"
)

func TestCalculateLuhnAndValidate(t *testing.T) {
	tests := []struct {
		name    string
		payload string
	}{
		{"Branch 001 Product 10 Random 847291", "00110847291"},
		{"Branch 001 Product 20 Random 123456", "00120123456"},
		{"Standard payload 7992739871", "7992739871"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkDigit := CalculateLuhn(tt.payload)
			if checkDigit < 0 || checkDigit > 9 {
				t.Fatalf("expected valid check digit (0-9), got %d", checkDigit)
			}

			fullNumber := tt.payload + string(rune('0'+checkDigit))
			if !ValidateLuhn(fullNumber) {
				t.Fatalf("ValidateLuhn failed for %s", fullNumber)
			}
		})
	}
}

func TestGenerateAccountNumber(t *testing.T) {
	accNum, err := GenerateAccountNumber("001", domain.ProductTypeRegularSavings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(accNum) != 12 {
		t.Fatalf("expected 12 digit account number, got %d (%s)", len(accNum), accNum)
	}

	if accNum[:3] != "001" {
		t.Fatalf("expected branch 001, got %s", accNum[:3])
	}

	if accNum[3:5] != "10" {
		t.Fatalf("expected product 10 for regular savings, got %s", accNum[3:5])
	}

	if !ValidateLuhn(accNum) {
		t.Fatalf("generated account number fails Luhn validation: %s", accNum)
	}
}
