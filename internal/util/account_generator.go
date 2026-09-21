package util

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"customer-service/internal/domain"
)

// ProductTypeCode mengonversi AccountProductType ke kode 2-digit standar perbankan
func ProductTypeCode(productType domain.AccountProductType) string {
	switch productType {
	case domain.ProductTypePrioritySavings:
		return "20"
	case domain.ProductTypeStudentSavings:
		return "30"
	case domain.ProductTypeRegularSavings:
		fallthrough
	default:
		return "10"
	}
}

// CalculateLuhn menghitung digit kontrol Luhn (checksum) untuk string numerik
func CalculateLuhn(payload string) int {
	sum := 0
	alternate := true // digit terakhir sebelum check digit dikalikan 2

	for i := len(payload) - 1; i >= 0; i-- {
		digit, err := strconv.Atoi(string(payload[i]))
		if err != nil {
			return -1
		}

		if alternate {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}
		sum += digit
		alternate = !alternate
	}

	checksum := (10 - (sum % 10)) % 10
	return checksum
}

// ValidateLuhn memeriksa apakah nomor rekening (termasuk check digit) valid menurut algoritma Luhn
func ValidateLuhn(number string) bool {
	if len(number) < 2 {
		return false
	}
	payload := number[:len(number)-1]
	expectedCheckDigit, err := strconv.Atoi(string(number[len(number)-1]))
	if err != nil {
		return false
	}

	return CalculateLuhn(payload) == expectedCheckDigit
}

// GenerateAccountNumber menghasilkan nomor rekening 12 digit:
// 3 digit Branch + 2 digit Product + 6 digit Random + 1 digit Luhn Checksum
func GenerateAccountNumber(branchCode string, productType domain.AccountProductType) (string, error) {
	branch := strings.TrimSpace(branchCode)
	if len(branch) != 3 {
		branch = "001"
	}

	prodCode := ProductTypeCode(productType)

	// Generate 6 digit angka acak (000000 - 999999) menggunakan crypto/rand
	nBig, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", fmt.Errorf("gagal menghasilkan nomor acak: %w", err)
	}
	randomPart := fmt.Sprintf("%06d", nBig.Int64())

	prefix11 := fmt.Sprintf("%s%s%s", branch, prodCode, randomPart)
	checkDigit := CalculateLuhn(prefix11)
	if checkDigit < 0 {
		return "", fmt.Errorf("gagal menghitung Luhn check digit")
	}

	accountNumber := fmt.Sprintf("%s%d", prefix11, checkDigit)
	return accountNumber, nil
}
