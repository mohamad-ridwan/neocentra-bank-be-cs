package security

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidVerificationToken = errors.New("token verifikasi tidak valid")
	ErrExpiredVerificationToken = errors.New("token verifikasi telah kadaluwarsa")
)

type VerificationClaims struct {
	CustomerID     string `json:"customer_id"`
	VerificationID string `json:"verification_id"`
	jwt.RegisteredClaims
}

// GenerateVerificationToken creates a 1-minute JWT containing customer_id and verification_id
func GenerateVerificationToken(customerID, verificationID, secretKey string, duration time.Duration) (string, error) {
	if duration <= 0 {
		duration = 1 * time.Minute
	}
	if secretKey == "" {
		secretKey = "neocentra_default_verification_jwt_secret_key"
	}

	claims := VerificationClaims{
		CustomerID:     customerID,
		VerificationID: verificationID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "neocentra-bank",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return "", fmt.Errorf("gagal menandatangani verification token: %w", err)
	}

	return tokenString, nil
}

// ParseVerificationToken validates and extracts claims from a verification JWT
func ParseVerificationToken(tokenString, secretKey string) (*VerificationClaims, error) {
	if secretKey == "" {
		secretKey = "neocentra_default_verification_jwt_secret_key"
	}

	token, err := jwt.ParseWithClaims(tokenString, &VerificationClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secretKey), nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredVerificationToken
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidVerificationToken, err)
	}

	if claims, ok := token.Claims.(*VerificationClaims); ok && token.Valid {
		if claims.CustomerID == "" || claims.VerificationID == "" {
			return nil, ErrInvalidVerificationToken
		}
		return claims, nil
	}

	return nil, ErrInvalidVerificationToken
}
