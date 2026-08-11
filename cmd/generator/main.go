package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"customer-service/internal/config"
	"customer-service/internal/dto"
	"customer-service/internal/repository/postgres"
	"customer-service/internal/usecase"
	"customer-service/pkg/database"

	"github.com/golang-jwt/jwt/v5"
)

func main() {
	cfg := config.LoadConfig()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. Hubungkan ke PostgreSQL agar menggunakan Keyset yang SAMA dengan API Server
	dbPool, err := database.NewPostgresPool(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to connect DB in generator: %v", err)
	}
	defer dbPool.Close()

	kmsRepo := postgres.NewKMSRepository(dbPool)

	// 2. Inisialisasi KMS dengan kmsRepo (Membaca customer_pii_keyset dari DB)
	kmsService, err := usecase.NewLocalKMSService(cfg.LocalKMSMasterKey, kmsRepo)
	if err != nil {
		log.Fatalf("Failed to init KMS service: %v", err)
	}

	// Generate Valid JWT Token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": "usr-c1234567-89ab-cdef-0123-456789abcdef",
		"role":    "CUSTOMER",
		"exp":     time.Now().Add(24 * time.Hour).Unix(),
	})
	tokenString, _ := token.SignedString([]byte(cfg.JWTSecret))

	// Data Plaintext
	nikPlain := "3271012345670001"
	fullNamePlain := "Budi Santoso"
	emailPlain := "budi.santoso@example.com"
	phonePlain := "+6281234567890"
	addressPlain := "Jl. Jendral Sudirman No. 10, Jakarta Selatan"

	// Enkripsi tiap field
	nikEnc, _ := kmsService.EncryptPII(nikPlain, usecase.AAD_NIK)
	fullNameEnc, _ := kmsService.EncryptPII(fullNamePlain, usecase.AAD_FULL_NAME)
	emailEnc, _ := kmsService.EncryptPII(emailPlain, usecase.AAD_EMAIL)
	phoneEnc, _ := kmsService.EncryptPII(phonePlain, usecase.AAD_PHONE)
	addressEnc, _ := kmsService.EncryptPII(addressPlain, usecase.AAD_ADDRESS)

	reqPayload := dto.EncryptedRegisterCustomerRequest{
		NIK:         nikEnc,
		FullName:    fullNameEnc,
		Email:       emailEnc,
		PhoneNumber: phoneEnc,
		Address:     addressEnc,
	}

	jsonBytes, _ := json.MarshalIndent(reqPayload, "", "  ")

	fmt.Println("==========================================================================")
	fmt.Println(" 1. HEADER POSTMAN: Authorization")
	fmt.Println("==========================================================================")
	fmt.Printf("Bearer %s\n\n", tokenString)
	fmt.Println("==========================================================================")
	fmt.Println(" 2. BODY POSTMAN (raw -> JSON)")
	fmt.Println("==========================================================================")
	fmt.Println(string(jsonBytes))
	fmt.Println("==========================================================================")
}
