package main

import (
	"context"
	"log"
	"os"
	"time"

	"customer-service/internal/config"
	"customer-service/pkg/database"
)

func main() {
	cfg := config.LoadConfig()

	dbURL := cfg.DatabaseURL
	if dbURL == "" {
		dbURL = os.Getenv("DATABASE_URL")
	}
	if dbURL == "" {
		dbURL = "postgres://postgres:postgres@localhost:5432/ems?sslmode=disable"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := database.NewPostgresPool(ctx, dbURL)
	if err != nil {
		log.Fatalf("[FATAL] Failed to connect to database: %v", err)
	}
	defer pool.Close()

	log.Println("[INFO] Connected to PostgreSQL. Running AutoMigrate...")
	if err := database.AutoMigrate(ctx, pool); err != nil {
		log.Fatalf("[FATAL] AutoMigrate failed: %v", err)
	}

	// Verify column exists
	var colName string
	err = pool.QueryRow(ctx, `
		SELECT column_name 
		FROM information_schema.columns 
		WHERE table_name = 'customers' AND column_name = 'password_hash'
	`).Scan(&colName)
	if err != nil {
		log.Fatalf("[FATAL] Column password_hash verification failed: %v", err)
	}

	log.Printf("[SUCCESS] Migration complete! Verified column '%s' exists on table 'customers'.", colName)
}
