package config

import (
	"bufio"
	"os"
	"strings"
)

type Config struct {
	Port              string
	JWTSecret         string
	LocalKMSMasterKey string
	DatabaseURL       string
	RedisURL          string
}

func LoadConfig() *Config {
	// Read .env if present
	loadDotEnv(".env")

	return &Config{
		Port:              getEnv("PORT", "8085"),
		JWTSecret:         getEnv("JWT_SECRET", "neocentra_jwt_secret_2026"),
		LocalKMSMasterKey: getEnv("LOCAL_KMS_MASTER_KEY", "neocentra_master_kek_secret_key_32b!"),
		DatabaseURL:       getEnv("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/neocentra_cs?sslmode=disable"),
		RedisURL:          getEnv("REDIS_URL", "redis://localhost:6379/0"),
	}
}

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

func loadDotEnv(filepath string) {
	file, err := os.Open(filepath)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			// remove quotes if present
			val = strings.Trim(val, `"'`)
			if os.Getenv(key) == "" {
				os.Setenv(key, val)
			}
		}
	}
}
