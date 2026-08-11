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
		Port:              os.Getenv("PORT"),
		JWTSecret:         os.Getenv("JWT_SECRET"),
		LocalKMSMasterKey: os.Getenv("LOCAL_KMS_MASTER_KEY"),
		DatabaseURL:       os.Getenv("DATABASE_URL"),
		RedisURL:          os.Getenv("REDIS_URL"),
	}
}

// func getEnv(key, fallback string) string {
// 	if val := os.Getenv(key); val != "" {
// 		return val
// 	}
// 	return fallback
// }

func loadDotEnv(filepath string) {
	paths := []string{filepath, "../.env", "../../.env"}
	var file *os.File
	var err error
	for _, p := range paths {
		file, err = os.Open(p)
		if err == nil {
			break
		}
	}
	if err != nil || file == nil {
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
