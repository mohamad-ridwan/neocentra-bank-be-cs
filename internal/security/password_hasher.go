package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

var (
	ErrInvalidHashFormat = errors.New("format hash password tidak valid")
	ErrIncompatibleHash  = errors.New("versi atau tipe algoritma hash tidak kompatibel")
)

// Argon2idParams mendefinisikan parameter kriptografi Argon2id sesuai rekomendasi OWASP
type Argon2idParams struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// DefaultArgon2idParams mengonfigurasi parameter OWASP yang seimbang antara keamanan tinggi dan efisiensi server
var DefaultArgon2idParams = &Argon2idParams{
	Memory:      64 * 1024, // 64 MB
	Iterations:  1,         // 1 iterasi (efisien dengan 64MB)
	Parallelism: 2,         // 2 threads
	SaltLength:  16,        // 16 bytes random salt
	KeyLength:   32,        // 32 bytes derived key
}

// HashPassword mengenkripsi plaintext password menggunakan Argon2id dan mengembalikan PHC string
// Format: $argon2id$v=19$m=65536,t=1,p=2$<base64_salt>$<base64_hash>
func HashPassword(password string) (string, error) {
	params := DefaultArgon2idParams
	salt := make([]byte, params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("gagal menghasilkan salt acak: %w", err)
	}

	hash := argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Parallelism, params.KeyLength)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, params.Memory, params.Iterations, params.Parallelism, b64Salt, b64Hash)

	return encoded, nil
}

// ComparePasswordAndHash memverifikasi kecocokan antara plaintext password dan PHC encoded hash
func ComparePasswordAndHash(password, encodedHash string) (bool, error) {
	parts := strings.Split(encodedHash, "$")
	// Expected parts: ["", "argon2id", "v=19", "m=65536,t=1,p=2", "<salt>", "<hash>"]
	if len(parts) != 6 {
		return false, ErrInvalidHashFormat
	}

	if parts[1] != "argon2id" {
		return false, ErrIncompatibleHash
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, ErrIncompatibleHash
	}

	params := &Argon2idParams{}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &params.Memory, &params.Iterations, &params.Parallelism); err != nil {
		return false, ErrInvalidHashFormat
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("gagal decode salt base64: %w", err)
	}

	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("gagal decode hash base64: %w", err)
	}

	params.KeyLength = uint32(len(expectedHash))

	calculatedHash := argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Parallelism, params.KeyLength)

	// Constant time comparison untuk mencegah timing attack
	if subtle.ConstantTimeCompare(calculatedHash, expectedHash) == 1 {
		return true, nil
	}

	return false, nil
}
