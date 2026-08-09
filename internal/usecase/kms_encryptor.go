package usecase

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/tink-crypto/tink-go/v2/aead"
	subtle "github.com/tink-crypto/tink-go/v2/aead/subtle"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/tink"
)

// KMSRepository interface untuk menyimpan & memuat keyset dari database (tabel kms_keysets)
type KMSRepository interface {
	GetKeysetByName(ctx context.Context, keyName string) ([]byte, int, error)
	SaveKeyset(ctx context.Context, keyName string, encryptedKeyset []byte, primaryKeyID uint32, version int) error
	UpdateKeyset(ctx context.Context, keyName string, encryptedKeyset []byte, primaryKeyID uint32, version int) error
}

type LocalKMSService struct {
	masterKEK []byte         // 32-byte key dari ENV (LOCAL_KMS_MASTER_KEY)
	handle    *keyset.Handle // Current Tink Keyset Handle
	aead      tink.AEAD      // AEAD Primitive untuk Encrypt/Decrypt
	repo      KMSRepository
	version   int
}

// NewLocalKMSService menginisialisasi KMS dan memuat Keyset dari PostgreSQL
func NewLocalKMSService(masterKeyHex string, repo KMSRepository) (*LocalKMSService, error) {
	// Decode Master Key (KEK) dari String (SHA-256 hash untuk memastikan 32-byte AES-256)
	masterKEK := sha256.Sum256([]byte(masterKeyHex))

	service := &LocalKMSService{
		masterKEK: masterKEK[:],
		repo:      repo,
	}

	// Load atau Inisialisasi Keyset dari DB
	if err := service.loadOrCreateKeyset(context.Background(), "customer_pii_keyset"); err != nil {
		return nil, fmt.Errorf("failed to init kms keyset: %w", err)
	}

	return service, nil
}

func (s *LocalKMSService) loadOrCreateKeyset(ctx context.Context, keyName string) error {
	masterAEAD, err := subtle.NewAESGCM(s.masterKEK)
	if err != nil {
		return fmt.Errorf("failed to create master AEAD primitive: %w", err)
	}

	encryptedKeyset, version, err := s.repo.GetKeysetByName(ctx, keyName)
	if err != nil || len(encryptedKeyset) == 0 {
		// Keyset belum ada, buat keyset baru
		kh, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
		if err != nil {
			return fmt.Errorf("failed to create new keyset handle: %w", err)
		}

		var buf bytes.Buffer
		writer := keyset.NewBinaryWriter(&buf)
		if err := kh.Write(writer, masterAEAD); err != nil {
			return fmt.Errorf("failed to encrypt and write keyset: %w", err)
		}

		primaryKeyID := kh.KeysetInfo().GetPrimaryKeyId()
		if err := s.repo.SaveKeyset(ctx, keyName, buf.Bytes(), primaryKeyID, 1); err != nil {
			return fmt.Errorf("failed to save keyset to repository: %w", err)
		}

		primitive, err := aead.New(kh)
		if err != nil {
			return fmt.Errorf("failed to create AEAD primitive from keyset handle: %w", err)
		}

		s.handle = kh
		s.aead = primitive
		s.version = 1
		return nil
	}

	// Keyset sudah ada di DB, dekripsi dengan Master KEK
	reader := keyset.NewBinaryReader(bytes.NewReader(encryptedKeyset))
	kh, err := keyset.Read(reader, masterAEAD)
	if err != nil {
		return fmt.Errorf("failed to decrypt and read keyset from DB: %w", err)
	}

	primitive, err := aead.New(kh)
	if err != nil {
		return fmt.Errorf("failed to create AEAD primitive: %w", err)
	}

	s.handle = kh
	s.aead = primitive
	s.version = version
	return nil
}

// EncryptPII mengenkripsi plaintext (misal NIK) dengan AAD (Associated Authenticated Data)
func (s *LocalKMSService) EncryptPII(plaintext string, aad string) (string, error) {
	ciphertext, err := s.aead.Encrypt([]byte(plaintext), []byte(aad))
	if err != nil {
		return "", fmt.Errorf("failed to encrypt PII: %w", err)
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptPII mendekripsi ciphertext PII (Tink otomatis mendeteksi Key ID mana yang dipakai)
func (s *LocalKMSService) DecryptPII(ciphertextBase64 string, aad string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		return "", fmt.Errorf("invalid base64 ciphertext: %w", err)
	}

	plaintext, err := s.aead.Decrypt(ciphertext, []byte(aad))
	if err != nil {
		return "", fmt.Errorf("failed to decrypt PII: %w", err)
	}
	return string(plaintext), nil
}

// RotateKey melakukan rotasi kunci (Zero-Downtime Key Rotation)
func (s *LocalKMSService) RotateKey(ctx context.Context, keyName string) error {
	masterAEAD, err := subtle.NewAESGCM(s.masterKEK)
	if err != nil {
		return fmt.Errorf("failed to create master AEAD primitive: %w", err)
	}

	mgr := keyset.NewManagerFromHandle(s.handle)
	newKeyID, err := mgr.Add(aead.AES256GCMKeyTemplate())
	if err != nil {
		return fmt.Errorf("failed to add new key for rotation: %w", err)
	}

	if err := mgr.SetPrimary(newKeyID); err != nil {
		return fmt.Errorf("failed to set new primary key: %w", err)
	}

	kh, err := mgr.Handle()
	if err != nil {
		return fmt.Errorf("failed to get handle after rotation: %w", err)
	}

	var buf bytes.Buffer
	writer := keyset.NewBinaryWriter(&buf)
	if err := kh.Write(writer, masterAEAD); err != nil {
		return fmt.Errorf("failed to encrypt rotated keyset: %w", err)
	}

	primaryKeyID := kh.KeysetInfo().GetPrimaryKeyId()
	newVersion := s.version + 1
	if err := s.repo.UpdateKeyset(ctx, keyName, buf.Bytes(), primaryKeyID, newVersion); err != nil {
		return fmt.Errorf("failed to update rotated keyset in repository: %w", err)
	}

	primitive, err := aead.New(kh)
	if err != nil {
		return fmt.Errorf("failed to create AEAD primitive after rotation: %w", err)
	}

	s.handle = kh
	s.aead = primitive
	s.version = newVersion
	return nil
}
