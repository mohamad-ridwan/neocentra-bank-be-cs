package usecase_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"customer-service/internal/usecase"
)

type MockKMSRepository struct {
	keysets map[string][]byte
	version map[string]int
}

func (m *MockKMSRepository) GetKeysetByName(ctx context.Context, keyName string) ([]byte, int, error) {
	if data, ok := m.keysets[keyName]; ok {
		return data, m.version[keyName], nil
	}
	return nil, 0, errors.New("not found")
}

func (m *MockKMSRepository) SaveKeyset(ctx context.Context, keyName string, encryptedKeyset []byte, primaryKeyID uint32, version int) error {
	m.keysets[keyName] = encryptedKeyset
	m.version[keyName] = version
	return nil
}

func (m *MockKMSRepository) UpdateKeyset(ctx context.Context, keyName string, encryptedKeyset []byte, primaryKeyID uint32, version int) error {
	m.keysets[keyName] = encryptedKeyset
	m.version[keyName] = version
	return nil
}

func mockRepo() *MockKMSRepository {
	return &MockKMSRepository{
		keysets: make(map[string][]byte),
		version: make(map[string]int),
	}
}

func TestKMSEncryptorAndRotation(t *testing.T) {
	repo := mockRepo()
	masterKey := "super-secret-master-key-32bytes!"

	service, err := usecase.NewLocalKMSService(masterKey, repo)
	if err != nil {
		t.Fatalf("failed to create kms service: %v", err)
	}

	plaintext := "3271012345670001"
	aad := "customer_nik_aad"

	// 1. Test Encrypt & Decrypt
	ciphertext, err := service.EncryptPII(plaintext, aad)
	if err != nil {
		t.Fatalf("failed to encrypt PII: %v", err)
	}

	decrypted, err := service.DecryptPII(ciphertext, aad)
	if err != nil {
		t.Fatalf("failed to decrypt PII: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("expected %s, got %s", plaintext, decrypted)
	}

	// 2. Test Manual Rotation
	ctx := context.Background()
	if err := service.RotateKey(ctx, "customer_pii_keyset"); err != nil {
		t.Fatalf("failed to rotate key: %v", err)
	}

	// Old ciphertext should still decrypt cleanly (zero-downtime key rotation)
	decryptedAfterRotation, err := service.DecryptPII(ciphertext, aad)
	if err != nil {
		t.Fatalf("failed to decrypt legacy ciphertext after rotation: %v", err)
	}
	if decryptedAfterRotation != plaintext {
		t.Errorf("expected %s after rotation, got %s", plaintext, decryptedAfterRotation)
	}

	// 3. Test Background Worker Ticker
	workerCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	service.StartRotationWorker(workerCtx, "customer_pii_keyset", 50*time.Millisecond)

	time.Sleep(120 * time.Millisecond)
	cancel()
}
