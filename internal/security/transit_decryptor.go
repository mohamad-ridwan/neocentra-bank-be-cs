package security

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
)

const (
	RSAEncryptedKeyLength = 256 // RSA-2048 produces 256 bytes ciphertext
	GCMNonceLength        = 12  // 12-byte standard GCM IV/Nonce
	GCMTagLength          = 16  // 16-byte standard GCM Auth Tag
	MinTransitPayloadSize = RSAEncryptedKeyLength + GCMNonceLength + GCMTagLength // 284 bytes
)

type TransitDecryptor struct {
	privKey *rsa.PrivateKey
}

func NewTransitDecryptor(privKey *rsa.PrivateKey) *TransitDecryptor {
	return &TransitDecryptor{privKey: privKey}
}

// DecryptRawTransitPayload mendekripsi payload biner Pola 1:
// [ 256-Byte RSA Encrypted Key ] + [ 12-Byte IV ] + [ Ciphertext + 16-Byte Tag ]
func (d *TransitDecryptor) DecryptRawTransitPayload(body []byte) ([]byte, error) {
	if len(body) < MinTransitPayloadSize {
		return nil, fmt.Errorf("transit payload too short: got %d bytes, minimum required %d bytes", len(body), MinTransitPayloadSize)
	}

	if d.privKey == nil {
		return nil, errors.New("transit decryptor private key is not configured")
	}

	// 1. Slicing wire format
	encKey := body[:RSAEncryptedKeyLength]
	iv := body[RSAEncryptedKeyLength : RSAEncryptedKeyLength+GCMNonceLength]
	ciphertextWithTag := body[RSAEncryptedKeyLength+GCMNonceLength:]

	// 2. Dekripsi Ephemeral Session Key via RSA-OAEP SHA-256
	sessionKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, d.privKey, encKey, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt session key via RSA-OAEP: %w", err)
	}

	if len(sessionKey) != 32 {
		return nil, fmt.Errorf("invalid session key length: expected 32 bytes for AES-256, got %d", len(sessionKey))
	}

	// 3. Dekripsi Ciphertext via AES-256-GCM
	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM block: %w", err)
	}

	plaintext, err := gcm.Open(nil, iv, ciphertextWithTag, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt AES-GCM ciphertext: %w", err)
	}

	return plaintext, nil
}

// EncryptRawTransitPayload mengenkripsi plaintext biner menggunakan skema Hybrid RSA-OAEP + AES-256-GCM (Pola 1)
func EncryptRawTransitPayload(pubKey *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	if pubKey == nil {
		return nil, errors.New("public key cannot be nil")
	}

	// 1. Generate 32-byte ephemeral AES-256 session key
	sessionKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, sessionKey); err != nil {
		return nil, fmt.Errorf("failed to generate random session key: %w", err)
	}

	// 2. Enkripsi session key dengan RSA-OAEP SHA-256 (256 bytes)
	encKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, sessionKey, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt session key with RSA-OAEP: %w", err)
	}

	// 3. Generate 12-byte IV untuk AES-GCM
	iv := make([]byte, GCMNonceLength)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	// 4. Enkripsi plaintext dengan AES-256-GCM (hasilnya: ciphertext + 16-byte tag)
	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM block: %w", err)
	}

	ciphertextWithTag := gcm.Seal(nil, iv, plaintext, nil)

	// 5. Gabungkan menjadi full raw binary: [256B EncKey] + [12B IV] + [Ciphertext + Tag]
	payload := make([]byte, 0, len(encKey)+len(iv)+len(ciphertextWithTag))
	payload = append(payload, encKey...)
	payload = append(payload, iv...)
	payload = append(payload, ciphertextWithTag...)

	return payload, nil
}

// GenerateRSAKeyPair menghasilkan pasangan kunci RSA-2048 baru
func GenerateRSAKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return privKey, &privKey.PublicKey, nil
}

// ParsePrivateKeyFromPEM mem-parse RSA Private Key dari format PEM (PKCS#1 atau PKCS#8)
func ParsePrivateKeyFromPEM(pemData []byte) (*rsa.PrivateKey, error) {
	if bytes.Contains(pemData, []byte(`\n`)) {
		pemData = bytes.ReplaceAll(pemData, []byte(`\n`), []byte("\n"))
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	// Coba parse PKCS#1 terlebih dahulu
	if priv, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return priv, nil
	}

	// Coba parse PKCS#8
	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key as PKCS1 or PKCS8: %w", err)
	}

	privKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("PEM block does not contain an RSA private key")
	}

	return privKey, nil
}

// ExportPrivateKeyToPEM mengekspor RSA Private Key ke format PEM (PKCS#1)
func ExportPrivateKeyToPEM(privKey *rsa.PrivateKey) []byte {
	bytes := x509.MarshalPKCS1PrivateKey(privKey)
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: bytes,
	})
}

// ExportPublicKeyToPEM mengekspor RSA Public Key ke format PEM (PKIX)
func ExportPublicKeyToPEM(pubKey *rsa.PublicKey) ([]byte, error) {
	bytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: bytes,
	}), nil
}
