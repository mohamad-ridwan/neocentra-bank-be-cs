package security_test

import (
	"bytes"
	"os"
	"testing"

	"customer-service/internal/security"
)

func TestTransitDecryptor_Success(t *testing.T) {
	privKey, pubKey, err := security.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key pair: %v", err)
	}

	decryptor := security.NewTransitDecryptor(privKey)

	originalData := []byte(`{"nik":"3271012345670001","full_name":"Budi Santoso","email":"budi@example.com","phone_number":"+6281234567890","address":"Jl. Sudirman No. 10"}`)

	// Encrypt using helper
	encryptedPayload, err := security.EncryptRawTransitPayload(pubKey, originalData)
	if err != nil {
		t.Fatalf("failed to encrypt transit payload: %v", err)
	}

	if len(encryptedPayload) < security.MinTransitPayloadSize {
		t.Fatalf("expected payload length >= %d, got %d", security.MinTransitPayloadSize, len(encryptedPayload))
	}

	// Decrypt
	decryptedData, sessionKey, err := decryptor.DecryptRawTransitPayloadWithKey(encryptedPayload)
	if err != nil {
		t.Fatalf("failed to decrypt transit payload: %v", err)
	}

	if !bytes.Equal(originalData, decryptedData) {
		t.Fatalf("decrypted data mismatch: expected %s, got %s", string(originalData), string(decryptedData))
	}

	if len(sessionKey) != 32 {
		t.Fatalf("expected sessionKey 32 bytes, got %d", len(sessionKey))
	}

	// Test EncryptTransitResponse
	responsePlaintext := []byte("budi@example.com")
	encResponse, err := security.EncryptTransitResponse(sessionKey, responsePlaintext)
	if err != nil {
		t.Fatalf("failed to encrypt transit response: %v", err)
	}

	if len(encResponse) < 12+16 {
		t.Fatalf("response too short, expected >= 28 bytes, got %d", len(encResponse))
	}
}

func TestTransitDecryptor_PayloadTooShort(t *testing.T) {
	privKey, _, _ := security.GenerateRSAKeyPair(2048)
	decryptor := security.NewTransitDecryptor(privKey)

	shortPayload := make([]byte, 200)
	_, err := decryptor.DecryptRawTransitPayload(shortPayload)
	if err == nil {
		t.Fatal("expected error for payload too short, got nil")
	}
}

func TestTransitDecryptor_CorruptedCiphertext(t *testing.T) {
	privKey, pubKey, _ := security.GenerateRSAKeyPair(2048)
	decryptor := security.NewTransitDecryptor(privKey)

	payload, err := security.EncryptRawTransitPayload(pubKey, []byte("sensitive info"))
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	// Corrupt the tag / ciphertext
	payload[len(payload)-1] ^= 0xFF

	_, err = decryptor.DecryptRawTransitPayload(payload)
	if err == nil {
		t.Fatal("expected decryption error on corrupted ciphertext, got nil")
	}
}

func TestPEMExportAndParse(t *testing.T) {
	privKey, _, err := security.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	pemBytes := security.ExportPrivateKeyToPEM(privKey)
	parsedPriv, err := security.ParsePrivateKeyFromPEM(pemBytes)
	if err != nil {
		t.Fatalf("failed to parse PEM: %v", err)
	}

	if privKey.N.Cmp(parsedPriv.N) != 0 {
		t.Fatal("parsed private key modulus does not match original")
	}
}

func TestInteroperabilityWithNodeJS(t *testing.T) {
	privKeyPEM := []byte(`-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDWew1gaUeOzOPS
Uybd3pdHwDZYE9YmIA3zB4HhPDtGmjOjvi8DrXIsB5Ziv4ntLfRHBvnGNuE8LHUW
9h6j+YkXZYzV6NIh8D69t1xoi6nGWx9iT0o43hHqTHvrjH7gct5XbGBm7SIKeggO
f0S+a++1EcxJtbmkYJrMXIlpgnA7A7/YrzbGGCigXhWqSUo7DdieQoSa7fsNRn4H
mmCCyshczEiizPUqnzAJ6dfqQfMxijvBdqkdHcsdYg6F5p0SnugT9gED7Nu47Die
bEb/AN+fAG02Qnbfm9R+lqfQ1Ujv6i9RlR22NLELO5wB9Hd5yP472Pq/s80nc2u5
WAcdW3T1AgMBAAECggEAZIIqrRT49xbV5jCYRJ20Z+fPr6uwDZK05sAMYbffkUDe
1SthDcigebiehSz8Hh0MXaKLtxLtrsyonDd++VmNIF0yx+VAX64dQLtl/wn/59e4
19GPVyHd5F2uLp5asKSzw+UiMemLK7yu/NgwJ0oefUxXXu1djwXEVONCc6KwJD7M
QYsY53M1gMQRyzcCcGktbHVtdxMOS0lOBurKeND/AJutqUL7f78TnmZIOhxDKQTa
q+ABpLMtPYUeO6BZ8gvBDh0pI1LgF1bMmfuOvgLJ1LAfOAaafaEBO8frPDubyrD7
8uJehghuUqGLXa97lMP0/DofmI0/7Xzn6hG7zbJDewKBgQD0J+UwdJNNP069+hc/
YBLfs7MJt5sQbk0t/PaU2ihOvJ3+R1J4JfD1uU/SH9i2lO7aVPwvukqe8eB6EvHV
/YdQCsMmWP4mjhFA7gL1UyXA0Fuqs0nlObklkM8Q3gDnbq9u1BYsVwd9NGExbDjM
FLTnkZRKBz5CbMcsx8XltVit5wKBgQDg4qERZWcXPNH0R3sLbmQZP8Kh365Y2C9J
mKSkfRkPNkmapqCSXBqort7HMN9zV1mk5QkIxzVVYkXC31Ksg23qvCNV1MGkSkTk
pv62cLbdpL6xWOgaC9nqVaUFiDSgzZtOf01TYyDHiKY6GDU7+GPGcP5EpLJWi82M
LX6Xwq1SwwKBgBF1INAcJcQqOKkgzrS7W94e7ThOponAOUiGg+MUzjkDB5D87Iqm
u9n2DB0MJeS4NXPrC7Ul7tv6k4BnBl+0pw40FswRJOsA0X8BBbkg3twwib1k4G3B
eNmUxxl/pjTmFyknhQZamrB7JE/yWwVMnbrJD/9TEUKSoJM1HZNVKigVAoGBANGT
4y9nJRAO6kuRYiZhFoBBX42j+8NolYks7CMvQm9e1HF/4B0GIQIbFhrkfRnsyepW
WHkJzbZpA0J9BXsocQNVmkifImeNn27IApDbslAU/HIivQupB8jPUB87tHA3rQkW
smWH+EB8JQ33CYV+Et4Y553pLxpg54o/y756+zQpAoGBALlWzHe7ekZYRoi1I9LB
5KSGV7uVz8ci6xGZN5NrVhAMkz0jvMX3HFSz1wxeSpL0+ccvv8oMiSsxautfVQOT
0MKpOL1ZHEGBwtmzf7u6eF4OectntYsbIB/ljZW6IwKL3iO1pmPFe+7NaCErb1/F
I8Ezn3xLWBmpnUfxCEhzfU+c
-----END PRIVATE KEY-----`)

	privKey, err := security.ParsePrivateKeyFromPEM(privKeyPEM)
	if err != nil {
		t.Fatalf("failed to parse private key: %v", err)
	}

	wireBytes, err := os.ReadFile("/tmp/test_hybrid_wire.bin")
	if err != nil {
		t.Skip("skipping interop test: /tmp/test_hybrid_wire.bin not present")
	}

	decryptor := security.NewTransitDecryptor(privKey)
	decrypted, err := decryptor.DecryptRawTransitPayload(wireBytes)
	if err != nil {
		t.Fatalf("failed to decrypt wire binary from Node.js: %v", err)
	}

	t.Logf("Successfully decrypted payload from Node.js: %s", string(decrypted))
}

