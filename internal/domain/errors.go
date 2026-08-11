package domain

import "errors"

var (
	ErrDuplicateNIK      = errors.New("NIK sudah terdaftar di sistem")
	ErrDuplicateEmail    = errors.New("Email sudah terdaftar di sistem")
	ErrDuplicatePhone    = errors.New("Nomor telepon sudah terdaftar di sistem")
	ErrInvalidDecryption = errors.New("Gagal mendekripsi payload PII")
	ErrCustomerNotFound  = errors.New("Data nasabah tidak ditemukan")
	ErrKeysetNotFound    = errors.New("Keyset KMS tidak ditemukan")
)
