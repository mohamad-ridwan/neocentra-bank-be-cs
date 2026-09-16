package domain

import "errors"

var (
	ErrDuplicateNIK      = errors.New("NIK sudah terdaftar di sistem")
	ErrDuplicateEmail    = errors.New("Email sudah terdaftar di sistem")
	ErrDuplicatePhone    = errors.New("Nomor telepon sudah terdaftar di sistem")
	ErrInvalidDecryption = errors.New("Gagal mendekripsi payload PII")
	ErrCustomerNotFound  = errors.New("Data nasabah tidak ditemukan")
	ErrCustomerNotActive   = errors.New("Akun nasabah belum aktif. Silakan lakukan verifikasi terlebih dahulu")
	ErrCustomerSuspended   = errors.New("Akun nasabah telah ditangguhkan")
	ErrKeysetNotFound      = errors.New("Keyset KMS tidak ditemukan")
	ErrInvalidCredentials  = errors.New("Kredensial login tidak valid. Periksa kembali identifier dan password Anda")
	ErrPasswordEmpty       = errors.New("Password wajib diisi")
)
