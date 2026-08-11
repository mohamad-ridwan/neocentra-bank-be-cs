package dto

// EncryptedRegisterCustomerRequest menerima payload ciphertext biner (BYTEA) dari frontend/client
type EncryptedRegisterCustomerRequest struct {
	NIK         []byte `json:"nik" validate:"required"`         // Encrypted Binary BYTEA Bytes
	FullName    []byte `json:"full_name" validate:"required"`   // Encrypted Binary BYTEA Bytes
	Email       []byte `json:"email" validate:"required"`       // Encrypted Binary BYTEA Bytes
	PhoneNumber []byte `json:"phone_number" validate:"required"`// Encrypted Binary BYTEA Bytes
	Address     []byte `json:"address" validate:"required"`     // Encrypted Binary BYTEA Bytes
}

// PlaintextRegisterCustomer internal struct setelah didekripsi
type PlaintextRegisterCustomer struct {
	NIK         string `validate:"required,numeric,len=16"`
	FullName    string `validate:"required,min=3,max=100"`
	Email       string `validate:"required,email"`
	PhoneNumber string `validate:"required,e164"`
	Address     string `validate:"required,min=10"`
}
