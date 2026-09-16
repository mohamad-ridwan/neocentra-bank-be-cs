package dto

// EncryptedRegisterCustomerRequest menerima payload ciphertext biner (BYTEA) dari frontend/client
type EncryptedRegisterCustomerRequest struct {
	NIK         []byte `json:"nik" validate:"required"`         // Encrypted Binary BYTEA Bytes
	FullName    []byte `json:"full_name" validate:"required"`   // Encrypted Binary BYTEA Bytes
	Email       []byte `json:"email" validate:"required"`       // Encrypted Binary BYTEA Bytes
	PhoneNumber []byte `json:"phone_number" validate:"required"`// Encrypted Binary BYTEA Bytes
	Address     []byte `json:"address" validate:"required"`     // Encrypted Binary BYTEA Bytes
	Password    string `json:"password,omitempty"`
}

// PlaintextRegisterCustomer internal struct setelah didekripsi
type PlaintextRegisterCustomer struct {
	NIK         string `json:"nik" validate:"required,numeric,len=16"`
	FullName    string `json:"full_name" validate:"required,min=3,max=100"`
	Email       string `json:"email" validate:"required,email"`
	PhoneNumber string `json:"phone_number" validate:"required,e164"`
	Address     string `json:"address" validate:"required,min=10"`
	Password    string `json:"password,omitempty"`
}

