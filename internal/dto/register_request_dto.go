package dto

// EncryptedRegisterCustomerRequest menerima payload ciphertext dari frontend
type EncryptedRegisterCustomerRequest struct {
	NIK         string `json:"nik" validate:"required"`         // Encrypted Base64 Tink String
	FullName    string `json:"full_name" validate:"required"`   // Encrypted Base64 Tink String
	Email       string `json:"email" validate:"required"`       // Encrypted Base64 Tink String
	PhoneNumber string `json:"phone_number" validate:"required"`// Encrypted Base64 Tink String
	Address     string `json:"address" validate:"required"`     // Encrypted Base64 Tink String
}

// PlaintextRegisterCustomer internal struct setelah didekripsi
type PlaintextRegisterCustomer struct {
	NIK         string `validate:"required,numeric,len=16"`
	FullName    string `validate:"required,min=3,max=100"`
	Email       string `validate:"required,email"`
	PhoneNumber string `validate:"required,e164"`
	Address     string `validate:"required,min=10"`
}
