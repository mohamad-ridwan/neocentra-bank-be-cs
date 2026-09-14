package dto

type RegisterCustomerResponseData struct {
	Email []byte `json:"email"` // Ciphertext biner (BYTEA) terenkripsi KMS
}

type RegisterCustomerAPIResponse struct {
	Success bool                         `json:"success"`
	Code    int                          `json:"code"`
	Message string                       `json:"message"`
	Data    RegisterCustomerResponseData `json:"data"`
}
