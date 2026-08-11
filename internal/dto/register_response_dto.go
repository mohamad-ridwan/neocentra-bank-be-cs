package dto

type RegisterCustomerResponseData struct {
	CustomerID  string `json:"customer_id"`
	NIK         []byte `json:"nik"`          // Ciphertext biner (BYTEA) hasil simpanan DB
	FullName    []byte `json:"full_name"`    // Ciphertext biner (BYTEA) hasil simpanan DB
	Email       []byte `json:"email"`        // Ciphertext biner (BYTEA) hasil simpanan DB
	PhoneNumber []byte `json:"phone_number"` // Ciphertext biner (BYTEA) hasil simpanan DB
	Status      string `json:"status"`       // "PENDING_VERIFICATION"
	CreatedAt   string `json:"created_at"`
}

type RegisterCustomerAPIResponse struct {
	Success bool                         `json:"success"`
	Code    int                          `json:"code"`
	Message string                       `json:"message"`
	Data    RegisterCustomerResponseData `json:"data"`
}
