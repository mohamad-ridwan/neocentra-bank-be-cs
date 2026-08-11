package dto

type RegisterCustomerResponseData struct {
	CustomerID  string `json:"customer_id"`
	NIK         string `json:"nik"`          // Ciphertext hasil simpanan DB
	FullName    string `json:"full_name"`    // Ciphertext hasil simpanan DB
	Email       string `json:"email"`        // Ciphertext hasil simpanan DB
	PhoneNumber string `json:"phone_number"` // Ciphertext hasil simpanan DB
	Status      string `json:"status"`       // "PENDING_VERIFICATION"
	CreatedAt   string `json:"created_at"`
}

type RegisterCustomerAPIResponse struct {
	Success bool                         `json:"success"`
	Code    int                          `json:"code"`
	Message string                       `json:"message"`
	Data    RegisterCustomerResponseData `json:"data"`
}
