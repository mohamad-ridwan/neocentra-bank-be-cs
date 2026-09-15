package dto

type RegisterCustomerResponseData struct {
	VerificationToken string `json:"verificationToken"`
	Email             string `json:"email"` // Masked email (e.g. u***r@example.co)
}

type RegisterCustomerAPIResponse struct {
	Success bool                         `json:"success"`
	Code    int                          `json:"code"`
	Message string                       `json:"message"`
	Data    RegisterCustomerResponseData `json:"data"`
}
