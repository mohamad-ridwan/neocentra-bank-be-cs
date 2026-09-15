package dto

type VerifyCustomerRequest struct {
	VerificationToken string `json:"verificationToken" binding:"required"`
	Code              string `json:"code" binding:"required,len=5,numeric"`
}

type VerifyCustomerResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}
