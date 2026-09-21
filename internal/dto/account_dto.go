package dto

import "time"

type EmploymentDataDTO struct {
	Occupation    string `json:"occupation"`
	MonthlyIncome string `json:"monthly_income"`
	SourceOfFunds string `json:"source_of_funds"`
}

type OpenAccountRequest struct {
	ProductType    string             `json:"product_type"`
	BranchCode     string             `json:"branch_code"`
	EncryptedPIN   string             `json:"encrypted_pin"`
	PIN            string             `json:"pin"`
	EmploymentData *EmploymentDataDTO `json:"employment_data"`
}

type OpenAccountResponseData struct {
	AccountID     string    `json:"account_id"`
	AccountNumber string    `json:"account_number"`
	Currency      string    `json:"currency"`
	Balance       float64   `json:"balance"`
	ProductType   string    `json:"product_type"`
	Status        string    `json:"status"`
	CreatedAt     time.Time `json:"created_at"`
}

type SessionElevationData struct {
	ElevatedToken string `json:"elevated_token"`
	Role          string `json:"role"`
}

type VerifyPINRequest struct {
	AccountID    string `json:"account_id"`
	EncryptedPIN string `json:"encrypted_pin"`
	PIN          string `json:"pin"`
}

type VerifyPINResponseData struct {
	IsValid              bool   `json:"is_valid"`
	TransactionAuthToken string `json:"transaction_auth_token,omitempty"`
	ExpiresInSeconds     int    `json:"expires_in_seconds,omitempty"`
}
