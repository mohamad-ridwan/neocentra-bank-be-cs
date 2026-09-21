package dto

type PlaintextLoginCustomer struct {
	Identifier string `json:"identifier"`
	Password   string `json:"password"`
}

type LoginCustomerResponseData struct {
	CustomerID  string `json:"customer_id"`
	NIK         string `json:"nik"`
	FullName    string `json:"full_name"`
	Email       string `json:"email"`
	PhoneNumber string `json:"phone_number"`
	Status      string `json:"status"`
	AccessToken string `json:"access_token"`
}
