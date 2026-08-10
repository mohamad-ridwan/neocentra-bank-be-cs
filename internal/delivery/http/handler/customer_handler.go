package handler

import (
	"net/http"

	"customer-service/internal/dto"
	"customer-service/internal/usecase"

	"github.com/gin-gonic/gin"
)

type CustomerHandler struct {
	useCase *usecase.CustomerUseCase
}

func NewCustomerHandler(u *usecase.CustomerUseCase) *CustomerHandler {
	return &CustomerHandler{useCase: u}
}

func (h *CustomerHandler) RegisterCustomer(c *gin.Context) {
	var req dto.OpenAccountRequest

	// Validasi JSON Body & Go-Playground Validator
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"code":    http.StatusBadRequest,
			"message": "Validasi input gagal: " + err.Error(),
		})
		return
	}

	// Eksekusi Register via UseCase
	res, err := h.useCase.RegisterNewCustomer(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"success": false,
			"code":    http.StatusUnprocessableEntity,
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"success": true,
		"code":    http.StatusCreated,
		"message": "Formulir pendaftaran calon nasabah berhasil diterima dengan status PENDING_VERIFICATION",
		"data":    res,
	})
}
