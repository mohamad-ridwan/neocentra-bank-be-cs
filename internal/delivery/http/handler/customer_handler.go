package handler

import (
	"errors"
	"net/http"

	"customer-service/internal/domain"
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
	var req dto.EncryptedRegisterCustomerRequest

	// Validasi JSON Body Binding
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"code":    http.StatusBadRequest,
			"message": "Validasi input JSON gagal: " + err.Error(),
		})
		return
	}

	// Eksekusi Register via UseCase
	res, err := h.useCase.RegisterNewCustomer(c.Request.Context(), req)
	if err != nil {
		if errors.Is(err, domain.ErrDuplicateNIK) ||
			errors.Is(err, domain.ErrDuplicateEmail) ||
			errors.Is(err, domain.ErrDuplicatePhone) {
			c.JSON(http.StatusConflict, gin.H{
				"success": false,
				"code":    http.StatusConflict,
				"message": err.Error(),
			})
			return
		}

		if errors.Is(err, domain.ErrInvalidDecryption) {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"code":    http.StatusBadRequest,
				"message": err.Error(),
			})
			return
		}

		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"success": false,
			"code":    http.StatusUnprocessableEntity,
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, dto.RegisterCustomerAPIResponse{
		Success: true,
		Code:    http.StatusCreated,
		Message: "Formulir pendaftaran calon nasabah berhasil diterima dengan status PENDING_VERIFICATION",
		Data:    *res,
	})
}
