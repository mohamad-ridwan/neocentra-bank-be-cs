package handler

import (
	"errors"
	"io"
	"net/http"
	"strings"

	"customer-service/internal/delivery/http/serializer"
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
	contentType := c.GetHeader("Content-Type")

	if strings.Contains(contentType, "application/octet-stream") {
		// 1. Baca Raw Binary Stream dari Request Body
		bodyBytes, err := io.ReadAll(c.Request.Body)
		if err != nil || len(bodyBytes) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"code":    http.StatusBadRequest,
				"message": "Gagal membaca binary request body",
			})
			return
		}

		// 2. Unpack TLV Binary Framing
		parsedReq, _, err := serializer.UnpackCustomerTLV(bodyBytes)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"code":    http.StatusBadRequest,
				"message": "Format binary TLV tidak valid: " + err.Error(),
			})
			return
		}
		req = *parsedReq
	} else {
		// Fallback untuk client yang mengirim format JSON
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"code":    http.StatusBadRequest,
				"message": "Validasi input JSON gagal: " + err.Error(),
			})
			return
		}
	}

	// 3. Eksekusi Register via UseCase
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
				"message": "Dekripsi payload gagal. Kredensial kriptografi tidak sesuai.",
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
