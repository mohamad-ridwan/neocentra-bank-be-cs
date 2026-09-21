package handler

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"customer-service/internal/delivery/http/serializer"
	"customer-service/internal/domain"
	"customer-service/internal/dto"
	"customer-service/internal/security"
	"customer-service/internal/usecase"

	"github.com/gin-gonic/gin"
)

type CustomerHandler struct {
	useCase        *usecase.CustomerUseCase
	accountUseCase *usecase.AccountUseCase
}

func NewCustomerHandler(u *usecase.CustomerUseCase, accUC ...*usecase.AccountUseCase) *CustomerHandler {
	h := &CustomerHandler{useCase: u}
	if len(accUC) > 0 {
		h.accountUseCase = accUC[0]
	}
	return h
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

		// Pola 1: Full Raw Binary Transit Payload (Hybrid Asymmetric RSA-OAEP + AES-256-GCM >= 284 Bytes)
		if len(bodyBytes) >= security.MinTransitPayloadSize && h.useCase.HasTransitDecryptor() {
			res, err := h.useCase.RegisterNewCustomerRaw(c.Request.Context(), bodyBytes)
			if err == nil {
				c.JSON(http.StatusCreated, dto.RegisterCustomerAPIResponse{
					Success: true,
					Code:    http.StatusCreated,
					Message: "Formulir pendaftaran calon nasabah berhasil diterima dengan status PENDING_VERIFICATION",
					Data:    *res,
				})
				return
			}

			if errors.Is(err, domain.ErrInvalidEmailGoogle) {
				c.JSON(http.StatusBadRequest, gin.H{
					"success": false,
					"code":    http.StatusBadRequest,
					"message": err.Error(),
				})
				return
			}

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
				// Coba fallback TLV jika payload sebenarnya TLV legacy
				parsedReq, rawPassword, errTLV := serializer.UnpackCustomerTLV(bodyBytes)
				if errTLV == nil && parsedReq != nil {
					parsedReq.Password = rawPassword
					req = *parsedReq
					goto executeUseCase
				}

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

		// Fallback untuk TLV Binary Framing (< 284 Bytes)
		parsedReq, rawPassword, err := serializer.UnpackCustomerTLV(bodyBytes)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"code":    http.StatusBadRequest,
				"message": "Format binary TLV tidak valid: " + err.Error(),
			})
			return
		}
		parsedReq.Password = rawPassword
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

executeUseCase:

	// 3. Eksekusi Register via UseCase
	res, err := h.useCase.RegisterNewCustomer(c.Request.Context(), req)
	if err != nil {
		if errors.Is(err, domain.ErrInvalidEmailGoogle) {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"code":    http.StatusBadRequest,
				"message": err.Error(),
			})
			return
		}

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

func (h *CustomerHandler) VerifyCustomer(c *gin.Context) {
	var req dto.VerifyCustomerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"code":    http.StatusBadRequest,
			"message": "Format request verifikasi tidak valid. Pastikan verificationToken dan code 5-digit disertakan.",
		})
		return
	}

	res, err := h.useCase.VerifyCustomer(c.Request.Context(), req)
	if err != nil {
		if errors.Is(err, domain.ErrVerificationNotFound) {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"code":    http.StatusBadRequest,
				"message": "Kode verifikasi tidak sesuai atau telah kadaluwarsa.",
			})
			return
		}

		if errors.Is(err, domain.ErrVerificationExpired) || errors.Is(err, security.ErrExpiredVerificationToken) {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"code":    http.StatusBadRequest,
				"message": "Kode verifikasi telah kadaluwarsa. Silakan lakukan registrasi ulang.",
			})
			return
		}

		if errors.Is(err, security.ErrInvalidVerificationToken) {
			c.JSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"code":    http.StatusUnauthorized,
				"message": "Token verifikasi tidak valid.",
			})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"code":    http.StatusInternalServerError,
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, res)
}

// LoginCustomer menangani autentikasi login nasabah via raw binary stream
func (h *CustomerHandler) LoginCustomer(c *gin.Context) {
	contentType := c.GetHeader("Content-Type")
	if !strings.Contains(contentType, "application/octet-stream") {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"code":    http.StatusBadRequest,
			"message": "Header Content-Type harus application/octet-stream",
		})
		return
	}

	bodyBytes, err := io.ReadAll(c.Request.Body)
	if err != nil || len(bodyBytes) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"code":    http.StatusBadRequest,
			"message": "Gagal membaca binary request body",
		})
		return
	}

	if len(bodyBytes) < security.MinTransitPayloadSize || !h.useCase.HasTransitDecryptor() {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"code":    http.StatusBadRequest,
			"message": "Payload transit login tidak valid atau terlalu pendek",
		})
		return
	}

	encryptedResponse, err := h.useCase.LoginCustomerRaw(c.Request.Context(), bodyBytes)
	if err != nil {
		if errors.Is(err, domain.ErrInvalidDecryption) {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"code":    http.StatusBadRequest,
				"message": "Dekripsi payload login gagal. Kredensial kriptografi tidak sesuai.",
			})
			return
		}

		if errors.Is(err, domain.ErrCustomerNotFound) {
			c.JSON(http.StatusNotFound, gin.H{
				"success": false,
				"code":    http.StatusNotFound,
				"message": "Akun tidak ditemukan. Periksa kembali NIK / Email / No. Handphone Anda.",
			})
			return
		}

		if errors.Is(err, domain.ErrCustomerNotActive) {
			c.JSON(http.StatusForbidden, gin.H{
				"success": false,
				"code":    http.StatusForbidden,
				"message": "Akun Anda belum aktif. Silakan lakukan verifikasi terlebih dahulu.",
			})
			return
		}

		if errors.Is(err, domain.ErrInvalidCredentials) {
			c.JSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"code":    http.StatusUnauthorized,
				"message": "Kredensial login tidak valid. Periksa kembali identifier dan password Anda.",
			})
			return
		}

		if errors.Is(err, domain.ErrPasswordEmpty) {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"code":    http.StatusBadRequest,
				"message": "Password login wajib diisi.",
			})
			return
		}

		if errors.Is(err, domain.ErrCustomerSuspended) {
			c.JSON(http.StatusForbidden, gin.H{
				"success": false,
				"code":    http.StatusForbidden,
				"message": "Akun Anda telah ditangguhkan. Hubungi Customer Service Neocentra.",
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

	c.Data(http.StatusOK, "application/octet-stream", encryptedResponse)
}

type GetAccountsRequest struct {
	CustomerID string `json:"customer_id" form:"customer_id"`
}

// GetAccounts mengambil data rekening customer dari database PostgreSQL dan mengenkripsi respons biner
func (h *CustomerHandler) GetAccounts(c *gin.Context) {
	var req GetAccountsRequest

	// Bind JSON atau Query params (customer_id)
	if err := c.ShouldBind(&req); err != nil || req.CustomerID == "" {
		// Coba baca dari query string
		req.CustomerID = c.Query("customer_id")
		if req.CustomerID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"code":    http.StatusBadRequest,
				"message": "Parameter customer_id wajib disertakan",
			})
			return
		}
	}

	if h.accountUseCase == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"code":    http.StatusInternalServerError,
			"message": "Layanan rekening belum dikonfigurasi",
		})
		return
	}

	encryptedPayload, err := h.accountUseCase.GetAccountsEncrypted(c.Request.Context(), req.CustomerID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"code":    http.StatusInternalServerError,
			"message": fmt.Sprintf("Gagal memproses rekening: %v", err),
		})
		return
	}

	c.Data(http.StatusOK, "application/octet-stream", encryptedPayload)
}
