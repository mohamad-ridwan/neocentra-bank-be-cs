package handler

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"customer-service/internal/dto"
	"customer-service/internal/security"
	"customer-service/internal/usecase"
	"customer-service/internal/util"

	"github.com/gin-gonic/gin"
)

type AccountHandler struct {
	accountUseCase *usecase.AccountUseCase
}

func NewAccountHandler(accountUseCase *usecase.AccountUseCase) *AccountHandler {
	return &AccountHandler{
		accountUseCase: accountUseCase,
	}
}

// OpenAccount memproses inisiasi pembukaan rekening baru di dalam aplikasi
func (h *AccountHandler) OpenAccount(c *gin.Context) {
	userIDVal, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"code":    http.StatusUnauthorized,
			"message": "Pengguna tidak terautentikasi",
		})
		return
	}

	customerID, ok := userIDVal.(string)
	if !ok || customerID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"code":    http.StatusUnauthorized,
			"message": "ID Pengguna tidak valid",
		})
		return
	}

	var req dto.OpenAccountRequest
	contentType := c.GetHeader("Content-Type")

	if strings.Contains(contentType, "application/octet-stream") {
		bodyBytes, err := io.ReadAll(c.Request.Body)
		if err != nil || len(bodyBytes) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"code":    http.StatusBadRequest,
				"message": "Gagal membaca binary request body",
			})
			return
		}

		if len(bodyBytes) < security.MinTransitPayloadSize {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"code":    http.StatusBadRequest,
				"message": "Ukuran binary payload transit tidak valid",
			})
			return
		}

		decryptedPayload, err := h.accountUseCase.DecryptTransitPayload(bodyBytes)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"code":    http.StatusBadRequest,
				"message": "Dekripsi payload gagal. Kredensial kriptografi tidak sesuai.",
			})
			return
		}

		if err := json.Unmarshal(decryptedPayload, &req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"code":    http.StatusBadRequest,
				"message": "Format JSON hasil dekripsi tidak valid: " + err.Error(),
			})
			return
		}
	} else {
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"code":    http.StatusBadRequest,
				"message": "Format request pembukaan rekening tidak valid: " + err.Error(),
			})
			return
		}
	}

	data, session, err := h.accountUseCase.OpenAccount(c.Request.Context(), customerID, req)
	if err != nil {
		if errors.Is(err, util.ErrPINInvalidFormat) || errors.Is(err, util.ErrPINRepetitive) || errors.Is(err, util.ErrPINSequential) {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"code":    http.StatusBadRequest,
				"message": err.Error(),
			})
			return
		}

		if err.Error() == "nasabah sudah memiliki rekening aktif" {
			c.JSON(http.StatusConflict, gin.H{
				"success": false,
				"code":    http.StatusConflict,
				"message": "Nasabah sudah memiliki rekening aktif",
			})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"code":    http.StatusInternalServerError,
			"message": "Gagal membuka rekening: " + err.Error(),
		})
		return
	}

	respMap := gin.H{
		"success": true,
		"code":    http.StatusCreated,
		"message": "Rekening Neocentra berhasil dibuka",
		"data":    data,
		"session": session,
	}

	// Jika client meminta biner application/octet-stream atau mengirim application/octet-stream, kirim response terenkripsi
	acceptHeader := c.GetHeader("Accept")
	if strings.Contains(contentType, "application/octet-stream") || strings.Contains(acceptHeader, "application/octet-stream") {
		jsonBytes, err := json.Marshal(respMap)
		if err == nil {
			encryptedResp, encErr := h.accountUseCase.EncryptServerEnvelope(jsonBytes)
			if encErr == nil {
				c.Data(http.StatusCreated, "application/octet-stream", encryptedResp)
				return
			}
		}
	}

	c.JSON(http.StatusCreated, respMap)
}

// VerifyPIN memverifikasi keabsahan PIN 6 digit sebelum transaksi finansial
func (h *AccountHandler) VerifyPIN(c *gin.Context) {
	userIDVal, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"code":    http.StatusUnauthorized,
			"message": "Pengguna tidak terautentikasi",
		})
		return
	}

	customerID, ok := userIDVal.(string)
	if !ok || customerID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"code":    http.StatusUnauthorized,
			"message": "ID Pengguna tidak valid",
		})
		return
	}

	var req dto.VerifyPINRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"code":    http.StatusBadRequest,
			"message": "Format request verifikasi PIN tidak valid: " + err.Error(),
		})
		return
	}

	data, remaining, err := h.accountUseCase.VerifyPIN(c.Request.Context(), customerID, req)
	if err != nil {
		if errors.Is(err, util.ErrPINLocked) {
			c.JSON(http.StatusForbidden, gin.H{
				"success":    false,
				"code":       http.StatusForbidden,
				"error_code": "PIN_LOCKED",
				"message":    "Rekening Anda terkunci sementara karena salah memasukkan PIN 3 kali. Silakan coba lagi setelah 15 menit.",
			})
			return
		}

		if errors.Is(err, util.ErrPINMismatch) {
			c.JSON(http.StatusUnauthorized, gin.H{
				"success":            false,
				"code":               http.StatusUnauthorized,
				"error_code":         "INVALID_PIN",
				"message":            "PIN transaksi salah",
				"attempts_remaining": remaining,
			})
			return
		}

		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"code":    http.StatusBadRequest,
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"code":    http.StatusOK,
		"message": "PIN transaksi valid",
		"data":    data,
	})
}
