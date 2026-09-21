package middleware

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

const (
	DefaultAppSigningKey = "neocentra_app_signature_key_2026"
)

// AntiReplayMiddleware memvalidasi kesesuaian waktu X-Timestamp dan keunikan X-Nonce
func AntiReplayMiddleware(rdb *redis.Client, maxSkew time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		timestampStr := c.GetHeader("X-Timestamp")
		if timestampStr == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"success": false,
				"code":    http.StatusBadRequest,
				"message": "Header X-Timestamp wajib disertakan untuk perlindungan anti-replay",
			})
			return
		}

		reqTime, err := time.Parse(time.RFC3339Nano, timestampStr)
		if err != nil {
			reqTime, err = time.Parse(time.RFC3339, timestampStr)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
					"success": false,
					"code":    http.StatusBadRequest,
					"message": "Format X-Timestamp tidak valid (harus ISO8601 / RFC3339)",
				})
				return
			}
		}

		// Validasi Clock Skew Window
		timeDiff := math.Abs(time.Since(reqTime).Seconds())
		if timeDiff > maxSkew.Seconds() {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"code":    http.StatusUnauthorized,
				"message": fmt.Sprintf("Timestamp request kadaluwarsa atau berada di luar toleransi (drift: %.1fs, max: %.1fs)", timeDiff, maxSkew.Seconds()),
			})
			return
		}

		nonce := c.GetHeader("X-Nonce")
		if nonce == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"success": false,
				"code":    http.StatusBadRequest,
				"message": "Header X-Nonce wajib disertakan",
			})
			return
		}

		// Verifikasi keunikan Nonce pada Redis jika instance Redis aktif
		if rdb != nil {
			redisKey := fmt.Sprintf("anti_replay:nonce:%s", nonce)
			ttl := maxSkew * 2
			if ttl < 2*time.Minute {
				ttl = 2 * time.Minute
			}

			success, err := rdb.SetNX(c.Request.Context(), redisKey, "1", ttl).Result()
			if err != nil {
				// Jika redis connection error, log dan lanjutkan jika toleran
			} else if !success {
				c.AbortWithStatusJSON(http.StatusConflict, gin.H{
					"success": false,
					"code":    http.StatusConflict,
					"message": "Request replay terdeteksi. Nonce sudah pernah digunakan sebelumnya.",
				})
				return
			}
		}

		c.Next()
	}
}

// RequestSignatureMiddleware memvalidasi HMAC-SHA256 request payload & headers
// String to sign: METHOD:PATH:SHA256(BODY):TIMESTAMP:NONCE
func RequestSignatureMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		signatureHeader := c.GetHeader("X-Signature")
		if signatureHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"code":    http.StatusUnauthorized,
				"message": "Header X-Signature wajib disertakan untuk verifikasi integritas data",
			})
			return
		}

		timestamp := c.GetHeader("X-Timestamp")
		nonce := c.GetHeader("X-Nonce")

		// Baca body dan kembalikan reader agar bisa dibaca kembali oleh handler
		var bodyBytes []byte
		if c.Request.Body != nil {
			var err error
			bodyBytes, err = io.ReadAll(c.Request.Body)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
					"success": false,
					"code":    http.StatusBadRequest,
					"message": "Gagal membaca body request untuk verifikasi signature",
				})
				return
			}
			c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}

		// 1. Hash body ke Hex
		bodySha := sha256.Sum256(bodyBytes)
		bodyHashHex := hex.EncodeToString(bodySha[:])

		// 2. Format String to Sign
		stringToSign := fmt.Sprintf("%s:%s:%s:%s:%s",
			c.Request.Method,
			c.Request.URL.Path,
			bodyHashHex,
			timestamp,
			nonce,
		)

		// 3. Ambil Secret Key
		signingKey := os.Getenv("APP_SIGNING_KEY")
		if signingKey == "" {
			signingKey = DefaultAppSigningKey
		}

		// 4. Hitung HMAC-SHA256
		mac := hmac.New(sha256.New, []byte(signingKey))
		mac.Write([]byte(stringToSign))
		expectedSignature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

		// 5. Constant-time comparison
		if !hmac.Equal([]byte(signatureHeader), []byte(expectedSignature)) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"code":    http.StatusUnauthorized,
				"message": "Verifikasi signature gagal. Integritas request tidak valid.",
			})
			return
		}

		c.Next()
	}
}
