package middleware

import (
	"bytes"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

type bodyLogWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (w bodyLogWriter) Write(b []byte) (int, error) {
	w.body.Write(b)
	return w.ResponseWriter.Write(b)
}

func IdempotencyMiddleware(rdb *redis.Client, ttl time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 1. Ambil Header Idempotency Key
		idempotencyKey := c.GetHeader("X-Idempotency-Key")

		// Jika request tidak mengirim Idempotency Key, lewati middleware
		if idempotencyKey == "" {
			c.Next()
			return
		}

		ctx := c.Request.Context()
		lockKey := fmt.Sprintf("idempotency:lock:%s", idempotencyKey)
		respKey := fmt.Sprintf("idempotency:resp:%s", idempotencyKey)

		// 2. Cek apakah response hasil execution sebelumnya sudah ada di Redis
		cachedResp, err := rdb.Get(ctx, respKey).Result()
		if err == nil && cachedResp != "" {
			// Response sudah ada di cache! Kembalikan langsung ke client tanpa hit DB
			c.Header("Content-Type", "application/json")
			c.Header("X-Cache", "HIT-IDEMPOTENCY")
			c.String(http.StatusOK, cachedResp)
			c.Abort()
			return
		}

		// 3. Coba kunci (SETNX) untuk mencegah concurrent execution request yang sama
		acquired, err := rdb.SetNX(ctx, lockKey, "LOCKED", 30*time.Second).Result()
		if err != nil || !acquired {
			c.AbortWithStatusJSON(http.StatusConflict, gin.H{
				"success": false,
				"code":    http.StatusConflict,
				"message": "Request sedang diproses. Mohon tidak menekan tombol registrasi berulang kali.",
			})
			return
		}

		// Hapus lock jika terjadi crash
		defer rdb.Del(ctx, lockKey)

		// 4. Intercept response body agar bisa disimpan di Redis
		blw := &bodyLogWriter{body: bytes.NewBufferString(""), ResponseWriter: c.Writer}
		c.Writer = blw

		c.Next()

		// 5. Simpan response HTTP yang sukses (2xx) ke Redis selama TTL (misal 10 menit)
		if c.Writer.Status() >= 200 && c.Writer.Status() < 300 {
			rdb.Set(ctx, respKey, blw.body.String(), ttl)
		}
	}
}
