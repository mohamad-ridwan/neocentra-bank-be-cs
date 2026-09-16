package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// RequireRole memeriksa klaim peran pengguna di dalam JWT context
func RequireRole(allowedRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		roleVal, exists := c.Get("role")
		if !exists {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"code":    http.StatusUnauthorized,
				"message": "Sesi tidak terautentikasi atau role tidak ditemukan",
			})
			return
		}

		userRole, ok := roleVal.(string)
		if !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"success": false,
				"code":    http.StatusForbidden,
				"message": "Tipe data peran tidak valid",
			})
			return
		}

		for _, allowed := range allowedRoles {
			// Mengizinkan kecocokan langsung atau interoperabilitas dengan role dasar "customer"
			if userRole == allowed || (userRole == "customer" && allowed == "ROLE_CUSTOMER_BASIC") {
				c.Next()
				return
			}
		}

		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"success": false,
			"code":    http.StatusForbidden,
			"message": "Akses ditolak. Anda belum memiliki hak akses untuk transaksi ini. Silakan buka rekening terlebih dahulu.",
		})
	}
}
