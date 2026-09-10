package http

import (
	"time"

	"customer-service/internal/delivery/http/handler"
	"customer-service/internal/delivery/http/middleware"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

func SetupRouter(custHandler *handler.CustomerHandler, rdb *redis.Client) *gin.Engine {
	r := gin.New()

	// Global Middlewares
	r.Use(middleware.CORSMiddleware())
	r.Use(middleware.RecoveryMiddleware())
	r.Use(gin.Logger())

	// Public Healthcheck Endpoint
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":  "UP",
			"service": "neocentra-bank-be-cs",
		})
	})

	// API Routes v1
	v1 := r.Group("/api/v1")
	{
		// 1. PUBLIC ONBOARDING & AUTH (Tanpa User JWT)
		public := v1.Group("")
		public.Use(
			middleware.AntiReplayMiddleware(rdb, 60*time.Second),
			middleware.RequestSignatureMiddleware(),
			middleware.IdempotencyMiddleware(rdb, 10*time.Minute),
		)
		{
			public.POST("/customers/register", custHandler.RegisterCustomer)
		}

		// 2. PROTECTED ROUTES (Wajib User JWT Terverifikasi)
		protected := v1.Group("")
		protected.Use(middleware.JWTAuthMiddleware())
		{
			// Endpoint yang membutuhkan autentikasi JWT pengguna terdaftar
		}
	}

	return r
}
