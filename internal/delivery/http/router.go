package http

import (
	"time"

	"customer-service/internal/delivery/http/handler"
	"customer-service/internal/delivery/http/middleware"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

func SetupRouter(custHandler *handler.CustomerHandler, rdb *redis.Client, accHandlers ...*handler.AccountHandler) *gin.Engine {
	r := gin.New()

	var accHandler *handler.AccountHandler
	if len(accHandlers) > 0 && accHandlers[0] != nil {
		accHandler = accHandlers[0]
	}

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
			public.POST("/customers/login", custHandler.LoginCustomer)
			public.POST("/accounts", custHandler.GetAccounts)
			public.GET("/accounts", custHandler.GetAccounts)
		}

		// Public Verification Endpoint (Direct JSON payload { verificationToken, code })
		v1.POST("/customers/verification", custHandler.VerifyCustomer)

		// 2. PROTECTED ROUTES (Wajib User JWT Terverifikasi)
		protected := v1.Group("")
		protected.Use(middleware.JWTAuthMiddleware())
		{
			if accHandler != nil {
				// Pembukaan rekening baru (ROLE_CUSTOMER_BASIC)
				protected.POST("/accounts/open", middleware.RequireRole("ROLE_CUSTOMER_BASIC", "customer"), accHandler.OpenAccount)
				// Verifikasi PIN transaksi (ROLE_CUSTOMER_TRANSACTIONAL)
				protected.POST("/accounts/verify-pin", middleware.RequireRole("ROLE_CUSTOMER_TRANSACTIONAL"), accHandler.VerifyPIN)
			}
		}
	}

	return r
}
