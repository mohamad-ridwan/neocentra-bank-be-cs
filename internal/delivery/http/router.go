package http

import (
	"customer-service/internal/delivery/http/handler"
	"customer-service/internal/delivery/http/middleware"

	"github.com/gin-gonic/gin"
)

func SetupRouter(custHandler *handler.CustomerHandler) *gin.Engine {
	r := gin.New()

	// Global Middlewares
	r.Use(middleware.CORSMiddleware())
	r.Use(middleware.RecoveryMiddleware())
	r.Use(gin.Logger())

	// Public Healthcheck
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "UP", "service": "neocentra-bank-be-cs"})
	})

	// Protected API Routes v1
	v1 := r.Group("/api/v1")
	v1.Use(middleware.JWTAuthMiddleware())
	{
		v1.POST("/customers/register", custHandler.RegisterCustomer)
	}

	return r
}
