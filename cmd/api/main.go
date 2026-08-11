package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"customer-service/internal/config"
	deliveryHttp "customer-service/internal/delivery/http"
	"customer-service/internal/delivery/http/handler"
	"customer-service/internal/repository/postgres"
	"customer-service/internal/usecase"
	"customer-service/pkg/database"
)

func main() {
	log.Println("[INFO] Starting Neocentra Customer Service Backend (neocentra-bank-be-cs)...")

	// 1. Load Environment Configuration
	cfg := config.LoadConfig()
	log.Printf("[INFO] Environment loaded. Target Port: %s", cfg.Port)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 2. Initialize PostgreSQL Pool
	dbPool, err := database.NewPostgresPool(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Printf("[WARNING] PostgreSQL connection failed: %v. App running in degraded mode.", err)
	} else {
		defer dbPool.Close()
		log.Println("[INFO] PostgreSQL connection pool initialized successfully.")
	}

	// 3. Initialize Redis Client
	redisClient, err := database.NewRedisClient(cfg.RedisURL)
	if err != nil {
		log.Printf("[WARNING] Redis connection failed: %v. Idempotency caching disabled.", err)
		redisClient = nil
	} else {
		defer redisClient.Close()
		log.Println("[INFO] Redis client connected successfully.")
	}

	// 4. Initialize Local KMS & Rotation Worker
	var kmsRepo usecase.KMSRepository
	if dbPool != nil {
		kmsRepo = postgres.NewKMSRepository(dbPool)
	}

	kmsService, err := usecase.NewLocalKMSService(cfg.LocalKMSMasterKey, kmsRepo)
	if err != nil {
		log.Fatalf("[FATAL] Failed to initialize Local KMS Service: %v", err)
	}
	log.Println("[INFO] Local KMS Service (Google Tink AEAD) initialized successfully.")

	// Start 90-day background key rotation worker
	kmsWorkerCtx, cancelKMSWorker := context.WithCancel(context.Background())
	defer cancelKMSWorker()
	kmsService.StartRotationWorker(kmsWorkerCtx, "customer_pii_keyset", 90*24*time.Hour)

	// 5. Initialize Repository, WorkerPool & UseCase
	var custRepo usecase.CustomerRepository
	if dbPool != nil {
		custRepo = postgres.NewCustomerRepository(dbPool, kmsService)
	}

	workerPool := usecase.NewWorkerPool(5, 100)

	custUseCase := usecase.NewCustomerUseCase(custRepo, kmsService, workerPool)

	// 6. Initialize Delivery Layer (Handler & Router)
	custHandler := handler.NewCustomerHandler(custUseCase)
	router := deliveryHttp.SetupRouter(custHandler, redisClient)

	// 7. Start HTTP Server
	serverAddr := fmt.Sprintf(":%s", cfg.Port)
	srv := &http.Server{
		Addr:         serverAddr,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Printf("[INFO] Neocentra Customer Service listening on port %s...", cfg.Port)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("[FATAL] HTTP server ListenAndServe error: %v", err)
		}
	}()

	// 8. Graceful Shutdown Listener
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("[INFO] Shutting down Neocentra Customer Service...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("[ERROR] Server forced to shutdown: %v", err)
	}

	// Stop Async Worker Pool
	workerPool.Shutdown(shutdownCtx)

	log.Println("[INFO] Server exited gracefully.")
}
