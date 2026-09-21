package database

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

func NewRedisClient(redisURL string) (*redis.Client, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		// Fallback if redisURL is address format like "localhost:6379"
		opts = &redis.Options{
			Addr: redisURL,
		}
	}

	opts.DialTimeout = 5 * time.Second
	opts.ReadTimeout = 3 * time.Second
	opts.WriteTimeout = 3 * time.Second

	client := redis.NewClient(opts)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to ping redis: %w", err)
	}

	return client, nil
}
