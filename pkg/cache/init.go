package cache

import (
	"fmt"

	"github.com/0x726f6f6b6965/go-auth/config"
	"github.com/redis/go-redis/v9"
)

func NewRedis(cfg *config.RedisConfig) (Cache, func(), error) {
	redisClient := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Password: cfg.Password,
		DB:       cfg.DBNum,
		PoolSize: cfg.PoolSize,
	})
	return &RedisCache{
		Client: redisClient,
	}, func() { redisClient.Close() }, nil
}
