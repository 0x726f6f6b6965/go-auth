package cache

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	ErrKeyNotFound = errors.New("key not found")
	ErrUnexpected  = errors.New("unexpected error")
)

type Cache interface {
	Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error
	Get(ctx context.Context, key string) (interface{}, error)
	Delete(ctx context.Context, key string) error
}

type RedisCache struct {
	Client *redis.Client
}
