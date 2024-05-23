package cache

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

func (c *RedisCache) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	err := c.Client.Set(ctx, key, value, ttl).Err()
	if err != nil {
		return errors.Join(ErrUnexpected, err)
	}
	return nil
}

func (c *RedisCache) Get(ctx context.Context, key string) (interface{}, error) {
	val, err := c.Client.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrKeyNotFound
		}
		return nil, errors.Join(ErrUnexpected, err)
	}
	return val, nil
}

func (c *RedisCache) Delete(ctx context.Context, key string) error {
	err := c.Client.Del(ctx, key).Err()
	if err != nil {
		return errors.Join(ErrUnexpected, err)
	}
	return nil
}
