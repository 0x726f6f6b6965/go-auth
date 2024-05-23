package main

import (
	"github.com/0x726f6f6b6965/go-auth/config"
	"github.com/0x726f6f6b6965/go-auth/internal/services"
	"github.com/0x726f6f6b6965/go-auth/internal/storage"
	"github.com/0x726f6f6b6965/go-auth/pkg/cache"
	jwtauth "github.com/0x726f6f6b6965/go-auth/pkg/jwt-auth"
	"github.com/0x726f6f6b6965/go-auth/pkg/logger"
	"github.com/google/wire"
)

var userService = wire.NewSet(authSet, dbSet, cacheSet, loggerSet, services.NewUserService)

var cacheSet = wire.NewSet(redisConfig, cache.NewRedis)

var authSet = wire.NewSet(jwtAuthConfig, jwtauth.NewJWTAuth)

var dbSet = wire.NewSet(dbConfig, storage.NewPostgres)

var loggerSet = wire.NewSet(logConfig, logger.NewLogger)

func logConfig(cfg *config.AppConfig) *config.LogConfig {
	return &cfg.Log
}

func dbConfig(cfg *config.AppConfig) *config.DBConfig {
	return &cfg.DB
}

func jwtAuthConfig(cfg *config.AppConfig) *jwtauth.Config {
	return &cfg.Jwt
}

func redisConfig(cfg *config.AppConfig) *config.RedisConfig {
	return &cfg.Redis
}
