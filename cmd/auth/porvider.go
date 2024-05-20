package main

import (
	apiService "github.com/0x726f6f6b6965/go-auth/api/services"
	"github.com/0x726f6f6b6965/go-auth/config"
	"github.com/0x726f6f6b6965/go-auth/internal/services"
	"github.com/0x726f6f6b6965/go-auth/internal/storage"
	jwtauth "github.com/0x726f6f6b6965/go-auth/pkg/jwt_auth"
	"github.com/0x726f6f6b6965/go-auth/pkg/logger"
	"github.com/google/wire"
)

var engineSet = wire.NewSet(InitGin)

var policyAPI = wire.NewSet(apiService.NewPolicyAPI)

var userAPI = wire.NewSet(apiService.NewUserAPI)

var policyGrpcClient = wire.NewSet(policyGrpcConfig, RegisterPolicyClient)

var policyService = wire.NewSet(loggerSet, services.NewPolicyService)

var userService = wire.NewSet(dbSet, loggerSet, services.NewUserService)

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

func policyGrpcConfig(cfg *config.AppConfig) *config.Grpc {
	return &cfg.PolicyGrpc
}
