package api

import (
	"fmt"

	"github.com/0x726f6f6b6965/go-auth/app/api/middleware"
	"github.com/0x726f6f6b6965/go-auth/config"
	"github.com/0x726f6f6b6965/go-auth/pkg/cache"
	jwtauth "github.com/0x726f6f6b6965/go-auth/pkg/jwt-auth"
	pbPolicy "github.com/0x726f6f6b6965/go-auth/protos/policy/v1"
	"github.com/google/wire"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var middleWareSet = wire.NewSet(policyGrpcClient, middleware.NewAuthMiddleware)

var policyGrpcClient = wire.NewSet(policyGrpcConfig, registerPolicyClient)

var cacheSet = wire.NewSet(redisConfig, cache.NewRedis)

var authSet = wire.NewSet(jwtAuthConfig, jwtauth.NewJWTAuth)

func jwtAuthConfig(cfg *config.AppConfig) *jwtauth.Config {
	return &cfg.Jwt
}

func redisConfig(cfg *config.AppConfig) *config.RedisConfig {
	return &cfg.Redis
}

func policyGrpcConfig(cfg *config.AppConfig) *config.Grpc {
	policy := cfg.Clients["policy-client"]
	return &policy
}

func registerPolicyClient(cfg *config.Grpc) (pbPolicy.PolicyServiceClient, func(), error) {
	conn, err := grpc.NewClient(fmt.Sprintf("%s:%d", cfg.Host, cfg.Port), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, func() {}, err
	}
	client := pbPolicy.NewPolicyServiceClient(conn)
	return client, func() { conn.Close() }, nil
}
