//go:build wireinject
// +build wireinject

package api

import (
	"github.com/0x726f6f6b6965/go-auth/app/api/middleware"
	"github.com/0x726f6f6b6965/go-auth/config"
	"github.com/0x726f6f6b6965/go-auth/pkg/cache"
	jwtauth "github.com/0x726f6f6b6965/go-auth/pkg/jwt-auth"
	"github.com/google/wire"
)

func InitMiddleware(cfg *config.AppConfig, auth *jwtauth.JwtAuth, cache cache.Cache) (service *middleware.AuthMiddleware, cleanup func(), err error) {
	panic(wire.Build(middleWareSet))
}

func InitCache(cfg *config.AppConfig) (cache cache.Cache, cleanup func(), err error) {
	panic(wire.Build(cacheSet))
}

func InitJwtAuth(cfg *config.AppConfig) (auth *jwtauth.JwtAuth) {
	panic(wire.Build(authSet))
}
