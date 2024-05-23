//go:build wireinject
// +build wireinject

package user

import (
	"github.com/0x726f6f6b6965/go-auth/config"
	"github.com/0x726f6f6b6965/go-auth/pkg/cache"
	jwtauth "github.com/0x726f6f6b6965/go-auth/pkg/jwt-auth"
	pbUser "github.com/0x726f6f6b6965/go-auth/protos/user/v1"
	"github.com/google/wire"
)

func InitUserService(cfg *config.AppConfig, auth *jwtauth.JwtAuth, cache cache.Cache) (service pbUser.UserServiceServer, cleanup func(), err error) {
	panic(wire.Build(userService))
}
