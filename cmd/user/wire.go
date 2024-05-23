//go:build wireinject
// +build wireinject

package main

import (
	"github.com/0x726f6f6b6965/go-auth/config"
	pbUser "github.com/0x726f6f6b6965/go-auth/protos/user/v1"
	"github.com/google/wire"
)

func initUserService(cfg *config.AppConfig) (service pbUser.UserServiceServer, cleanup func(), err error) {
	panic(wire.Build(userService))
}
