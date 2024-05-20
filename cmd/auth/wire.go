//go:build wireinject
// +build wireinject

package main

import (
	apiService "github.com/0x726f6f6b6965/go-auth/api/services"
	"github.com/0x726f6f6b6965/go-auth/config"
	jwtauth "github.com/0x726f6f6b6965/go-auth/pkg/jwt_auth"
	pbPolicy "github.com/0x726f6f6b6965/go-auth/protos/policy/v1"
	pbUser "github.com/0x726f6f6b6965/go-auth/protos/user/v1"
	"github.com/gin-gonic/gin"
	"github.com/google/wire"
)

func initUserAPI(ser pbUser.UserServiceServer) (application *apiService.UserAPI, err error) {
	panic(wire.Build(userAPI))
}

func initPolicyAPI(ser pbPolicy.PolicyServiceServer) (application *apiService.PolicyAPI, err error) {
	panic(wire.Build(policyAPI))
}

func initGin(cfg *config.AppConfig) (engine *gin.Engine, err error) {
	panic(wire.Build(engineSet))
}

func initPolicyService(cfg *config.AppConfig) (service pbPolicy.PolicyServiceServer, cleanup func(), err error) {
	panic(wire.Build(policyService))
}

func initUserService(cfg *config.AppConfig, auth *jwtauth.JwtAuth) (service pbUser.UserServiceServer, cleanup func(), err error) {
	panic(wire.Build(userService))
}

func initAuth(cfg *config.AppConfig) (service *jwtauth.JwtAuth) {
	panic(wire.Build(authSet))
}

func initPolicyGrpcClient(cfg *config.AppConfig) (service pbPolicy.PolicyServiceClient, cleanup func(), err error) {
	panic(wire.Build(policyGrpcClient))
}
