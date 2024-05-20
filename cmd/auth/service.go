package main

import (
	"fmt"
	"net"
	"net/http"

	"github.com/0x726f6f6b6965/go-auth/config"
	pbPolicy "github.com/0x726f6f6b6965/go-auth/protos/policy/v1"
	pbUser "github.com/0x726f6f6b6965/go-auth/protos/user/v1"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func RegisterPolicy(cfg *config.Grpc, service pbPolicy.PolicyServiceServer) error {
	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", cfg.Port))
	if err != nil {
		return err
	}
	server := grpc.NewServer()
	pbPolicy.RegisterPolicyServiceServer(server, service)
	server.Serve(lis)
	return nil
}

func RegisterUser(cfg *config.Grpc, service pbUser.UserServiceServer) error {
	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", cfg.Port))
	if err != nil {
		return err
	}
	server := grpc.NewServer()
	pbUser.RegisterUserServiceServer(server, service)
	server.Serve(lis)
	return nil
}

func RegisterPolicyClient(cfg *config.Grpc) (pbPolicy.PolicyServiceClient, func(), error) {
	conn, err := grpc.NewClient(fmt.Sprintf("localhost:%d", cfg.Port), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, func() {}, err
	}
	client := pbPolicy.NewPolicyServiceClient(conn)
	return client, func() { conn.Close() }, nil
}

func InitGin(cfg *config.AppConfig) *gin.Engine {
	gin.SetMode(func() string {
		if cfg.Env == "dev" {
			return gin.DebugMode
		}
		return gin.ReleaseMode
	}())
	engine := gin.New()
	engine.Use(cors.Default())
	engine.Use(gin.CustomRecovery(func(c *gin.Context, err interface{}) {
		c.AbortWithStatusJSON(http.StatusOK, gin.H{
			"code": 500,
			"msg":  "Service internal exception!",
		})
	}))
	return engine
}
