package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/0x726f6f6b6965/go-auth/app/api"
	"github.com/0x726f6f6b6965/go-auth/app/api/router"
	"github.com/0x726f6f6b6965/go-auth/app/api/services"
	"github.com/0x726f6f6b6965/go-auth/app/policy"
	"github.com/0x726f6f6b6965/go-auth/app/user"
	"github.com/0x726f6f6b6965/go-auth/config"
	pbPolicy "github.com/0x726f6f6b6965/go-auth/protos/policy/v1"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"google.golang.org/grpc"
	"gopkg.in/yaml.v3"
)

func main() {
	godotenv.Load()
	path := os.Getenv("CONFIG")
	cfg := new(config.AppConfig)
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatal("read yaml error", err)
		return
	}
	err = yaml.Unmarshal(data, &cfg)
	if err != nil {
		log.Fatal("unmarshal yaml error", err)
		return
	}
	auth := api.InitJwtAuth(cfg)

	cacheStorage, cacheCleanup, err := api.InitCache(cfg)
	if err != nil {
		log.Fatal("init cache error", err)
		return
	}
	defer cacheCleanup()

	policyService, policyCleanup, err := policy.InitPolicyService(cfg)
	if err != nil {
		log.Fatal("init policy service error", err)
		return
	}
	defer policyCleanup()

	policyCfg := getPolicyGrpcConfig(cfg)
	go func() {
		err = RegisterPolicy(policyCfg, policyService)
		if err != nil {
			log.Fatal("register policy error", err)
			return
		}
	}()
	userService, userCleanup, err := user.InitUserService(cfg, auth, cacheStorage)
	if err != nil {
		log.Fatal("init user service error", err)
		return
	}
	defer userCleanup()

	middle, middleCleanup, err := api.InitMiddleware(cfg, auth, cacheStorage)
	if err != nil {
		log.Fatal("init middleware error", err)
		return
	}
	defer middleCleanup()

	userAPI := services.NewUserAPI(userService)
	router := router.NewRouter(userAPI, auth, middle)

	engine := InitGin(cfg)
	router.RegisterRoutes(engine)

	engine.Run(fmt.Sprintf(":%d", cfg.HttpPort))
}

func RegisterPolicy(cfg *config.Grpc, service pbPolicy.PolicyServiceServer) error {
	lis, err := net.Listen("tcp", fmt.Sprintf("%s:%d", cfg.Host, cfg.Port))
	if err != nil {
		return err
	}
	server := grpc.NewServer()
	pbPolicy.RegisterPolicyServiceServer(server, service)
	server.Serve(lis)
	return nil
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

func getPolicyGrpcConfig(cfg *config.AppConfig) *config.Grpc {
	policy := cfg.Clients["policy-client"]
	return &policy
}
