package main

import (
	"fmt"
	"log"
	"os"

	"github.com/0x726f6f6b6965/go-auth/api/router"
	"github.com/0x726f6f6b6965/go-auth/config"
	"github.com/joho/godotenv"
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
	auth := initAuth(cfg)

	policy, cleanup, err := initPolicyService(cfg)
	if err != nil {
		log.Fatal("init policy service error", err)
		return
	}
	defer cleanup()
	go func() {
		err = RegisterPolicy(&cfg.PolicyGrpc, policy)
		if err != nil {
			log.Fatal("init policy grpc error", err)
			return
		}
	}()
	user, cleanup2, err := initUserService(cfg, auth)
	if err != nil {
		log.Fatal("init user service error", err)
		return
	}
	defer cleanup2()
	go func() {
		err = RegisterUser(&cfg.Grpc, user)
		if err != nil {
			log.Fatal("init user grpc error", err)
			return
		}
	}()

	userAPI, err := initUserAPI(user)
	if err != nil {
		log.Fatal("init user api error", err)
		return
	}

	policyAPI, err := initPolicyAPI(policy)
	if err != nil {
		log.Fatal("init policy api error", err)
		return
	}

	policyGrpcClient, cleanup3, err := initPolicyGrpcClient(cfg)
	if err != nil {
		log.Fatal("init policy grpc client error", err)
		return
	}
	defer cleanup3()

	engine, err := initGin(cfg)
	if err != nil {
		log.Fatal("init gin engine error", err)
		return
	}
	router.SetPolicyAPI(policyAPI)
	router.SetUserAPI(userAPI)
	router.SetJwtAuth(auth)
	router.SetPolicyClient(policyGrpcClient)

	router.RegisterRoutes(engine)

	engine.Run(fmt.Sprintf(":%d", cfg.Port))

}
