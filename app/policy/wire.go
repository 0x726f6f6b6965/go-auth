//go:build wireinject
// +build wireinject

package policy

import (
	"github.com/0x726f6f6b6965/go-auth/config"
	pbPolicy "github.com/0x726f6f6b6965/go-auth/protos/policy/v1"
	"github.com/google/wire"
)

func InitPolicyService(cfg *config.AppConfig) (service pbPolicy.PolicyServiceServer, cleanup func(), err error) {
	panic(wire.Build(policyService))
}
