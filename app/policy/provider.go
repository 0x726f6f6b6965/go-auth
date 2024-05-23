package policy

import (
	"github.com/0x726f6f6b6965/go-auth/config"
	"github.com/0x726f6f6b6965/go-auth/internal/services"
	"github.com/0x726f6f6b6965/go-auth/pkg/logger"
	"github.com/google/wire"
)

var policyService = wire.NewSet(loggerSet, services.NewPolicyService)

var loggerSet = wire.NewSet(logConfig, logger.NewLogger)

func logConfig(cfg *config.AppConfig) *config.LogConfig {
	return &cfg.Log
}
