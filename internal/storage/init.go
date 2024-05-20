package storage

import (
	"fmt"
	"os"

	"github.com/0x726f6f6b6965/go-auth/config"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func NewPostgres(cfg *config.DBConfig) (*gorm.DB, error) {
	dsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%d sslmode=%s",
		cfg.Host, cfg.User, os.Getenv(cfg.Password), cfg.DBName,
		cfg.Port, cfg.SSLmode,
	)
	return gorm.Open(postgres.Open(dsn), &gorm.Config{})
}
