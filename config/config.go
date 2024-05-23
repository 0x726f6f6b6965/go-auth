package config

import jwtauth "github.com/0x726f6f6b6965/go-auth/pkg/jwt-auth"

type AppConfig struct {
	Env      string         `yaml:"env" mapstructure:"env" cobra-usage:"the application environment" cobra-default:"dev"`
	HttpPort uint64         `yaml:"http-port" mapstructure:"grpc-port" validate:"required,gte=0" cobra-usage:"the application port" cobra-default:"8080"`
	GrpcPort uint64         `yaml:"grpc-port" mapstructure:"grpc-port"`
	Log      LogConfig      `yaml:"log" mapstructure:"log"`
	DB       DBConfig       `yaml:"db" mapstructure:"db"`
	Jwt      jwtauth.Config `yaml:"jwt" mapstructure:"jwt"`
	Redis    RedisConfig    `yaml:"redis" mapstructure:"redis"`
}

type DBConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	DBName   string `yaml:"db-name"`
	SSLmode  string `yaml:"ssl-mode" default:"disable"`
}

type LogConfig struct {
	Level            int    `yaml:"level" mapstructure:"level" validate:"omitempty,gte=-1,lte=5" cobra-usage:"the application log level" cobra-default:"1"`
	TimeFormat       string `yaml:"time-format" mapstructure:"time-format" cobra-usage:"the application log time format" cobra-default:"2006-01-02T15:04:05Z07:00"`
	TimestampEnabled bool   `yaml:"timestamp-enabled" mapstructure:"timestamp-enabled" cobra-usage:"specify if the timestamp is enabled"  cobra-default:"false"`
	ServiceName      string `yaml:"service-name" mapstructure:"service-name" cobra-usage:"the application service name" cobra-default:""`
}

type RedisConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Password string `yaml:"password"`
	DBNum    int    `yaml:"db-num"`
	PoolSize int    `yaml:"pool-size"`
}
