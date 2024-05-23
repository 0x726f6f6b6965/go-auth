package jwtauth

type Config struct {
	Issuer        string `yaml:"issuer" mapstructure:"issuer" validate:"required" cobra-usage:"the application issuer" cobra-default:""`
	ExpiresIn     int64  `yaml:"expires-in" mapstructure:"expires-in" validate:"required" cobra-usage:"the application expires in" cobra-default:"86400"`
	AccessSecret  string `yaml:"access-secret" mapstructure:"access-secret" validate:"required" cobra-usage:"the application access secret" cobra-default:""`
	RefreshSecret string `yaml:"refresh-secret" mapstructure:"refresh-secret" validate:"required" cobra-usage:"the application refresh secret" cobra-default:""`
}
