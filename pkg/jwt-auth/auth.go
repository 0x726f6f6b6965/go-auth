package jwtauth

import (
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type ClaimsWithRoles struct {
	jwt.RegisteredClaims
	Roles []string `json:"role"`
}

type TokenMetadata struct {
	ExpiresAt time.Time
	Subject   string
	Roles     []string
}

type JwtAuth struct {
	issuer        string
	accessSecret  string
	refreshSecret string
	refreshExpire time.Duration
	accessExpire  time.Duration
}

func NewJWTAuth(cfg *Config) *JwtAuth {
	return &JwtAuth{
		issuer:        cfg.Issuer,
		accessSecret:  os.Getenv(cfg.AccessSecret),
		refreshSecret: os.Getenv(cfg.RefreshSecret),
		accessExpire:  time.Duration(cfg.ExpiresIn) * time.Second,
		refreshExpire: time.Duration(cfg.ExpiresIn) * time.Second * 2,
	}
}

func (auth *JwtAuth) GenerateNewAccessToken(user string, roles []string) (string, error) {
	token := auth.generateToken(user, roles, auth.accessExpire)
	return token.SignedString([]byte(auth.accessSecret))
}

func (auth *JwtAuth) GenerateNewRefreshToken(user string, roles []string) (string, error) {
	token := auth.generateToken(user, roles, auth.refreshExpire)
	return token.SignedString([]byte(auth.refreshSecret))
}

func (auth *JwtAuth) GetAccessExpire() time.Duration {
	return auth.accessExpire
}

func (auth *JwtAuth) GetRefreshExpire() time.Duration {
	return auth.refreshExpire
}

func (auth *JwtAuth) SetAccessExpire(expire time.Duration) {
	auth.accessExpire = expire
}

func (auth *JwtAuth) SetRefreshExpire(expire time.Duration) {
	auth.refreshExpire = expire
}

func (auth *JwtAuth) generateToken(user string, roles []string, times time.Duration) *jwt.Token {
	claims := ClaimsWithRoles{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    auth.issuer,
			Subject:   user,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(times)),
		},
		Roles: roles,
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
}

func (auth *JwtAuth) ExtractTokenMetadata(r *http.Request, isRefresh bool) (*TokenMetadata, error) {
	tokenString := extractToken(r)
	token, err := auth.VerifyToken(tokenString, isRefresh)
	if err != nil {
		switch {
		case errors.Is(err, jwt.ErrTokenExpired):
			return nil, ErrTokenExpired
		case errors.Is(err, jwt.ErrSignatureInvalid):
			return nil, ErrTokenInvalid
		case errors.Is(err, jwt.ErrTokenNotValidYet):
			return nil, ErrTokenNotValidYet
		default:
			return nil, err
		}
	}
	if !token.Valid {
		return nil, ErrTokenNotValid
	}
	claims, ok := token.Claims.(*ClaimsWithRoles)
	if !ok {
		return nil, ErrTokenParse
	}
	return &TokenMetadata{
		ExpiresAt: claims.ExpiresAt.Time,
		Subject:   claims.Subject,
		Roles:     claims.Roles,
	}, nil
}

func (auth *JwtAuth) VerifyToken(token string, isRefresh bool) (*jwt.Token, error) {
	if isRefresh {
		return jwt.ParseWithClaims(token, &ClaimsWithRoles{}, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return []byte(auth.refreshSecret), nil
		})
	}
	return jwt.ParseWithClaims(token, &ClaimsWithRoles{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(auth.accessSecret), nil
	})
}

func extractToken(r *http.Request) string {
	bearToken := r.Header.Get("Authorization")
	strArr := strings.Split(bearToken, " ")

	isEmpty := bearToken == "" || len(strArr) < 2

	if isEmpty {
		return ""
	}

	return strArr[1]
}
