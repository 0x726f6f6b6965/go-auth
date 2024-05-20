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
	duration      time.Duration
}

func NewJWTAuth(cfg *Config) *JwtAuth {
	return &JwtAuth{
		issuer:        cfg.Issuer,
		accessSecret:  os.Getenv(cfg.AccessSecret),
		refreshSecret: os.Getenv(cfg.RefreshSecret),
		duration:      time.Duration(cfg.ExpiresIn) * time.Second,
	}
}

func (auth *JwtAuth) GenerateNewAccessToken(user string, roles []string) (string, error) {
	token := auth.generateToken(user, roles, 1)
	return token.SignedString([]byte(auth.accessSecret))
}

func (auth *JwtAuth) GenerateNewRefreshToken(user string, roles []string) (string, error) {
	token := auth.generateToken(user, roles, 2)
	return token.SignedString([]byte(auth.refreshSecret))
}

func (auth *JwtAuth) generateToken(user string, roles []string, times time.Duration) *jwt.Token {
	claims := ClaimsWithRoles{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    auth.issuer,
			Subject:   user,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(auth.duration * times)),
		},
		Roles: roles,
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
}

func (auth *JwtAuth) ExtractTokenMetadata(r *http.Request, isRefresh bool) (*TokenMetadata, error) {
	token, err := auth.verifyToken(r, isRefresh)
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

func (auth *JwtAuth) verifyToken(r *http.Request, isRefresh bool) (*jwt.Token, error) {
	tokenString := extractToken(r)
	if isRefresh {
		return jwt.ParseWithClaims(tokenString, &ClaimsWithRoles{}, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return []byte(auth.refreshSecret), nil
		})
	}
	return jwt.ParseWithClaims(tokenString, &ClaimsWithRoles{}, func(t *jwt.Token) (interface{}, error) {
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
