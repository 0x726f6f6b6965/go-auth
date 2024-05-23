package middleware

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/0x726f6f6b6965/go-auth/pkg/cache"
	jwtauth "github.com/0x726f6f6b6965/go-auth/pkg/jwt-auth"
	pbPolicy "github.com/0x726f6f6b6965/go-auth/protos/policy/v1"
	"github.com/gin-gonic/gin"
)

type AuthMiddleware struct {
	auth   *jwtauth.JwtAuth
	client pbPolicy.PolicyServiceClient
	cache  cache.Cache
}

func NewAuthMiddleware(auth *jwtauth.JwtAuth, client pbPolicy.PolicyServiceClient, cache cache.Cache) *AuthMiddleware {
	return &AuthMiddleware{
		auth:   auth,
		client: client,
		cache:  cache,
	}
}

func (m *AuthMiddleware) UserAuthorization(isRefresh bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		// check logout
		if m.isLogout(c, c.Request) {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		token, err := m.auth.ExtractTokenMetadata(c.Request, isRefresh)
		if err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		roles := []pbPolicy.RoleType{}
		for _, role := range token.Roles {
			roles = append(roles, pbPolicy.RoleType(pbPolicy.RoleType_value[role]))
		}
		var action pbPolicy.ActionType
		switch c.Request.Method {
		case "GET":
			action = pbPolicy.ActionType_ACTION_TYPE_READ
		case "POST":
			action = pbPolicy.ActionType_ACTION_TYPE_WRITE
		case "PUT":
			action = pbPolicy.ActionType_ACTION_TYPE_WRITE
		case "PATCH":
			action = pbPolicy.ActionType_ACTION_TYPE_WRITE
		case "DELETE":
			action = pbPolicy.ActionType_ACTION_TYPE_DELETE
		default:
			action = pbPolicy.ActionType_ACTION_TYPE_UNSPECIFIED
		}
		allow, err := m.client.GetAllow(c, &pbPolicy.GetAllowRequest{
			Roles:    roles,
			Action:   action,
			Resource: c.Request.URL.Path,
		})
		if err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		if !allow.Value {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Next()
	}
}

func (m *AuthMiddleware) isLogout(ctx context.Context, r *http.Request) bool {
	bearToken := r.Header.Get("Authorization")
	strArr := strings.Split(bearToken, " ")

	isEmpty := bearToken == "" || len(strArr) < 2

	if isEmpty {
		return false
	}

	_, err := m.cache.Get(ctx, strArr[1])
	if err != nil && errors.Is(err, cache.ErrKeyNotFound) {
		return true
	}

	return false
}
