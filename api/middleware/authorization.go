package middleware

import (
	"net/http"

	jwtauth "github.com/0x726f6f6b6965/go-auth/pkg/jwt_auth"
	pbPolicy "github.com/0x726f6f6b6965/go-auth/protos/policy/v1"
	"github.com/gin-gonic/gin"
)

func UserAuthorization(auth *jwtauth.JwtAuth, isRefresh bool, client pbPolicy.PolicyServiceClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := auth.ExtractTokenMetadata(c.Request, isRefresh)
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
		allow, err := client.GetAllow(c, &pbPolicy.GetAllowRequest{
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
		c.Set("token", token)
		c.Next()
	}
}
