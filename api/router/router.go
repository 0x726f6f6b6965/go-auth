package router

import (
	"github.com/0x726f6f6b6965/go-auth/api/middleware"
	"github.com/0x726f6f6b6965/go-auth/api/services"
	jwtauth "github.com/0x726f6f6b6965/go-auth/pkg/jwt_auth"
	pbPolicy "github.com/0x726f6f6b6965/go-auth/protos/policy/v1"
	"github.com/gin-gonic/gin"
)

var (
	userAPI      *services.UserAPI
	policyAPI    *services.PolicyAPI
	policyClient pbPolicy.PolicyServiceClient
	auth         *jwtauth.JwtAuth
)

func RegisterRoutes(server *gin.Engine) {
	RegisterAuthRouter(server.Group("/v1/auth/"))
	RegisterUserRouter(server.Group("/v1/user/"))
	RegisterTokenRouter(server.Group("/v1/token/"))
}

func RegisterAuthRouter(group *gin.RouterGroup) {
	group.POST("/register", userAPI.Register)
	group.POST("/login", userAPI.Login)
}

func RegisterUserRouter(group *gin.RouterGroup) {
	group.Use(middleware.UserAuthorization(auth, false, policyClient))
	group.POST("/update", userAPI.UpdateUser)
}

func RegisterTokenRouter(group *gin.RouterGroup) {
	group.Use(middleware.UserAuthorization(auth, true, policyClient))
	group.GET("/refresh", userAPI.RefreshToken)
}

func SetUserAPI(api *services.UserAPI) {
	userAPI = api
}
func SetPolicyAPI(api *services.PolicyAPI) {
	policyAPI = api
}

func SetPolicyClient(client pbPolicy.PolicyServiceClient) {
	policyClient = client
}
func SetJwtAuth(ser *jwtauth.JwtAuth) {
	auth = ser
}
