package router

import (
	"github.com/0x726f6f6b6965/go-auth/app/api/middleware"
	"github.com/0x726f6f6b6965/go-auth/app/api/services"
	jwtauth "github.com/0x726f6f6b6965/go-auth/pkg/jwt-auth"
	"github.com/gin-gonic/gin"
)

type router struct {
	userAPI *services.UserAPI
	middle  *middleware.AuthMiddleware
	auth    *jwtauth.JwtAuth
}

func NewRouter(userAPI *services.UserAPI, auth *jwtauth.JwtAuth, middle *middleware.AuthMiddleware) *router {
	return &router{
		userAPI: userAPI,
		middle:  middle,
		auth:    auth,
	}
}

func (r *router) RegisterRoutes(server *gin.Engine) {
	r.registerAuthRouter(server.Group("/v1/auth/"))
	r.registerUserRouter(server.Group("/v1/user/"))
	r.registerTokenRouter(server.Group("/v1/token/"))
}

func (r *router) registerAuthRouter(group *gin.RouterGroup) {
	group.POST("/register", r.userAPI.Register)
	group.POST("/login", r.userAPI.Login)
}

func (r *router) registerUserRouter(group *gin.RouterGroup) {
	group.Use(r.middle.UserAuthorization(false))
	group.POST("/update", r.userAPI.UpdateUser)
}

func (r *router) registerTokenRouter(group *gin.RouterGroup) {
	group.Use(r.middle.UserAuthorization(true))
	group.GET("/refresh", r.userAPI.RefreshToken)
}

func (r *router) SetUserAPI(api *services.UserAPI) {
	r.userAPI = api
}

func (r *router) SetJwtAuth(ser *jwtauth.JwtAuth) {
	r.auth = ser
}
