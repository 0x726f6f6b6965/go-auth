package services

import (
	"errors"

	"github.com/0x726f6f6b6965/go-auth/internal/helper"
	"github.com/0x726f6f6b6965/go-auth/internal/services"
	jwtauth "github.com/0x726f6f6b6965/go-auth/pkg/jwt_auth"
	utils "github.com/0x726f6f6b6965/go-auth/pkg/response"
	pbUser "github.com/0x726f6f6b6965/go-auth/protos/user/v1"
	"github.com/gin-gonic/gin"
)

type UserAPI struct {
	user pbUser.UserServiceServer
}

func NewUserAPI(user pbUser.UserServiceServer) *UserAPI {
	api := &UserAPI{
		user: user,
	}
	return api
}

func (s *UserAPI) Login(ctx *gin.Context) {
	data := new(pbUser.LoginRequest)
	if err := ctx.ShouldBindJSON(data); err != nil {
		utils.InvalidParamErr.Message = "Please enter correct data."
		utils.Response(ctx, utils.SuccessCode, utils.InvalidParamErr, nil)
		return
	}
	if data.Email == "" || data.Password == "" {
		utils.InvalidParamErr.Message = "email or password is not correct."
		utils.Response(ctx, utils.SuccessCode, utils.InvalidParamErr, nil)
		return
	}
	token, err := s.user.Login(ctx, data)
	if err != nil {
		if errors.Is(err, services.ErrDB) ||
			errors.Is(err, services.ErrCreateToken) ||
			errors.Is(err, services.ErrSalt) {
			utils.InternalServerError.Message = "please try again later."
			utils.Response(ctx, utils.SuccessCode, utils.InternalServerError, nil)
			return
		}
		utils.InvalidParamErr.Message = "email or password is not correct."
		utils.Response(ctx, utils.SuccessCode, utils.InvalidParamErr, nil)
		return
	}
	utils.Response(ctx, utils.SuccessCode, utils.Success, token)
}

func (s *UserAPI) Register(ctx *gin.Context) {
	data := new(pbUser.CreateUserRequest)
	if err := ctx.ShouldBindJSON(data); err != nil {
		utils.InvalidParamErr.Message = "Please enter correct data."
		utils.Response(ctx, utils.SuccessCode, utils.InvalidParamErr, nil)
		return
	}

	if helper.Empty(data.Email) {
		utils.InvalidParamErr.Message = "email is empty."
		utils.Response(ctx, utils.SuccessCode, utils.InvalidParamErr, nil)
		return
	}

	if helper.Empty(data.Password) {
		utils.InvalidParamErr.Message = "password is empty."
		utils.Response(ctx, utils.SuccessCode, utils.InvalidParamErr, nil)
		return
	}

	if helper.Empty(data.Username) {
		utils.InvalidParamErr.Message = "username is empty."
		utils.Response(ctx, utils.SuccessCode, utils.InvalidParamErr, nil)
		return
	}

	if !helper.ValidEmailFormat(data.Email) {
		utils.InvalidParamErr.Message = "email format invalid."
		utils.Response(ctx, utils.SuccessCode, utils.InvalidParamErr, nil)
		return
	}
	token, err := s.user.CreateUser(ctx, data)
	if err != nil {
		if errors.Is(err, services.ErrDB) ||
			errors.Is(err, services.ErrCreateToken) ||
			errors.Is(err, services.ErrSalt) {
			utils.InternalServerError.Message = "please try again later."
			utils.Response(ctx, utils.SuccessCode, utils.InternalServerError, nil)
			return
		}
		if errors.Is(err, services.ErrRecordExist) {
			utils.InvalidParamErr.Message = "email has been used."
			utils.Response(ctx, utils.SuccessCode, utils.InvalidParamErr, nil)
			return
		}

		utils.Response(ctx, utils.SuccessCode, utils.InternalServerError, nil)
		return
	}
	utils.Response(ctx, utils.SuccessCode, utils.Success, token)
}

func (s *UserAPI) RefreshToken(ctx *gin.Context) {
	data := new(pbUser.UpdateTokenRequest)
	if info, ok := ctx.Get("token"); !ok {
		utils.InvalidParamErr.Message = "Please carry token."
		utils.Response(ctx, utils.SuccessCode, utils.InvalidParamErr, nil)
		return
	} else {
		claims := info.(*jwtauth.TokenMetadata)
		data.Subject = claims.Subject
		data.Roles = claims.Roles
	}

	token, err := s.user.UpdateToken(ctx, data)
	if err != nil {
		utils.InvalidParamErr.Message = "invalid token"
		utils.Response(ctx, utils.SuccessCode, utils.InvalidParamErr, nil)
		return
	}
	utils.Response(ctx, utils.SuccessCode, utils.Success, token)
}

func (s *UserAPI) UpdateUser(ctx *gin.Context) {
	data := new(pbUser.UpdateUserRequest)
	if err := ctx.ShouldBindJSON(data); err != nil {
		utils.InvalidParamErr.Message = "Please enter correct data."
		utils.Response(ctx, utils.SuccessCode, utils.InvalidParamErr, nil)
		return
	}
	if len(data.UpdateMask.GetPaths()) == 0 {
		utils.InvalidParamErr.Message = "update mask is empty."
		utils.Response(ctx, utils.SuccessCode, utils.InvalidParamErr, nil)
		return
	}

	if data.User == nil {
		utils.InvalidParamErr.Message = "user data is empty."
		utils.Response(ctx, utils.SuccessCode, utils.InvalidParamErr, nil)
		return
	}

	if helper.Empty(data.User.Email) {
		utils.InvalidParamErr.Message = "user email is empty."
		utils.Response(ctx, utils.SuccessCode, utils.InvalidParamErr, nil)
		return
	}

	_, err := s.user.UpdateUser(ctx, data)
	if err != nil {
		utils.InternalServerError.Message = "please try again later."
		utils.Response(ctx, utils.SuccessCode, utils.InternalServerError, nil)
		return
	}
	utils.Response(ctx, utils.SuccessCode, utils.Success, nil)
}
