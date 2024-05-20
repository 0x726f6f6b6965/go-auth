package services

import (
	"errors"

	"github.com/0x726f6f6b6965/go-auth/internal/helper"
	"github.com/0x726f6f6b6965/go-auth/internal/services"
	utils "github.com/0x726f6f6b6965/go-auth/pkg/response"
	pbPolicy "github.com/0x726f6f6b6965/go-auth/protos/policy/v1"
	"github.com/gin-gonic/gin"
	"google.golang.org/protobuf/types/known/emptypb"
)

type PolicyAPI struct {
	policy pbPolicy.PolicyServiceServer
}

func NewPolicyAPI(policy pbPolicy.PolicyServiceServer) *PolicyAPI {
	return &PolicyAPI{
		policy: policy,
	}
}

func (p *PolicyAPI) GetAllow(ctx *gin.Context) {
	data := new(pbPolicy.GetAllowRequest)
	if err := ctx.ShouldBindJSON(data); err != nil {
		utils.InvalidParamErr.Message = "Please enter correct data."
		utils.Response(ctx, utils.SuccessCode, utils.InvalidParamErr, nil)
		return
	}
	if len(data.Roles) == 0 {
		utils.InvalidParamErr.Message = "role is empty."
		utils.Response(ctx, utils.SuccessCode, utils.InvalidParamErr, nil)
		return
	}
	if data.Action == 0 {
		utils.InvalidParamErr.Message = "action is empty."
		utils.Response(ctx, utils.SuccessCode, utils.InvalidParamErr, nil)
		return
	}
	if helper.Empty(data.Resource) {
		utils.InvalidParamErr.Message = "resource is empty."
		utils.Response(ctx, utils.SuccessCode, utils.InvalidParamErr, nil)
		return
	}

	resp, err := p.policy.GetAllow(ctx, data)
	if err != nil {
		if errors.Is(err, services.ErrorInvalid) {
			utils.InvalidParamErr.Message = "data invalid."
			utils.Response(ctx, utils.SuccessCode, utils.InvalidParamErr, nil)
			return
		}
		utils.InternalServerError.Message = "please try again later"
		utils.Response(ctx, utils.SuccessCode, utils.InternalServerError, nil)
		return
	}
	utils.Response(ctx, utils.SuccessCode, utils.Success, resp)
}

func (p *PolicyAPI) GetPermissions(ctx *gin.Context) {
	resp, err := p.policy.GetPermissions(ctx, &emptypb.Empty{})
	if err != nil {
		utils.InternalServerError.Message = "please try again later"
		utils.Response(ctx, utils.SuccessCode, utils.InternalServerError, nil)
		return
	}
	utils.Response(ctx, utils.SuccessCode, utils.Success, resp)
}

func (p *PolicyAPI) GetRolePermissions(ctx *gin.Context) {
	data := ctx.Query("role")
	if helper.Empty(data) {
		utils.InvalidParamErr.Message = "role is empty."
		utils.Response(ctx, utils.SuccessCode, utils.InvalidParamErr, nil)
		return
	}
	role := pbPolicy.RoleType_value[data]
	if role == 0 {
		utils.InvalidParamErr.Message = "role is invalid."
		utils.Response(ctx, utils.SuccessCode, utils.InvalidParamErr, nil)
		return
	}
	resp, err := p.policy.GetRolePermissions(ctx,
		&pbPolicy.GetRolePermissionsRequest{Role: pbPolicy.RoleType(role)})
	if err != nil {
		utils.InternalServerError.Message = "please try again later"
		utils.Response(ctx, utils.SuccessCode, utils.InternalServerError, nil)
		return
	}
	utils.Response(ctx, utils.SuccessCode, utils.Success, resp)
}
