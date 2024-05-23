package services

import (
	"context"
	"testing"

	"github.com/0x726f6f6b6965/go-auth/policy"
	pbPolicy "github.com/0x726f6f6b6965/go-auth/protos/policy/v1"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestGetAllow(t *testing.T) {
	ser := initPolicyService()
	ctx := context.Background()

	t.Run("sucess", func(t *testing.T) {
		req := &pbPolicy.GetAllowRequest{
			Roles:    []pbPolicy.RoleType{pbPolicy.RoleType_ROLE_TYPE_NORMAL},
			Action:   pbPolicy.ActionType_ACTION_TYPE_READ,
			Resource: "/v1/user",
		}
		resp, err := ser.GetAllow(ctx, req)
		assert.Nil(t, err)
		assert.True(t, resp.Value)
	})
	t.Run("not allow by action", func(t *testing.T) {
		req := &pbPolicy.GetAllowRequest{
			Roles:    []pbPolicy.RoleType{pbPolicy.RoleType_ROLE_TYPE_NORMAL},
			Action:   pbPolicy.ActionType_ACTION_TYPE_DELETE,
			Resource: "/v1/user",
		}
		resp, err := ser.GetAllow(ctx, req)
		assert.Nil(t, err)
		assert.False(t, resp.Value)
	})

	t.Run("not allow by resource", func(t *testing.T) {
		req := &pbPolicy.GetAllowRequest{
			Roles:    []pbPolicy.RoleType{pbPolicy.RoleType_ROLE_TYPE_NORMAL},
			Action:   pbPolicy.ActionType_ACTION_TYPE_WRITE,
			Resource: "/v1/notExist",
		}
		resp, err := ser.GetAllow(ctx, req)
		assert.Nil(t, err)
		assert.False(t, resp.Value)
	})
	t.Run("invalid role", func(t *testing.T) {
		req := &pbPolicy.GetAllowRequest{
			Roles:    []pbPolicy.RoleType{-1},
			Action:   pbPolicy.ActionType_ACTION_TYPE_READ,
			Resource: "/v1/user",
		}
		_, err := ser.GetAllow(ctx, req)
		assert.NotNil(t, err)
		assert.ErrorIs(t, err, ErrorInvalid)
	})
	t.Run("invalid action", func(t *testing.T) {
		req := &pbPolicy.GetAllowRequest{
			Roles:    []pbPolicy.RoleType{1},
			Action:   -1,
			Resource: "/v1/user",
		}
		_, err := ser.GetAllow(ctx, req)
		assert.NotNil(t, err)
		assert.ErrorIs(t, err, ErrorInvalid)
	})
}

func TestGetPermissions(t *testing.T) {
	ser := initPolicyService()
	ctx := context.Background()
	t.Run("success", func(t *testing.T) {
		resp, err := ser.GetPermissions(ctx, nil)
		assert.Nil(t, err)
		data, err := policy.GetData()
		assert.Nil(t, err)
		grants := data[ROLE_GRANTS].(map[string]interface{})
		count := 0
		for _, grant := range grants {
			rules := grant.([]interface{})
			count += len(rules)
		}
		assert.Equal(t, count, len(resp.Permissions))
	})
}

func TestGetRolePermissions(t *testing.T) {
	ser := initPolicyService()
	ctx := context.Background()
	t.Run("success", func(t *testing.T) {
		req := &pbPolicy.GetRolePermissionsRequest{
			Role: pbPolicy.RoleType_ROLE_TYPE_NORMAL,
		}
		resp, err := ser.GetRolePermissions(ctx, req)
		assert.Nil(t, err)
		data, err := policy.GetData()
		assert.Nil(t, err)
		info := data[USER_ROLES].(map[string]interface{})
		roles := info[req.Role.String()].([]interface{})
		grants := data[ROLE_GRANTS].(map[string]interface{})
		count := 0
		for _, role := range roles {
			rules := grants[role.(string)].([]interface{})
			count += len(rules)
		}
		assert.Equal(t, count, len(resp.Permissions))
	})

	t.Run("role not exist", func(t *testing.T) {
		req := &pbPolicy.GetRolePermissionsRequest{
			Role: -1,
		}
		_, err := ser.GetRolePermissions(ctx, req)
		assert.NotNil(t, err)
		assert.ErrorIs(t, err, ErrorInvalid)
	})
}

func initPolicyService() pbPolicy.PolicyServiceServer {
	logger, _ := zap.NewDevelopment()
	ser := NewPolicyService(logger)
	return ser
}
