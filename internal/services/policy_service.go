package services

import (
	"context"
	"errors"
	"fmt"

	"github.com/0x726f6f6b6965/go-auth/policy"
	pb "github.com/0x726f6f6b6965/go-auth/protos/policy/v1"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	USER_ROLES    = "user_roles"
	ROLE_GRANTS   = "role_grants"
	DEFAULT_QUERY = "x = data.rbac.authz.allow"
)

type policyService struct {
	pb.UnimplementedPolicyServiceServer
	logger *zap.Logger
	rbac   *rego.Rego
	data   storage.Store
}

func NewPolicyService(logger *zap.Logger) pb.PolicyServiceServer {
	file := policy.GetRbac()
	data, _ := policy.GetStorage()
	rbac := rego.New(
		rego.Query(DEFAULT_QUERY),
		rego.Store(data),
		rego.Module("rbac.authz.rego", string(file)))

	rbac.PrepareForEval(context.Background())
	return &policyService{
		logger: logger,
		rbac:   rbac,
		data:   data,
	}
}

// GetAllow: get the result of whether
// the role has permission to perform actions on the resource.
func (s *policyService) GetAllow(ctx context.Context, req *pb.GetAllowRequest) (*wrapperspb.BoolValue, error) {
	resp := &wrapperspb.BoolValue{Value: false}
	valid := []int32{}
	for _, role := range req.Roles {
		if val, exist := pb.RoleType_value[role.String()]; exist {
			valid = append(valid, val)
		}
	}
	if len(valid) == 0 {
		return resp, errors.Join(ErrorInvalid,
			fmt.Errorf("roles: %v", req.Roles))
	}

	if _, exist := pb.ActionType_value[req.Action.String()]; !exist {
		return resp, errors.Join(ErrorInvalid,
			fmt.Errorf("action: %s", req.Action.String()))
	}
	query, err := s.rbac.PrepareForEval(ctx)
	if err != nil {
		s.logger.Error("GetAllow: error prepare eval",
			zap.Any("request", req),
			zap.Error(err))
		return resp, errors.Join(ErrorOPA, err)
	}
	for _, role := range valid {
		data := map[string]interface{}{
			"role":     pb.RoleType_name[role],
			"action":   req.Action.String(),
			"resource": req.Resource,
		}
		result, err := query.Eval(ctx, rego.EvalInput(data))
		if err != nil {
			s.logger.Error("GetAllow: error eval",
				zap.Any("request", req),
				zap.Error(err))
			return resp, errors.Join(ErrorOPA, err)
		}
		if result[0].Bindings["x"].(bool) {
			resp.Value = true
			break
		}
	}
	return resp, nil
}

// GetPermissions: get all permissions
func (s *policyService) GetPermissions(ctx context.Context, req *emptypb.Empty) (*pb.GetPermissionsResponse, error) {
	txn, err := s.data.NewTransaction(ctx)
	if err != nil {
		s.logger.Error("GetPermissions: error new transaction",
			zap.Error(err))
		return nil, errors.Join(ErrorTransaction, err)
	}

	// Cancel transaction because no writes are performed.
	defer s.data.Abort(ctx, txn)
	info, err := s.data.Read(ctx, txn, storage.Path{ROLE_GRANTS})
	if err != nil {
		s.logger.Error("GetPermissions: error read",
			zap.Error(err))
		return nil, errors.Join(ErrorOPA, err)
	}

	permissions, ok := info.(map[string]interface{})
	if !ok {
		s.logger.Error("GetPermissions: error parse",
			zap.Any("data", info))
		return nil, errors.Join(ErrorInvalid, errors.New("error parse data"))
	}
	resp := &pb.GetPermissionsResponse{
		Permissions: make([]*pb.Permission, 0),
	}
	for key, val := range permissions {
		rules, ok := val.([]interface{})
		if !ok {
			s.logger.Error("GetPermissions: error parse",
				zap.Any("data", val))
			return nil, errors.Join(ErrorInvalid, errors.New("error parse permission list"))
		}
		for _, rule := range rules {
			r, ok := rule.(map[string]interface{})
			if !ok {
				s.logger.Error("GetPermissions: error parse",
					zap.Any("data", rule))
				return nil, errors.Join(ErrorInvalid, errors.New("error parse permission"))
			}
			p := &pb.Permission{
				Name: key,
			}
			for k, v := range r {
				if k == "action" {
					p.Action = pb.ActionType(pb.ActionType_value[v.(string)])
				} else if k == "resource" {
					p.Resource = v.(string)
				}
			}
			resp.Permissions = append(resp.Permissions, p)
		}
	}
	return resp, nil
}

// GetRolePermissions implements v1.PolicyServiceServer.
func (s *policyService) GetRolePermissions(ctx context.Context, req *pb.GetRolePermissionsRequest) (*pb.RolePermissions, error) {
	if _, exist := pb.RoleType_value[req.Role.String()]; !exist {
		return nil, errors.Join(ErrorInvalid,
			fmt.Errorf("role: %s", req.Role.String()))
	}

	txn, err := s.data.NewTransaction(ctx)
	if err != nil {
		s.logger.Error("GetRolePermissions: error new transaction",
			zap.Any("request", req),
			zap.Error(err))
		return nil, errors.Join(ErrorTransaction, err)
	}

	// Cancel transaction because no writes are performed.
	defer s.data.Abort(ctx, txn)
	info, err := s.data.Read(ctx, txn, storage.Path{USER_ROLES, req.Role.String()})
	if err != nil {
		s.logger.Error("GetRolePermissions: error read",
			zap.Any("request", req),
			zap.Error(err))
		return nil, errors.Join(ErrorOPA, err)
	}

	rules, ok := info.([]interface{})
	if !ok {
		s.logger.Error("GetRolePermissions: error parse",
			zap.Any("data", info))
		return nil, errors.Join(ErrorInvalid, errors.New("error parse data"))
	}
	resp := &pb.RolePermissions{
		Role:        req.Role,
		Permissions: make([]*pb.Permission, 0),
	}
	for _, val := range rules {
		rule, ok := val.(string)
		if !ok {
			s.logger.Error("GetRolePermissions: error parse",
				zap.Any("data", val))
			return nil, errors.Join(ErrorInvalid, errors.New("error parse permission name"))
		}
		ruleInfo, err := s.data.Read(ctx, txn, storage.Path{ROLE_GRANTS, rule})
		if err != nil {
			s.logger.Error("GetRolePermissions: error read permission",
				zap.String("permission name", rule),
				zap.Error(err))
			return nil, errors.Join(ErrorOPA, err)
		}
		permissions, ok := ruleInfo.([]interface{})
		if !ok {
			s.logger.Error("GetRolePermissions: error parse",
				zap.Any("data", ruleInfo))
			return nil, errors.Join(ErrorInvalid, errors.New("error parse permission list"))
		}
		for _, permission := range permissions {
			r, ok := permission.(map[string]interface{})
			if !ok {
				s.logger.Error("GetRolePermissions: error parse",
					zap.Any("data", permission))
				return nil, errors.Join(ErrorInvalid, errors.New("error parse permission"))
			}
			p := &pb.Permission{
				Name: rule,
			}
			for k, v := range r {
				if k == "action" {
					p.Action = pb.ActionType(pb.ActionType_value[v.(string)])
				} else if k == "resource" {
					p.Resource = v.(string)
				}
			}
			resp.Permissions = append(resp.Permissions, p)
		}
	}
	return resp, nil
}
