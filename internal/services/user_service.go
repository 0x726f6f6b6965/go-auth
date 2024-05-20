package services

import (
	"context"
	"errors"
	"strings"

	"github.com/0x726f6f6b6965/go-auth/internal/helper"
	"github.com/0x726f6f6b6965/go-auth/internal/storage/models"
	"github.com/0x726f6f6b6965/go-auth/internal/storage/user"
	jwtauth "github.com/0x726f6f6b6965/go-auth/pkg/jwt_auth"
	"github.com/0x726f6f6b6965/go-auth/pkg/mask"
	pbPolicy "github.com/0x726f6f6b6965/go-auth/protos/policy/v1"
	pb "github.com/0x726f6f6b6965/go-auth/protos/user/v1"
	"github.com/iancoleman/strcase"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/emptypb"
	"gorm.io/gorm"
)

var (
	ROLE_DEFAULT = pbPolicy.RoleType_ROLE_TYPE_NORMAL.String()
	testSalt     *helper.Salt
)

const (
	TAG_DB = "gorm"
)

type userService struct {
	pb.UnimplementedUserServiceServer
	logger *zap.Logger
	store  *user.SotrageUsers
	auth   *jwtauth.JwtAuth
}

func NewUserService(auth *jwtauth.JwtAuth, db *gorm.DB, logger *zap.Logger) pb.UserServiceServer {
	store := user.New(db)
	return &userService{
		logger: logger,
		store:  store,
		auth:   auth,
	}
}

// CreateUser: create a new user account.
func (s *userService) CreateUser(ctx context.Context, req *pb.CreateUserRequest) (*pb.Token, error) {
	// check if user already exists
	_, err := s.store.GetUserInfo(req.Email)
	if err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			s.logger.Error("CreateUser: error getting user",
				zap.Any("request", req),
				zap.Error(err))
			return nil, errors.Join(ErrDB, err)
		}
	} else {
		return nil, ErrRecordExist
	}

	// salt pwd
	var salt *helper.Salt
	if testSalt == nil {
		salt = helper.CreateNewSalt()
	} else {
		salt = testSalt
	}
	pwd, err := salt.SaltInput(req.Password)
	if err != nil {
		s.logger.Error("CreateUser: error hashing password",
			zap.Any("request", req),
			zap.Error(err))
		return nil, errors.Join(ErrSalt, err)
	}
	//insert data
	insertData := models.UserWithRoles{
		User: models.User{
			Username: req.Username,
			Email:    req.Email,
			Password: pwd,
			Salt:     salt.SaltString,
		},
		Roles: []models.Role{{RoleName: ROLE_DEFAULT}},
	}

	user, err := s.store.InsertUserWithRoles(insertData)
	if err != nil {
		s.logger.Error("CreateUser: error inserting user",
			zap.Any("request", req),
			zap.Error(err))
		return nil, errors.Join(ErrDB, err)
	}

	roles := []string{}
	for _, role := range user.Roles {
		roles = append(roles, role.RoleName)
	}
	return s.generateToken(user.Email, roles)
}

// Login: get a validate token based on user information.
func (s *userService) Login(ctx context.Context, req *pb.LoginRequest) (*pb.Token, error) {
	user, err := s.store.GetUserInfoWithRoles(req.Email)
	if err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			s.logger.Error("Login: error getting user",
				zap.String("email", req.Email),
				zap.Error(err))
			return nil, errors.Join(ErrDB, err)
		} else {
			return nil, ErrRecordNotFound
		}
	}

	slat, err := helper.CreateSaltByString(user.Salt)
	if err != nil {
		return nil, errors.Join(ErrSalt, err)
	}
	if pwd, _ := slat.SaltInput(req.Password); pwd != user.Password {
		return nil, ErrPassword
	}
	roles := []string{}
	for _, role := range user.Roles {
		roles = append(roles, role.RoleName)
	}
	return s.generateToken(user.Email, roles)
}

// Logout implements v1.UserServiceServer.
func (u *userService) Logout(context.Context, *pb.LogoutRequest) (*emptypb.Empty, error) {
	panic("unimplemented")
}

// UpdateToken: update a used verified token to extend its expiration.
func (u *userService) UpdateToken(ctx context.Context, req *pb.UpdateTokenRequest) (*pb.Token, error) {
	access, err := u.auth.GenerateNewAccessToken(req.Subject, req.Roles)
	if err != nil {
		u.logger.Error("UpdateToken: error generating new access token",
			zap.Any("request", req),
			zap.Error(err))
		return nil, errors.Join(ErrCreateToken, err)
	}
	return &pb.Token{AccessToken: access}, nil
}

// UpdateUser: update user information
func (s *userService) UpdateUser(ctx context.Context, req *pb.UpdateUserRequest) (*emptypb.Empty, error) {
	if len(req.UpdateMask.GetPaths()) == 0 {
		return nil, errors.Join(ErrorInvalid, errors.New("update_mask is empty"))
	}
	if req.User == nil {
		return nil, errors.Join(ErrorInvalid, errors.New("user is empty"))
	}
	data, err := mask.GetValueByMask(req, req.UpdateMask, strcase.ToCamel)
	if err != nil {
		s.logger.Error("UpdateUser: error getting data",
			zap.Any("update_mask", req.UpdateMask),
			zap.Error(err))
		return nil, errors.Join(ErrorInvalid, err)
	}
	email := req.User.Email
	user, err := s.store.GetUserInfo(email)
	if err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			s.logger.Error("UpdateUser: error getting user",
				zap.String("email", email),
				zap.Error(err))
			return nil, errors.Join(ErrDB, err)
		} else {
			return nil, ErrRecordNotFound
		}
	}

	dbData := make(map[string]interface{})
	for key, val := range data {
		if key == "user.email" {
			continue
		}
		fields := strings.Split(key, ".")
		if len(fields) != 2 || fields[0] != "user" {
			continue
		}
		dbField := helper.GetNameByTag(strcase.ToCamel(fields[1]), TAG_DB, models.User{})
		dbData[dbField] = val
	}
	err = s.store.UpdateUser(user.Id, dbData)
	if err != nil {
		s.logger.Error("UpdateUser: error updating user",
			zap.String("email", email),
			zap.Error(err))
		return nil, errors.Join(ErrDB, err)
	}
	return &emptypb.Empty{}, nil
}

func (s *userService) generateToken(email string, roles []string) (*pb.Token, error) {
	access, err := s.auth.GenerateNewAccessToken(email, roles)
	if err != nil {
		s.logger.Error("generateToken: error generating access token",
			zap.String("email", email),
			zap.Error(err))
		return nil, errors.Join(ErrCreateToken, err)
	}
	refresh, err := s.auth.GenerateNewRefreshToken(email, roles)
	if err != nil {
		s.logger.Error("generateToken: error generating refresh token",
			zap.String("email", email),
			zap.Error(err))
		return nil, errors.Join(ErrCreateToken, err)
	}
	tokens := &pb.Token{
		AccessToken:  access,
		RefreshToken: refresh,
	}
	return tokens, nil
}
