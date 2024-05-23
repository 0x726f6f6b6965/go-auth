package services

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/0x726f6f6b6965/go-auth/internal/helper"
	"github.com/0x726f6f6b6965/go-auth/pkg/cache"
	jwtauth "github.com/0x726f6f6b6965/go-auth/pkg/jwt-auth"
	pbPolicy "github.com/0x726f6f6b6965/go-auth/protos/policy/v1"
	pbUser "github.com/0x726f6f6b6965/go-auth/protos/user/v1"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/go-redis/redismock/v9"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestUserLogin(t *testing.T) {
	ser, cleanup, mock, _, auth, err := initUserService()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	ctx := context.Background()
	roleId := 3
	userId := 1
	t.Run("success", func(t *testing.T) {
		req := &pbUser.LoginRequest{
			Email:    "abc@gmail.com",
			Password: "123456",
		}
		salt := helper.CreateNewSalt()
		pwd, _ := salt.SaltInput(req.Password)

		mock.MatchExpectationsInOrder(true)
		mock.ExpectQuery("SELECT * FROM \"t_user\" WHERE email = $1 ORDER BY \"t_user\".\"id\" LIMIT $2").
			WithArgs(req.Email, 1).
			WillReturnRows(sqlmock.NewRows(
				[]string{"id", "username", "password", "salt", "email", "validate", "create_time", "update_time"}).
				AddRow(userId, "test-user", pwd, salt.SaltString, req.Email, true, time.Now(), time.Now()))
		mock.ExpectQuery("SELECT * FROM \"r_user_role\" WHERE \"r_user_role\".\"user_id\" = $1").
			WithArgs(1).WillReturnRows(sqlmock.NewRows(
			[]string{"user_id", "role_id", "create_time", "update_time"}).
			AddRow(userId, roleId, time.Now(), time.Now()))

		mock.ExpectQuery("SELECT * FROM \"t_role\" WHERE \"t_role\".\"id\" = $1").
			WithArgs(roleId).
			WillReturnRows(sqlmock.NewRows(
				[]string{"id", "role_name", "create_time", "update_time"}).
				AddRow(roleId, pbPolicy.RoleType_ROLE_TYPE_NORMAL.String(), time.Now(), time.Now()))
		resp, err := ser.Login(ctx, req)
		assert.Nil(t, err)
		token, err := auth.ExtractTokenMetadata(&http.Request{
			Header: map[string][]string{
				"Authorization": {fmt.Sprintf("Bear %s", resp.AccessToken)},
			},
		}, false)
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, req.Email, token.Subject)
		assert.Equal(t, pbPolicy.RoleType_ROLE_TYPE_NORMAL.String(), token.Roles[0])
	})

	t.Run("failed by wrong password", func(t *testing.T) {
		req := &pbUser.LoginRequest{
			Email:    "abc@gmail.com",
			Password: "abc",
		}
		correctPWD := "123456"
		salt := helper.CreateNewSalt()
		pwd, _ := salt.SaltInput(correctPWD)

		mock.MatchExpectationsInOrder(true)
		mock.ExpectQuery("SELECT * FROM \"t_user\" WHERE email = $1 ORDER BY \"t_user\".\"id\" LIMIT $2").
			WithArgs(req.Email, 1).
			WillReturnRows(sqlmock.NewRows(
				[]string{"id", "username", "password", "salt", "email", "validate", "create_time", "update_time"}).
				AddRow(userId, "test-user", pwd, salt.SaltString, req.Email, true, time.Now(), time.Now()))
		mock.ExpectQuery("SELECT * FROM \"r_user_role\" WHERE \"r_user_role\".\"user_id\" = $1").
			WithArgs(1).WillReturnRows(sqlmock.NewRows(
			[]string{"user_id", "role_id", "create_time", "update_time"}).
			AddRow(userId, roleId, time.Now(), time.Now()))

		mock.ExpectQuery("SELECT * FROM \"t_role\" WHERE \"t_role\".\"id\" = $1").
			WithArgs(roleId).
			WillReturnRows(sqlmock.NewRows(
				[]string{"id", "role_name", "create_time", "update_time"}).
				AddRow(roleId, pbPolicy.RoleType_ROLE_TYPE_NORMAL.String(), time.Now(), time.Now()))
		_, err := ser.Login(ctx, req)
		assert.NotNil(t, err)
		assert.ErrorIs(t, err, ErrPassword)
	})

	t.Run("failed by user not exist", func(t *testing.T) {
		req := &pbUser.LoginRequest{
			Email:    "abc@gmail.com",
			Password: "abc",
		}

		mock.MatchExpectationsInOrder(true)
		mock.ExpectQuery("SELECT * FROM \"t_user\" WHERE email = $1 ORDER BY \"t_user\".\"id\" LIMIT $2").
			WithArgs(req.Email, 1).
			WillReturnError(gorm.ErrRecordNotFound)
		_, err := ser.Login(ctx, req)
		assert.NotNil(t, err)
		assert.ErrorIs(t, err, ErrRecordNotFound)
	})

	t.Run("failed by db error", func(t *testing.T) {
		req := &pbUser.LoginRequest{
			Email:    "abc@gmail.com",
			Password: "abc",
		}

		mock.MatchExpectationsInOrder(true)
		mock.ExpectQuery("SELECT * FROM \"t_user\" WHERE email = $1 ORDER BY \"t_user\".\"id\" LIMIT $2").
			WithArgs(req.Email, 1).
			WillReturnError(gorm.ErrInvalidDB)
		_, err := ser.Login(ctx, req)
		assert.NotNil(t, err)
		assert.ErrorIs(t, err, ErrDB)
	})
}

func TestCreateUser(t *testing.T) {
	ser, cleanup, mock, _, auth, err := initUserService()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	ctx := context.Background()
	roleId := 3
	userId := 1
	t.Run("success", func(t *testing.T) {
		req := &pbUser.CreateUserRequest{
			Username: "abc",
			Password: "123456",
			Email:    "abcde@gmail.com",
		}
		testSalt = helper.CreateNewSalt()
		pwd, _ := testSalt.SaltInput(req.Password)

		mock.ExpectQuery("SELECT * FROM \"t_user\" WHERE email = $1 ORDER BY \"t_user\".\"id\" LIMIT $2").
			WithArgs(req.Email, 1).
			WillReturnError(gorm.ErrRecordNotFound)
		mock.ExpectBegin()
		mock.ExpectQuery("INSERT INTO \"t_user\" (\"username\",\"password\",\"salt\",\"email\",\"validate\") VALUES ($1,$2,$3,$4,$5) RETURNING \"id\",\"create_time\",\"update_time\"").
			WithArgs(req.Username, pwd, testSalt.SaltString, req.Email, false).
			WillReturnRows(sqlmock.NewRows(
				[]string{"id", "create_time", "update_time"}).
				AddRow(userId, time.Now(), time.Now()))
		mock.ExpectQuery("INSERT INTO \"t_role\" (\"role_name\") VALUES ($1) ON CONFLICT DO NOTHING RETURNING \"create_time\",\"update_time\",\"id\"").
			WithArgs(pbPolicy.RoleType_ROLE_TYPE_NORMAL.String()).
			WillReturnRows(sqlmock.NewRows(
				[]string{"create_time", "update_time", "id"}).
				AddRow(time.Now(), time.Now(), roleId))
		mock.ExpectExec("INSERT INTO \"r_user_role\" (\"user_id\",\"role_id\") VALUES ($1,$2) ON CONFLICT DO NOTHING").
			WithArgs(userId, roleId).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()
		resp, err := ser.CreateUser(ctx, req)
		assert.Nil(t, err)
		token, err := auth.ExtractTokenMetadata(&http.Request{
			Header: map[string][]string{
				"Authorization": {fmt.Sprintf("Bear %s", resp.AccessToken)},
			},
		}, false)
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, req.Email, token.Subject)
		assert.Equal(t, pbPolicy.RoleType_ROLE_TYPE_NORMAL.String(), token.Roles[0])
	})

	t.Run("email exist", func(t *testing.T) {
		req := &pbUser.CreateUserRequest{
			Username: "abc",
			Password: "123456",
			Email:    "abcde@gmail.com",
		}
		testSalt = helper.CreateNewSalt()
		pwd, _ := testSalt.SaltInput(req.Password)

		mock.ExpectQuery("SELECT * FROM \"t_user\" WHERE email = $1 ORDER BY \"t_user\".\"id\" LIMIT $2").
			WithArgs(req.Email, 1).
			WillReturnRows(sqlmock.NewRows(
				[]string{"id", "username", "password", "salt", "email", "validate", "create_time", "update_time"}).
				AddRow(userId, "test-user", pwd, testSalt.SaltString, req.Email, true, time.Now(), time.Now()))
		_, err := ser.CreateUser(ctx, req)
		assert.NotNil(t, err)
		assert.ErrorIs(t, err, ErrRecordExist)
	})

	t.Run("chek email failed by db error", func(t *testing.T) {
		req := &pbUser.CreateUserRequest{
			Username: "abc",
			Password: "123456",
			Email:    "abcde@gmail.com",
		}
		testSalt = helper.CreateNewSalt()
		pwd, _ := testSalt.SaltInput(req.Password)

		mock.ExpectQuery("SELECT * FROM \"t_user\" WHERE email = $1 ORDER BY \"t_user\".\"id\" LIMIT $2").
			WithArgs(req.Email, 1).
			WillReturnError(gorm.ErrRecordNotFound)
		mock.ExpectBegin()
		mock.ExpectQuery("INSERT INTO \"t_user\" (\"username\",\"password\",\"salt\",\"email\",\"validate\") VALUES ($1,$2,$3,$4,$5) RETURNING \"id\",\"create_time\",\"update_time\"").
			WithArgs(req.Username, pwd, testSalt.SaltString, req.Email, false).
			WillReturnError(gorm.ErrInvalidDB)
		mock.ExpectCommit()
		_, err := ser.CreateUser(ctx, req)
		assert.NotNil(t, err)
		assert.ErrorIs(t, err, ErrDB)
	})

	t.Run("insert data failed by db error", func(t *testing.T) {
		req := &pbUser.CreateUserRequest{
			Username: "abc",
			Password: "123456",
			Email:    "abcde@gmail.com",
		}

		testSalt = helper.CreateNewSalt()
		pwd, _ := testSalt.SaltInput(req.Password)

		mock.ExpectQuery("SELECT * FROM \"t_user\" WHERE email = $1 ORDER BY \"t_user\".\"id\" LIMIT $2").
			WithArgs(req.Email, 1).
			WillReturnError(gorm.ErrRecordNotFound)
		mock.ExpectBegin()
		mock.ExpectQuery("INSERT INTO \"t_user\" (\"username\",\"password\",\"salt\",\"email\",\"validate\") VALUES ($1,$2,$3,$4,$5) RETURNING \"id\",\"create_time\",\"update_time\"").
			WithArgs(req.Username, pwd, testSalt.SaltString, req.Email, false).
			WillReturnError(gorm.ErrInvalidDB)
		mock.ExpectCommit()
		_, err := ser.CreateUser(ctx, req)
		assert.NotNil(t, err)
		assert.ErrorIs(t, err, ErrDB)
	})
}

func TestUpdateToken(t *testing.T) {
	ser, cleanup, _, _, auth, err := initUserService()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	ctx := context.Background()

	t.Run("update token", func(t *testing.T) {
		req := &pbUser.UpdateTokenRequest{
			Subject: "test-user",
			Roles:   []string{pbPolicy.RoleType_ROLE_TYPE_NORMAL.String()},
		}
		resp, err := ser.UpdateToken(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		access, err := auth.ExtractTokenMetadata(&http.Request{
			Header: map[string][]string{
				"Authorization": {fmt.Sprintf("Bear %s", resp.AccessToken)},
			},
		}, false)
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, "test-user", access.Subject)
		assert.True(t, access.ExpiresAt.After(time.Now()))
	})
}

func TestUpdateUser(t *testing.T) {
	ser, cleanup, mock, _, _, err := initUserService()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	ctx := context.Background()
	userId := 1

	t.Run("success", func(t *testing.T) {
		req := &pbUser.UpdateUserRequest{
			User: &pbUser.User{
				Email:    "adc@gmail.com",
				Password: "567",
			},
			UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"user.password"}},
		}
		mock.ExpectQuery("SELECT * FROM \"t_user\" WHERE email = $1 ORDER BY \"t_user\".\"id\" LIMIT $2").
			WithArgs(req.User.Email, 1).
			WillReturnRows(sqlmock.NewRows(
				[]string{"id", "username", "password", "salt", "email", "validate", "create_time", "update_time"}).
				AddRow(userId, "test-user", "123456", "123456", req.User.Email, true, time.Now(), time.Now()))
		mock.ExpectBegin()
		mock.ExpectExec("UPDATE \"t_user\" SET \"password\"=$1 WHERE id = $2").
			WithArgs(req.User.Password, userId).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()
		_, err := ser.UpdateUser(ctx, req)
		assert.Nil(t, err)
	})

	t.Run("empty update mask", func(t *testing.T) {
		req := &pbUser.UpdateUserRequest{
			User: &pbUser.User{
				Email:    "XXXXXXXXXXXXX",
				Password: "567",
			},
			UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{}},
		}
		_, err := ser.UpdateUser(ctx, req)
		assert.NotNil(t, err)
		assert.ErrorIs(t, err, ErrorInvalid)
	})

	t.Run("empty user", func(t *testing.T) {
		req := &pbUser.UpdateUserRequest{
			UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"a.b.c"}},
		}
		_, err := ser.UpdateUser(ctx, req)
		assert.NotNil(t, err)
		assert.ErrorIs(t, err, ErrorInvalid)
	})

	t.Run("error update mask", func(t *testing.T) {
		req := &pbUser.UpdateUserRequest{
			User: &pbUser.User{
				Email:    "XXXXXXXXXXXXX",
				Password: "567",
			},
			UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"a.b.c"}},
		}
		_, err := ser.UpdateUser(ctx, req)
		assert.NotNil(t, err)
		assert.ErrorIs(t, err, ErrorInvalid)
	})

	t.Run("user not found", func(t *testing.T) {
		req := &pbUser.UpdateUserRequest{
			User: &pbUser.User{
				Email:    "adc@gmail.com",
				Password: "567",
			},
			UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"user.password"}},
		}
		mock.ExpectQuery("SELECT * FROM \"t_user\" WHERE email = $1 ORDER BY \"t_user\".\"id\" LIMIT $2").
			WithArgs(req.User.Email, 1).
			WillReturnError(gorm.ErrRecordNotFound)
		_, err := ser.UpdateUser(ctx, req)
		assert.NotNil(t, err)
		assert.ErrorIs(t, err, ErrRecordNotFound)
	})

	t.Run("db error when find user", func(t *testing.T) {
		req := &pbUser.UpdateUserRequest{
			User: &pbUser.User{
				Email:    "adc@gmail.com",
				Password: "567",
			},
			UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"user.password"}},
		}
		mock.ExpectQuery("SELECT * FROM \"t_user\" WHERE email = $1 ORDER BY \"t_user\".\"id\" LIMIT $2").
			WithArgs(req.User.Email, 1).
			WillReturnError(gorm.ErrInvalidDB)
		_, err := ser.UpdateUser(ctx, req)
		assert.NotNil(t, err)
		assert.ErrorIs(t, err, ErrDB)
	})
}

func TestUserLogout(t *testing.T) {
	ser, cleanup, _, rmock, auth, err := initUserService()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		access, err := auth.GenerateNewAccessToken("test-user", []string{"role-1"})
		if err != nil {
			t.Fatal(err)
		}
		refresh, err := auth.GenerateNewRefreshToken("test-user", []string{"role-1"})
		if err != nil {
			t.Fatal(err)
		}
		req := &pbUser.LogoutRequest{
			Token: &pbUser.Token{
				AccessToken:  access,
				RefreshToken: refresh,
			},
		}
		rmock.ExpectGet(fmt.Sprintf(LOGOUT_KEY, refresh)).SetErr(redis.Nil)
		rmock.ExpectSet(fmt.Sprintf(LOGOUT_KEY, access), true, auth.GetAccessExpire()).SetVal("OK")
		rmock.ExpectSet(fmt.Sprintf(LOGOUT_KEY, refresh), true, auth.GetRefreshExpire()).SetVal("OK")
		_, err = ser.Logout(ctx, req)
		assert.Nil(t, err)
	})

	t.Run("already logout", func(t *testing.T) {
		access, err := auth.GenerateNewAccessToken("test-user", []string{"role-1"})
		if err != nil {
			t.Fatal(err)
		}
		refresh, err := auth.GenerateNewRefreshToken("test-user", []string{"role-1"})
		if err != nil {
			t.Fatal(err)
		}
		req := &pbUser.LogoutRequest{
			Token: &pbUser.Token{
				AccessToken:  access,
				RefreshToken: refresh,
			},
		}
		rmock.ExpectGet(fmt.Sprintf(LOGOUT_KEY, refresh)).SetVal("true")
		_, err = ser.Logout(ctx, req)
		assert.Nil(t, err)
	})

	t.Run("invalid token", func(t *testing.T) {
		access, err := auth.GenerateNewAccessToken("test-user", []string{"role-1"})
		if err != nil {
			t.Fatal(err)
		}
		refresh, err := auth.GenerateNewRefreshToken("test-user", []string{"role-1"})
		if err != nil {
			t.Fatal(err)
		}
		req := &pbUser.LogoutRequest{
			Token: &pbUser.Token{
				AccessToken:  refresh,
				RefreshToken: access,
			},
		}
		_, err = ser.Logout(ctx, req)
		assert.NotNil(t, err)
		assert.ErrorIs(t, err, ErrorInvalid)
	})

	t.Run("error getting refresh cache", func(t *testing.T) {
		access, err := auth.GenerateNewAccessToken("test-user", []string{"role-1"})
		if err != nil {
			t.Fatal(err)
		}
		refresh, err := auth.GenerateNewRefreshToken("test-user", []string{"role-1"})
		if err != nil {
			t.Fatal(err)
		}
		req := &pbUser.LogoutRequest{
			Token: &pbUser.Token{
				AccessToken:  access,
				RefreshToken: refresh,
			},
		}
		rmock.ExpectGet(fmt.Sprintf(LOGOUT_KEY, refresh)).SetErr(fmt.Errorf("unknow"))
		_, err = ser.Logout(ctx, req)
		assert.NotNil(t, err)
		assert.ErrorIs(t, err, ErrDB)
	})

	t.Run("error setting access cache", func(t *testing.T) {
		access, err := auth.GenerateNewAccessToken("test-user", []string{"role-1"})
		if err != nil {
			t.Fatal(err)
		}
		refresh, err := auth.GenerateNewRefreshToken("test-user", []string{"role-1"})
		if err != nil {
			t.Fatal(err)
		}
		req := &pbUser.LogoutRequest{
			Token: &pbUser.Token{
				AccessToken:  access,
				RefreshToken: refresh,
			},
		}
		rmock.ExpectGet(fmt.Sprintf(LOGOUT_KEY, refresh)).SetErr(redis.Nil)
		rmock.ExpectSet(fmt.Sprintf(LOGOUT_KEY, access), true, auth.GetAccessExpire()).SetErr(fmt.Errorf("unknow"))
		_, err = ser.Logout(ctx, req)
		assert.NotNil(t, err)
		assert.ErrorIs(t, err, ErrDB)
	})

	t.Run("error setting refresh cache", func(t *testing.T) {
		access, err := auth.GenerateNewAccessToken("test-user", []string{"role-1"})
		if err != nil {
			t.Fatal(err)
		}
		refresh, err := auth.GenerateNewRefreshToken("test-user", []string{"role-1"})
		if err != nil {
			t.Fatal(err)
		}
		req := &pbUser.LogoutRequest{
			Token: &pbUser.Token{
				AccessToken:  access,
				RefreshToken: refresh,
			},
		}
		rmock.ExpectGet(fmt.Sprintf(LOGOUT_KEY, refresh)).SetErr(redis.Nil)
		rmock.ExpectSet(fmt.Sprintf(LOGOUT_KEY, access), true, auth.GetAccessExpire()).SetVal("OK")
		rmock.ExpectSet(fmt.Sprintf(LOGOUT_KEY, refresh), true, auth.GetRefreshExpire()).SetErr(fmt.Errorf("unknow"))
		_, err = ser.Logout(ctx, req)
		assert.NotNil(t, err)
		assert.ErrorIs(t, err, ErrDB)
	})
}

func initUserService() (pbUser.UserServiceServer, func() error, sqlmock.Sqlmock, redismock.ClientMock, *jwtauth.JwtAuth, error) {
	logger, _ := zap.NewDevelopment()
	os.Setenv("test-access", "test-access")
	os.Setenv("test-refresh", "test-refresh")
	cfg := &jwtauth.Config{
		Issuer:        "test-issuer",
		AccessSecret:  "test-access",
		RefreshSecret: "test-refresh",
		ExpiresIn:     10,
	}
	auth := jwtauth.NewJWTAuth(cfg)
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	if err != nil {
		return nil, func() error { return nil }, nil, nil, nil, err
	}
	gormdb, err := gorm.Open(postgres.New(postgres.Config{
		Conn: db,
	}), &gorm.Config{})
	if err != nil {
		return nil, db.Close, mock, nil, nil, err
	}

	rdb, rmock := redismock.NewClientMock()
	redisClient := &cache.RedisCache{
		Client: rdb,
	}
	ser := NewUserService(auth, gormdb.Debug(), redisClient, logger)
	return ser, func() error {
		db.Close()
		rdb.Close()
		return nil
	}, mock, rmock, auth, nil
}
