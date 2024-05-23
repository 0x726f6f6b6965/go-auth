package jwtauth

import (
	"fmt"
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractTokenMetadata(t *testing.T) {
	os.Setenv("test-access", "test-access")
	os.Setenv("test-refresh", "test-refresh")
	cfg := &Config{
		Issuer:        "test-issuer",
		AccessSecret:  "test-access",
		RefreshSecret: "test-refresh",
		ExpiresIn:     5,
	}
	auth := NewJWTAuth(cfg)
	t.Run("success access", func(t *testing.T) {
		token, err := auth.GenerateNewAccessToken("abc", []string{"test"})
		if err != nil {
			t.Error(err)
		}
		req := &http.Request{
			Header: map[string][]string{
				"Authorization": {fmt.Sprintf("Bear %s", token)},
			},
		}
		metadata, err := auth.ExtractTokenMetadata(req, false)
		if err != nil {
			t.Error(err)
		}
		assert.Equal(t, "abc", metadata.Subject)
	})

	t.Run("success refresh", func(t *testing.T) {
		token, err := auth.GenerateNewRefreshToken("abc", []string{"test"})
		if err != nil {
			t.Error(err)
		}
		req := &http.Request{
			Header: map[string][]string{
				"Authorization": {fmt.Sprintf("Bear %s", token)},
			},
		}
		metadata, err := auth.ExtractTokenMetadata(req, true)
		if err != nil {
			t.Error(err)
		}
		assert.Equal(t, "abc", metadata.Subject)
	})

	t.Run("invalid error", func(t *testing.T) {
		token, err := auth.GenerateNewRefreshToken("abc", []string{"test"})
		if err != nil {
			t.Error(err)
		}
		req := &http.Request{
			Header: map[string][]string{
				"Authorization": {fmt.Sprintf("Bear %s", token)},
			},
		}
		_, err = auth.ExtractTokenMetadata(req, false)
		assert.NotNil(t, err)
		assert.ErrorIs(t, err, ErrTokenInvalid)
	})

	t.Run("expire", func(t *testing.T) {
		auth.accessExpire = 0
		token, err := auth.GenerateNewAccessToken("abc", []string{"test"})
		if err != nil {
			t.Error(err)
		}
		req := &http.Request{
			Header: map[string][]string{
				"Authorization": {fmt.Sprintf("Bear %s", token)},
			},
		}
		_, err = auth.ExtractTokenMetadata(req, false)
		assert.NotNil(t, err)
		assert.ErrorIs(t, err, ErrTokenExpired)
	})

	t.Run("unknow error", func(t *testing.T) {
		auth.accessExpire = 0
		token, err := auth.GenerateNewAccessToken("abc", []string{"test"})
		if err != nil {
			t.Error(err)
		}
		req := &http.Request{
			Header: map[string][]string{
				"Authorization": {token},
			},
		}
		_, err = auth.ExtractTokenMetadata(req, false)
		assert.NotNil(t, err)
	})
}
