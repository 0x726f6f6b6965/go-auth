package services

import "errors"

var (
	ErrDB             = errors.New("database error")
	ErrRecordExist    = errors.New("data already exist")
	ErrRecordNotFound = errors.New("data not found")
	ErrSalt           = errors.New("salt error")
	ErrCreateToken    = errors.New("create token error")
	ErrPassword       = errors.New("password error")
	ErrorInvalid      = errors.New("invalid")
	ErrorOPA          = errors.New("opa error")
	ErrorTransaction  = errors.New("transaction error")
)
