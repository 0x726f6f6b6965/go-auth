package jwtauth

import "errors"

var (
	ErrTokenExpired     error = errors.New("token is expired")
	ErrTokenInvalid     error = errors.New("token is invalid")
	ErrTokenNotValidYet error = errors.New("token is not valid yet")
	ErrTokenNotValid    error = errors.New("token is not valid")
	ErrTokenParse       error = errors.New("error while parsing token")
)
